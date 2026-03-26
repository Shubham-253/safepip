"""
safepip.honeypot — Fake credential bait for the import sandbox.

The sandbox evasion problem:
  Sophisticated supply chain malware checks os.environ or reads ~/.aws/credentials
  BEFORE doing anything malicious. In a stripped environment, it sees nothing
  and behaves cleanly. In a real developer environment it steals everything.

The honeypot solution:
  Populate the fake home directory with realistic-looking but completely fake
  credentials, then observe whether the package:
    1. Reads any of those files, AND
    2. Makes a network call shortly after

  A package that reads ~/.aws/credentials and then calls socket.connect
  is a credential stealer — even if no static analysis pattern matched.

Fake credential design:
  - AWS key format: AKIA + 16 uppercase alphanumeric (passes format validation)
  - No real account behind them — they will fail if actually used
  - Unique per sandbox run (so they can't be cached/pre-blocked by attackers)
  - The SSH key is a real RSA key format but with random bytes — not valid
  - The .env file uses realistic variable names seen in real AI/ML projects

Detection logic:
  The probe script records (file_read_event, timestamp) and (network_event, timestamp).
  If any network call happens within READ_THEN_NETWORK_WINDOW_S seconds after
  a credential file read, the sequence is flagged as credential exfiltration.
"""

from __future__ import annotations

import hashlib
import os
import random
import string
import tempfile
import time
from pathlib import Path


# How many seconds between a cred file read and a network call
# still counts as "read then exfiltrate" sequence
READ_THEN_NETWORK_WINDOW_S = 5.0


def _random_upper_alnum(n: int, seed: str = "") -> str:
    """Generate a deterministic-but-unique uppercase alphanumeric string."""
    rng = random.Random(seed + str(time.monotonic_ns()))
    return "".join(rng.choices(string.ascii_uppercase + string.digits, k=n))


def _fake_aws_key_id(seed: str = "") -> str:
    """Realistic AWS access key ID format: AKIA + 16 chars."""
    return "AKIA" + _random_upper_alnum(16, seed + "keyid")


def _fake_aws_secret(seed: str = "") -> str:
    """Realistic AWS secret: 40 base64-ish chars."""
    chars = string.ascii_letters + string.digits + "+/"
    rng = random.Random(seed + "secret" + str(time.monotonic_ns()))
    return "".join(rng.choices(chars, k=40))


def _fake_rsa_private_key() -> str:
    """
    A syntactically valid PEM private key header/footer with random body.
    Not a real key — will fail any crypto operation — but looks real to a scanner
    that grabs the file without validating it.
    """
    rng = random.Random(time.monotonic_ns())
    # 1700 bytes of random base64 body (realistic RSA-2048 PEM size)
    body_bytes = bytes(rng.randint(0, 255) for _ in range(1275))
    import base64
    b64 = base64.b64encode(body_bytes).decode()
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    body = "\n".join(lines)
    return f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n"


def populate_honeypot_home(fake_home: Path, seed: str = "") -> dict:
    """
    Populate a fake home directory with realistic-looking credential files.

    Returns a dict mapping each bait file path to what credential type it represents,
    so the caller can identify *which* credential was read.
    """
    bait_files: dict[str, str] = {}

    aws_key_id = _fake_aws_key_id(seed)
    aws_secret = _fake_aws_secret(seed)

    # ~/.aws/credentials
    aws_dir = fake_home / ".aws"
    aws_dir.mkdir(parents=True, exist_ok=True)
    aws_creds = aws_dir / "credentials"
    aws_creds.write_text(
        f"[default]\n"
        f"aws_access_key_id = {aws_key_id}\n"
        f"aws_secret_access_key = {aws_secret}\n"
        f"region = us-east-1\n"
    )
    bait_files[str(aws_creds)] = "aws_credentials"

    # ~/.aws/config
    (aws_dir / "config").write_text(
        "[default]\nregion = us-east-1\noutput = json\n"
    )
    bait_files[str(aws_dir / "config")] = "aws_config"

    # ~/.ssh/id_rsa
    ssh_dir = fake_home / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    id_rsa = ssh_dir / "id_rsa"
    id_rsa.write_text(_fake_rsa_private_key())
    id_rsa.chmod(0o600)
    bait_files[str(id_rsa)] = "ssh_private_key"

    # ~/.kube/config
    kube_dir = fake_home / ".kube"
    kube_dir.mkdir(parents=True, exist_ok=True)
    fake_token = _random_upper_alnum(32, seed + "kubetoken").lower()
    (kube_dir / "config").write_text(
        f"apiVersion: v1\nclusters:\n- cluster:\n    server: https://fake-k8s.local\n"
        f"  name: fake-cluster\ncontexts:\n- context:\n    cluster: fake-cluster\n"
        f"    user: fake-user\n  name: fake-context\ncurrent-context: fake-context\n"
        f"kind: Config\nusers:\n- name: fake-user\n  user:\n    token: {fake_token}\n"
    )
    bait_files[str(kube_dir / "config")] = "kubeconfig"

    # ~/.env (common in AI/ML projects)
    dotenv = fake_home / ".env"
    fake_openai = "sk-" + _random_upper_alnum(48, seed + "openai").lower()
    fake_anthropic = "sk-ant-" + _random_upper_alnum(40, seed + "anthropic").lower()
    dotenv.write_text(
        f"OPENAI_API_KEY={fake_openai}\n"
        f"ANTHROPIC_API_KEY={fake_anthropic}\n"
        f"DATABASE_URL=postgresql://user:fakepass@localhost/mydb\n"
        f"SECRET_KEY={_random_upper_alnum(32, seed + 'django')}\n"
    )
    bait_files[str(dotenv)] = "dotenv_api_keys"

    # ~/.config/gcloud/application_default_credentials.json
    gcloud_dir = fake_home / ".config" / "gcloud"
    gcloud_dir.mkdir(parents=True, exist_ok=True)
    (gcloud_dir / "application_default_credentials.json").write_text(
        '{"type": "authorized_user", '
        '"client_id": "fake-client-id.apps.googleusercontent.com", '
        '"client_secret": "fake-client-secret", '
        '"refresh_token": "1//fake-' + _random_upper_alnum(20, seed + "gcp").lower() + '"'
        "}\n"
    )
    bait_files[str(gcloud_dir / "application_default_credentials.json")] = "gcp_credentials"

    return bait_files


# ---------------------------------------------------------------------------
# Updated probe script with honeypot awareness
# ---------------------------------------------------------------------------
# This replaces the probe script in sandbox.py when honeypot mode is active.

HONEYPOT_PROBE_SCRIPT = r"""
import sys, os, json, time, site

_events = []
_start = time.monotonic()
_bait_paths = set(json.loads(sys.argv[2])) if len(sys.argv) > 2 else set()
_sandbox_dir = sys.argv[3] if len(sys.argv) > 3 else ""

def _audit(event, args):
    elapsed = round(time.monotonic() - _start, 3)

    if event in ("socket.connect", "socket.getaddrinfo"):
        host = ""
        if event == "socket.getaddrinfo" and args:
            host = str(args[0])
        elif event == "socket.connect" and args and len(args) > 1:
            addr = args[1]
            host = str(addr[0]) if isinstance(addr, (tuple, list)) else str(addr)
        _events.append({"type": "network", "event": event,
                        "host": host, "args": str(args)[:200], "t": elapsed})

    elif event in ("open", "io.open") and args:
        path = os.path.abspath(str(args[0])) if args else ""
        if path in _bait_paths:
            _events.append({"type": "bait_read", "path": path, "t": elapsed})
        path_lower = path.lower()
        cred_anchors = ("/.aws/", "/.ssh/id_", "/.kube/config",
                        "/.config/gcloud", "/.env", "/.azure/")
        if any(p in path_lower for p in cred_anchors) and path not in _bait_paths:
            _events.append({"type": "file_read", "path": path, "t": elapsed})

    elif event == "subprocess.Popen":
        _events.append({"type": "subprocess", "args": str(args)[:200], "t": elapsed})

    elif event == "os.system":
        _events.append({"type": "os_system", "args": str(args)[:200], "t": elapsed})

sys.addaudithook(_audit)

# ── Process .pth files AFTER hook is installed ────────────────────────────────
# Hook is now active. Manually call site.addpackage for each .pth in the
# extracted wheel dir, so .pth payloads fire INSIDE our audit hook's scope.
# This catches the exact LiteLLM 1.82.8 attack vector.
if _sandbox_dir and os.path.isdir(_sandbox_dir):
    known = set()
    for fname in os.listdir(_sandbox_dir):
        if fname.endswith(".pth"):
            try:
                site.addpackage(_sandbox_dir, fname, known)
            except Exception:
                pass

# ── Attempt the import ────────────────────────────────────────────────────────
pkg = sys.argv[1] if len(sys.argv) > 1 else ""
import_error = None
import_time = None

try:
    t0 = time.monotonic()
    __import__(pkg)
    import_time = round(time.monotonic() - t0, 3)
except Exception as e:
    import_error = f"{type(e).__name__}: {e}"

# ── Detect read-then-exfiltrate sequence ──────────────────────────────────────
bait_reads = [e for e in _events if e["type"] == "bait_read"]
network_events = [e for e in _events if e["type"] == "network"]

exfil_sequences = []
for br in bait_reads:
    for ne in network_events:
        delta = ne["t"] - br["t"]
        if -0.5 <= delta <= 5.0:
            exfil_sequences.append({
                "bait_file": br["path"],
                "network_event": ne,
                "delta_s": round(delta, 3),
            })

result = {
    "pkg": pkg,
    "import_ok": import_error is None,
    "import_time": import_time,
    "import_error": import_error,
    "events": _events,
    "exfil_sequences": exfil_sequences,
    "bait_reads": bait_reads,
}
print(json.dumps(result))
"""
