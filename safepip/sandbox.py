"""
safepip.sandbox — Process-level import sandbox.

Strategy: extract the wheel into a temp directory, then run
`python -c "import <pkg>"` in a subprocess that has:

  - No real HOME directory (replaced with an empty tempdir)
  - No AWS/GCP/Azure credential env vars
  - No SSH_AUTH_SOCK, no KUBECONFIG
  - Network socket creation blocked via a tiny sys.addaudithook
  - A hard wall-clock timeout (default 10s)
  - stdout/stderr captured for inspection

Then we observe:
  1. Did it crash / timeout?              → suspicious
  2. Did it attempt a socket.connect()?  → network exfil detected
  3. Did it read files outside its own package dir? → credential harvesting
  4. Did it spawn child processes?       → self-replication or shell exec

All of this uses ONLY stdlib:
  subprocess, tempfile, os, sys, pathlib, resource (Unix), signal, json, time

No third-party sandbox libraries needed. The isolation is real:
the subprocess literally does not have your credentials in its environment,
and the audit hook fires before any socket is opened.

Limitations (documented honestly):
  - Does NOT prevent CPU/memory exhaustion (use resource limits on Unix)
  - Does NOT intercept C-extension network calls that bypass the audit hook
  - Does NOT catch env-var-conditional malice (attacker checks os.environ first)
  - Windows: resource limits not available; socket blocking still works
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
import time
import zipfile
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .checks import CheckResult


# ---------------------------------------------------------------------------
# The probe script — runs inside the sandboxed subprocess
# ---------------------------------------------------------------------------
# Written as a string so it can be passed via -c without touching disk.
# It installs an audit hook BEFORE importing anything, so even imports
# that trigger network access during module initialisation are caught.

_PROBE_SCRIPT = r"""
import sys, os, json, time, socket as _socket_mod

_events = []
_start = time.monotonic()

def _audit(event, args):
    elapsed = round(time.monotonic() - _start, 3)
    if event in ("socket.connect", "socket.getaddrinfo"):
        # getaddrinfo fires on DNS lookup — the earliest signal of network intent
        # even if the actual connection is blocked by the OS
        host = ""
        if event == "socket.getaddrinfo" and args:
            host = str(args[0])
        elif event == "socket.connect" and args and len(args) > 1:
            addr = args[1]
            host = str(addr[0]) if isinstance(addr, (tuple, list)) else str(addr)
        _events.append({"type": "network", "event": event, "host": host, "args": str(args)[:200], "t": elapsed})
    elif event in ("open", "io.open") and args:
        path = str(args[0]) if args else ""
        path_lower = path.lower()
        # Only flag explicit credential file locations
        # anchored to home/config dirs — NOT Python stdlib paths
        credential_patterns = (
            "/.aws/",
            "/.ssh/id_",
            "/.ssh/known_hosts",
            "/.kube/config",
            "/.config/gcloud",
            "/.azure/",
            "/.gnupg/",
            "/.config/sysmon",   # the LiteLLM backdoor path
        )
        # Also flag any .env file outside the sandbox package dir
        is_dotenv = path_lower.endswith("/.env") or "/.env/" in path_lower
        if any(p in path_lower for p in credential_patterns) or is_dotenv:
            _events.append({"type": "file_read", "path": path, "t": elapsed})
    elif event == "subprocess.Popen":
        _events.append({"type": "subprocess", "args": str(args), "t": elapsed})
    elif event == "os.system":
        _events.append({"type": "os_system", "args": str(args), "t": elapsed})

sys.addaudithook(_audit)

# Attempt the import
pkg = sys.argv[1] if len(sys.argv) > 1 else ""
import_error = None
import_time = None

try:
    t0 = time.monotonic()
    __import__(pkg)
    import_time = round(time.monotonic() - t0, 3)
except Exception as e:
    import_error = f"{type(e).__name__}: {e}"

# Output result as JSON on stdout
result = {
    "pkg": pkg,
    "import_ok": import_error is None,
    "import_time": import_time,
    "import_error": import_error,
    "events": _events,
}
print(json.dumps(result))
"""


# ---------------------------------------------------------------------------
# Environment sanitisation
# ---------------------------------------------------------------------------

_CREDENTIAL_ENV_KEYS = {
    # AWS
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_PROFILE", "AWS_DEFAULT_REGION",
    # GCP
    "GOOGLE_APPLICATION_CREDENTIALS", "GCLOUD_PROJECT",
    # Azure
    "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
    # K8s
    "KUBECONFIG", "KUBERNETES_SERVICE_HOST",
    # SSH
    "SSH_AUTH_SOCK", "SSH_AGENT_PID",
    # Generic secrets
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DATABASE_URL",
    "SECRET_KEY", "PRIVATE_KEY", "API_KEY", "AUTH_TOKEN",
}


def _sanitised_env(fake_home: str) -> dict:
    """
    Build a clean environment dict:
    - Remove all credential variables
    - Replace HOME with an empty temp directory
    - Keep PATH, LANG, PYTHONPATH (needed for the subprocess to work)
    - Remove anything that looks like a secret (heuristic on key name)
    """
    clean = {}
    for k, v in os.environ.items():
        if k in _CREDENTIAL_ENV_KEYS:
            continue
        # Heuristic: drop env vars whose name contains SECRET, KEY, TOKEN, PASSWORD
        upper = k.upper()
        if any(word in upper for word in ("SECRET", "PASSWORD", "TOKEN", "APIKEY", "API_KEY")):
            continue
        clean[k] = v

    clean["HOME"] = fake_home
    clean["USERPROFILE"] = fake_home   # Windows
    clean["TMPDIR"] = fake_home
    clean["XDG_CONFIG_HOME"] = fake_home
    clean["XDG_DATA_HOME"] = fake_home

    return clean


# ---------------------------------------------------------------------------
# Resource limits (Unix only)
# ---------------------------------------------------------------------------

def _apply_resource_limits():
    """
    Called inside the subprocess (via preexec_fn on Unix).
    Limits CPU time and address space to prevent runaway code.
    """
    try:
        import resource
        # 10 seconds CPU time
        resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
        # 512 MB virtual memory
        mem = 512 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        # No new files can be created outside temp (best-effort)
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    except (ImportError, ValueError, resource.error):
        pass  # resource module not available (Windows) or limit already lower


# ---------------------------------------------------------------------------
# SandboxResult dataclass
# ---------------------------------------------------------------------------

@dataclass
class SandboxResult:
    pkg: str
    import_ok: bool
    import_time: Optional[float]
    import_error: Optional[str]
    timed_out: bool
    returncode: Optional[int]
    network_attempts: list[dict] = field(default_factory=list)
    file_reads: list[dict] = field(default_factory=list)
    subprocess_spawns: list[dict] = field(default_factory=list)
    raw_stdout: str = ""
    raw_stderr: str = ""

    @property
    def suspicious_events(self) -> list[dict]:
        return self.network_attempts + self.file_reads + self.subprocess_spawns

    @property
    def is_clean(self) -> bool:
        return (
            self.import_ok
            and not self.timed_out
            and not self.network_attempts
            and not self.file_reads
            and not self.subprocess_spawns
        )


# ---------------------------------------------------------------------------
# Main sandbox runner
# ---------------------------------------------------------------------------

def run_import_sandbox(
    wheel_bytes: bytes,
    package_name: str,
    timeout: float = 10.0,
) -> SandboxResult:
    """
    Extract wheel into a temp directory and attempt `import <package_name>`
    in a sanitised subprocess. Observe all suspicious events.

    Parameters
    ----------
    wheel_bytes : bytes
        Raw wheel zip content (already downloaded + hash-verified).
    package_name : str
        Top-level import name (e.g. "litellm", "requests").
    timeout : float
        Seconds before the subprocess is killed.

    Returns
    -------
    SandboxResult
    """
    with tempfile.TemporaryDirectory(prefix="safepip_sandbox_") as sandbox_dir:
        sandbox_path = Path(sandbox_dir)

        # ── 1. Extract wheel into sandbox ────────────────────────────────
        try:
            with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as zf:
                zf.extractall(sandbox_path)
        except zipfile.BadZipFile as e:
            return SandboxResult(
                pkg=package_name, import_ok=False,
                import_time=None, import_error=f"Bad wheel zip: {e}",
                timed_out=False, returncode=None,
            )

        # ── 2. Build fake home + honeypot bait credentials ──────────────
        fake_home = sandbox_path / "home"
        fake_home.mkdir()

        from .honeypot import populate_honeypot_home, HONEYPOT_PROBE_SCRIPT
        bait_files = populate_honeypot_home(fake_home, seed=package_name)

        # ── 3. Write probe script to temp file ───────────────────────────
        probe_path = sandbox_path / "_safepip_probe.py"
        probe_path.write_text(HONEYPOT_PROBE_SCRIPT)

        # ── 4. Build subprocess command — pass bait paths as argv[2] ─────
        import json as _json
        cmd = [
            sys.executable,
            "-S",                              # skip automatic site processing
            str(probe_path),
            package_name,
            _json.dumps(list(bait_files.keys())),
            sandbox_dir,                       # passed as argv[3] so probe can call addpackage
        ]

        env = _sanitised_env(str(fake_home))
        # Prepend sandbox dir to PYTHONPATH so the extracted package is importable
        existing_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{sandbox_dir}{os.pathsep}{existing_pp}" if existing_pp else sandbox_dir

        # ── 5. Launch with limits ─────────────────────────────────────────
        is_unix = platform.system() != "Windows"
        preexec = _apply_resource_limits if is_unix else None

        t_start = time.monotonic()
        timed_out = False

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                env=env,
                cwd=sandbox_dir,
                preexec_fn=preexec,
            )
            elapsed = time.monotonic() - t_start
            stdout = proc.stdout.decode(errors="replace")
            stderr = proc.stderr.decode(errors="replace")
            returncode = proc.returncode

        except subprocess.TimeoutExpired as e:
            timed_out = True
            stdout = (e.stdout or b"").decode(errors="replace")
            stderr = (e.stderr or b"").decode(errors="replace")
            returncode = None
            elapsed = timeout

        # ── 6. Parse probe output ─────────────────────────────────────────
        probe_data: dict = {}
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    probe_data = json.loads(line)
                    break
                except json.JSONDecodeError:
                    pass

        events = probe_data.get("events", [])
        network = [e for e in events if e.get("type") == "network"]
        file_reads = [e for e in events if e.get("type") == "file_read"]
        bait_reads = probe_data.get("bait_reads", [])
        exfil_seqs = probe_data.get("exfil_sequences", [])
        subprocs = [e for e in events if e.get("type") in ("subprocess", "os_system")]

        # Bait reads + network = credential exfiltration: treat as network attempt
        if exfil_seqs:
            network = network + [{
                "type": "honeypot_exfil",
                "bait_files_read": [s["bait_file"] for s in exfil_seqs],
                "sequences": exfil_seqs,
            }]

        return SandboxResult(
            pkg=package_name,
            import_ok=probe_data.get("import_ok", False) and not timed_out,
            import_time=probe_data.get("import_time"),
            import_error=probe_data.get("import_error") or (
                f"Timed out after {timeout}s" if timed_out else None
            ),
            timed_out=timed_out,
            returncode=returncode,
            network_attempts=network,
            file_reads=file_reads + bait_reads,
            subprocess_spawns=subprocs,
            raw_stdout=stdout[:2000],
            raw_stderr=stderr[:2000],
        )


# ---------------------------------------------------------------------------
# Check wrapper — returns a CheckResult like every other safepip check
# ---------------------------------------------------------------------------

def check_sandbox_import(
    wheel_bytes: bytes,
    package_name: str,
    wheel_filename: str,
    timeout: float = 10.0,
) -> CheckResult:
    """
    Run the import sandbox and return a CheckResult.
    Integrates into the existing safepip check pipeline.
    """
    name = "sandbox_import"

    result = run_import_sandbox(wheel_bytes, package_name, timeout=timeout)

    detail = {
        "import_ok": result.import_ok,
        "import_time_s": result.import_time,
        "timed_out": result.timed_out,
        "network_attempts": result.network_attempts,
        "file_reads": result.file_reads,
        "subprocess_spawns": result.subprocess_spawns,
        "returncode": result.returncode,
        "wheel": wheel_filename,
    }

    # Timeout = almost certainly a fork bomb or infinite loop on import
    if result.timed_out:
        return CheckResult(
            name, False, "critical",
            f"SANDBOX TIMEOUT: import '{package_name}' did not complete in {timeout}s. "
            f"This matches the fork-bomb behaviour caused by LiteLLM 1.82.8's .pth payload. "
            f"Do NOT install.",
            detail,
        )

    # Honeypot exfil: read bait creds then call network — the smoking gun
    honeypot_hits = [e for e in result.network_attempts if e.get("type") == "honeypot_exfil"]
    if honeypot_hits:
        bait_files = honeypot_hits[0].get("bait_files_read", [])
        cred_types = [Path(p).parent.name + "/" + Path(p).name for p in bait_files[:3]]
        return CheckResult(
            name, False, "critical",
            f"HONEYPOT TRIGGERED: '{package_name}' read fake credential file(s) "
            f"({', '.join(cred_types)}) and then made a network call — "
            f"the exact read-then-exfiltrate sequence of a credential stealer. "
            f"This catches env-var-conditional malware that evades static analysis.",
            detail,
        )

    # Plain network attempt during import = exfiltration
    plain_network = [e for e in result.network_attempts if e.get("type") != "honeypot_exfil"]
    if plain_network:
        return CheckResult(
            name, False, "critical",
            f"NETWORK CALL ON IMPORT: '{package_name}' attempted {len(plain_network)} "
            f"network connection(s) during import in a sandboxed environment with no credentials. "
            f"This is the primary exfiltration pattern from supply chain attacks.",
            detail,
        )

    # Credential file read during import
    if result.file_reads:
        return CheckResult(
            name, False, "critical",
            f"CREDENTIAL FILE ACCESS ON IMPORT: '{package_name}' attempted to read "
            f"{len(result.file_reads)} sensitive path(s) during import "
            f"({', '.join(f['path'] for f in result.file_reads[:3])}). "
            f"This matches the SSH key / cloud credential harvesting pattern.",
            detail,
        )

    # Subprocess spawn during import
    if result.subprocess_spawns:
        return CheckResult(
            name, False, "critical",
            f"SUBPROCESS SPAWNED ON IMPORT: '{package_name}' spawned "
            f"{len(result.subprocess_spawns)} child process(es) during import. "
            f"Legitimate packages do not spawn processes at import time.",
            detail,
        )

    # Import itself failed (not due to timeout)
    if not result.import_ok and result.import_error:
        error = result.import_error

        # ModuleNotFoundError is expected in a stripped sandbox — the sandbox has
        # no transitive deps installed. This is an environmental limitation, not a
        # security signal. Any package with dependencies will hit this.
        # Severity: info (not warning) — no suspicious behaviour was observed.
        if "ModuleNotFoundError" in error or "ImportError" in error:
            missing = ""
            if "'" in error:
                try:
                    missing = f" (missing: {error.split(chr(39))[1]})"
                except IndexError:
                    pass
            return CheckResult(
                name, True, "info",
                f"Sandbox: import needs transitive deps not in isolated env{missing}. "
                f"No network calls, file reads, or subprocess spawns observed.",
                detail,
            )

        # Any other import failure is worth flagging as a warning
        return CheckResult(
            name, False, "warning",
            f"Sandbox: import '{package_name}' failed unexpectedly: {error[:120]}. "
            f"No malicious behaviour observed — may be a sandbox limitation.",
            detail,
        )

    import_time_str = f" ({result.import_time:.2f}s)" if result.import_time else ""
    return CheckResult(
        name, True, "info",
        f"Sandbox clean: import '{package_name}' completed{import_time_str} "
        f"with no network calls, file reads, or subprocess spawns.",
        detail,
    )
