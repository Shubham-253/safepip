# pipsentinel

> **Hack-proof pip.** Supply chain security checks + import sandbox before every package install.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![Zero dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#zero-dependencies)
[![Tests](https://img.shields.io/badge/tests-66%20passing-brightgreen.svg)](#testing)
[![Version](https://img.shields.io/badge/version-0.2.1-blue.svg)](#)

---

PyPI packages can be hijacked, tampered in transit, or silently backdoored through malicious wheels that pass every standard integrity check. safepip intercepts the install flow, runs a full security suite before touching disk, and blocks anything suspicious.

---

## What it catches

| Check | What it detects |
|---|---|
| Git tag divergence | Version on PyPI with no matching GitHub tag |
| `.pth` file scan | Wheels with `import` in `.pth` files — auto-executes on every Python start |
| Obfuscated code | `exec(base64.b64decode(...))`, double encoding, AST-level dynamic exec |
| Multi-source hash consensus | PyPI JSON API + Simple API + direct download — all three SHA-256s must agree |
| RECORD manifest integrity | Every file in the wheel vs its declared SHA-256 |
| Release timestamp delta | PyPI upload vs git tag creation time — under 1 min = suspicious |
| PyPI provenance | OIDC attestation — published from reproducible CI? |
| Lockfile verification | Wheel SHA-256 against `~/.pipsentinel/pipsentinel.lock` — zero network on repeat installs |
| Import sandbox | `import <pkg>` in isolated subprocess — no credentials, audit hook on all syscalls |
| Honeypot bait | Fake AWS/SSH/Kube/GCP credentials in sandbox — read bait + network call = caught |
| Post-install RECORD diff | What pip wrote to disk vs what RECORD declared |
| Post-install `.pth` audit | Scans `site-packages` after install for suspicious `.pth` files |

**Zero third-party dependencies.** pipsentinel uses only the Python standard library. It has no supply chain of its own to attack.

---

## Install

```bash
pip install pipsentinel
```

> **Bootstrap trust note:** The codebase is ~2,600 lines of stdlib-only Python — auditable in an afternoon. Read it before trusting it.

---

## CLI

```bash
# Check AND install — blocks on any critical failure
pipsentinel install requests
pipsentinel install numpy==1.26.4

# Check only — no install
pipsentinel check somepackage==1.0.0
pipsentinel check requests --json

# Audit current environment for suspicious .pth files
pipsentinel audit
```

### Clean package

```
🔍 pipsentinel: checking requests==2.31.0 ...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  pipsentinel Security Report
  Package : requests==2.31.0
  Risk    : LOW
  Verdict : ✅ SAFE TO INSTALL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ PASSED CHECKS:
   • [git_tag_divergence] PyPI version 2.31.0 has a matching git tag 'v2.31.0' ✓
   • [pth_files_in_wheel] No suspicious .pth files found.
   • [wheel_record_integrity] RECORD integrity verified: all 23 declared files match.
   • [obfuscated_code] No obfuscation patterns detected.
   • [sandbox_import] Sandbox clean: import completed (0.30s) — no network calls,
                      file reads, or subprocess spawns.

🔒 Lock entry written: ~/.pipsentinel/pipsentinel.lock
📦 Installing: requests==2.31.0 --hash=sha256:58cd2187...
✅ requests==2.31.0 installed and verified.
```

### Malicious package (blocked)

```
🔍 pipsentinel: checking badpkg==2.0.0 ...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  pipsentinel Security Report
  Package : badpkg==2.0.0
  Risk    : CRITICAL
  Verdict : 🚨 DO NOT INSTALL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🚨 CRITICAL FAILURES:
   • [git_tag_divergence] No git tag found for 2.0.0 — pushed to PyPI
     without a corresponding source release.
   • [pth_files_in_wheel] MALICIOUS .pth FILE DETECTED: badpkg_init.pth
     contains 'import' statements — executes on every Python process start.
   • [obfuscated_code] exec(base64.b64decode(...)) in badpkg_init.pth.
     Double base64 encoding detected.
   • [sandbox_import] SUBPROCESS SPAWNED ON IMPORT: 1 child process spawned.
     Legitimate packages do not spawn processes at import time.

🚫 Installation BLOCKED.
```

---

## User flow

```mermaid
flowchart TD
    START(["pipsentinel install pkg==ver"])
    META["Fetch PyPI metadata\n(name, version, wheel URLs)"]
    LOCK_HIT{"Lockfile\nhit?"}
    LOCK_VERIFY["Verify wheel SHA-256\nagainst local lock"]
    LOCK_FAIL(["BLOCKED\nlockfile mismatch"])
    FULL_SUITE["Run full check suite"]

    subgraph CHECKS ["Pre-install checks"]
        C1["① Multi-source hash consensus\nJSON API + Simple API + download"]
        C2["② RECORD manifest integrity\nevery file vs declared SHA-256"]
        C3["③ Obfuscated code\nregex + AST scan of .py / .pth"]
        C4["④ .pth file scan\nimport lines = auto-exec malware"]
        C5["⑤ Git tag divergence\nPyPI version exists on GitHub?"]
        C6["⑥ Timestamp delta\npublish before / <1 min after tag?"]
        C7["⑦ PyPI provenance\nOIDC attestation present?"]
    end

    REPORT["SecurityReport\nSAFE / MODERATE / CRITICAL"]
    GATE{"Critical\nfailures?"}
    BLOCKED(["BLOCKED\ninstallation aborted"])
    WRITE_LOCK["Write lockfile entry\nwheel SHA-256 + per-file RECORD"]
    PIP["pip install\n--require-hashes sha256:..."]

    subgraph POST ["Post-install audit"]
        P1["RECORD diff\ndisk vs declared files"]
        P2[".pth audit\nscan site-packages"]
    end

    DONE(["✅ Installed and verified"])
    ALERT(["🚨 POST-INSTALL ANOMALY\nRotate credentials"])

    START --> META
    META --> LOCK_HIT
    LOCK_HIT -- yes --> LOCK_VERIFY
    LOCK_VERIFY -- mismatch --> LOCK_FAIL
    LOCK_VERIFY -- ok --> PIP
    LOCK_HIT -- no --> FULL_SUITE
    FULL_SUITE --> C1 & C2 & C3 & C4 & C5 & C6 & C7
    C1 & C2 & C3 & C4 & C5 & C6 & C7 --> REPORT
    REPORT --> GATE
    GATE -- yes --> BLOCKED
    GATE -- no --> WRITE_LOCK
    WRITE_LOCK --> PIP
    PIP --> POST
    P1 & P2 --> DONE
    P1 & P2 -- anomaly --> ALERT
```

---

## Python API

```python
from safepip import safe_install, SecurityReport

# Full check suite + install
report = safe_install("requests", version="2.31.0")
print(report.safe_to_install)  # True
print(report.risk_level)       # "LOW"
print(report.to_json())        # machine-readable for CI

# Check only — no install
from safepip import (
    fetch_package_metadata,
    check_git_tag_divergence,
    check_pth_files_in_wheel,
    check_obfuscated_code,
    check_sandbox_import,
    SecurityReport,
)
import urllib.request

meta = fetch_package_metadata("somepackage", "1.0.0")
wheel = next(w for w in meta.wheel_urls if w["filename"].endswith(".whl"))
with urllib.request.urlopen(wheel["url"]) as r:
    wheel_bytes = r.read()

report = SecurityReport(meta.name, meta.version)
report.results = [
    check_git_tag_divergence(meta),
    check_pth_files_in_wheel(meta),
    check_obfuscated_code(wheel_bytes, wheel["filename"]),
    check_sandbox_import(wheel_bytes, meta.name, wheel["filename"]),
]
print(report.summary())

# Post-install audit
from safepip import check_post_install_pth
result = check_post_install_pth()
if not result.passed:
    for f in result.detail["suspicious_files"]:
        print(f"🚨 Suspicious: {f['path']}")
```

### CI/CD

```yaml
# .github/workflows/deps.yml
- name: Secure install
  run: |
    pip install pipsentinel
    cat requirements.txt | xargs -n1 pipsentinel install
    pipsentinel audit
    # exits 1 on critical failure → blocks the workflow
```

---

## How the checks work

### Git tag divergence
Queries the GitHub Tags API and checks whether the PyPI version maps to any tag (`1.2.3`, `v1.2.3`, `release-1.2.3`). A version published to PyPI without a corresponding git tag is a strong signal of a credential-stolen push — no legitimate release process skips tagging.

### `.pth` file scan
Downloads the wheel into memory, verifies its SHA-256, then inspects every `.pth` file for lines starting with `import`. Python's `site` module executes these on every interpreter startup — including `pip`, `python -c`, and IDE language servers. A `.pth` file with `import` has essentially no legitimate use.

### Obfuscated code detection
Scans every `.py` and `.pth` file using both regex and Python's own `ast` module. Catches `exec(base64.b64decode(...))`, double-encoded blobs, `eval(compile(...))`, large embedded base64 payloads, subprocess self-spawning in `.pth` files, and `exec()` with computed non-literal arguments. Tuned to avoid false positives on legitimate patterns like `__import__(package)` in loops.

### Multi-source hash consensus
Three independent paths to the same SHA-256 — PyPI's JSON API, PyPI's Simple API (PEP 503), and a direct download-and-hash. All must agree. A MITM or compromised CDN would serve a different hash via one path.

### RECORD manifest integrity
Verifies the wheel's internal chain of custody: every file in `<pkg>.dist-info/RECORD` must match its declared SHA-256. No RECORD, or a mismatching one, indicates tampering.

### Release timestamp delta
Compares git tag creation time against PyPI upload time. Upload before the tag = critical. Upload under 1 minute after tagging = warning (legitimate CI build+upload takes 2–5 min; under 1 min means the upload almost certainly happened before CI could start).

### Import sandbox
Runs `import <pkg>` in a subprocess with stripped credentials, a fake home directory, and `sys.addaudithook` monitoring all socket and subprocess calls. Python is started with `-S` (skip automatic site processing), then `site.addpackage()` is called *after* the hook installs — so `.pth` payloads fire inside the hook's scope. Hard-kills after timeout (default 10s).

Packages with transitive dependencies that fail to import in the stripped environment are reported as `info` (not a warning) — the sandbox observed no suspicious behaviour, it simply couldn't complete the import due to missing deps.

### Honeypot bait
Populates the sandbox's fake home with realistic-format credentials:

| File | Content |
|---|---|
| `~/.aws/credentials` | `AKIA` + 16-char key ID, 40-char secret |
| `~/.ssh/id_rsa` | Valid PEM header/footer, random body |
| `~/.kube/config` | Real YAML structure, fake bearer token |
| `~/.config/gcloud/application_default_credentials.json` | Real JSON schema, fake refresh token |
| `~/.env` | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DATABASE_URL` |

Credentials are unique per run and cryptographically useless — they fail real authentication. If the package reads one of these files *and then* makes a network call within 5 seconds, pipsentinel flags the sequence as a credential stealer. This catches the env-var-conditional attack class — malware that checks `os.environ.get('AWS_ACCESS_KEY_ID')` before acting, which evades sandboxes with empty environments.

### Lockfile
First install stores the wheel's SHA-256 and per-file RECORD in `~/.pipsentinel/pipsentinel.lock`. Repeat installs verify locally — no network for hash checks. Wheel changed since locking = blocked.

---

## Performance

Measured against live PyPI:

| Scenario | Wall time |
|---|---|
| Single package (mean) | ~487ms |
| 10 packages, serial | ~5s |
| 10 packages, 4 threads | ~4s |
| 20 packages, serial | ~9s |
| 20 packages, 4 threads | ~8s |
| Repeat install (lockfile hit) | ~200ms |

Phase breakdown per package: metadata 141ms · download 44ms · static checks 138ms · sandbox 164ms.

For a typical `pip install` of 10 packages (8–15s on a fast connection), safepip adds ~30–60% overhead on first install. Repeat installs are negligible.

---

## What safepip does not catch

| Threat | Reason |
|---|---|
| Logic bomb on hostname, date, or secret env var | Sandbox runs on the same machine |
| C-extension network calls via `ctypes` | Bypasses Python's socket audit hook |
| Perfectly clean-looking malicious logic | No static analysis can catch well-written backdoors |
| Nation-state quality attacks | Requires full VM sandboxing with OS-level syscall tracing |

Use safepip alongside `pip-audit` (known CVEs), dependency lockfiles, and reproducible builds.

---

## Architecture

```mermaid
graph TD
    CLI["cli.py\ncli entry point\ninstall / check / audit"]
    INSTALLER["installer.py\nsafe_install()\norchestrator"]
    CHECKS["checks.py\nall check functions\n9 pre-install · 2 post-install"]
    SANDBOX["sandbox.py\nrun_import_sandbox()\nsubprocess isolation"]
    HONEYPOT["honeypot.py\npopulate_honeypot_home()\nfake credentials"]
    LOCKFILE["lockfile.py\nLockfileManager\n~/.pipsentinel/pipsentinel.lock"]
    REPORT["report.py\nSecurityReport\nhuman + JSON output"]
    PIP["pip subprocess\n--require-hashes"]
    PYPI["PyPI\nJSON API · Simple API\nwheel download"]
    GITHUB["GitHub API\ntags · commit timestamps"]

    CLI --> INSTALLER
    CLI --> CHECKS
    INSTALLER --> CHECKS
    INSTALLER --> LOCKFILE
    INSTALLER --> SANDBOX
    INSTALLER --> REPORT
    INSTALLER --> PIP
    SANDBOX --> HONEYPOT
    CHECKS --> PYPI
    CHECKS --> GITHUB
    LOCKFILE -. "fast path\n(repeat install)" .-> INSTALLER
```

### Module responsibilities

```
pipsentinel/
├── checks.py     # all security checks: git tag, .pth scan, hash consensus,
│                 # RECORD integrity, obfuscation, timestamp delta, provenance,
│                 # post-install audit and RECORD diff
├── sandbox.py    # process-level import sandbox with audit hooks
├── honeypot.py   # fake credential generation + exfiltration sequence detection
├── lockfile.py   # ~/.pipsentinel/pipsentinel.lock management
├── installer.py  # orchestrates checks → pip install --require-hashes
├── report.py     # SecurityReport + human/JSON output
└── cli.py        # pipsentinel install / check / audit
```

Every check is a pure function returning `CheckResult(name, passed, severity, message, detail)`. No global state. Each check can be imported and called independently.

---

## Zero dependencies

safepip uses only the Python standard library:

```
urllib.request   PyPI API + wheel downloads
hashlib          SHA-256 verification
zipfile          wheel inspection (wheels are zip files)
subprocess       sandbox subprocess + pip delegation
ast              AST-level obfuscation detection
site             .pth processing in sandbox
json, re, tempfile, pathlib, ...
```

This is intentional and non-negotiable. A security tool with dependencies has a supply chain. safepip has none.

---

## Testing

```bash
pip install pytest
python -m pytest -v                              # 66 tests, ~0.1s

pip install pytest-cov
python -m pytest --cov=safepip --cov-report=term-missing
```

---

## License

MIT
