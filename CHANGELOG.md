# Changelog

All notable changes to pipsentinel are documented here.

---

## [0.2.6] — 2026-03-28

### Fixed
- Version bump to resolve PyPI upload conflict (0.2.5 artifact already existed on PyPI)

---

## [0.2.5] — 2026-03-28

### Changed
- `pipsentinel sync` now runs 4 metadata checks per package: hash consensus, git tag divergence, `.pth` scan, provenance — no wheel download (downloading all wheels in a lock file on every `uv sync` would be hundreds of MB)
- Real-world smoke tests merged into `test_checks.py` — all 148 tests run together, no separate test file or skip markers

### Fixed
- `exec(compile(...))` no longer triggers obfuscation false positive — legitimate pattern used by flask/werkzeug to load config files
- `distutils-precedence.pth` (setuptools infrastructure) no longer triggers false positive in `check_pth_files_in_wheel`
- `__version__` in `__init__.py` was stale at `0.2.4` — now correctly reports `0.2.5`
- `tomllib` (Python 3.11+ only) was imported at module level in `cli.py`, crashing all CLI commands on Python 3.10 — moved inside `sync` only with a clear error message

---

## [0.2.4] — 2026-03-28

### Added
- `pipsentinel check` now runs the full 8-check suite (was previously 3 checks only) — downloads wheel, verifies RECORD, scans for obfuscated code, runs import sandbox
- `pipsentinel audit` now includes an obfuscated code scan of all installed `.py` files in site-packages (12,000+ files scanned), in addition to the `.pth` audit
- Import sandbox (`sandbox.py`) and honeypot bait (`honeypot.py`) are now wired into the `pipsentinel install` flow — were implemented but not called in prior versions

### Fixed
- `project_urls` key matching is now case-insensitive — fixes false "no source repo" warning for packages like numpy that switched to lowercase keys
- PyPI publish workflow now requests sigstore provenance attestation (`attestations: true`) — pipsentinel will pass its own provenance check from next release onward

---

## [0.2.3] — 2026-03-27

### Added
- `pipsentinel install -r requirements.txt` — scan and install all packages from a requirements file
- `pipsentinel sync` — audit all packages in `uv.lock` before running `uv sync`, blocking if any fail
- `--force` flag on `sync` to run `uv sync` even if checks fail
- `--lockfile` flag on `sync` to specify a custom lock file path
- Extra args passthrough on `sync` (e.g. `pipsentinel sync -- --frozen`)

### Fixed
- `--require-hashes` pip flag removed — was failing for packages with transitive dependencies; hash is now verified internally before install
- `distutils-precedence.pth` (setuptools infrastructure) no longer triggers false positive in post-install audit
- Date-based version tags (e.g. certifi `2026.2.25` vs GitHub tag `2026.02.25`) now correctly matched via zero-padding normalization
- POST-INSTALL ANOMALY message now only triggers on `critical` severity, not warnings
- `project_urls` key matching is now case-insensitive — fixes false "no source repo" warning for packages like numpy that use lowercase keys in newer releases

---

## [0.2.2] — 2026-03-27

### Changed
- Renamed package from `safepip` to `pipsentinel` (PyPI name conflict)
- Renamed source folder `safepip/` → `pipsentinel/`
- Published via GitHub Actions OIDC trusted publishing — no manual `twine upload`
- Package now ships with provenance attestation (sigstore)

### Fixed
- Removed stale `checks_v2.py` and `installer_v2.py` — all checks merged into single `checks.py`
- Removed `test_checks_v2.py` — all tests consolidated into `test_checks.py`
- Removed pre-built `.whl` and `.tar.gz` artifacts from repository
- Fixed `pyproject.toml` license format deprecation warnings

---

## [0.2.1] — 2026-03-26

### Added
- **Multi-source hash consensus** — cross-checks SHA-256 across PyPI JSON API, Simple API, and direct download
- **RECORD manifest integrity** — verifies every file in the wheel matches its declared hash in `RECORD`
- **Obfuscated code detection** — AST + regex scan for `exec(base64.b64decode(...))`, dynamic `eval`, subprocess self-spawn, and large embedded base64 blobs
- **Release timestamp delta** — flags releases published within 1 minute of a git tag (too fast for CI) or before the tag exists
- **Post-install RECORD diff** — compares on-disk files against the pre-install RECORD snapshot
- **Lockfile** (`~/.pipsentinel/pipsentinel.lock`) — stores wheel SHA-256 + per-file hashes on first install; repeat installs verify against lock with zero network calls

### Changed
- `safe_install` now runs all 8 checks (4 original + 4 new) on first install
- Repeat installs use lockfile fast-path (download wheel → verify hash → install)

---

## [0.2.0] — 2026-03-25

### Added
- Initial release as `safepip`
- `pipsentinel install <package>` — check and install a single package
- `pipsentinel check <package>` — check without installing
- `pipsentinel audit` — post-install site-packages scan for suspicious `.pth` files
- **Git tag divergence check** — verifies PyPI version has a matching GitHub tag
- **Wheel `.pth` scan** — detects import statements inside `.pth` files in the wheel
- **PyPI provenance check** — verifies OIDC attestation exists
- **Post-install `.pth` audit** — scans site-packages after install
- Import sandbox (`sandbox.py`) — runs package import in isolated subprocess
- Honeypot credentials (`honeypot.py`) — fake secrets to detect exfiltration attempts
- JSON output via `--json` flag
