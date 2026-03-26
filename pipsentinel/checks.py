"""
Security check implementations for safepip.

Each check returns a CheckResult with:
  - passed: bool
  - severity: "critical" | "warning" | "info"
  - message: human-readable explanation
  - detail: raw data for further inspection

Design principle: every check is a pure function — no side effects,
no global state. Checks can be run independently or composed.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import io
import json
import re
import site
import urllib.request
import urllib.error
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    name: str
    passed: bool
    severity: str          # "critical" | "warning" | "info"
    message: str
    detail: dict = field(default_factory=dict)

    def __str__(self) -> str:
        icon = "✅" if self.passed else ("🚨" if self.severity == "critical" else "⚠️")
        return f"{icon} [{self.name}] {self.message}"


@dataclass
class PackageMetadata:
    name: str
    version: str
    source_url: Optional[str]      # GitHub / VCS URL from PyPI metadata
    pypi_release_date: Optional[str]
    requires_python: Optional[str]
    wheel_urls: list[dict]         # list of {url, sha256, filename}
    has_provenance: bool           # PyPI attestation present
    provenance_detail: dict


# ---------------------------------------------------------------------------
# PyPI metadata fetch
# ---------------------------------------------------------------------------

def fetch_package_metadata(package: str, version: Optional[str] = None) -> PackageMetadata:
    """
    Fetch package metadata from PyPI JSON API.
    No third-party dependencies — uses stdlib urllib only.
    """
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise ValueError(f"Package '{package}' not found on PyPI (HTTP {e.code})") from e
    except Exception as e:
        raise RuntimeError(f"Failed to fetch PyPI metadata: {e}") from e

    info = data["info"]
    releases = data["releases"]

    if version is None:
        version = info["version"]

    if version not in releases:
        raise ValueError(
            f"Version {version} of '{package}' not found on PyPI. "
            f"Latest is {info['version']}."
        )

    release_files = releases[version]

    # Extract wheel/sdist download info
    wheel_urls = []
    for f in release_files:
        digests = f.get("digests", {})
        wheel_urls.append({
            "filename": f["filename"],
            "url": f["url"],
            "sha256": digests.get("sha256", ""),
            "upload_time": f.get("upload_time", ""),
            "packagetype": f.get("packagetype", ""),
        })

    # Provenance: PyPI OIDC attestations (added mid-2024)
    # Available at /pypi/{package}/{version}/provenance
    provenance_detail = {}
    has_provenance = False
    try:
        prov_url = f"https://pypi.org/pypi/{package}/{version}/provenance"
        with urllib.request.urlopen(prov_url, timeout=10) as resp:
            provenance_detail = json.loads(resp.read().decode())
            has_provenance = True
    except Exception:
        pass  # Not all packages have provenance — that's itself a signal

    # Source URL from project_urls or home_page
    source_url = None
    project_urls = info.get("project_urls") or {}
    for key in ("Source", "Source Code", "Homepage", "Repository", "Code"):
        if key in project_urls and "github.com" in (project_urls[key] or ""):
            source_url = project_urls[key]
            break
    if not source_url and "github.com" in (info.get("home_page") or ""):
        source_url = info["home_page"]

    return PackageMetadata(
        name=info["name"],
        version=version,
        source_url=source_url,
        pypi_release_date=wheel_urls[0]["upload_time"] if wheel_urls else None,
        requires_python=info.get("requires_python"),
        wheel_urls=wheel_urls,
        has_provenance=has_provenance,
        provenance_detail=provenance_detail,
    )


# ---------------------------------------------------------------------------
# Check 1 — Git tag ↔ PyPI divergence
# The exact signal missed in the LiteLLM attack:
# malicious versions were pushed directly to PyPI with no corresponding git tag.
# ---------------------------------------------------------------------------

def check_git_tag_divergence(meta: PackageMetadata) -> CheckResult:
    """
    Verify that the PyPI version has a corresponding git tag on the source repo.
    A PyPI publish with no matching GitHub tag is a strong indicator of
    a compromised maintainer account pushing unauthorized code.
    """
    name = "git_tag_divergence"

    if not meta.source_url:
        return CheckResult(
            name=name,
            passed=False,
            severity="warning",
            message="No source repository URL found in PyPI metadata. "
                    "Cannot verify git tag alignment.",
            detail={"source_url": None},
        )

    # Normalize GitHub URL → owner/repo
    gh_match = re.search(r"github\.com/([^/]+/[^/\s#?]+)", meta.source_url)
    if not gh_match:
        return CheckResult(
            name=name,
            passed=False,
            severity="warning",
            message=f"Source URL is not a GitHub URL; tag check skipped. ({meta.source_url})",
            detail={"source_url": meta.source_url},
        )

    repo = gh_match.group(1).rstrip("/").removesuffix(".git")
    tags_url = f"https://api.github.com/repos/{repo}/tags?per_page=50"

    try:
        req = urllib.request.Request(
            tags_url,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "safepip/0.1"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            tags = json.loads(resp.read().decode())
    except Exception as e:
        return CheckResult(
            name=name,
            passed=False,
            severity="warning",
            message=f"Could not fetch GitHub tags (rate limit or network issue): {e}",
            detail={"repo": repo, "error": str(e)},
        )

    tag_names = [t["name"] for t in tags]
    version = meta.version

    # Common tag formats: v1.2.3, 1.2.3, release-1.2.3
    candidates = [version, f"v{version}", f"release-{version}", f"release/{version}"]
    matched_tag = next((c for c in candidates if c in tag_names), None)

    if matched_tag:
        return CheckResult(
            name=name,
            passed=True,
            severity="info",
            message=f"PyPI version {version} has a matching git tag '{matched_tag}' ✓",
            detail={"repo": repo, "matched_tag": matched_tag, "all_tags_checked": candidates},
        )
    else:
        return CheckResult(
            name=name,
            passed=False,
            severity="critical",
            message=(
                f"🚨 No git tag found for version {version} on {repo}. "
                f"This is the exact pattern of the LiteLLM supply chain attack — "
                f"a version pushed to PyPI without a corresponding source release."
            ),
            detail={
                "repo": repo,
                "version": version,
                "candidates_checked": candidates,
                "available_tags_sample": tag_names[:10],
            },
        )


# ---------------------------------------------------------------------------
# Check 2 — .pth file scan inside wheel
# The injection vector in LiteLLM 1.82.8:
# a .pth file with import statements runs on EVERY Python process start.
# ---------------------------------------------------------------------------

def check_pth_files_in_wheel(meta: PackageMetadata) -> CheckResult:
    """
    Download the wheel and inspect it for .pth files containing import statements.
    A .pth file with 'import' is almost never legitimate — Python uses .pth files
    for path manipulation only. The LiteLLM attack embedded a full credential
    stealer this way.
    """
    name = "pth_files_in_wheel"

    wheel_entry = next(
        (w for w in meta.wheel_urls if w["filename"].endswith(".whl")), None
    )
    if not wheel_entry:
        wheel_entry = next(iter(meta.wheel_urls), None)

    if not wheel_entry:
        return CheckResult(
            name=name,
            passed=False,
            severity="warning",
            message="No wheel file found on PyPI for this version.",
            detail={},
        )

    url = wheel_entry["url"]
    expected_sha256 = wheel_entry["sha256"]

    # Download wheel into memory (no disk write)
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            wheel_bytes = resp.read()
    except Exception as e:
        return CheckResult(
            name=name,
            passed=False,
            severity="warning",
            message=f"Could not download wheel for inspection: {e}",
            detail={"url": url},
        )

    # Verify SHA-256 before inspecting contents
    actual_sha256 = hashlib.sha256(wheel_bytes).hexdigest()
    if expected_sha256 and actual_sha256 != expected_sha256:
        return CheckResult(
            name=name,
            passed=False,
            severity="critical",
            message=(
                f"🚨 SHA-256 MISMATCH on downloaded wheel! "
                f"Expected {expected_sha256[:16]}… got {actual_sha256[:16]}… "
                f"The file on PyPI does not match the recorded hash."
            ),
            detail={"expected": expected_sha256, "actual": actual_sha256, "url": url},
        )

    # Inspect zip (wheels are zip files)
    suspicious_pth = []
    all_pth = []

    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as zf:
            for entry in zf.namelist():
                if entry.endswith(".pth"):
                    all_pth.append(entry)
                    content = zf.read(entry).decode(errors="replace")
                    lines = [l.strip() for l in content.splitlines() if l.strip()]
                    import_lines = [l for l in lines if l.startswith("import ") or l.startswith("import\t")]
                    if import_lines:
                        suspicious_pth.append({
                            "file": entry,
                            "import_lines": import_lines[:5],  # cap output
                            "total_lines": len(lines),
                            "size_bytes": len(content.encode()),
                        })
    except zipfile.BadZipFile:
        return CheckResult(
            name=name,
            passed=False,
            severity="warning",
            message="Downloaded file is not a valid zip/wheel archive.",
            detail={"url": url},
        )

    if suspicious_pth:
        return CheckResult(
            name=name,
            passed=False,
            severity="critical",
            message=(
                f"🚨 MALICIOUS .pth FILE DETECTED: {len(suspicious_pth)} .pth file(s) "
                f"contain 'import' statements — these execute on every Python process start. "
                f"This is the exact attack vector used in LiteLLM 1.82.8."
            ),
            detail={"suspicious_files": suspicious_pth, "all_pth_files": all_pth},
        )

    return CheckResult(
        name=name,
        passed=True,
        severity="info",
        message=f"No suspicious .pth files found. ({len(all_pth)} .pth file(s) scanned, none with import statements)",
        detail={
            "sha256_verified": actual_sha256,
            "wheel_file": wheel_entry["filename"],
            "all_pth_files": all_pth,
        },
    )


# ---------------------------------------------------------------------------
# Check 3 — PyPI Provenance / Trusted Publisher
# PyPI added OIDC-based provenance attestations in 2024.
# A package without provenance was published manually (twine upload),
# not from a reproducible, auditable CI pipeline.
# ---------------------------------------------------------------------------

def check_pypi_provenance(meta: PackageMetadata) -> CheckResult:
    name = "pypi_provenance"

    if meta.has_provenance:
        # Extract the workflow/repo from provenance if available
        attestations = meta.provenance_detail.get("attestations", [])
        workflow = None
        repo = None
        if attestations:
            stmt = attestations[0].get("statement", {})
            subject = stmt.get("subject", [{}])[0]
            pred = stmt.get("predicate", {})
            workflow = pred.get("buildDefinition", {}).get("buildType", "")
            repo = pred.get("buildDefinition", {}).get(
                "externalParameters", {}
            ).get("repository", "")

        return CheckResult(
            name=name,
            passed=True,
            severity="info",
            message=(
                f"Package has PyPI provenance attestation — "
                f"published from a verified CI pipeline, not manually uploaded."
                + (f" Workflow: {workflow}" if workflow else "")
            ),
            detail={
                "has_provenance": True,
                "workflow": workflow,
                "repo": repo,
                "raw": meta.provenance_detail,
            },
        )
    else:
        return CheckResult(
            name=name,
            passed=False,
            severity="warning",
            message=(
                "No PyPI provenance attestation found. "
                "This package was likely published via manual 'twine upload' rather than "
                "a reproducible, auditable GitHub Actions pipeline. "
                "Many legitimate packages lack this (it's a newer feature), "
                "but its absence is a risk signal."
            ),
            detail={"has_provenance": False},
        )


# ---------------------------------------------------------------------------
# Check 4 — Post-install .pth audit
# Scans actual site-packages for any .pth files with import statements.
# Run this after an install to catch what got written to disk.
# ---------------------------------------------------------------------------

def check_post_install_pth(site_packages_dirs: Optional[list[str]] = None) -> CheckResult:
    """
    Scan all site-packages directories for .pth files containing import statements.
    Should be run after installation to verify nothing malicious was installed.
    """
    name = "post_install_pth_audit"

    if site_packages_dirs is None:
        site_packages_dirs = site.getsitepackages() + [site.getusersitepackages()]

    suspicious = []
    scanned = 0

    for sp_dir in site_packages_dirs:
        sp_path = Path(sp_dir)
        if not sp_path.exists():
            continue
        for pth_file in sp_path.glob("*.pth"):
            scanned += 1
            try:
                content = pth_file.read_text(errors="replace")
            except Exception:
                continue
            lines = [l.strip() for l in content.splitlines() if l.strip()]
            import_lines = [l for l in lines if l.startswith("import ") or l.startswith("import\t")]
            if import_lines:
                suspicious.append({
                    "path": str(pth_file),
                    "import_lines": import_lines[:5],
                    "size_bytes": pth_file.stat().st_size,
                })

    if suspicious:
        return CheckResult(
            name=name,
            passed=False,
            severity="critical",
            message=(
                f"🚨 {len(suspicious)} suspicious .pth file(s) found in site-packages! "
                f"These execute on every Python interpreter startup. "
                f"Rotate credentials immediately and remove flagged files."
            ),
            detail={"suspicious_files": suspicious, "total_pth_scanned": scanned},
        )

    return CheckResult(
        name=name,
        passed=True,
        severity="info",
        message=f"Post-install audit clean: {scanned} .pth file(s) scanned, none with import statements.",
        detail={"total_pth_scanned": scanned, "site_packages_dirs": site_packages_dirs},
    )


# ---------------------------------------------------------------------------
# Check A — Multi-source hash consensus
# ---------------------------------------------------------------------------

def check_multi_source_hash_consensus(meta: PackageMetadata) -> CheckResult:
    name = "multi_source_hash_consensus"

    wheel_entry = next(
        (w for w in meta.wheel_urls if w["filename"].endswith(".whl")), None
    )
    if not wheel_entry:
        return CheckResult(name, False, "warning",
                           "No wheel found for this version — skipping consensus check.",
                           {})

    json_api_hash = wheel_entry.get("sha256", "")
    filename = wheel_entry["filename"]
    url = wheel_entry["url"]

    simple_hash = ""
    try:
        simple_url = f"https://pypi.org/simple/{meta.name.lower()}/"
        req = urllib.request.Request(
            simple_url,
            headers={
                "Accept": "application/vnd.pypi.simple.v1+json, text/html",
                "User-Agent": "safepip/0.2",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode(errors="replace")

        if "application/vnd.pypi.simple" in resp.headers.get("Content-Type", ""):
            data = json.loads(body)
            for f in data.get("files", []):
                if f.get("filename") == filename:
                    digests = f.get("digests", {})
                    simple_hash = digests.get("sha256", "")
                    break
        else:
            m = re.search(
                rf'href="[^"]*{re.escape(filename)}[^"]*#sha256=([a-f0-9]{{64}})"',
                body,
            )
            if m:
                simple_hash = m.group(1)
    except Exception as e:
        return CheckResult(name, False, "warning",
                           f"Could not fetch PyPI Simple API for consensus: {e}", {})

    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            wheel_bytes = resp.read()
        local_hash = hashlib.sha256(wheel_bytes).hexdigest()
    except Exception as e:
        return CheckResult(name, False, "warning",
                           f"Could not download wheel for hash verification: {e}", {})

    hashes = {
        "pypi_json_api": json_api_hash,
        "pypi_simple_api": simple_hash,
        "local_download": local_hash,
    }

    populated = {k: v for k, v in hashes.items() if v}
    unique_values = set(populated.values())

    if len(unique_values) == 1:
        h = next(iter(unique_values))
        return CheckResult(
            name, True, "info",
            f"All {len(populated)} hash sources agree: {h[:16]}…",
            {"hashes": hashes, "consensus": True},
        )
    else:
        return CheckResult(
            name, False, "critical",
            f"HASH CONSENSUS FAILURE: {len(unique_values)} different SHA-256 values "
            f"across {len(populated)} sources. Someone is serving a different wheel. "
            f"Do NOT install.",
            {"hashes": hashes, "consensus": False},
        )


# ---------------------------------------------------------------------------
# Check B — RECORD manifest integrity
# ---------------------------------------------------------------------------

def check_wheel_record_integrity(wheel_bytes: bytes, filename: str) -> CheckResult:
    name = "wheel_record_integrity"

    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as zf:
            all_names = set(zf.namelist())

            record_names = [n for n in all_names if n.endswith(".dist-info/RECORD")]
            if not record_names:
                return CheckResult(
                    name, False, "critical",
                    "No RECORD file found in wheel. A valid wheel must contain "
                    "<pkg>.dist-info/RECORD. Its absence suggests tampering.",
                    {"wheel": filename},
                )

            record_content = zf.read(record_names[0]).decode(errors="replace")
            entries: list[tuple[str, str, str]] = []
            for line in record_content.splitlines():
                parts = line.strip().split(",")
                if len(parts) == 3:
                    entries.append((parts[0], parts[1], parts[2]))

            if not entries:
                return CheckResult(
                    name, False, "warning",
                    "RECORD file is present but empty — cannot verify file integrity.",
                    {"wheel": filename},
                )

            mismatches = []
            missing = []

            for rel_path, hash_spec, _size in entries:
                if not hash_spec:
                    continue
                if not hash_spec.startswith("sha256:"):
                    continue

                expected_hex = hash_spec[len("sha256:"):]

                if rel_path not in all_names:
                    missing.append(rel_path)
                    continue

                actual_bytes = zf.read(rel_path)
                actual_hex = hashlib.sha256(actual_bytes).hexdigest()

                if actual_hex != expected_hex:
                    mismatches.append({
                        "file": rel_path,
                        "expected": expected_hex[:16] + "…",
                        "actual": actual_hex[:16] + "…",
                    })

    except zipfile.BadZipFile:
        return CheckResult(name, False, "warning",
                           "Wheel is not a valid zip archive.", {"wheel": filename})

    issues = mismatches + [{"file": f, "issue": "missing from zip"} for f in missing]

    if issues:
        return CheckResult(
            name, False, "critical",
            f"RECORD INTEGRITY FAILURE: {len(mismatches)} file(s) have wrong hashes, "
            f"{len(missing)} declared in RECORD but absent from zip. "
            f"The wheel's own chain-of-custody is broken.",
            {"issues": issues[:20], "wheel": filename},
        )

    return CheckResult(
        name, True, "info",
        f"RECORD integrity verified: all {len(entries)} declared files match their hashes.",
        {"files_verified": len(entries), "wheel": filename},
    )


# ---------------------------------------------------------------------------
# Check C — Obfuscated code detection
# ---------------------------------------------------------------------------

_OBFUSCATION_PATTERNS = [
    (re.compile(r"exec\s*\(\s*base64\.b64decode", re.IGNORECASE),
     "exec(base64.b64decode(...)): classic payload delivery"),
    (re.compile(r"eval\s*\(\s*base64\.b64decode", re.IGNORECASE),
     "eval(base64.b64decode(...)): base64 eval execution"),
    (re.compile(r"exec\s*\(\s*__import__\s*\(\s*['\"]base64['\"]", re.IGNORECASE),
     "exec(__import__('base64')...): hidden import obfuscation"),
    (re.compile(r"b64decode\s*\(\s*b64decode", re.IGNORECASE),
     "double base64 decode: obfuscation layer"),
    (re.compile(r"b64decode\s*\([^)]*b64decode", re.IGNORECASE),
     "nested b64decode calls: double obfuscation"),
    (re.compile(r"os\.system\s*\(['\"][^'\"]*\b(curl|wget|nc |ncat|bash -[cis])", re.IGNORECASE),
     "os.system with network/shell tool: exfiltration pattern"),
    (re.compile(r"subprocess\.(Popen|run|call)\s*\(\s*\[?\s*sys\.executable", re.IGNORECASE),
     "subprocess spawning current interpreter: self-replication pattern"),
    (re.compile(r"subprocess\.(Popen|run|call|check_output)", re.IGNORECASE),
     "subprocess call in source file: process execution pattern"),
]

_LARGE_B64_PATTERN = re.compile(r"['\"]([A-Za-z0-9+/]{200,}={0,2})['\"]")


def check_obfuscated_code(wheel_bytes: bytes, filename: str) -> CheckResult:
    name = "obfuscated_code"

    findings: list[dict] = []

    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as zf:
            targets = [n for n in zf.namelist()
                       if n.endswith(".py") or n.endswith(".pth")]

            for entry_name in targets:
                try:
                    content = zf.read(entry_name).decode(errors="replace")
                except Exception:
                    continue

                is_pth = entry_name.endswith(".pth")
                for pattern, description in _OBFUSCATION_PATTERNS:
                    if "subprocess call in source file" in description and not is_pth:
                        continue
                    if pattern.search(content):
                        findings.append({
                            "file": entry_name,
                            "type": "regex",
                            "description": description,
                            "snippet": _extract_snippet(content, pattern),
                        })

                blobs = _LARGE_B64_PATTERN.findall(content)
                if blobs:
                    valid_blobs = []
                    for blob in blobs:
                        try:
                            decoded = base64.b64decode(blob + "==")
                            if len(decoded) > 100:
                                valid_blobs.append({
                                    "encoded_length": len(blob),
                                    "decoded_length": len(decoded),
                                    "starts_with": blob[:40],
                                })
                        except Exception:
                            pass

                    if valid_blobs:
                        findings.append({
                            "file": entry_name,
                            "type": "large_base64_blob",
                            "description": f"Large embedded base64 blob(s) in source file",
                            "blobs": valid_blobs[:3],
                        })

                if entry_name.endswith(".py"):
                    ast_finding = _ast_check_dynamic_import(content, entry_name)
                    if ast_finding:
                        findings.append(ast_finding)

    except zipfile.BadZipFile:
        return CheckResult(name, False, "warning", "Wheel is not a valid archive.", {})

    if findings:
        return CheckResult(
            name, False, "critical",
            f"OBFUSCATED CODE DETECTED in {len(set(f['file'] for f in findings))} file(s). "
            f"These patterns match the exact techniques used in the LiteLLM 1.82.8 attack.",
            {"findings": findings[:10], "wheel": filename},
        )

    return CheckResult(
        name, True, "info",
        f"No obfuscation patterns detected in {filename}.",
        {"files_scanned": len(targets) if 'targets' in dir() else 0, "wheel": filename},
    )


def _extract_snippet(content: str, pattern: re.Pattern, context: int = 80) -> str:
    m = pattern.search(content)
    if not m:
        return ""
    start = max(0, m.start() - 20)
    end = min(len(content), m.end() + context)
    return content[start:end].strip()[:200]


def _ast_check_dynamic_import(source: str, filename: str) -> Optional[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and
                isinstance(node.func, ast.Name) and
                node.func.id == "__import__" and
                node.args and
                isinstance(node.args[0], ast.Call)):
            return {
                "file": filename,
                "type": "ast_dynamic_import",
                "description": "__import__ argument is a function call result (e.g. decode/b64decode): high-confidence obfuscation",
                "line": getattr(node, "lineno", "?"),
            }

        if (isinstance(node, ast.Call) and
                isinstance(node.func, ast.Name) and
                node.func.id in ("exec", "eval") and
                node.args and
                isinstance(node.args[0], ast.Call)):
            call_arg = node.args[0]
            if (isinstance(call_arg.func, ast.Attribute) and
                    call_arg.func.attr == "read"):
                continue
            return {
                "file": filename,
                "type": "ast_dynamic_exec",
                "description": f"{node.func.id}() called with a computed function result: dynamic execution indicator",
                "line": getattr(node, "lineno", "?"),
            }

    return None


# ---------------------------------------------------------------------------
# Check D — Release timestamp delta
# ---------------------------------------------------------------------------

SUSPICIOUS_DELTA_MINUTES = 1


def check_release_timestamp_delta(meta: PackageMetadata) -> CheckResult:
    name = "release_timestamp_delta"

    if not meta.source_url:
        return CheckResult(name, False, "warning",
                           "No source URL — cannot compute tag-to-publish delta.", {})

    gh_match = re.search(r"github\.com/([^/]+/[^/\s#?]+)", meta.source_url)
    if not gh_match:
        return CheckResult(name, False, "warning",
                           "Source is not GitHub — skipping timestamp delta check.", {})

    repo = gh_match.group(1).rstrip("/").removesuffix(".git")
    version = meta.version
    candidates = [version, f"v{version}", f"release-{version}"]

    tags_url = f"https://api.github.com/repos/{repo}/tags?per_page=50"
    try:
        req = urllib.request.Request(
            tags_url,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "safepip/0.2"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            tags = json.loads(resp.read().decode())
    except Exception as e:
        return CheckResult(name, False, "warning",
                           f"GitHub API unavailable for timestamp check: {e}", {})

    tag_by_name = {t["name"]: t for t in tags}
    matched = next((c for c in candidates if c in tag_by_name), None)

    if not matched:
        return CheckResult(name, False, "warning",
                           f"No git tag found for {version} — timestamp delta not computable. "
                           f"See git_tag_divergence check.", {})

    tag_data = tag_by_name[matched]
    commit_url = tag_data.get("commit", {}).get("url", "")
    tag_created_at = None

    if commit_url:
        try:
            req = urllib.request.Request(
                commit_url,
                headers={"Accept": "application/vnd.github+json", "User-Agent": "safepip/0.2"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                commit_data = json.loads(resp.read().decode())
            tag_created_at = commit_data.get("commit", {}).get("committer", {}).get("date")
        except Exception:
            pass

    pypi_upload_time = meta.pypi_release_date

    if not tag_created_at or not pypi_upload_time:
        return CheckResult(
            name, True, "info",
            f"Git tag '{matched}' exists. Could not fetch timestamps for delta check.",
            {"tag": matched, "tag_time": tag_created_at, "pypi_time": pypi_upload_time},
        )

    def parse_ts(s: str) -> Optional[datetime]:
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S+00:00"):
            try:
                return datetime.strptime(s[:19], fmt[:len(s[:19])]).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    tag_dt = parse_ts(tag_created_at)
    pypi_dt = parse_ts(pypi_upload_time)

    if not tag_dt or not pypi_dt:
        return CheckResult(name, True, "info",
                           f"Tag '{matched}' found. Timestamps unparseable for delta check.",
                           {"tag": matched})

    delta = pypi_dt - tag_dt
    delta_minutes = delta.total_seconds() / 60

    if delta_minutes < 0:
        return CheckResult(
            name, False, "critical",
            f"PyPI publish happened {abs(delta_minutes):.1f} minutes BEFORE the git tag. "
            f"This is a strong indicator of an unauthorized publish — "
            f"legitimate releases tag the source before publishing the artifact.",
            {"delta_minutes": round(delta_minutes, 1), "tag": matched,
             "tag_time": tag_created_at, "pypi_time": pypi_upload_time},
        )
    elif delta_minutes < SUSPICIOUS_DELTA_MINUTES:
        return CheckResult(
            name, False, "warning",
            f"PyPI publish was only {delta_minutes:.1f} minutes after git tag '{matched}'. "
            f"Typical CI build+publish takes 2-5 min; under 1 min suggests a "
            f"manual 'twine upload' rather than an automated pipeline.",
            {"delta_minutes": round(delta_minutes, 1), "tag": matched,
             "tag_time": tag_created_at, "pypi_time": pypi_upload_time},
        )
    else:
        return CheckResult(
            name, True, "info",
            f"Release delta normal: PyPI published {delta_minutes:.0f} min after tag '{matched}'.",
            {"delta_minutes": round(delta_minutes, 1), "tag": matched},
        )


# ---------------------------------------------------------------------------
# Check E — Post-install RECORD diff
# ---------------------------------------------------------------------------

def check_post_install_record_diff(
    package: str,
    version: str,
    declared_record: dict,
    site_packages_dirs: Optional[list[str]] = None,
) -> CheckResult:
    name = "post_install_record_diff"

    if not declared_record:
        return CheckResult(name, False, "warning",
                           "No RECORD data available for post-install diff.", {})

    if site_packages_dirs is None:
        site_packages_dirs = site.getsitepackages() + [site.getusersitepackages()]

    dist_info_name = f"{package.replace('-', '_')}-{version}.dist-info"
    dist_info_path: Optional[Path] = None

    for sp in site_packages_dirs:
        candidate = Path(sp) / dist_info_name
        if candidate.exists():
            dist_info_path = candidate.parent
            break

    if not dist_info_path:
        return CheckResult(name, False, "warning",
                           f"Could not locate {dist_info_name} in site-packages. "
                           f"Package may not be installed yet.", {})

    extra_files: list[str] = []
    hash_mismatches: list[dict] = []
    missing_files: list[str] = []

    for rel_path, hash_spec in declared_record.items():
        if not hash_spec.startswith("sha256:"):
            continue
        expected_hex = hash_spec[len("sha256:"):]
        full_path = dist_info_path / rel_path

        if not full_path.exists():
            missing_files.append(rel_path)
            continue

        try:
            actual_hex = hashlib.sha256(full_path.read_bytes()).hexdigest()
        except OSError:
            continue

        if actual_hex != expected_hex:
            hash_mismatches.append({
                "file": rel_path,
                "expected": expected_hex[:16] + "…",
                "actual": actual_hex[:16] + "…",
            })

    pkg_dir_name = package.replace("-", "_").lower()
    for sp in site_packages_dirs:
        for candidate_dir in [Path(sp) / pkg_dir_name, Path(sp) / dist_info_name]:
            if not candidate_dir.exists():
                continue
            for real_file in candidate_dir.rglob("*"):
                if real_file.is_file():
                    rel = str(real_file.relative_to(Path(sp)))
                    if rel not in declared_record and not rel.endswith((".pyc", ".pyo")):
                        extra_files.append(rel)

    issues = []
    if hash_mismatches:
        issues.append(f"{len(hash_mismatches)} file(s) have wrong on-disk hashes")
    if missing_files:
        issues.append(f"{len(missing_files)} RECORD-declared file(s) are missing from disk")
    if extra_files:
        issues.append(f"{len(extra_files)} file(s) on disk are NOT declared in RECORD")

    if issues:
        return CheckResult(
            name, False, "critical",
            f"POST-INSTALL RECORD DIFF FAILED: {'; '.join(issues)}. "
            f"The installed files do not match what was declared in the wheel.",
            {
                "hash_mismatches": hash_mismatches[:10],
                "missing_files": missing_files[:10],
                "extra_files": extra_files[:10],
            },
        )

    return CheckResult(
        name, True, "info",
        f"Post-install RECORD diff clean: installed files match wheel declarations.",
        {
            "files_checked": len(declared_record),
            "extra_on_disk": 0,
        },
    )
