"""
installer.py — safe_install with lockfile + full check suite.

Flow:
  1. Fetch PyPI metadata
  2. Check lockfile → if hit: verify wheel against lock (zero network) → install
  3. If no lock entry:
     a. Multi-source hash consensus (3 independent paths)
     b. Download wheel into memory
     c. RECORD manifest integrity
     d. Obfuscated code detection
     e. .pth file scan
     f. Git tag divergence
     g. Release timestamp delta
     h. PyPI provenance
  4. On all-pass: write lockfile entry, install with hash-pinned pip
  5. Post-install: RECORD diff + .pth audit
"""

from __future__ import annotations

import subprocess
import sys
import urllib.request
from typing import Optional

from .checks import (
    fetch_package_metadata,
    check_git_tag_divergence,
    check_pth_files_in_wheel,
    check_pypi_provenance,
    check_post_install_pth,
    check_multi_source_hash_consensus,
    check_wheel_record_integrity,
    check_obfuscated_code,
    check_release_timestamp_delta,
    check_post_install_record_diff,
)
from .lockfile import LockfileManager, build_lock_entry, verify_against_lock
from .report import SecurityReport


def safe_install(
    package: str,
    version: Optional[str] = None,
    *,
    force: bool = False,
    run_post_install_audit: bool = True,
    extra_pip_args: Optional[list[str]] = None,
    quiet: bool = False,
    lock_path=None,
) -> SecurityReport:
    """
    Securely install a PyPI package after all supply-chain checks.

    On first install: runs all checks, stores hash in lockfile.
    On repeat install: verifies against lockfile (zero network for hash checks).
    """
    if "==" in package and version is None:
        package, version = package.split("==", 1)

    lock_mgr = LockfileManager(lock_path)

    if not quiet:
        print(f"\n🔍 pipsentinel: checking {package}" +
              (f"=={version}" if version else " (latest)") + " ...")

    # ── 1. Metadata ──────────────────────────────────────────────────────────
    try:
        meta = fetch_package_metadata(package, version)
    except (ValueError, RuntimeError) as e:
        print(f"\n❌ {e}")
        sys.exit(1)

    report = SecurityReport(package=meta.name, version=meta.version)
    version = meta.version

    # ── 2. Lockfile fast-path ─────────────────────────────────────────────────
    existing_lock = lock_mgr.get(meta.name, version)

    if existing_lock and not force:
        if not quiet:
            print(f"🔒 Lock entry found from {existing_lock.locked_at}. "
                  f"Verifying wheel against local lock ...")

        wheel_entry = next(
            (w for w in meta.wheel_urls if w["filename"].endswith(".whl")), None
        )
        if wheel_entry:
            try:
                with urllib.request.urlopen(wheel_entry["url"], timeout=30) as resp:
                    wheel_bytes = resp.read()

                lock_passed, lock_msg = verify_against_lock(existing_lock, wheel_bytes)
                from .checks import CheckResult
                report.results.append(CheckResult(
                    "lockfile_verification",
                    lock_passed,
                    "info" if lock_passed else "critical",
                    lock_msg,
                    {"locked_at": existing_lock.locked_at},
                ))

                if not lock_passed:
                    print(report.summary())
                    print("🚫 Lockfile verification failed — installation blocked.")
                    return report

                report.results.append(check_pth_files_in_wheel(meta))

                if report.critical_failures and not force:
                    print(report.summary())
                    return report

                _do_pip_install(meta, wheel_entry, extra_pip_args, quiet)
                if run_post_install_audit:
                    _run_post_install(meta, existing_lock.record, report, quiet)
                if not quiet:
                    print(report.summary())
                return report

            except Exception as e:
                if not quiet:
                    print(f"⚠️  Could not download wheel for lock verification: {e}")

    # ── 3. Full check suite (first install) ──────────────────────────────────
    if not quiet:
        print("  Running full security check suite ...")

    report.results.append(check_multi_source_hash_consensus(meta))

    wheel_entry = next(
        (w for w in meta.wheel_urls if w["filename"].endswith(".whl")), None
    )
    wheel_bytes: Optional[bytes] = None

    if wheel_entry:
        try:
            with urllib.request.urlopen(wheel_entry["url"], timeout=30) as resp:
                wheel_bytes = resp.read()
        except Exception as e:
            if not quiet:
                print(f"  ⚠️  Could not download wheel for deep inspection: {e}")

    if wheel_bytes and wheel_entry:
        report.results.append(
            check_wheel_record_integrity(wheel_bytes, wheel_entry["filename"])
        )
        report.results.append(
            check_obfuscated_code(wheel_bytes, wheel_entry["filename"])
        )
        report.results.append(check_pth_files_in_wheel(meta))
    else:
        report.results.append(check_pth_files_in_wheel(meta))

    report.results.append(check_git_tag_divergence(meta))
    report.results.append(check_release_timestamp_delta(meta))
    report.results.append(check_pypi_provenance(meta))

    # ── 4. Report + gate ──────────────────────────────────────────────────────
    if not quiet:
        print(report.summary())

    if report.critical_failures and not force:
        print(
            f"🚫 pipsentinel: installation BLOCKED for {meta.name}=={version}.\n"
            f"   {len(report.critical_failures)} critical check(s) failed.\n"
            f"   Use force=True to override (strongly discouraged).\n"
        )
        return report

    # ── 5. Write lockfile entry ───────────────────────────────────────────────
    if wheel_bytes:
        lock_entry = build_lock_entry(meta.name, version, wheel_bytes)
        lock_mgr.put(lock_entry)
        if not quiet:
            print(f"🔒 Lock entry written: {lock_mgr.lock_path}")

    # ── 6. pip install with hash pinning ─────────────────────────────────────
    if wheel_entry:
        _do_pip_install(meta, wheel_entry, extra_pip_args, quiet)
    else:
        print(f"⚠️  No wheel entry available for hash-pinned install.")
        return report

    # ── 7. Post-install audit ─────────────────────────────────────────────────
    if run_post_install_audit:
        declared_record = lock_mgr.get(meta.name, version)
        _run_post_install(
            meta,
            declared_record.record if declared_record else {},
            report, quiet
        )

    if not quiet and not report.critical_failures:
        print(f"\n✅ {meta.name}=={version} installed and verified.\n")

    return report


def _do_pip_install(meta, wheel_entry, extra_pip_args, quiet):
    pip_cmd = [sys.executable, "-m", "pip", "install"]
    sha256 = wheel_entry.get("sha256", "")

    if sha256:
        pip_cmd += [
            "--require-hashes",
            f"{meta.name}=={meta.version}",
            f"--hash=sha256:{sha256}",
        ]
    else:
        pip_cmd += [f"{meta.name}=={meta.version}"]

    if extra_pip_args:
        pip_cmd += extra_pip_args

    if not quiet:
        print(f"📦 Installing: {' '.join(pip_cmd[3:])}")

    result = subprocess.run(pip_cmd, capture_output=not quiet)
    if result.returncode != 0:
        if quiet:
            sys.stderr.write(result.stderr.decode())
        print(f"\n❌ pip install failed (exit code {result.returncode})")


def _run_post_install(meta, declared_record, report, quiet):
    record_diff = check_post_install_record_diff(
        meta.name, meta.version, declared_record
    )
    report.results.append(record_diff)
    if not quiet:
        print(f"  {record_diff}")

    pth_audit = check_post_install_pth()
    report.results.append(pth_audit)
    if not quiet:
        print(f"  {pth_audit}")

    if not record_diff.passed or not pth_audit.passed:
        print(
            "\n🚨 POST-INSTALL ANOMALY DETECTED.\n"
            "   Rotate all credentials accessible from this machine.\n"
        )
