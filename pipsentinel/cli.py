"""
CLI entry point for pipsentinel.

Usage:
    pipsentinel install requests
    pipsentinel install numpy==1.26.4
    pipsentinel audit                    # post-install site-packages scan
    pipsentinel check somepackage==1.0.0 # check only, don't install
    pipsentinel check requests --json    # output JSON report
"""

from __future__ import annotations

import argparse
import json
import sys

from .checks import fetch_package_metadata, check_git_tag_divergence, check_pth_files_in_wheel, check_pypi_provenance, check_post_install_pth
from .installer import safe_install
from .report import SecurityReport


def cmd_install(args: argparse.Namespace) -> int:
    pkg = args.package
    version = None
    if "==" in pkg:
        pkg, version = pkg.split("==", 1)

    report = safe_install(
        pkg,
        version=version,
        force=args.force,
        quiet=args.quiet,
    )

    if args.json:
        print(report.to_json())

    return 0 if report.safe_to_install else 1


def cmd_check(args: argparse.Namespace) -> int:
    pkg = args.package
    version = None
    if "==" in pkg:
        pkg, version = pkg.split("==", 1)

    print(f"\n🔍 pipsentinel: checking {pkg}" + (f"=={version}" if version else " (latest)") + " ...")

    try:
        meta = fetch_package_metadata(pkg, version)
    except Exception as e:
        print(f"❌ {e}")
        return 1

    report = SecurityReport(package=meta.name, version=meta.version)
    report.results = [
        check_git_tag_divergence(meta),
        check_pth_files_in_wheel(meta),
        check_pypi_provenance(meta),
    ]

    if args.json:
        print(report.to_json())
    else:
        print(report.summary())

    return 0 if report.safe_to_install else 1


def cmd_audit(_args: argparse.Namespace) -> int:
    print("\n🔎 pipsentinel: auditing site-packages for suspicious .pth files ...\n")
    result = check_post_install_pth()
    print(result)
    if not result.passed:
        print("\nDetail:")
        for f in result.detail.get("suspicious_files", []):
            print(f"  🚨 {f['path']}")
            for line in f.get("import_lines", []):
                print(f"       import line: {line[:120]}")
    return 0 if result.passed else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="pipsentinel",
        description="Hack-proof pip: supply chain checks before every install.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # install
    p_install = sub.add_parser("install", help="Check and install a package securely")
    p_install.add_argument("package", help="Package name, e.g. requests or litellm==1.82.6")
    p_install.add_argument("--force", action="store_true", help="Install even if critical checks fail")
    p_install.add_argument("--quiet", "-q", action="store_true")
    p_install.add_argument("--json", action="store_true", help="Output JSON report")

    # check (no install)
    p_check = sub.add_parser("check", help="Run security checks without installing")
    p_check.add_argument("package")
    p_check.add_argument("--json", action="store_true")

    # audit (post-install scan)
    sub.add_parser("audit", help="Scan site-packages for suspicious .pth files")

    args = parser.parse_args()

    dispatch = {
        "install": cmd_install,
        "check": cmd_check,
        "audit": cmd_audit,
    }

    sys.exit(dispatch[args.command](args))


if __name__ == "__main__":
    main()
