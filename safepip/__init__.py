"""
safepip — Hack-proof package installer with supply chain verification.

Checks performed before any install:
  1. PyPI metadata fetch & version validation
  2. Git tag ↔ PyPI release divergence detection (the LiteLLM attack vector)
  3. .pth file scan inside the downloaded wheel (auto-execute malware vector)
  4. Provenance / Trusted Publisher attestation check
  5. Hash pinning — SHA-256 of every file in the wheel
  6. Post-install .pth audit across site-packages
"""

from .installer import safe_install
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
from .sandbox import check_sandbox_import, run_import_sandbox
from .honeypot import populate_honeypot_home
from .lockfile import LockfileManager
from .report import SecurityReport

__version__ = "0.2.1"
__all__ = [
    "safe_install",
    "check_git_tag_divergence",
    "check_pth_files_in_wheel",
    "check_pypi_provenance",
    "check_post_install_pth",
    "fetch_package_metadata",
    "SecurityReport",
]
