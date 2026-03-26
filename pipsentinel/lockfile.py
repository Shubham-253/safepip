"""
safepip.lockfile — Offline hash-pinned verification.

Design: once a package version is verified, its per-file SHA-256 manifest
is stored in safepip.lock (JSON). All subsequent installs verify against
this local record — zero network required.

This eliminates the "check the check" attack: even if PyPI's API lies about
hashes (MITM or compromised endpoint), your local lock still catches it.

Lock format:
{
  "litellm==1.82.6": {
    "locked_at": "2026-03-24T10:00:00Z",
    "wheel_sha256": "abc123...",        # whole-wheel digest
    "record": {                          # per-file digests from RECORD
      "litellm/__init__.py": "sha256:...",
      ...
    }
  }
}
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


DEFAULT_LOCK_PATH = Path.home() / ".pipsentinel" / "pipsentinel.lock"


@dataclass
class LockEntry:
    package: str        # "litellm"
    version: str        # "1.82.6"
    locked_at: str      # ISO-8601 UTC
    wheel_sha256: str   # SHA-256 of entire wheel file
    record: dict        # filename → "sha256:<hex>" from RECORD manifest


class LockfileManager:
    """
    Manages the safepip.lock file.
    Thread-safety: single process only; suitable for CLI use.
    """

    def __init__(self, lock_path: Optional[Path] = None):
        self.lock_path = lock_path or DEFAULT_LOCK_PATH
        self._data: dict = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        if self.lock_path.exists():
            try:
                self._data = json.loads(self.lock_path.read_text())
            except (json.JSONDecodeError, OSError):
                self._data = {}
        self._loaded = True

    def _save(self) -> None:
        self.lock_path.write_text(json.dumps(self._data, indent=2))

    def key(self, package: str, version: str) -> str:
        return f"{package.lower()}=={version}"

    def get(self, package: str, version: str) -> Optional[LockEntry]:
        self._ensure_loaded()
        entry = self._data.get(self.key(package, version))
        if not entry:
            return None
        return LockEntry(
            package=package,
            version=version,
            locked_at=entry["locked_at"],
            wheel_sha256=entry["wheel_sha256"],
            record=entry.get("record", {}),
        )

    def put(self, entry: LockEntry) -> None:
        self._ensure_loaded()
        self._data[self.key(entry.package, entry.version)] = {
            "locked_at": entry.locked_at,
            "wheel_sha256": entry.wheel_sha256,
            "record": entry.record,
        }
        self._save()

    def remove(self, package: str, version: str) -> bool:
        self._ensure_loaded()
        k = self.key(package, version)
        if k in self._data:
            del self._data[k]
            self._save()
            return True
        return False

    def list_all(self) -> list[LockEntry]:
        self._ensure_loaded()
        entries = []
        for k, v in self._data.items():
            pkg, ver = k.split("==", 1)
            entries.append(LockEntry(
                package=pkg, version=ver,
                locked_at=v["locked_at"],
                wheel_sha256=v["wheel_sha256"],
                record=v.get("record", {}),
            ))
        return entries


def build_lock_entry(package: str, version: str, wheel_bytes: bytes) -> LockEntry:
    """
    Build a LockEntry from a downloaded wheel's raw bytes.
    Extracts per-file hashes from the RECORD manifest inside the wheel.
    """
    wheel_sha256 = hashlib.sha256(wheel_bytes).hexdigest()
    record: dict = {}

    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as zf:
            # Find the RECORD file (always at <pkg>-<ver>.dist-info/RECORD)
            record_names = [n for n in zf.namelist() if n.endswith(".dist-info/RECORD")]
            if record_names:
                record_content = zf.read(record_names[0]).decode(errors="replace")
                for line in record_content.splitlines():
                    parts = line.strip().split(",")
                    if len(parts) >= 2 and parts[1].startswith("sha256:"):
                        record[parts[0]] = parts[1]  # path → "sha256:<hex>"
    except zipfile.BadZipFile:
        pass

    return LockEntry(
        package=package,
        version=version,
        locked_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        wheel_sha256=wheel_sha256,
        record=record,
    )


def verify_against_lock(entry: LockEntry, wheel_bytes: bytes) -> tuple[bool, str]:
    """
    Verify downloaded wheel bytes against a stored LockEntry.

    Returns (passed: bool, message: str)

    This is the zero-network verification path:
    - If the whole-wheel SHA-256 matches the lock → trusted, install.
    - If it mismatches → BLOCK, something changed since locking.
    """
    actual_sha256 = hashlib.sha256(wheel_bytes).hexdigest()

    if actual_sha256 != entry.wheel_sha256:
        return False, (
            f"LOCKFILE MISMATCH: wheel SHA-256 changed since locking on {entry.locked_at}. "
            f"Expected {entry.wheel_sha256[:16]}… got {actual_sha256[:16]}… "
            f"The wheel on PyPI has been modified. Do NOT install."
        )

    return True, (
        f"Wheel matches lockfile entry from {entry.locked_at}. "
        f"No network verification needed."
    )
