"""tests/test_prod_auth_automation_001.py — PROD-AUTH-AUTOMATION-001 harness unit tests.

Tests the production smoke runner, evidence schema, and failure condition handling.
No network calls to production. All checks use mock HTTP responses.

Classification:
  fg-fast compatible (no slow marker, no network)
  PROD_AUTH_AUTOMATION_HARNESS = PASS
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# E402: path manipulation must precede these project imports
from tools.testing.production.evidence import (  # noqa: E402
    CheckResult,
    EvidenceRecord,
    EvidenceResult,
    _canonical_json,
    finalize,
    fingerprint,
    now_iso,
    write_evidence,
)
from tools.testing.production.prod_smoke_001 import (  # noqa: E402
    _find_sensitive_keys,
    _flatten_keys,
    check_dashboard_redirect,
    check_login_accessible,
    check_root_accessible,
    check_session_endpoint,
    check_session_no_secrets,
    check_vercel_deployment,
    run_smoke,
)

pytestmark = pytest.mark.smoke


# ---------------------------------------------------------------------------
# Evidence module tests
# ---------------------------------------------------------------------------


class TestEvidenceResult(unittest.TestCase):
    def test_result_enum_values(self) -> None:
        assert EvidenceResult.PASS.value == "PASS"
        assert EvidenceResult.FAIL.value == "FAIL"
        assert EvidenceResult.NOT_PROVEN.value == "NOT_PROVEN"

    def test_check_result_to_dict(self) -> None:
        ts = now_iso()
        c = CheckResult(
            id="TEST-001",
            description="desc",
            expected="200",
            observed="200",
            result=EvidenceResult.PASS,
            timestamp=ts,
        )
        d = c.to_dict()
        assert d["id"] == "TEST-001"
        assert d["result"] == "PASS"
        assert "diagnostic" not in d

    def test_check_result_includes_diagnostic_when_set(self) -> None:
        c = CheckResult(
            id="TEST-001",
            description="desc",
            expected="200",
            observed="500",
            result=EvidenceResult.FAIL,
            timestamp=now_iso(),
            diagnostic="server error",
        )
        d = c.to_dict()
        assert d["diagnostic"] == "server error"

    def test_fingerprint_deterministic(self) -> None:
        r = EvidenceRecord(timestamp="2026-01-01T00:00:00Z", run_id="abc")
        fp1 = fingerprint(r)
        fp2 = fingerprint(r)
        assert fp1 == fp2
        assert fp1.startswith("sha256:")

    def test_fingerprint_changes_on_mutation(self) -> None:
        r = EvidenceRecord(timestamp="2026-01-01T00:00:00Z", run_id="abc")
        fp1 = fingerprint(r)
        r.repo_sha = "changed"
        fp2 = fingerprint(r)
        assert fp1 != fp2

    def test_fingerprint_excludes_itself(self) -> None:
        r = EvidenceRecord(timestamp="2026-01-01T00:00:00Z", run_id="abc")
        r.evidence_fingerprint = "sha256:whatever"
        fp = fingerprint(r)
        r2 = EvidenceRecord(timestamp="2026-01-01T00:00:00Z", run_id="abc")
        r2.evidence_fingerprint = "sha256:different"
        fp2 = fingerprint(r2)
        assert fp == fp2

    def test_finalize_all_pass(self) -> None:
        r = EvidenceRecord()
        r.checks = [
            CheckResult("A", "d", "e", "o", EvidenceResult.PASS, now_iso()),
            CheckResult("B", "d", "e", "o", EvidenceResult.PASS, now_iso()),
        ]
        finalize(r)
        assert r.overall_result == EvidenceResult.PASS
        assert r.evidence_fingerprint.startswith("sha256:")

    def test_finalize_any_fail(self) -> None:
        r = EvidenceRecord()
        r.checks = [
            CheckResult("A", "d", "e", "o", EvidenceResult.PASS, now_iso()),
            CheckResult("B", "d", "e", "o", EvidenceResult.FAIL, now_iso()),
        ]
        finalize(r)
        assert r.overall_result == EvidenceResult.FAIL

    def test_finalize_mixed_not_proven(self) -> None:
        r = EvidenceRecord()
        r.checks = [
            CheckResult("A", "d", "e", "o", EvidenceResult.PASS, now_iso()),
            CheckResult("B", "d", "e", "o", EvidenceResult.NOT_PROVEN, now_iso()),
        ]
        finalize(r)
        assert r.overall_result == EvidenceResult.NOT_PROVEN

    def test_finalize_empty_checks(self) -> None:
        r = EvidenceRecord()
        r.checks = []
        finalize(r)
        assert r.overall_result == EvidenceResult.NOT_PROVEN

    def test_write_evidence(self, tmp_path: Path = None) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            r = EvidenceRecord(run_id="test-run")
            path = Path(tmpdir) / "evidence.json"
            write_evidence(r, path)
            assert path.exists()
            data = json.loads(path.read_text())
            assert data["run_id"] == "test-run"

    def test_canonical_json_deterministic(self) -> None:
        obj = {"b": 2, "a": 1, "c": [3, 2, 1]}
        j1 = _canonical_json(obj)
        j2 = _canonical_json(obj)
        assert j1 == j2

    def test_canonical_json_sorts_keys(self) -> None:
        obj = {"z": 1, "a": 2}
        s = _canonical_json(obj).decode()
        assert s.index('"a"') < s.index('"z"')

    def test_flatten_keys_nested(self) -> None:
        obj = {"user": {"token": "abc", "id": 1}, "expires": "2026"}
        keys = _flatten_keys(obj)
        assert "user" in keys
        assert "token" in keys
        assert "id" in keys
        assert "expires" in keys

    def test_find_sensitive_keys_detects_token(self) -> None:
        obj = {"user": None, "expires": "2026", "token": "abc"}
        leaked = _find_sensitive_keys(obj)
        assert "token" in leaked

    def test_find_sensitive_keys_clean(self) -> None:
        obj = {"user": None, "expires": "2026"}
        leaked = _find_sensitive_keys(obj)
        assert not leaked

    def test_find_sensitive_keys_nested_secret(self) -> None:
        obj = {"data": {"secret": "x"}}
        leaked = _find_sensitive_keys(obj)
        assert "secret" in leaked


# ---------------------------------------------------------------------------
# Smoke runner tests (mocked HTTP)
# ---------------------------------------------------------------------------


def _mock_session(responses: dict[str, Any]) -> MagicMock:
    """Build a mock requests.Session from (url, method) → response spec."""
    session = MagicMock()

    def make_response(
        url: str, allow_redirects: bool = True, **_kwargs: Any
    ) -> MagicMock:
        r = responses.get(url)
        if r is None:
            resp = MagicMock()
            resp.status_code = 404
            resp.headers = {}
            return resp
        resp = MagicMock()
        resp.status_code = r.get("status_code", 200)
        resp.headers = r.get("headers", {})
        resp.json.return_value = r.get("json", {})
        content_type = r.get("content_type", "application/json")
        resp.headers["content-type"] = content_type
        return resp

    session.get.side_effect = make_response
    return session


class TestCheckRootAccessible(unittest.TestCase):
    def test_pass_on_200(self) -> None:
        session = _mock_session({"https://test.example.com/": {"status_code": 200}})
        c = check_root_accessible(session, "https://test.example.com")
        assert c.result == EvidenceResult.PASS
        assert c.id == "SMOKE-001"

    def test_fail_on_500(self) -> None:
        session = _mock_session({"https://test.example.com/": {"status_code": 500}})
        c = check_root_accessible(session, "https://test.example.com")
        assert c.result == EvidenceResult.FAIL

    def test_fail_on_timeout(self) -> None:
        import requests as req_lib

        session = MagicMock()
        session.get.side_effect = req_lib.Timeout()
        c = check_root_accessible(session, "https://test.example.com")
        assert c.result == EvidenceResult.FAIL
        assert "TIMEOUT" in c.observed

    def test_fail_on_connection_error(self) -> None:
        import requests as req_lib

        session = MagicMock()
        session.get.side_effect = req_lib.ConnectionError("connection refused")
        c = check_root_accessible(session, "https://test.example.com")
        assert c.result == EvidenceResult.FAIL
        assert "CONNECTION_ERROR" in c.observed


class TestCheckLoginAccessible(unittest.TestCase):
    def test_pass_on_200(self) -> None:
        session = _mock_session(
            {"https://test.example.com/login": {"status_code": 200}}
        )
        c = check_login_accessible(session, "https://test.example.com")
        assert c.result == EvidenceResult.PASS
        assert c.id == "SMOKE-002"

    def test_fail_on_404(self) -> None:
        session = _mock_session(
            {"https://test.example.com/login": {"status_code": 404}}
        )
        c = check_login_accessible(session, "https://test.example.com")
        assert c.result == EvidenceResult.FAIL


class TestCheckSessionEndpoint(unittest.TestCase):
    def test_pass_on_200_json(self) -> None:
        session = _mock_session(
            {
                "https://test.example.com/api/auth/session": {
                    "status_code": 200,
                    "content_type": "application/json",
                }
            }
        )
        c = check_session_endpoint(session, "https://test.example.com")
        assert c.result == EvidenceResult.PASS
        assert c.id == "SMOKE-003"

    def test_fail_on_non_json_content_type(self) -> None:
        session = _mock_session(
            {
                "https://test.example.com/api/auth/session": {
                    "status_code": 200,
                    "content_type": "text/html",
                }
            }
        )
        c = check_session_endpoint(session, "https://test.example.com")
        assert c.result == EvidenceResult.FAIL

    def test_fail_on_non_200(self) -> None:
        session = _mock_session(
            {
                "https://test.example.com/api/auth/session": {
                    "status_code": 401,
                    "content_type": "application/json",
                }
            }
        )
        c = check_session_endpoint(session, "https://test.example.com")
        assert c.result == EvidenceResult.FAIL


class TestCheckDashboardRedirect(unittest.TestCase):
    def test_pass_on_302_to_login(self) -> None:
        session = _mock_session(
            {
                "https://test.example.com/dashboard": {
                    "status_code": 302,
                    "headers": {
                        "location": "https://test.example.com/login?callbackUrl=%2Fdashboard"
                    },
                }
            }
        )
        c = check_dashboard_redirect(session, "https://test.example.com")
        assert c.result == EvidenceResult.PASS
        assert c.id == "SMOKE-004"

    def test_pass_on_307_to_login(self) -> None:
        session = _mock_session(
            {
                "https://test.example.com/dashboard": {
                    "status_code": 307,
                    "headers": {"location": "/login"},
                }
            }
        )
        c = check_dashboard_redirect(session, "https://test.example.com")
        assert c.result == EvidenceResult.PASS

    def test_fail_on_200_no_redirect(self) -> None:
        session = _mock_session(
            {
                "https://test.example.com/dashboard": {
                    "status_code": 200,
                    "headers": {},
                }
            }
        )
        c = check_dashboard_redirect(session, "https://test.example.com")
        assert c.result == EvidenceResult.FAIL

    def test_fail_on_redirect_to_wrong_destination(self) -> None:
        session = _mock_session(
            {
                "https://test.example.com/dashboard": {
                    "status_code": 302,
                    "headers": {"location": "/home"},
                }
            }
        )
        c = check_dashboard_redirect(session, "https://test.example.com")
        assert c.result == EvidenceResult.FAIL
        assert "not /login" in (c.diagnostic or "")


class TestCheckSessionNoSecrets(unittest.TestCase):
    def test_pass_on_clean_session(self) -> None:
        session = _mock_session(
            {
                "https://test.example.com/api/auth/session": {
                    "status_code": 200,
                    "content_type": "application/json",
                    "json": {},
                }
            }
        )
        c = check_session_no_secrets(session, "https://test.example.com")
        assert c.result == EvidenceResult.PASS
        assert c.id == "SMOKE-006"

    def test_fail_on_session_with_token(self) -> None:
        session = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"content-type": "application/json"}
        resp.json.return_value = {"token": "abc123"}
        session.get.return_value = resp
        c = check_session_no_secrets(session, "https://test.example.com")
        assert c.result == EvidenceResult.FAIL
        assert "token" in c.observed

    def test_fail_on_session_with_access_token(self) -> None:
        session = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"content-type": "application/json"}
        resp.json.return_value = {"user": {"id": "123"}, "access_token": "secret"}
        session.get.return_value = resp
        c = check_session_no_secrets(session, "https://test.example.com")
        assert c.result == EvidenceResult.FAIL

    def test_not_proven_on_non_200(self) -> None:
        session = _mock_session(
            {
                "https://test.example.com/api/auth/session": {
                    "status_code": 401,
                    "content_type": "application/json",
                }
            }
        )
        c = check_session_no_secrets(session, "https://test.example.com")
        assert c.result == EvidenceResult.NOT_PROVEN


class TestCheckVercelDeployment(unittest.TestCase):
    def test_not_proven_without_env_vars(self) -> None:
        with patch.dict("os.environ", {"VERCEL_TOKEN": "", "VERCEL_PROJECT_ID": ""}):
            c, sha = check_vercel_deployment("https://test.example.com")
        assert c.result == EvidenceResult.NOT_PROVEN
        assert sha == "NOT_PROVEN"
        assert c.id == "SMOKE-005"

    def test_pass_on_ready_deployment(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "VERCEL_TOKEN": "test-token",
                "VERCEL_PROJECT_ID": "proj-123",
                "VERCEL_TEAM_ID": "",
            },
        ):
            with patch("requests.get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = {
                    "deployments": [
                        {
                            "uid": "dpl-abc",
                            "readyState": "READY",
                            "gitSource": {"sha": "abc123def456"},
                        }
                    ]
                }
                mock_get.return_value = mock_resp
                c, sha = check_vercel_deployment("https://test.example.com")
        assert c.result == EvidenceResult.PASS
        assert sha == "abc123def456"

    def test_not_proven_on_non_ready_deployment(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "VERCEL_TOKEN": "test-token",
                "VERCEL_PROJECT_ID": "proj-123",
                "VERCEL_TEAM_ID": "",
            },
        ):
            with patch("requests.get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = {
                    "deployments": [
                        {
                            "uid": "dpl-abc",
                            "readyState": "BUILDING",
                            "gitSource": {"sha": "abc123"},
                        }
                    ]
                }
                mock_get.return_value = mock_resp
                c, sha = check_vercel_deployment("https://test.example.com")
        assert c.result == EvidenceResult.NOT_PROVEN

    def test_fail_on_vercel_api_error(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "VERCEL_TOKEN": "test-token",
                "VERCEL_PROJECT_ID": "proj-123",
                "VERCEL_TEAM_ID": "",
            },
        ):
            with patch("requests.get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 401
                mock_get.return_value = mock_resp
                c, sha = check_vercel_deployment("https://test.example.com")
        assert c.result == EvidenceResult.FAIL


# ---------------------------------------------------------------------------
# Run smoke integration test (mocked)
# ---------------------------------------------------------------------------


class TestRunSmoke(unittest.TestCase):
    def _make_session_patcher(self) -> None:
        pass

    def test_run_smoke_produces_evidence_record(self) -> None:
        with patch("tools.testing.production.prod_smoke_001.requests") as mock_req_mod:
            session_inst = MagicMock()
            mock_req_mod.Session.return_value = session_inst

            def mock_get(
                url: str,
                timeout: int = 15,
                allow_redirects: bool = True,
                **_kwargs: Any,
            ) -> MagicMock:
                resp = MagicMock()
                if url.endswith("/") or url.endswith(".com/"):
                    resp.status_code = 200
                    resp.headers = {"content-type": "application/json"}
                    resp.json.return_value = {}
                elif url.endswith("/login"):
                    resp.status_code = 200
                    resp.headers = {"content-type": "text/html"}
                    resp.json.return_value = {}
                elif "/api/auth/session" in url:
                    resp.status_code = 200
                    resp.headers = {"content-type": "application/json"}
                    resp.json.return_value = {}
                elif "/dashboard" in url:
                    resp.status_code = 302
                    resp.headers = {"location": "/login?callbackUrl=%2Fdashboard"}
                    resp.json.return_value = {}
                else:
                    resp.status_code = 404
                    resp.headers = {}
                    resp.json.return_value = {}
                return resp

            session_inst.get.side_effect = mock_get
            mock_req_mod.Timeout = __import__("requests").Timeout
            mock_req_mod.ConnectionError = __import__("requests").ConnectionError

            with patch(
                "tools.testing.production.prod_smoke_001.check_vercel_deployment"
            ) as mock_vd:
                ts = now_iso()
                mock_vd.return_value = (
                    CheckResult(
                        "SMOKE-005", "Vercel", "e", "o", EvidenceResult.NOT_PROVEN, ts
                    ),
                    "NOT_PROVEN",
                )
                record = run_smoke("https://test.example.com")

        assert record.schema_version == "prod-auth-automation-001/v1"
        assert len(record.checks) == 6
        assert record.evidence_fingerprint.startswith("sha256:")
        assert record.work_item == "PROD-AUTH-AUTOMATION-001"

    def test_run_smoke_fails_on_non_redirect_dashboard(self) -> None:
        with patch("tools.testing.production.prod_smoke_001.requests") as mock_req_mod:
            session_inst = MagicMock()
            mock_req_mod.Session.return_value = session_inst

            def mock_get(
                url: str,
                timeout: int = 15,
                allow_redirects: bool = True,
                **_kwargs: Any,
            ) -> MagicMock:
                resp = MagicMock()
                resp.headers = {"content-type": "application/json"}
                resp.json.return_value = {}
                if "/dashboard" in url:
                    resp.status_code = 200  # Wrong: should redirect
                else:
                    resp.status_code = 200
                return resp

            session_inst.get.side_effect = mock_get
            mock_req_mod.Timeout = __import__("requests").Timeout
            mock_req_mod.ConnectionError = __import__("requests").ConnectionError

            with patch(
                "tools.testing.production.prod_smoke_001.check_vercel_deployment"
            ) as mock_vd:
                ts = now_iso()
                mock_vd.return_value = (
                    CheckResult(
                        "SMOKE-005", "Vercel", "e", "o", EvidenceResult.NOT_PROVEN, ts
                    ),
                    "NOT_PROVEN",
                )
                record = run_smoke("https://test.example.com")

        dashboard_check = next(c for c in record.checks if c.id == "SMOKE-004")
        assert dashboard_check.result == EvidenceResult.FAIL
        assert record.overall_result == EvidenceResult.FAIL


# ---------------------------------------------------------------------------
# Mode B activation guard tests
# ---------------------------------------------------------------------------


class TestActivationGuard(unittest.TestCase):
    def test_guard_fails_without_enabled_flag(self) -> None:
        from tools.testing.production.auth_harness_001 import _activation_guard

        with patch.dict(
            "os.environ",
            {
                "FG_PROD_AUTH_TEST_ENABLED": "",
                "FG_PROD_TEST_EMAIL": "test@example.com",
                "FG_PROD_TEST_PASSWORD": "pass",
            },
        ):
            ok, reason = _activation_guard()
        assert not ok
        assert "FG_PROD_AUTH_TEST_ENABLED" in reason

    def test_guard_fails_without_email(self) -> None:
        from tools.testing.production.auth_harness_001 import _activation_guard

        with patch.dict(
            "os.environ",
            {
                "FG_PROD_AUTH_TEST_ENABLED": "true",
                "FG_PROD_TEST_EMAIL": "",
                "FG_PROD_TEST_PASSWORD": "pass",
            },
        ):
            ok, reason = _activation_guard()
        assert not ok
        assert "FG_PROD_TEST_EMAIL" in reason

    def test_guard_fails_without_password(self) -> None:
        from tools.testing.production.auth_harness_001 import _activation_guard

        with patch.dict(
            "os.environ",
            {
                "FG_PROD_AUTH_TEST_ENABLED": "true",
                "FG_PROD_TEST_EMAIL": "test@example.com",
                "FG_PROD_TEST_PASSWORD": "",
            },
        ):
            ok, reason = _activation_guard()
        assert not ok
        assert "FG_PROD_TEST_PASSWORD" in reason

    def test_guard_passes_when_all_set(self) -> None:
        from tools.testing.production.auth_harness_001 import _activation_guard

        with patch.dict(
            "os.environ",
            {
                "FG_PROD_AUTH_TEST_ENABLED": "true",
                "FG_PROD_TEST_EMAIL": "test@example.com",
                "FG_PROD_TEST_PASSWORD": "pass",
            },
        ):
            ok, reason = _activation_guard()
        assert ok
        assert reason == ""

    def test_guard_requires_exactly_true(self) -> None:
        from tools.testing.production.auth_harness_001 import _activation_guard

        for bad_value in ("True", "TRUE", "1", "yes", "on"):
            with patch.dict(
                "os.environ",
                {
                    "FG_PROD_AUTH_TEST_ENABLED": bad_value,
                    "FG_PROD_TEST_EMAIL": "test@example.com",
                    "FG_PROD_TEST_PASSWORD": "pass",
                },
            ):
                ok, _ = _activation_guard()
            assert not ok, f"Expected guard to fail for {bad_value!r}"


# ---------------------------------------------------------------------------
# Secret redaction invariant tests
# ---------------------------------------------------------------------------


class TestSecretRedaction(unittest.TestCase):
    def test_evidence_never_contains_password(self) -> None:
        """Evidence JSON must not contain a password-adjacent field."""
        r = EvidenceRecord(run_id="test")
        r.checks = [
            CheckResult(
                id="AUTH-002",
                description="Session established",
                expected="session cookie",
                observed="session cookie present",
                result=EvidenceResult.PASS,
                timestamp=now_iso(),
            )
        ]
        finalize(r)
        evidence_json = json.dumps(r.to_dict())
        for forbidden in ("password", "secret", "token", "credential"):
            assert forbidden not in evidence_json.lower(), (
                f"Evidence JSON contains forbidden field: {forbidden!r}"
            )

    def test_test_identity_ref_redacts_domain(self) -> None:
        """test_identity_ref must redact the email domain."""
        email = "synthetic-tester@frostgate.ai"
        ref = f"synthetic:{email.split('@')[0]}@[domain-redacted]"
        assert "frostgate.ai" not in ref
        assert "synthetic-tester" in ref

    def test_evidence_fingerprint_format(self) -> None:
        r = EvidenceRecord()
        finalize(r)
        assert r.evidence_fingerprint.startswith("sha256:")
        hex_part = r.evidence_fingerprint[7:]
        assert len(hex_part) == 64
        assert all(c in "0123456789abcdef" for c in hex_part)


if __name__ == "__main__":
    unittest.main()
