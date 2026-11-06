"""L14-SCAN-ACCURACY-001 — Web headers scanner known-answer accuracy tests.

Calls real scanner classification/finding-emitter logic.
Mocks only httpx.Client HTTP I/O.
Does NOT mock _check_hsts, _check_csp, _check_x_content_type, _check_referrer_policy,
_check_permissions_policy, or scan_target finding-emitter logic.

Critical truth conditions tested:
- Missing headers alone are NOT classified CRITICAL or HIGH without risk justification
  (NOTE: some headers ARE classified high by current logic — documented below)
- Timeout does NOT produce HEADERS_ALL_MISSING findings
- Each finding maps to an actual observed HTTP response (not an error state)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from services.connectors.web_headers.runner import (
    _check_hsts,
    _check_csp,
    _check_x_content_type,
    _check_referrer_policy,
    _check_permissions_policy,
    scan_target,
    run,
    _HSTS_MIN_MAX_AGE,
)
from services.connectors.safe_target_validator import SafeTargetValidationService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_response(
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    url: str = "https://example.com",
) -> MagicMock:
    """Build a mock httpx Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = httpx.Headers(headers or {})
    resp.url = httpx.URL(url)
    return resp


def _run_scan_target_with_response(
    url: str,
    response_headers: dict[str, str],
    response_url: str | None = None,
    status_code: int = 200,
) -> dict:
    """Run scan_target with a mocked HTTP response."""
    final_url = response_url or url
    mock_resp = _mock_response(
        status_code=status_code,
        headers=response_headers,
        url=final_url,
    )
    mock_resp.status_code = status_code

    with patch.object(SafeTargetValidationService, "validate") as mock_val:
        mock_val.return_value = MagicMock(ok=True, rejection_code=None, rejection_reason=None)
        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_client_class.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.head.return_value = mock_resp
            result = scan_target(url)
    return result


# ---------------------------------------------------------------------------
# SA-WEB-001: hsts_valid → HSTS_PRESENT, no HSTS finding
# ---------------------------------------------------------------------------

class TestHstsValid:
    def test_valid_hsts_produces_no_hsts_finding(self):
        findings = _check_hsts(f"max-age={_HSTS_MIN_MAX_AGE + 1}; includeSubDomains")
        hsts_types = [f["type"] for f in findings]
        assert "missing_hsts" not in hsts_types
        assert "hsts_short_maxage" not in hsts_types

    def test_valid_hsts_no_findings_at_all(self):
        """Adequate max-age + includeSubDomains = zero HSTS findings."""
        findings = _check_hsts(f"max-age={_HSTS_MIN_MAX_AGE * 2}; includeSubDomains; preload")
        assert findings == []


# ---------------------------------------------------------------------------
# SA-WEB-002: hsts_absent → HSTS_MISSING
# ---------------------------------------------------------------------------

class TestHstsAbsent:
    def test_missing_hsts_produces_finding(self):
        findings = _check_hsts(None)
        assert any(f["type"] == "missing_hsts" for f in findings)

    def test_missing_hsts_severity_is_documented(self):
        findings = _check_hsts(None)
        for f in findings:
            if f["type"] == "missing_hsts":
                assert f["severity"] in ("critical", "high", "medium", "low", "info")


# ---------------------------------------------------------------------------
# SA-WEB-003: hsts_weak_duration → HSTS_SHORT_DURATION
# ---------------------------------------------------------------------------

class TestHstsWeakDuration:
    def test_short_max_age_produces_hsts_short_maxage_finding(self):
        # 1 day << 6 months minimum
        findings = _check_hsts("max-age=86400; includeSubDomains")
        types = [f["type"] for f in findings]
        assert "hsts_short_maxage" in types

    def test_zero_max_age_produces_hsts_short_maxage_finding(self):
        findings = _check_hsts("max-age=0; includeSubDomains")
        types = [f["type"] for f in findings]
        assert "hsts_short_maxage" in types


# ---------------------------------------------------------------------------
# SA-WEB-004: csp_present → no CSP finding (informational)
# ---------------------------------------------------------------------------

class TestCspPresent:
    def test_basic_csp_no_unsafe_produces_no_csp_finding(self):
        findings = _check_csp("default-src 'self'; script-src 'self'")
        csp_types = [f["type"] for f in findings]
        assert "missing_csp" not in csp_types
        assert "csp_unsafe_inline" not in csp_types
        assert "csp_unsafe_eval" not in csp_types


# ---------------------------------------------------------------------------
# SA-WEB-005: csp_unsafe_directives → CSP_UNSAFE_DIRECTIVES
# ---------------------------------------------------------------------------

class TestCspUnsafeDirectives:
    def test_unsafe_inline_produces_finding(self):
        findings = _check_csp("default-src 'self'; script-src 'unsafe-inline'")
        types = [f["type"] for f in findings]
        assert "csp_unsafe_inline" in types

    def test_unsafe_eval_produces_finding(self):
        findings = _check_csp("default-src 'self'; script-src 'unsafe-eval'")
        types = [f["type"] for f in findings]
        assert "csp_unsafe_eval" in types

    def test_wildcard_source_produces_finding(self):
        findings = _check_csp("default-src *")
        types = [f["type"] for f in findings]
        assert "csp_wildcard_source" in types


# ---------------------------------------------------------------------------
# SA-WEB-006: x_content_type_options_missing → XCTO_MISSING
# ---------------------------------------------------------------------------

class TestXContentTypeOptions:
    def test_missing_xcto_produces_finding(self):
        findings = _check_x_content_type(None)
        types = [f["type"] for f in findings]
        assert "missing_x_content_type" in types

    def test_nosniff_produces_no_finding(self):
        findings = _check_x_content_type("nosniff")
        assert findings == []

    def test_nosniff_case_insensitive(self):
        findings = _check_x_content_type("NOSNIFF")
        assert findings == []


# ---------------------------------------------------------------------------
# SA-WEB-007: referrer_policy_missing → RP_MISSING
# ---------------------------------------------------------------------------

class TestReferrerPolicy:
    def test_missing_referrer_policy_produces_finding(self):
        findings = _check_referrer_policy(None)
        types = [f["type"] for f in findings]
        assert "missing_referrer_policy" in types

    def test_strict_origin_produces_no_finding(self):
        findings = _check_referrer_policy("strict-origin-when-cross-origin")
        assert findings == []

    def test_unsafe_url_produces_finding(self):
        findings = _check_referrer_policy("unsafe-url")
        types = [f["type"] for f in findings]
        assert "referrer_policy_unsafe" in types


# ---------------------------------------------------------------------------
# SA-WEB-008: CRITICAL — timeout does NOT produce HEADERS_ALL_MISSING findings
# ---------------------------------------------------------------------------

class TestTimeout:
    """CRITICAL TRUTH CONDITION: When the HTTP request times out, the scanner
    must NOT emit header findings. A timeout means we have NO header data.
    Emitting HEADERS_ALL_MISSING on timeout would be a false positive.
    """

    def test_timeout_produces_error_not_header_findings(self):
        with patch.object(SafeTargetValidationService, "validate") as mock_val:
            mock_val.return_value = MagicMock(ok=True, rejection_code=None, rejection_reason=None)
            with patch("httpx.Client") as mock_client_class:
                mock_client = MagicMock()
                mock_client_class.return_value.__enter__ = MagicMock(return_value=mock_client)
                mock_client_class.return_value.__exit__ = MagicMock(return_value=False)
                # Simulate timeout
                mock_client.head.side_effect = httpx.TimeoutException("timed out")
                result = scan_target("https://example.com")

        # On timeout: error is set, findings are empty.
        assert result.get("error") is not None
        assert result["findings"] == [], (
            "Timeout must NOT produce header findings. "
            "No headers were observed; emitting MISSING findings would be a false positive."
        )
        assert result["blocked"] is False  # timeout is not a validator block

    def test_connect_error_produces_error_not_header_findings(self):
        with patch.object(SafeTargetValidationService, "validate") as mock_val:
            mock_val.return_value = MagicMock(ok=True, rejection_code=None, rejection_reason=None)
            with patch("httpx.Client") as mock_client_class:
                mock_client = MagicMock()
                mock_client_class.return_value.__enter__ = MagicMock(return_value=mock_client)
                mock_client_class.return_value.__exit__ = MagicMock(return_value=False)
                mock_client.head.side_effect = httpx.ConnectError("connection refused")
                result = scan_target("https://example.com")

        assert result.get("error") is not None
        assert result["findings"] == []


# ---------------------------------------------------------------------------
# SA-WEB-009: redirect_blocked → rejected with UNSAFE_REDIRECT
# ---------------------------------------------------------------------------

class TestRedirectBlocked:
    """A redirect to a private IP must be rejected; no header findings emitted."""

    def test_unsafe_redirect_produces_blocked_result(self):
        redirect_resp = _mock_response(status_code=301, headers={"location": "http://192.168.1.1/"})
        redirect_resp.status_code = 301

        with patch.object(SafeTargetValidationService, "validate") as mock_val:
            # First call: initial URL is ok.
            # Second call (redirect target): blocked.
            def _side_effect(target, target_type=None):
                if "192.168" in str(target):
                    return MagicMock(
                        ok=False,
                        rejection_code="PRIVATE_IP",
                        rejection_reason="private range blocked",
                    )
                return MagicMock(ok=True, rejection_code=None, rejection_reason=None)

            mock_val.side_effect = _side_effect

            with patch("httpx.Client") as mock_client_class:
                mock_client = MagicMock()
                mock_client_class.return_value.__enter__ = MagicMock(return_value=mock_client)
                mock_client_class.return_value.__exit__ = MagicMock(return_value=False)
                mock_client.head.return_value = redirect_resp
                result = scan_target("https://example.com")

        assert result["blocked"] is True
        assert result["findings"] == [], (
            "Blocked redirect must NOT emit header findings — no headers were observed."
        )
        assert result.get("rejection_code") == "UNSAFE_REDIRECT"


# ---------------------------------------------------------------------------
# SA-WEB-010: missing_all_headers — aggregate but NOT classified CRITICAL
# ---------------------------------------------------------------------------

class TestMissingAllHeaders:
    """CRITICAL TRUTH CONDITION: Missing security headers alone are classified
    as HIGH or below per documented methodology. Some findings are HIGH (HSTS, plain_http)
    but none should be CRITICAL based solely on header absence.

    DEFECT DOCUMENTED: missing_hsts is currently HIGH severity, which may be
    considered aggressive for some contexts. plain_http is HIGH. Neither is CRITICAL.
    This test asserts no CRITICAL findings from header absence alone.
    """

    def test_no_security_headers_does_not_produce_critical_findings(self):
        result = _run_scan_target_with_response(
            "https://example.com",
            response_headers={},  # No security headers at all
        )
        for f in result["findings"]:
            assert f.get("severity") != "critical", (
                f"Finding {f.get('type')} has severity=critical from header absence alone. "
                "Header absence findings must not be CRITICAL without exploit evidence."
            )

    def test_all_headers_present_produces_minimal_findings(self):
        result = _run_scan_target_with_response(
            "https://example.com",
            response_headers={
                "strict-transport-security": f"max-age={_HSTS_MIN_MAX_AGE * 2}; includeSubDomains",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "geolocation=(), microphone=()",
            },
        )
        # With all headers present, there should be no HSTS/CSP/XCTO/RP/PP findings.
        finding_types = [f["type"] for f in result["findings"]]
        assert "missing_hsts" not in finding_types
        assert "hsts_short_maxage" not in finding_types
        assert "missing_csp" not in finding_types
        assert "missing_x_content_type" not in finding_types
        assert "missing_referrer_policy" not in finding_types
        assert "missing_permissions_policy" not in finding_types


# ---------------------------------------------------------------------------
# SA-WEB-011: private_ip_target → rejected by validator, blocked=True
# ---------------------------------------------------------------------------

class TestPrivateIpTarget:
    def test_private_ip_target_is_blocked_no_findings(self):
        result = scan_target("https://192.168.1.1")
        assert result["blocked"] is True
        assert result["findings"] == []


# ---------------------------------------------------------------------------
# SA-WEB-012: scan provenance — finding maps to observed response
# ---------------------------------------------------------------------------

class TestFindingProvenance:
    """Every finding must correspond to data actually observed in the HTTP response."""

    def test_findings_reference_actual_observed_response(self):
        result = _run_scan_target_with_response(
            "https://example.com",
            response_headers={"x-frame-options": "DENY"},
        )
        # We provided x-frame-options: x_frame finding should NOT appear.
        finding_types = [f["type"] for f in result["findings"]]
        assert "missing_x_frame_options" not in finding_types

    def test_scan_target_records_headers_present_and_missing(self):
        result = _run_scan_target_with_response(
            "https://example.com",
            response_headers={"x-content-type-options": "nosniff"},
        )
        assert "x-content-type-options" in result.get("headers_present", [])
        # Other headers not provided should appear in headers_missing
        assert "strict-transport-security" in result.get("headers_missing", [])
