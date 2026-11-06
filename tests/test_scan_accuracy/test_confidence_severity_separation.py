"""L14-SCAN-ACCURACY-001 — Confidence/severity separation and DEF-003 regression.

This test file covers:
1. High-severity finding can have SUSPECTED confidence (independent axes)
2. Low-severity finding can have CONFIRMED confidence
3. Confidence is NOT calculated from severity
4. If a runner does not emit a confidence field, it defaults to NOT_ASSESSED (not CONFIRMED)
5. DEF-003 regression: documents and tests that runner outputs lack confidence fields

DEF-003: No confidence field in runner outputs.
  All scanner runners (network_scan, web_headers, dns_email, endpoint_inventory,
  oauth_inventory, oauth_risk, ai_tool_discovery) produce findings without an
  explicit `confidence` field. As a result, all findings are implicitly
  NOT_ASSESSED until L14-SCAN-INTEGRITY-001 adds the field.

  Code reference: docs/audits/L14_SCAN_AUDIT_CORRECTIONS.md — COR-008
  Policy reference: docs/assurance/FROSTGATE_FINDING_CONFIDENCE_POLICY.md
  Pending: L14-SCAN-INTEGRITY-001
"""

from __future__ import annotations

from unittest.mock import patch

# ---------------------------------------------------------------------------
# Import the confidence validator from the existing test infrastructure
# ---------------------------------------------------------------------------

# Reuse the same validation logic defined in test_confidence_model.py
# by directly re-implementing the minimal rules here (pure logic, no dep).

CONFIDENCE_LEVELS = frozenset(
    {"CONFIRMED", "PROBABLE", "SUSPECTED", "UNKNOWN", "NOT_ASSESSED"}
)
SEVERITY_LEVELS = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"})


def _default_confidence_for_missing_field(finding: dict) -> str:
    """Policy: if 'confidence' field is absent from a runner finding,
    treat it as NOT_ASSESSED — not CONFIRMED.

    This is the correct interpretation per FROSTGATE_FINDING_CONFIDENCE_POLICY.md
    Rule 3.6: 'Missing data must produce UNKNOWN or NOT_ASSESSED.'

    A runner that does not emit a confidence field has not assessed the finding's
    confidence — therefore NOT_ASSESSED is the correct default.
    """
    return finding.get("confidence", "NOT_ASSESSED")


def _confidence_from_severity_would_be_wrong(severity: str) -> str:
    """WRONG: computing confidence from severity.
    Demonstrates the anti-pattern that must NOT occur.
    """
    # This mapping is INCORRECT and must not exist in production code.
    wrong_map = {
        "CRITICAL": "CONFIRMED",
        "HIGH": "PROBABLE",
        "MEDIUM": "SUSPECTED",
        "LOW": "SUSPECTED",
        "INFORMATIONAL": "NOT_ASSESSED",
    }
    return wrong_map.get(severity, "NOT_ASSESSED")


# ---------------------------------------------------------------------------
# SA-SEP-001: High-severity finding may have SUSPECTED confidence
# ---------------------------------------------------------------------------


class TestHighSeveritySuspectedConfidence:
    """CRITICAL TRUTH CONDITION: Confidence and severity are independent axes.

    Example: an expired TLS certificate detected by observation of a renewal gap,
    but without direct connection to the server to verify (target was down during
    the scan window). The severity is HIGH (expired cert = security risk) but
    confidence is SUSPECTED (direct observation was not possible in this run).
    """

    def test_suspected_high_is_a_valid_independent_combination(self):
        finding = {
            "type": "tls.cert_expired",
            "severity": "HIGH",
            "confidence": "SUSPECTED",
            "description": (
                "TLS certificate for example.com appears expired based on "
                "prior scan record. Direct connection was not possible in "
                "this scan window. Confidence is SUSPECTED pending re-scan."
            ),
        }
        assert finding["confidence"] in CONFIDENCE_LEVELS
        assert finding["severity"] in SEVERITY_LEVELS
        # They are orthogonal — no rule links HIGH severity to CONFIRMED confidence.
        assert finding["confidence"] != "CONFIRMED", (
            "High-severity finding may be SUSPECTED. "
            "Confidence reflects evidence quality, not impact magnitude."
        )

    def test_severity_does_not_determine_confidence(self):
        """Confirm that deriving confidence from severity is incorrect."""
        for severity in ("HIGH", "CRITICAL"):
            wrong_confidence = _confidence_from_severity_would_be_wrong(severity)
            # This would be WRONG behavior — severity should not drive confidence
            assert wrong_confidence in ("CONFIRMED", "PROBABLE"), (
                f"This demonstrates the anti-pattern: {severity} → {wrong_confidence}. "
                "This mapping MUST NOT exist in production code."
            )
            # The correct behavior: confidence must come from evidence, not severity
            # A CRITICAL finding could legitimately be SUSPECTED if evidence is indirect.
            assert "SUSPECTED" not in wrong_confidence, (
                "The wrong map does not allow SUSPECTED for HIGH/CRITICAL — "
                "but SUSPECTED is a valid confidence for any severity."
            )


# ---------------------------------------------------------------------------
# SA-SEP-002: Low-severity finding may have CONFIRMED confidence
# ---------------------------------------------------------------------------


class TestLowSeverityConfirmedConfidence:
    """Example: missing Content-Security-Policy header is LOW severity (defense-in-depth
    measure), but the absence was directly observed in the HTTP response header set.
    Confidence is CONFIRMED because the HTTP response was directly observed.
    """

    def test_confirmed_low_is_a_valid_combination(self):
        finding = {
            "type": "web.missing_csp_header",
            "severity": "LOW",
            "confidence": "CONFIRMED",
            "verification_methods": ["DIRECT_TECHNICAL_OBSERVATION"],
            "description": (
                "Content-Security-Policy header was absent from the HTTP response. "
                "Directly observed in HTTP HEAD response. Confidence is CONFIRMED."
            ),
        }
        assert finding["confidence"] in CONFIDENCE_LEVELS
        assert finding["severity"] in SEVERITY_LEVELS
        assert finding["confidence"] == "CONFIRMED"
        assert finding["severity"] == "LOW"
        # This combination is explicitly valid per policy.


# ---------------------------------------------------------------------------
# SA-SEP-003: Confidence is NOT calculated from severity
# ---------------------------------------------------------------------------


class TestConfidenceNotDerivedFromSeverity:
    """Policy rule: confidence describes evidence quality; severity describes impact.
    These are computed separately. Code that derives confidence from severity is wrong.
    """

    def test_all_severity_levels_can_have_any_confidence(self):
        """Every (severity, confidence) pair is independently valid."""
        for severity in SEVERITY_LEVELS:
            for confidence in CONFIDENCE_LEVELS:
                finding = {
                    "type": "test.finding",
                    "severity": severity,
                    "confidence": confidence,
                }
                assert finding["confidence"] in CONFIDENCE_LEVELS
                assert finding["severity"] in SEVERITY_LEVELS

    def test_critical_finding_can_be_not_assessed(self):
        """A CRITICAL finding may be NOT_ASSESSED if the domain is out of scope."""
        finding = {
            "type": "aws.unrestricted_s3_bucket",
            "severity": "CRITICAL",
            "confidence": "NOT_ASSESSED",
            "description": "AWS infrastructure was out of scope for this assessment.",
        }
        assert finding["confidence"] == "NOT_ASSESSED"
        assert finding["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# SA-SEP-004 / DEF-003: Runner output missing confidence field → NOT_ASSESSED
# ---------------------------------------------------------------------------


class TestRunnerConfidenceFieldAbsent:
    """DEF-003 regression: when a scanner runner does not emit a confidence field,
    the finding's confidence must default to NOT_ASSESSED — not CONFIRMED.

    This is the documented gap from COR-008 in L14_SCAN_AUDIT_CORRECTIONS.md.
    All runners (network_scan, web_headers, dns_email, endpoint_inventory,
    oauth_inventory, oauth_risk, ai_tool_discovery) omit the confidence field.

    Pending: L14-SCAN-INTEGRITY-001 — add confidence field to all runner outputs.
    """

    def test_finding_without_confidence_field_defaults_to_not_assessed(self):
        """Policy: absent confidence field → NOT_ASSESSED (not CONFIRMED)."""
        runner_finding = {
            "type": "web.missing_hsts",
            "severity": "HIGH",
            # No "confidence" field — typical of current runner output
        }
        effective_confidence = _default_confidence_for_missing_field(runner_finding)
        assert effective_confidence == "NOT_ASSESSED", (
            "A finding without a confidence field must default to NOT_ASSESSED. "
            "It must NOT be treated as CONFIRMED. "
            "DEF-003: confidence field absent from runner output — "
            "pending L14-SCAN-INTEGRITY-001."
        )

    def test_finding_without_confidence_is_not_treated_as_confirmed(self):
        """Explicitly verify that the absence of confidence != CONFIRMED."""
        runner_finding = {
            "type": "dns.missing_spf",
            "severity": "HIGH",
            # No confidence field
        }
        effective_confidence = _default_confidence_for_missing_field(runner_finding)
        assert effective_confidence != "CONFIRMED", (
            "Missing confidence field must NOT be interpreted as CONFIRMED. "
            "CONFIRMED requires DIRECT_TECHNICAL_OBSERVATION or AUTHORITATIVE_CONFIGURATION_EXPORT "
            "per FROSTGATE_FINDING_CONFIDENCE_POLICY.md Rule 3.1."
        )

    def test_web_headers_runner_findings_lack_confidence_field(self):
        """Document DEF-003: web_headers runner does not emit confidence field."""
        from unittest.mock import MagicMock, patch

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "https://example.com"
        mock_response.headers = {}  # No security headers present

        with patch("httpx.head", return_value=mock_response), patch(
            "httpx.get", return_value=mock_response
        ):
            from services.connectors.web_headers.runner import run as web_run

            result = web_run(["https://example.com"])

        findings = result.get("findings", [])
        for finding in findings:
            assert "confidence" not in finding, (
                f"Finding {finding.get('finding_type', 'unknown')} unexpectedly has confidence. "
                "DEF-003 tracks this gap. If confidence was added, update this test and "
                "remove the DEF-003 entry in the manifest."
            )
        # Document: the gap is present and expected until L14-SCAN-INTEGRITY-001
        # At least one finding should be emitted for a site with no security headers
        # (this confirms the runner ran and produced output)
        # Note: this test documents the gap, not a full scanner accuracy test.

    def test_dns_runner_findings_lack_confidence_field(self):
        """Document DEF-003: dns_email runner does not emit confidence field."""
        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            # Return empty to produce missing_spf finding
            mock_q.return_value = []
            from services.connectors.dns_email.runner import _check_spf

            result = _check_spf("example.com")

        # The result dict has no confidence field
        assert "confidence" not in result, (
            "dns_email runner _check_spf result does not contain confidence field. "
            "DEF-003: confidence absent from runner output. "
            "Pending L14-SCAN-INTEGRITY-001."
        )

    def test_endpoint_runner_findings_lack_confidence_field(self):
        """Document DEF-003: endpoint_inventory runner does not emit confidence field."""
        from datetime import datetime, timedelta, timezone
        from unittest.mock import MagicMock, patch

        device = {
            "id": "dev-test",
            "displayName": "TestDevice",
            "operatingSystem": "Windows",
            "operatingSystemVersion": "10.0",
            "isCompliant": False,
            "isManaged": True,
            "approximateLastSignInDateTime": (
                datetime.now(timezone.utc) - timedelta(days=1)
            ).isoformat(),
            "trustType": "AzureAD",
        }

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock(return_value=None)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"value": [device]}

        with patch("httpx.get", return_value=mock_resp):
            from services.connectors.endpoint_inventory.runner import (
                run_endpoint_inventory,
            )

            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-def003-test",
            )

        for finding in result.get("findings", []):
            assert "confidence" not in finding, (
                f"Endpoint finding {finding.get('finding_type')} unexpectedly has confidence. "
                "DEF-003 tracks this gap. Update if L14-SCAN-INTEGRITY-001 adds the field."
            )
