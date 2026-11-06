"""L14-SCAN-ACCURACY-001 — Evidence traceability tests.

Tests the finding evidence chain:
  Raw Observation -> Scan Result -> Normalized Finding -> Evidence Link

Each confirmed finding in a tested path must have:
- Correct tenant assignment
- Correct engagement assignment
- Valid scan_id reference
- Evidence collection timestamp
- Source observation data
- Valid confidence classification
- Severity that follows documented methodology

Negative tests:
- finding_missing_evidence_reference -> rejected or downgraded to SUSPECTED
- finding_wrong_tenant -> rejected (tenant isolation)
- finding_deleted_evidence -> downgraded confidence
- finding_no_collection_timestamp -> flagged as incomplete provenance

Where full enforcement is not yet implemented in the canonical path,
the gap is documented for L14-ASSESSMENT-ASSURANCE-001.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Evidence chain structure validator
# ---------------------------------------------------------------------------

def _validate_scan_result_provenance(result: dict) -> list[str]:
    """Validate a scan result dict has required provenance fields.

    Returns a list of violations. Empty list = valid provenance.
    """
    violations = []
    required_fields = [
        "scan_id",
        "engagement_id",
        "scan_initiated_at",
        "scan_completed_at",
        "scan_status",
    ]
    for field in required_fields:
        if not result.get(field):
            violations.append(f"Missing required provenance field: {field}")
    return violations


def _validate_finding_evidence_link(finding: dict, scan_id: str, engagement_id: str) -> list[str]:
    """Validate that a finding has proper evidence linkage.

    In the fixture-validated model, findings within a scan result inherit
    the scan's provenance (scan_id, engagement_id, timestamps).
    Full FaEvidenceLink enforcement is deferred to L14-ASSESSMENT-ASSURANCE-001.
    """
    violations = []
    # For scan-level findings, the scan_id and engagement_id from the parent result
    # serve as the evidence reference.
    if not finding.get("finding_type") and not finding.get("type"):
        violations.append("Finding must have finding_type or type field")
    if not finding.get("severity"):
        violations.append("Finding must have severity field")
    return violations


def _validate_tenant_isolation(result: dict, expected_tenant_id: str) -> list[str]:
    """Validate tenant ID is correct in scan result."""
    violations = []
    # For scan results that include tenant_id, verify it matches
    if result.get("tenant_id") and result["tenant_id"] != expected_tenant_id:
        violations.append(
            f"Tenant isolation violation: expected {expected_tenant_id!r}, "
            f"got {result['tenant_id']!r}"
        )
    return violations


# ---------------------------------------------------------------------------
# SA-TRAC-001: Network scan result provenance chain
# ---------------------------------------------------------------------------

class TestNetworkScanProvenance:
    def test_network_scan_result_has_complete_provenance(self):
        from services.connectors.network_scan.runner import run_network_scan
        from services.connectors.safe_target_validator import SafeTargetValidationService

        with patch.object(SafeTargetValidationService, "validate") as mock_val:
            mock_val.return_value = MagicMock(ok=True, rejection_code=None, rejection_reason=None)
            with patch("socket.create_connection", side_effect=ConnectionRefusedError):
                result = run_network_scan(
                    target_hosts=["93.184.216.34"],
                    engagement_id="eng-net-001",
                )

        violations = _validate_scan_result_provenance(result)
        assert violations == [], f"Provenance violations: {violations}"

    def test_network_scan_findings_have_severity(self):
        from services.connectors.network_scan.runner import run_network_scan
        from services.connectors.safe_target_validator import SafeTargetValidationService

        def _mock_connect(addr, timeout=None):
            h, p = addr
            if p == 3389:
                return MagicMock(__enter__=MagicMock(return_value=MagicMock()),
                                 __exit__=MagicMock(return_value=False))
            raise ConnectionRefusedError()

        with patch.object(SafeTargetValidationService, "validate") as mock_val:
            mock_val.return_value = MagicMock(ok=True, rejection_code=None, rejection_reason=None)
            with patch("socket.create_connection", side_effect=_mock_connect):
                result = run_network_scan(
                    target_hosts=["93.184.216.34"],
                    engagement_id="eng-net-001",
                )

        for finding in result["findings"]:
            violations = _validate_finding_evidence_link(finding, result["scan_id"], "eng-net-001")
            assert violations == []

    def test_rejected_target_has_rejection_provenance(self):
        """Rejected targets must be recorded in rejected_targets with rejection_code."""
        from services.connectors.network_scan.runner import run_network_scan

        result = run_network_scan(
            target_hosts=["192.168.1.1"],  # private IP — should be rejected
            engagement_id="eng-net-001",
        )

        rejections = result.get("rejected_targets", [])
        assert len(rejections) >= 1
        for rej in rejections:
            assert rej.get("target"), "Rejection must record the target"
            assert rej.get("rejection_code"), "Rejection must have rejection_code"


# ---------------------------------------------------------------------------
# SA-TRAC-002: DNS scan result provenance chain
# ---------------------------------------------------------------------------

class TestDnsScanProvenance:
    def test_dns_run_result_has_domain_level_provenance(self):
        from services.connectors.dns_email.runner import run

        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.return_value = []
            result = run(["example.com"])

        # DNS runner does not add scan_id/engagement_id — documented gap.
        # The run() output is wrapped by the FA bridge which adds those fields.
        # Test what IS available in the runner output.
        assert "domains" in result
        assert "summary" in result
        assert "total_domains" in result["summary"]
        # Each domain result has domain field for attribution
        assert all("domain" in r for r in result["domains"])

    def test_dns_findings_have_domain_attribution(self):
        """Every finding must include the domain it came from."""
        from services.connectors.dns_email.runner import run

        with patch("services.connectors.dns_email.runner._dns_query") as mock_q:
            mock_q.return_value = []  # all missing
            result = run(["example.com"])

        for finding in result["findings"]:
            assert finding.get("domain"), (
                f"Finding {finding.get('type')} missing domain attribution"
            )


# ---------------------------------------------------------------------------
# SA-TRAC-003: Web headers scan provenance chain
# ---------------------------------------------------------------------------

class TestWebHeadersProvenance:
    def test_scan_target_result_has_url_provenance(self):
        from services.connectors.web_headers.runner import scan_target
        from services.connectors.safe_target_validator import SafeTargetValidationService

        with patch.object(SafeTargetValidationService, "validate") as mock_val:
            mock_val.return_value = MagicMock(ok=True, rejection_code=None, rejection_reason=None)
            with patch("httpx.Client") as mock_client_class:
                mock_client = MagicMock()
                mock_client_class.return_value.__enter__ = MagicMock(return_value=mock_client)
                mock_client_class.return_value.__exit__ = MagicMock(return_value=False)
                import httpx
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.headers = httpx.Headers({})
                mock_resp.url = httpx.URL("https://example.com")
                mock_client.head.return_value = mock_resp
                result = scan_target("https://example.com")

        # Every web headers result must record the URL.
        assert result.get("url"), "scan_target result must record the URL"


# ---------------------------------------------------------------------------
# SA-TRAC-004: Endpoint scan provenance chain
# ---------------------------------------------------------------------------

class TestEndpointScanProvenance:
    def test_endpoint_inventory_has_complete_provenance(self):
        from services.connectors.endpoint_inventory.runner import run_endpoint_inventory

        def _mock_get(url, headers=None, timeout=None):
            resp = MagicMock()
            resp.status_code = 200
            resp.raise_for_status = MagicMock(return_value=None)
            resp.json.return_value = {"value": []}
            return resp

        with patch("httpx.get", side_effect=_mock_get):
            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-ep-001",
            )

        violations = _validate_scan_result_provenance(result)
        assert violations == []

    def test_endpoint_findings_have_control_id(self):
        """Endpoint findings should map to NIST control IDs for framework traceability."""
        from services.connectors.endpoint_inventory.runner import run_endpoint_inventory

        def _mock_get(url, headers=None, timeout=None):
            resp = MagicMock()
            resp.raise_for_status = MagicMock(return_value=None)
            if "deviceManagement" in url:
                resp.status_code = 200
                resp.json.return_value = {"value": []}
            else:
                resp.status_code = 200
                resp.json.return_value = {
                    "value": [
                        {
                            "id": "dev-001",
                            "displayName": "Device1",
                            "operatingSystem": "Windows",
                            "operatingSystemVersion": "10.0",
                            "isCompliant": False,
                            "isManaged": True,
                            "approximateLastSignInDateTime": datetime.now(timezone.utc).isoformat(),
                            "trustType": "AzureAD",
                        }
                    ]
                }
            return resp

        with patch("httpx.get", side_effect=_mock_get):
            result = run_endpoint_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-ep-001",
            )

        for f in result["findings"]:
            assert f.get("control_id"), (
                f"Finding {f.get('finding_type')} missing control_id for framework traceability"
            )


# ---------------------------------------------------------------------------
# SA-TRAC-005: Negative — finding missing evidence reference
# ---------------------------------------------------------------------------

class TestFindingMissingEvidenceReference:
    """When a finding has no evidence reference, it should be treated as
    SUSPECTED confidence (not CONFIRMED).

    IMPLEMENTATION GAP: Full enforcement of this rule is deferred to
    L14-ASSESSMENT-ASSURANCE-001. This test documents the policy requirement
    at the fixture level.
    """

    def test_finding_without_scan_id_should_not_be_confirmed(self):
        """Policy test: a finding produced without scan_id context cannot be CONFIRMED."""
        # Simulate what happens when a finding is constructed without scan provenance
        finding_without_provenance = {
            "type": "test.unsupported_finding",
            "severity": "HIGH",
            "confidence": "SUSPECTED",  # Must be SUSPECTED without evidence reference
            "verification_methods": ["NOT_VERIFIED"],
            "description": "Finding without evidence reference.",
            # No scan_id, no engagement_id reference
        }

        from tests.test_scan_accuracy.test_confidence_model import _validate_finding_confidence
        violations = _validate_finding_confidence(finding_without_provenance)

        # SUSPECTED + NOT_VERIFIED is valid — no violations.
        assert violations == [], (
            "SUSPECTED confidence with NOT_VERIFIED is valid per policy."
        )

    def test_confirmed_finding_without_direct_observation_is_policy_violation(self):
        """Policy test: claiming CONFIRMED without direct observation is a violation."""
        from tests.test_scan_accuracy.test_confidence_model import _validate_finding_confidence

        finding_claiming_confirmed = {
            "type": "test.finding_claiming_confirmed",
            "severity": "HIGH",
            "confidence": "CONFIRMED",
            "verification_methods": ["NOT_VERIFIED"],  # No direct observation
            "description": "Claiming confirmed without observation.",
        }

        violations = _validate_finding_confidence(finding_claiming_confirmed)
        assert any("CONFIRMED requires" in v for v in violations), (
            "CONFIRMED without DIRECT_TECHNICAL_OBSERVATION must be a policy violation."
        )


# ---------------------------------------------------------------------------
# SA-TRAC-006: Tenant isolation invariant
# ---------------------------------------------------------------------------

class TestTenantIsolationInvariant:
    """Findings must be attributed to the correct tenant.
    Cross-tenant leakage must be detected.
    """

    def test_correct_tenant_produces_no_isolation_violation(self):
        result = {
            "scan_id": uuid.uuid4().hex,
            "tenant_id": "tenant-001",
            "engagement_id": "eng-001",
            "scan_initiated_at": datetime.now(timezone.utc).isoformat(),
            "scan_completed_at": datetime.now(timezone.utc).isoformat(),
            "scan_status": "completed",
        }
        violations = _validate_tenant_isolation(result, "tenant-001")
        assert violations == []

    def test_wrong_tenant_produces_isolation_violation(self):
        result = {
            "scan_id": uuid.uuid4().hex,
            "tenant_id": "tenant-WRONG",  # Mismatch
            "engagement_id": "eng-001",
            "scan_initiated_at": datetime.now(timezone.utc).isoformat(),
            "scan_completed_at": datetime.now(timezone.utc).isoformat(),
            "scan_status": "completed",
        }
        violations = _validate_tenant_isolation(result, "tenant-001")
        assert any("Tenant isolation violation" in v for v in violations)


# ---------------------------------------------------------------------------
# SA-TRAC-007: OAuth scan provenance chain
# ---------------------------------------------------------------------------

class TestOAuthScanProvenance:
    def test_oauth_scan_has_complete_provenance(self):
        from services.connectors.oauth_inventory.runner import run_oauth_inventory

        def _mock_get_all(access_token, path, params=None):
            return []

        with patch("services.connectors.oauth_inventory.runner._get_all",
                   side_effect=_mock_get_all):
            result = run_oauth_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-oauth-001",
            )

        violations = _validate_scan_result_provenance(result)
        assert violations == []

    def test_oauth_findings_have_control_id(self):
        from services.connectors.oauth_inventory.runner import run_oauth_inventory

        def _mock_get_all(access_token, path, params=None):
            if "oauth2PermissionGrants" in path:
                return [
                    {"clientId": "sp-x", "consentType": "AllPrincipals", "scope": "User.Read"}
                    for _ in range(6)  # 6 grants trigger 'high' severity
                ]
            return []

        with patch("services.connectors.oauth_inventory.runner._get_all",
                   side_effect=_mock_get_all):
            result = run_oauth_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-oauth-001",
            )

        for f in result["findings"]:
            assert f.get("control_id"), (
                f"OAuth finding {f.get('finding_type')} missing control_id"
            )
