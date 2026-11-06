"""L14-SCAN-ACCURACY-001 — OAuth and AI governance known-answer accuracy tests.

Critical truth conditions tested:
- OAuth permission granted != data accessed != data disclosed
- AI vendor name match != unauthorized (must check governance status)
- Unknown contract status != confirmed DPA absent
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_app(
    app_id: str = "app-001",
    display_name: str = "TestApp",
    verified_publisher: bool = True,
    scope_count: int = 3,
) -> dict:
    return {
        "app_id": app_id,
        "display_name": display_name,
        "created": datetime.now(timezone.utc).isoformat(),
        "sign_in_audience": "AzureADMyOrg",
        "verified_publisher": verified_publisher,
        "required_scope_count": scope_count,
    }


# ---------------------------------------------------------------------------
# SA-OAUTH-001: verified_publisher_app → no unverified finding
# ---------------------------------------------------------------------------

class TestVerifiedPublisherApp:
    def test_verified_publisher_does_not_produce_unverified_finding(self):
        from services.connectors.oauth_inventory.runner import run_oauth_inventory
        from unittest.mock import patch as upatch

        def _mock_get_all(access_token, path, params=None):
            if "applications" in path:
                return [
                    {
                        "id": "reg-001",
                        "appId": "app-001",
                        "displayName": "VerifiedApp",
                        "createdDateTime": datetime.now(timezone.utc).isoformat(),
                        "signInAudience": "AzureADMyOrg",
                        "requiredResourceAccess": [
                            {"resourceAccess": [{"id": "scope1", "type": "Scope"}]}
                        ],
                    }
                ]
            elif "servicePrincipals" in path:
                return [
                    {
                        "id": "sp-001",
                        "appId": "app-001",
                        "displayName": "VerifiedApp",
                        "verifiedPublisher": {"displayName": "Microsoft"},
                        "createdDateTime": datetime.now(timezone.utc).isoformat(),
                    }
                ]
            elif "oauth2PermissionGrants" in path:
                return []
            return []

        with upatch("services.connectors.oauth_inventory.runner._get_all",
                    side_effect=_mock_get_all):
            result = run_oauth_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        finding_types = [f["finding_type"] for f in result["findings"]]
        # Verified publisher should not produce unverified_publishers finding.
        assert "oauth.unverified_publishers" not in finding_types


# ---------------------------------------------------------------------------
# SA-OAUTH-002: unverified_publisher + sensitive scope → UNVERIFIED_PUBLISHER finding
# ---------------------------------------------------------------------------

class TestUnverifiedPublisherSensitiveScope:
    def test_unverified_publisher_produces_finding(self):
        from services.connectors.oauth_inventory.runner import run_oauth_inventory
        from unittest.mock import patch as upatch

        def _mock_get_all(access_token, path, params=None):
            if "applications" in path:
                return [
                    {
                        "id": "reg-002",
                        "appId": "app-002",
                        "displayName": "UnknownApp",
                        "createdDateTime": datetime.now(timezone.utc).isoformat(),
                        "signInAudience": "AzureADMyOrg",
                        "requiredResourceAccess": [
                            {"resourceAccess": [{"id": f"scope{i}", "type": "Scope"} for i in range(5)]}
                        ],
                    }
                ]
            elif "servicePrincipals" in path:
                return [
                    {
                        "id": "sp-002",
                        "appId": "app-002",
                        "displayName": "UnknownApp",
                        # No verifiedPublisher
                        "createdDateTime": datetime.now(timezone.utc).isoformat(),
                    }
                ]
            return []

        with upatch("services.connectors.oauth_inventory.runner._get_all",
                    side_effect=_mock_get_all):
            result = run_oauth_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        finding_types = [f["finding_type"] for f in result["findings"]]
        assert "oauth.unverified_publishers" in finding_types


# ---------------------------------------------------------------------------
# SA-OAUTH-003: admin_consented_app → ADMIN_CONSENT_GRANT observation
# ---------------------------------------------------------------------------

class TestAdminConsentGrant:
    def test_admin_consent_produces_observation_finding(self):
        from services.connectors.oauth_inventory.runner import run_oauth_inventory
        from unittest.mock import patch as upatch

        def _mock_get_all(access_token, path, params=None):
            if "applications" in path:
                return [
                    {
                        "id": "reg-003",
                        "appId": "app-003",
                        "displayName": "AdminApp",
                        "createdDateTime": datetime.now(timezone.utc).isoformat(),
                        "signInAudience": "AzureADMyOrg",
                        "requiredResourceAccess": [],
                    }
                ]
            elif "servicePrincipals" in path:
                return [
                    {
                        "id": "sp-003",
                        "appId": "app-003",
                        "displayName": "AdminApp",
                        "verifiedPublisher": {"displayName": "TrustCo"},
                        "createdDateTime": datetime.now(timezone.utc).isoformat(),
                    }
                ]
            elif "oauth2PermissionGrants" in path:
                # Admin-consented grant (AllPrincipals = tenant-wide)
                return [
                    {"clientId": "sp-003", "consentType": "AllPrincipals", "scope": "User.Read"}
                ]
            return []

        with upatch("services.connectors.oauth_inventory.runner._get_all",
                    side_effect=_mock_get_all):
            result = run_oauth_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        finding_types = [f["finding_type"] for f in result["findings"]]
        assert "oauth.admin_consented_grants" in finding_types


# ---------------------------------------------------------------------------
# SA-OAUTH-004: CRITICAL — permission_granted != data_accessed != data_disclosed
# ---------------------------------------------------------------------------

class TestOAuthPermissionGrantedNotData:
    """CRITICAL TRUTH CONDITION: OAuth permission granted means the app HAS PERMISSION
    to access data. It does NOT mean the app DID ACCESS the data, and it certainly
    does NOT mean data was disclosed externally.

    The scanner must NOT classify permission grants as 'data accessed' or
    'data disclosed' findings.
    """

    def test_admin_consent_grant_is_permission_observation_not_data_accessed(self):
        """admin_consented_grants finding = permission observation, not data breach."""
        from services.connectors.oauth_inventory.runner import run_oauth_inventory
        from unittest.mock import patch as upatch

        def _mock_get_all(access_token, path, params=None):
            if "applications" in path:
                return []
            elif "servicePrincipals" in path:
                return []
            elif "oauth2PermissionGrants" in path:
                return [
                    {"clientId": "sp-x", "consentType": "AllPrincipals", "scope": "Mail.Read"}
                ]
            return []

        with upatch("services.connectors.oauth_inventory.runner._get_all",
                    side_effect=_mock_get_all):
            result = run_oauth_inventory(
                access_token="mock-token",
                tenant_id="tenant-001",
                engagement_id="eng-001",
            )

        for f in result["findings"]:
            # Finding titles must NOT claim data was accessed.
            title = f.get("title", "").lower()
            assert "data accessed" not in title, (
                f"Finding title claims 'data accessed' — this is incorrect. "
                f"Permission granted != data accessed. Title: {title}"
            )
            assert "data disclosed" not in title
            assert "data breach" not in title


# ---------------------------------------------------------------------------
# SA-OAUTH-005: AI governance — dpa_status_unknown != confirmed DPA absent
# ---------------------------------------------------------------------------

class TestAiGovernanceDpaUnknown:
    """CRITICAL TRUTH CONDITION: If DPA status is unknown (not in registry),
    the scanner must classify this as GOVERNANCE_UNKNOWN, not DPA_ABSENT.
    Unknown != confirmed absent.
    """

    def test_ai_vendor_no_dpa_in_registry_produces_no_dpa_finding(self):
        """When a vendor's DPA status is not set, the finding is 'no_dpa'
        which is an observation that no DPA is on record — not proof of absence."""
        from services.connectors.ai_vendor_governance.governance_engine import (
            generate_findings,
        )

        tool_record = {
            "tool_name": "TestAI",
            "vendor": "TestVendor",
            "risk_score": "high",
            "risk_categories": [],
            "workflow_state": "discovered",
            "business_owner": None,
            "technical_owner": None,
            "executive_sponsor": None,
            "security_review_status": "unknown",
            "privacy_review_status": "unknown",
            "dpa_required": True,
            "regulated_data_present": True,
            "dpa_status": "unknown",  # Unknown, NOT confirmed absent
            "baa_required": False,
            "baa_status": "not_required",
            "contract_status": "unknown",
            "soc2_available": False,
            "iso27001_available": False,
            "review_due_date": None,
            "risk_acceptance_required": False,
            "risk_acceptance_expiration": None,
        }

        findings = generate_findings(
            record=tool_record,
            now_str=datetime.now(timezone.utc).isoformat(),
        )

        # dpa_status="unknown" must produce a no_dpa finding with hedged language:
        # "could not be verified" — NOT the definitive "is in place" / "confirmed absent"
        # language reserved for cases where absence is established. DEF-004 root cause:
        # the scanner previously fired the same definitive description for unknown and
        # absent statuses alike, making an unsupported absence claim from unknown evidence.
        no_dpa_findings = [f for f in findings if "no_dpa" in f.get("type", "")]
        assert no_dpa_findings, (
            "Expected a no_dpa governance gap finding for unknown DPA status"
        )
        for f in no_dpa_findings:
            desc = f.get("description", "").lower()
            # Must use hedged language for unknown status
            assert "could not be verified" in desc, (
                f"Unknown DPA status should produce hedged description, got: {desc!r}"
            )
            # Must NOT claim confirmed absence
            assert "is in place" not in desc, (
                f"Unknown DPA status must not assert absence; got: {desc!r}"
            )
            assert "confirmed absent" not in desc


# ---------------------------------------------------------------------------
# SA-OAUTH-006: risk_acceptance_expired → EXPIRED_RISK_ACCEPTANCE finding
# ---------------------------------------------------------------------------

class TestRiskAcceptanceExpired:
    def test_expired_risk_acceptance_produces_finding(self):
        from services.connectors.ai_vendor_governance.governance_engine import (
            generate_findings,
        )

        past_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()

        tool_record = {
            "tool_name": "TestAI",
            "vendor": "TestVendor",
            "risk_score": "high",
            "risk_categories": [],
            "workflow_state": "discovered",
            "business_owner": "Alice",
            "technical_owner": "Bob",
            "executive_sponsor": None,
            "security_review_status": "completed",
            "privacy_review_status": "completed",
            "dpa_required": False,
            "regulated_data_present": False,
            "dpa_status": "executed",
            "baa_required": False,
            "baa_status": "not_required",
            "contract_status": "executed",
            "soc2_available": True,
            "iso27001_available": False,
            "review_due_date": None,
            "risk_acceptance_required": True,  # required
            "risk_acceptance_expiration": past_date,  # expired
        }

        findings = generate_findings(
            record=tool_record,
            now_str=datetime.now(timezone.utc).isoformat(),
        )

        finding_types = [f.get("type", "") for f in findings]
        assert "ai_vendor_governance.risk_acceptance_expired" in finding_types


# ---------------------------------------------------------------------------
# SA-OAUTH-007: restricted_ai_tool → RESTRICTED_TOOL_DETECTED
# ---------------------------------------------------------------------------

class TestRestrictedAiTool:
    def test_restricted_vendor_still_active_produces_finding(self):
        from services.connectors.ai_vendor_governance.governance_engine import (
            generate_findings,
        )

        tool_record = {
            "tool_name": "RestrictedAI",
            "vendor": "BannedVendor",
            "risk_score": "critical",
            "risk_categories": [],
            "workflow_state": "restricted",  # restricted state
            "business_owner": "Alice",
            "technical_owner": "Bob",
            "executive_sponsor": "Carol",
            "security_review_status": "completed",
            "privacy_review_status": "completed",
            "dpa_required": False,
            "regulated_data_present": False,
            "dpa_status": "executed",
            "baa_required": False,
            "baa_status": "not_required",
            "contract_status": "executed",
            "soc2_available": True,
            "iso27001_available": True,
            "review_due_date": None,
            "risk_acceptance_required": False,
            "risk_acceptance_expiration": None,
        }

        findings = generate_findings(
            record=tool_record,
            now_str=datetime.now(timezone.utc).isoformat(),
        )

        finding_types = [f.get("type", "") for f in findings]
        assert "ai_vendor_governance.restricted_still_active" in finding_types


# ---------------------------------------------------------------------------
# SA-OAUTH-008: approved_ai_tool → no adverse finding
# ---------------------------------------------------------------------------

class TestApprovedAiTool:
    def test_fully_governed_tool_produces_no_critical_findings(self):
        from services.connectors.ai_vendor_governance.governance_engine import (
            generate_findings,
        )

        future_date = (datetime.now(timezone.utc) + timedelta(days=180)).isoformat()

        # medium risk tool — generate_findings skips medium unless shadow_ai
        tool_record = {
            "tool_name": "ApprovedAI",
            "vendor": "TrustVendor",
            "risk_score": "high",  # use high to trigger generation
            "risk_categories": [],
            "workflow_state": "approved",
            "business_owner": "Alice",
            "technical_owner": "Bob",
            "executive_sponsor": "Carol",
            "security_review_status": "completed",
            "privacy_review_status": "completed",
            "dpa_required": False,
            "regulated_data_present": False,
            "dpa_status": "not_required",
            "baa_required": False,
            "baa_status": "not_required",
            "contract_status": "executed",
            "soc2_available": True,
            "soc2_reviewed": True,
            "iso27001_available": True,
            "iso27001_reviewed": True,
            "review_due_date": future_date,
            "risk_acceptance_required": True,
            "risk_acceptance_expiration": future_date,
        }

        findings = generate_findings(
            record=tool_record,
            now_str=datetime.now(timezone.utc).isoformat(),
        )

        # Fully governed tool should produce no critical findings.
        for f in findings:
            severity = f.get("severity", "")
            assert severity not in ("critical",), (
                f"Fully governed approved tool produced critical finding: {f}"
            )


# ---------------------------------------------------------------------------
# SA-OAUTH-009: CRITICAL — AI vendor name match != unauthorized
# ---------------------------------------------------------------------------

class TestAiVendorMatchNotUnauthorized:
    """CRITICAL TRUTH CONDITION: Matching an app to an AI vendor in the registry
    does NOT mean the app is unauthorized. The governance status must be checked
    separately. A matched vendor could be approved, restricted, or unknown.
    """

    def test_ai_tool_discovery_match_does_not_set_unauthorized_risk(self):
        """AI tool found via vendor registry should have risk_indicators set
        but NOT automatically classified as unauthorized."""
        from services.connectors.ai_tool_discovery.runner import _risk_indicators

        # A tool that matches but has no high-risk indicators
        tool = {
            "tool_name": "ApprovedAI",
            "vendor": "TrustVendor",
            "verified_publisher": True,
            "admin_consent": False,
            "consent_type": "Principal",
            "delegated_permissions": ["User.Read"],
            "application_permissions": [],
            "publisher": "TrustVendor",
            "last_seen": datetime.now(timezone.utc).isoformat(),
        }

        indicators = _risk_indicators(tool)

        # ai_vendor_detected is always present (it matched the vendor registry)
        assert "ai_vendor_detected" in indicators
        # But should NOT have unauthorized or high-risk indicators
        assert "unauthorized_vendor" not in indicators
        assert "confirmed_exploit" not in indicators
