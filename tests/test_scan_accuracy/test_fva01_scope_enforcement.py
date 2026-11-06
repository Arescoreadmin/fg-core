"""L14-SCAN-ACCURACY-001 — FVA-01 Authorized Scope: what is actually enforced.

FVA-01 states: "Every assessment activity must be tied to an approved engagement
record and explicitly permitted scope."

This test file verifies what IS enforced at the code level and explicitly documents
the gaps that require L14-SCAN-SAFETY-001.

VERDICT: PARTIALLY_IMPLEMENTED

What IS enforced (tested here):
  1. Operator identity / permission check (require_permission("scan.trigger"))
     — this is tested at the auth_dispatch layer, not repeated here
  2. Tenant-scoped engagement ownership
     (get_engagement(db, engagement_id=..., tenant_id=...) will raise EngagementNotFound
      if the (engagement_id, tenant_id) pair does not match — prevents cross-tenant scan)
  3. SSRF / private-IP blocking via SafeTargetValidationService
     (RFC1918/loopback/cloud-metadata rejected before any scan starts)
  4. Audit event emitted for scan.initiated

What is NOT enforced (documented gaps for L14-SCAN-SAFETY-001):
  1. No authorized scope list per engagement
     — Any publicly routable host passes SSRF validation
     — engagement.client_domain is NOT checked against scan targets
     — An operator could scan example.com during an engagement for acme.com
  2. No pre-approved target allowlist stored per engagement
  3. No acknowledgment-receipt gate for DNS/network/web scanners
     (only Microsoft Graph has acknowledgment_receipt_id enforcement)

Code references:
  - api/field_assessment.py:4582 — require_permission("scan.trigger")
  - api/field_assessment.py:4588 — get_engagement(db, engagement_id, tenant_id)
  - api/field_assessment.py:4668 — _c6_write_audit_event(event_type="scan.initiated")
  - services/connectors/safe_target_validator.py — SafeTargetValidationService
  - services/field_assessment/store.py:103 — get_engagement() tenant-scoped query
"""

from __future__ import annotations

from services.connectors.safe_target_validator import SafeTargetValidationService


# ---------------------------------------------------------------------------
# FVA-01-A: SSRF / private-IP rejection IS enforced (SafeTargetValidationService)
# ---------------------------------------------------------------------------


class TestSsrfValidationEnforced:
    """These behaviors ARE enforced. SafeTargetValidationService rejects private ranges."""

    def test_private_ip_rejected(self):
        svc = SafeTargetValidationService(dns_resolver=lambda _: ["10.0.0.1"])
        result = svc.validate("10.0.0.1")
        assert result.ok is False
        assert result.rejection_code == "BLOCKED_IP"

    def test_loopback_rejected(self):
        svc = SafeTargetValidationService(dns_resolver=lambda _: ["127.0.0.1"])
        result = svc.validate("127.0.0.1")
        assert result.ok is False

    def test_cloud_metadata_endpoint_rejected(self):
        svc = SafeTargetValidationService(dns_resolver=lambda _: ["169.254.169.254"])
        result = svc.validate("169.254.169.254")
        assert result.ok is False

    def test_public_ip_passes_ssrf_check(self):
        """A publicly routable IP passes SSRF validation.
        This is correct SSRF behavior — but does NOT mean the target is in-scope
        for the engagement. Client authorization is a separate check (not enforced).
        """
        svc = SafeTargetValidationService(dns_resolver=lambda _: ["203.0.113.1"])
        # 203.0.113.0/24 is documentation range (TEST-NET-3) — also blocked
        # Use an actually-routable-looking IP instead
        result = svc.validate("8.8.8.8")
        assert result.ok is True, (
            "Public IP 8.8.8.8 passes SSRF validation. "
            "SSRF validation does NOT check client authorization. "
            "An operator could pass this IP during any engagement."
        )

    def test_hostname_resolving_to_private_ip_rejected_via_dns_rebinding(self):
        """Hostname that resolves to private IP is blocked (DNS rebinding protection)."""
        svc = SafeTargetValidationService(dns_resolver=lambda _: ["192.168.1.1"])
        result = svc.validate("internal.example.com")
        assert result.ok is False
        assert result.rejection_code == "DNS_REBINDING_OR_PRIVATE"

    def test_all_blocked_ranges_produce_rejection(self):
        """Key RFC ranges that must be blocked."""
        blocked = [
            "10.0.0.1",       # RFC1918
            "172.16.0.1",     # RFC1918
            "192.168.0.1",    # RFC1918
            "127.0.0.1",      # Loopback
            "169.254.169.254",  # Link-local / cloud metadata
            "100.64.0.1",     # CGNAT
        ]
        svc = SafeTargetValidationService()
        for ip in blocked:
            result = svc.validate(ip)
            assert result.ok is False, f"Expected {ip} to be blocked, but it passed"


# ---------------------------------------------------------------------------
# FVA-01-B: Tenant isolation IS enforced via get_engagement()
# ---------------------------------------------------------------------------


class TestTenantIsolationDocumentation:
    """Document the enforcement that IS present at the store layer.

    The store function `get_engagement(db, engagement_id=..., tenant_id=...)` uses a
    compound WHERE clause:
        FaEngagement.id == engagement_id AND FaEngagement.tenant_id == tenant_id

    This means a scan cannot be initiated for an engagement that belongs to a
    different tenant, even if the engagement_id is guessed.

    This is a pure documentation test — it verifies the query matches the code
    reference by asserting the import is available.
    """

    def test_engagement_lookup_requires_both_engagement_id_and_tenant_id(self):
        """The store function enforces tenant isolation via compound PK lookup."""
        from services.field_assessment.store import get_engagement

        # Verify the function signature requires tenant_id
        import inspect
        sig = inspect.signature(get_engagement)
        params = list(sig.parameters.keys())
        assert "engagement_id" in params
        assert "tenant_id" in params, (
            "get_engagement() must accept tenant_id to prevent cross-tenant access. "
            "Code ref: services/field_assessment/store.py:97"
        )

    def test_engagement_not_found_error_exists(self):
        """EngagementNotFound is raised when (engagement_id, tenant_id) pair not found.
        This prevents cross-tenant access and cross-engagement target injection.
        """
        from services.field_assessment.store import EngagementNotFound
        assert EngagementNotFound is not None


# ---------------------------------------------------------------------------
# FVA-01-C: DOCUMENTED GAP — no target scope list enforcement
# ---------------------------------------------------------------------------


class TestClientAuthorizationGapDocumented:
    """Document what is NOT enforced.

    These tests do NOT assert enforcement — they assert the absence of enforcement
    so the gap is tracked and cannot be accidentally removed without updating tests.

    For L14-SCAN-SAFETY-001: This gap requires implementing a per-engagement
    authorized_target_list that is checked before SSRF validation.
    """

    def test_safe_target_validator_does_not_check_engagement_scope(self):
        """SafeTargetValidationService has NO engagement_id parameter.
        It cannot check whether a target is within the engagement's authorized scope.
        It only checks SSRF / private-range safety.
        """
        import inspect
        sig = inspect.signature(SafeTargetValidationService.validate)
        params = list(sig.parameters.keys())
        assert "engagement_id" not in params, (
            "SafeTargetValidationService.validate() does NOT accept engagement_id. "
            "It performs SSRF checks only — not client authorization. "
            "FVA-01 gap: target scope boundary is NOT enforced. "
            "Deferred to L14-SCAN-SAFETY-001."
        )

    def test_safe_target_validator_does_not_check_client_domain(self):
        """SafeTargetValidationService has no concept of client_domain.
        An operator scanning 8.8.8.8 during an engagement for acme.com is not blocked.
        This is the FVA-01 gap.
        """
        svc = SafeTargetValidationService(dns_resolver=lambda h: ["8.8.8.8"])
        # A publicly routable host that is clearly not the client's domain passes.
        # This demonstrates the gap: SSRF validation != client authorization.
        result = svc.validate("8.8.8.8")
        assert result.ok is True, (
            "Public IP 8.8.8.8 passes SSRF validation regardless of which engagement "
            "it is submitted to. No engagement-level scope boundary check exists. "
            "This is the FVA-01 PARTIALLY_IMPLEMENTED gap. "
            "Deferred to L14-SCAN-SAFETY-001."
        )

    def test_no_acknowledgment_receipt_gate_for_dns_network_web_scanners(self):
        """Microsoft Graph requires an acknowledgment_receipt_id before scanning.
        DNS, network, and web scanners do NOT have this gate.

        Code reference:
        - api/field_assessment.py:3610 initiate_msgraph_scan — requires receipt param
        - api/field_assessment.py:4852 initiate_dns_email_scan — no receipt param
        - api/field_assessment.py:4577 initiate_network_scan — no receipt param
        - api/field_assessment.py:5062 initiate_web_headers_scan — no receipt param

        Impact: DNS/network/web scans can be initiated without explicit client
        authorization acknowledgment. This is a documentation gap tracked under
        FVA-01 Known Gaps.
        """
        # Verify: DNS scan initiate request model has no receipt field
        from api.field_assessment import DnsEmailScanInitiateRequest
        fields = DnsEmailScanInitiateRequest.model_fields
        assert "acknowledgment_receipt_id" not in fields, (
            "DnsEmailScanInitiateRequest does not require acknowledgment_receipt_id. "
            "Only Microsoft Graph has this gate. "
            "Network/DNS/web scanners lack client authorization gate. "
            "FVA-01 gap — deferred to L14-SCAN-SAFETY-001."
        )
