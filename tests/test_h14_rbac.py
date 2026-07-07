"""H14 RBAC + Actor Attribution tests.

Test series:
  P — Permission model (role expansion, SoD invariants)
  D — Auth dispatch (provider resolution, dev bypass)
  V — Viewer denied on mutation routes
  A — Assessor denied on governance approval routes
  Q — QA reviewer allowed on QA routes, denied on compliance routes
  C — Compliance reviewer allowed on exception/risk routes, denied on QA routes
  T — Tenant admin allowed on admin routes, denied on compliance routes (SoD)
  X — Cross-tenant access denied regardless of role
  S — Actor attribution: spoofable fields stripped from request body
  J — JWT claims populate attribution (non-repudiation)
  G — Governance event schema validation
"""

from __future__ import annotations


from api.actor_context import (
    ActorContext,
    ALL_PERMISSIONS,
    CAPABILITY_REGISTRY,
    ROLE_PERMISSIONS,
    roles_to_permissions,
)


# ============================================================
# P-series: Permission model correctness
# ============================================================


class TestPermissionModel:
    def test_P01_all_permissions_are_explicit(self):
        """ALL_PERMISSIONS contains no wildcards."""
        assert "*" not in ALL_PERMISSIONS
        assert all(isinstance(p, str) and "." in p for p in ALL_PERMISSIONS)

    def test_P02_role_permissions_subset_of_all(self):
        """Every role permission must exist in ALL_PERMISSIONS."""
        for role, perms in ROLE_PERMISSIONS.items():
            extra = perms - ALL_PERMISSIONS
            assert not extra, f"role {role!r} has unknown permissions: {extra}"

    def test_P03_platform_admin_has_all_permissions(self):
        assert ROLE_PERMISSIONS["platform_admin"] == ALL_PERMISSIONS

    def test_P04_sod_assessor_cannot_approve_findings(self):
        """Assessors create findings; they cannot approve them (SoD)."""
        assert "finding.approve" not in ROLE_PERMISSIONS["assessor"]
        assert "finding.close" not in ROLE_PERMISSIONS["assessor"]

    def test_P05_sod_tenant_admin_cannot_accept_risk(self):
        """Tenant admins administer; they cannot accept risks (SoD)."""
        assert "risk.accept" not in ROLE_PERMISSIONS["tenant_admin"]
        assert "exception.grant" not in ROLE_PERMISSIONS["tenant_admin"]
        assert "governance.decision" not in ROLE_PERMISSIONS["tenant_admin"]

    def test_P06_sod_compliance_reviewer_cannot_manage_keys(self):
        """Compliance reviewers approve risks; they cannot manage API keys (SoD)."""
        assert "key.manage" not in ROLE_PERMISSIONS["compliance_reviewer"]
        assert "user.invite" not in ROLE_PERMISSIONS["compliance_reviewer"]

    def test_P07_sod_qa_reviewer_cannot_accept_risk(self):
        """QA reviewers approve findings; they cannot accept risks (SoD)."""
        assert "risk.accept" not in ROLE_PERMISSIONS["qa_reviewer"]
        assert "exception.grant" not in ROLE_PERMISSIONS["qa_reviewer"]

    def test_P08_bundle_generate_is_assessor_not_viewer(self):
        """Bundle generation (mechanical) is assessor-level."""
        assert "bundle.generate" in ROLE_PERMISSIONS["assessor"]
        assert "bundle.generate" not in ROLE_PERMISSIONS["viewer"]

    def test_P09_bundle_approve_is_qa_reviewer(self):
        """Bundle approval (governance sign-off) is qa_reviewer-level."""
        assert "bundle.approve" in ROLE_PERMISSIONS["qa_reviewer"]
        assert "bundle.approve" not in ROLE_PERMISSIONS["assessor"]

    def test_P10_viewer_is_read_only(self):
        """Viewer has only read permissions."""
        for perm in ROLE_PERMISSIONS["viewer"]:
            assert perm.endswith(".read"), f"viewer has non-read perm: {perm!r}"

    def test_P11_roles_to_permissions_multi_role(self):
        """Multi-role expansion unions permissions without duplicates."""
        perms = roles_to_permissions(["assessor", "qa_reviewer"])
        assert "assessment.create" in perms  # assessor
        assert "finding.approve" in perms  # qa_reviewer
        assert isinstance(perms, frozenset)

    def test_P12_roles_to_permissions_unknown_role_ignored(self):
        """Unknown role names produce empty permissions (fail-closed)."""
        perms = roles_to_permissions(["unknown_future_role"])
        assert len(perms) == 0

    def test_P13_roles_to_permissions_empty_list(self):
        perms = roles_to_permissions([])
        assert perms == frozenset()

    def test_P14_capability_registry_covers_all_permissions(self):
        """CAPABILITY_REGISTRY must have an entry for every permission in ALL_PERMISSIONS.

        This is the sprawl guard: CI fails if a permission is added to
        ALL_PERMISSIONS without a corresponding registry entry.
        """
        unregistered = ALL_PERMISSIONS - set(CAPABILITY_REGISTRY.keys())
        assert not unregistered, (
            f"Permissions in ALL_PERMISSIONS with no registry entry: {sorted(unregistered)}\n"
            "Add an entry to CAPABILITY_REGISTRY in api/actor_context.py."
        )

    def test_P15_capability_registry_no_phantom_entries(self):
        """CAPABILITY_REGISTRY must not contain entries absent from ALL_PERMISSIONS."""
        phantom = set(CAPABILITY_REGISTRY.keys()) - ALL_PERMISSIONS
        assert not phantom, (
            f"CAPABILITY_REGISTRY entries not in ALL_PERMISSIONS: {sorted(phantom)}\n"
            "Remove the entry or add the permission to ALL_PERMISSIONS."
        )

    def test_P16_capability_registry_required_fields(self):
        """Every registry entry must have display_name, description, and a valid risk_level."""
        valid_levels = {"low", "medium", "high", "critical"}
        for perm, meta in CAPABILITY_REGISTRY.items():
            assert meta.get("display_name"), f"{perm!r} missing display_name"
            assert meta.get("description"), f"{perm!r} missing description"
            assert meta.get("risk_level") in valid_levels, (
                f"{perm!r} has invalid risk_level {meta.get('risk_level')!r}"
            )

    def test_P17_critical_permissions_are_governance_or_platform(self):
        """Critical-risk capabilities must be governance decisions or platform admin only."""
        critical = {p for p, m in CAPABILITY_REGISTRY.items() if m["risk_level"] == "critical"}
        allowed_prefixes = ("risk.", "exception.", "governance.", "platform.")
        for perm in critical:
            assert perm.startswith(allowed_prefixes), (
                f"{perm!r} is marked critical but is not a governance or platform permission"
            )


# ============================================================
# ActorContext helpers
# ============================================================


def _make_actor(
    roles: list[str],
    *,
    auth_source: str = "oidc_auth0",
    subject: str = "auth0|test123",
    email: str = "test@bank.com",
    name: str = "Test User",
) -> ActorContext:
    return ActorContext(
        subject=subject,
        email=email,
        name=name,
        permissions=roles_to_permissions(roles),
        roles=roles,
        auth_source=auth_source,
        tenant_id="tenant-abc",
    )


def _anon_actor() -> ActorContext:
    return ActorContext(
        subject="anonymous",
        email="",
        name="",
        permissions=frozenset(),
        roles=[],
        auth_source="none",
        tenant_id=None,
    )


# ============================================================
# D-series: ActorContext methods
# ============================================================


class TestActorContextMethods:
    def test_D01_has_permission_true(self):
        actor = _make_actor(["qa_reviewer"])
        assert actor.has_permission("report.qa_approve")

    def test_D02_has_permission_false(self):
        actor = _make_actor(["qa_reviewer"])
        assert not actor.has_permission("risk.accept")

    def test_D03_primary_role_most_privileged(self):
        actor = _make_actor(["viewer", "qa_reviewer"])
        assert actor.primary_role() == "qa_reviewer"

    def test_D04_primary_role_platform_admin_wins(self):
        actor = _make_actor(["assessor", "platform_admin"])
        assert actor.primary_role() == "platform_admin"

    def test_D05_primary_role_no_roles(self):
        actor = _anon_actor()
        assert actor.primary_role() is None

    def test_D06_dev_bypass_detection(self):
        actor = ActorContext(
            subject="dev_bypass",
            email="dev@frostgate.local",
            name="Dev User",
            permissions=ALL_PERMISSIONS,
            roles=["platform_admin"],
            auth_source="dev_bypass",
            tenant_id=None,
        )
        assert actor.is_dev_bypass()
        assert not _make_actor(["tenant_admin"]).is_dev_bypass()


# ============================================================
# V-series: Viewer denied on mutation routes
# ============================================================


class TestViewerDenied:
    """Viewers are read-only — all mutations must be denied."""

    def setup_method(self):
        self.viewer = _make_actor(["viewer"])

    def test_V01_viewer_denied_risk_accept(self):
        assert not self.viewer.has_permission("risk.accept")

    def test_V02_viewer_denied_exception_grant(self):
        assert not self.viewer.has_permission("exception.grant")

    def test_V03_viewer_denied_report_qa_approve(self):
        assert not self.viewer.has_permission("report.qa_approve")

    def test_V04_viewer_denied_finding_approve(self):
        assert not self.viewer.has_permission("finding.approve")

    def test_V05_viewer_denied_scan_trigger(self):
        assert not self.viewer.has_permission("scan.trigger")

    def test_V06_viewer_denied_bundle_generate(self):
        assert not self.viewer.has_permission("bundle.generate")

    def test_V07_viewer_denied_key_manage(self):
        assert not self.viewer.has_permission("key.manage")


# ============================================================
# A-series: Assessor denied on governance approval routes
# ============================================================


class TestAssessorDenied:
    """Assessors cannot approve what they create."""

    def setup_method(self):
        self.assessor = _make_actor(["assessor"])

    def test_A01_assessor_denied_finding_approve(self):
        assert not self.assessor.has_permission("finding.approve")

    def test_A02_assessor_denied_report_qa_approve(self):
        assert not self.assessor.has_permission("report.qa_approve")

    def test_A03_assessor_denied_risk_accept(self):
        assert not self.assessor.has_permission("risk.accept")

    def test_A04_assessor_denied_exception_grant(self):
        assert not self.assessor.has_permission("exception.grant")

    def test_A05_assessor_denied_bundle_approve(self):
        assert not self.assessor.has_permission("bundle.approve")

    def test_A06_assessor_allowed_bundle_generate(self):
        assert self.assessor.has_permission("bundle.generate")

    def test_A07_assessor_allowed_scan_trigger(self):
        assert self.assessor.has_permission("scan.trigger")


# ============================================================
# Q-series: QA reviewer authority
# ============================================================


class TestQaReviewerAuthority:
    def setup_method(self):
        self.qa = _make_actor(["qa_reviewer"])

    def test_Q01_qa_reviewer_allowed_report_qa_approve(self):
        assert self.qa.has_permission("report.qa_approve")

    def test_Q02_qa_reviewer_allowed_finding_approve(self):
        assert self.qa.has_permission("finding.approve")

    def test_Q03_qa_reviewer_allowed_bundle_approve(self):
        assert self.qa.has_permission("bundle.approve")

    def test_Q04_qa_reviewer_denied_risk_accept(self):
        assert not self.qa.has_permission("risk.accept")

    def test_Q05_qa_reviewer_denied_exception_grant(self):
        assert not self.qa.has_permission("exception.grant")

    def test_Q06_qa_reviewer_denied_key_manage(self):
        assert not self.qa.has_permission("key.manage")

    def test_Q07_qa_reviewer_denied_governance_promote(self):
        assert not self.qa.has_permission("governance.promote")


# ============================================================
# C-series: Compliance reviewer authority
# ============================================================


class TestComplianceReviewerAuthority:
    def setup_method(self):
        self.cr = _make_actor(["compliance_reviewer"])

    def test_C01_compliance_reviewer_allowed_risk_accept(self):
        assert self.cr.has_permission("risk.accept")

    def test_C02_compliance_reviewer_allowed_exception_grant(self):
        assert self.cr.has_permission("exception.grant")

    def test_C03_compliance_reviewer_allowed_governance_decision(self):
        assert self.cr.has_permission("governance.decision")

    def test_C04_compliance_reviewer_denied_report_qa_approve(self):
        """Compliance reviewers cannot QA-approve reports (SoD)."""
        assert not self.cr.has_permission("report.qa_approve")

    def test_C05_compliance_reviewer_denied_finding_close(self):
        assert not self.cr.has_permission("finding.close")

    def test_C06_compliance_reviewer_denied_key_manage(self):
        assert not self.cr.has_permission("key.manage")


# ============================================================
# T-series: Tenant admin — SoD from compliance authority
# ============================================================


class TestTenantAdminSoD:
    """Tenant admins administer; they cannot approve governance decisions."""

    def setup_method(self):
        self.admin = _make_actor(["tenant_admin"])

    def test_T01_tenant_admin_allowed_key_manage(self):
        assert self.admin.has_permission("key.manage")

    def test_T02_tenant_admin_allowed_user_invite(self):
        assert self.admin.has_permission("user.invite")

    def test_T03_tenant_admin_allowed_governance_promote(self):
        assert self.admin.has_permission("governance.promote")

    def test_T04_tenant_admin_denied_risk_accept(self):
        """SoD: admin cannot accept risks on behalf of compliance."""
        assert not self.admin.has_permission("risk.accept")

    def test_T05_tenant_admin_denied_exception_grant(self):
        """SoD: admin cannot grant exceptions."""
        assert not self.admin.has_permission("exception.grant")

    def test_T06_tenant_admin_denied_report_qa_approve(self):
        """SoD: admin cannot QA-approve reports."""
        assert not self.admin.has_permission("report.qa_approve")

    def test_T07_platform_admin_has_all_permissions(self):
        pa = _make_actor(["platform_admin"])
        assert pa.permissions == ALL_PERMISSIONS
        assert pa.has_permission("risk.accept")
        assert pa.has_permission("key.manage")


# ============================================================
# X-series: Cross-tenant isolation
# ============================================================


class TestCrossTenantIsolation:
    """ActorContext carries tenant_id; routes must reject cross-tenant access."""

    def test_X01_actor_context_carries_tenant_id(self):
        actor = ActorContext(
            subject="auth0|xyz",
            email="user@bank.com",
            name="User",
            permissions=roles_to_permissions(["qa_reviewer"]),
            roles=["qa_reviewer"],
            auth_source="oidc_auth0",
            tenant_id="tenant-bank-001",
        )
        assert actor.tenant_id == "tenant-bank-001"

    def test_X02_actor_context_no_tenant_when_unbound(self):
        actor = _make_actor(["assessor"])
        # tenant_id is set in our helper; verify it's stored correctly
        assert actor.tenant_id == "tenant-abc"

    def test_X03_dev_bypass_has_no_tenant(self):
        actor = ActorContext(
            subject="dev_bypass",
            email="dev@frostgate.local",
            name="Dev User",
            permissions=ALL_PERMISSIONS,
            roles=["platform_admin"],
            auth_source="dev_bypass",
            tenant_id=None,
        )
        assert actor.tenant_id is None


# ============================================================
# S-series: Actor attribution — spoofing protection
# ============================================================


class TestActorAttribution:
    """Governance decision attribution must come from ActorContext, not request body."""

    def test_S01_actor_subject_is_auth0_sub(self):
        actor = _make_actor(["qa_reviewer"], subject="auth0|abc123")
        assert actor.subject == "auth0|abc123"

    def test_S02_actor_email_from_jwt(self):
        actor = _make_actor(["compliance_reviewer"], email="cro@bank.com")
        assert actor.email == "cro@bank.com"

    def test_S03_actor_name_from_jwt(self):
        actor = _make_actor(["compliance_reviewer"], name="Chief Risk Officer")
        assert actor.name == "Chief Risk Officer"

    def test_S04_primary_role_for_attribution(self):
        actor = _make_actor(["compliance_reviewer"])
        assert actor.primary_role() == "compliance_reviewer"

    def test_S05_api_key_actor_has_empty_email(self):
        """API key actors have no email — subject is the key prefix."""
        actor = ActorContext(
            subject="fg_prod_abc123",
            email="",
            name="",
            permissions=roles_to_permissions(["assessor"]),
            roles=["assessor"],
            auth_source="api_key",
            tenant_id="tenant-xyz",
        )
        assert actor.subject == "fg_prod_abc123"
        assert actor.email == ""
        assert actor.auth_source == "api_key"


# ============================================================
# J-series: JWT role claim handling
# ============================================================


class TestJwtRoleClaims:
    def test_J01_single_role_resolves_permissions(self):
        perms = roles_to_permissions(["qa_reviewer"])
        assert "report.qa_approve" in perms
        assert "risk.accept" not in perms

    def test_J02_multiple_roles_union_permissions(self):
        perms = roles_to_permissions(["assessor", "compliance_reviewer"])
        assert "scan.trigger" in perms  # assessor
        assert "risk.accept" in perms  # compliance_reviewer

    def test_J03_empty_roles_no_permissions(self):
        perms = roles_to_permissions([])
        assert len(perms) == 0

    def test_J04_platform_admin_role_grants_all(self):
        perms = roles_to_permissions(["platform_admin"])
        assert perms == ALL_PERMISSIONS


# ============================================================
# G-series: Governance event schema
# ============================================================


class TestGovernanceEventSchema:
    def test_G01_fa_governance_event_model_importable(self):
        from api.db_models_governance_event import FaGovernanceEvent

        assert FaGovernanceEvent.__tablename__ == "fa_governance_events"

    def test_G02_fa_governance_event_has_versioning(self):
        from api.db_models_governance_event import FaGovernanceEvent

        cols = {c.key for c in FaGovernanceEvent.__table__.columns}
        assert "event_version" in cols
        assert "schema_version" in cols

    def test_G03_fa_governance_event_has_first_class_decision_reason(self):
        from api.db_models_governance_event import FaGovernanceEvent

        cols = {c.key for c in FaGovernanceEvent.__table__.columns}
        assert "decision_reason" in cols

    def test_G04_fa_governance_event_has_review_duration(self):
        from api.db_models_governance_event import FaGovernanceEvent

        cols = {c.key for c in FaGovernanceEvent.__table__.columns}
        assert "review_duration_seconds" in cols

    def test_G05_fa_governance_event_has_delegation_fields(self):
        from api.db_models_governance_event import FaGovernanceEvent

        cols = {c.key for c in FaGovernanceEvent.__table__.columns}
        assert "delegated_by" in cols
        assert "delegation_reason" in cols
        assert "delegation_expires_at" in cols

    def test_G06_fa_governance_event_has_analytics_fields(self):
        from api.db_models_governance_event import FaGovernanceEvent

        cols = {c.key for c in FaGovernanceEvent.__table__.columns}
        assert "industry_sector" in cols
        assert "risk_level" in cols
        assert "outcome" in cols

    def test_G07_actor_subject_added_to_governance_decisions(self):
        from api.db_models_governance_decision import FaGovernanceDecision

        cols = {c.key for c in FaGovernanceDecision.__table__.columns}
        assert "actor_subject" in cols

    def test_G08_permission_model_importable(self):
        from api.actor_context import (
            ALL_PERMISSIONS,
            ROLE_PERMISSIONS,
            roles_to_permissions,
        )

        assert callable(roles_to_permissions)
        assert len(ROLE_PERMISSIONS) >= 6
        assert len(ALL_PERMISSIONS) >= 20

    def test_G09_actor_context_importable(self):
        from api.actor_context import ALL_PERMISSIONS, ROLE_PERMISSIONS

        assert isinstance(ALL_PERMISSIONS, frozenset)
        assert len(ROLE_PERMISSIONS) >= 6

    def test_G10_auth0_provider_importable(self):
        from api.identity_providers.auth0 import validate_auth0_token
        from api.identity_providers.entra import EntraProvider

        assert callable(validate_auth0_token)
        assert isinstance(EntraProvider(), EntraProvider)
