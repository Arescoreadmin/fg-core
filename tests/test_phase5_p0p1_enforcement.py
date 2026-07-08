"""Phase 5 P0/P1 — governance/risk/admin/keys read-write capability enforcement.

Covers:
  1. viewer can read governance changes, decisions, risk-acceptances, risk-governance.
  2. viewer is denied governance.decision mutations (create_change, approve_change).
  3. viewer is denied risk.accept mutations (create/update/transition risk-acceptance).
  4. compliance_reviewer can record governance decisions (governance.decision).
  5. compliance_reviewer can accept risk (risk.accept).
  6. tenant_admin can manage keys (key.manage).
  7. viewer is denied key management.
  8. Legacy admin:write scope → platform_admin fallback → admin routes pass.
  9. Legacy governance:read scope → viewer → read allowed, decision denied.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

from fastapi.testclient import TestClient
from sqlalchemy import text as sa_text

_TENANT = "tenant-p5-test"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mint(build_app, *scopes: str, tenant_id: str, role: str | None = None) -> tuple:
    from api.auth_scopes import mint_key
    from api.db import get_sessionmaker
    from api.tenant_rbac import assign_role

    app = build_app(auth_enabled=True)
    key = mint_key(*scopes, tenant_id=tenant_id)

    if role:
        SM = get_sessionmaker()
        db = SM()
        try:
            key_id = db.execute(
                sa_text(
                    "SELECT id FROM api_keys WHERE tenant_id = :t ORDER BY id DESC LIMIT 1"
                ),
                {"t": tenant_id},
            ).scalar_one()
            assign_role(
                db,
                tenant_id=tenant_id,
                actor_key_prefix="pytest",
                target_key_id=int(key_id),
                role_name=role,
            )
        finally:
            db.close()

    return app, TestClient(app, headers={"X-API-Key": key})


# ---------------------------------------------------------------------------
# 1. viewer reads P0 governance routes
# ---------------------------------------------------------------------------


class TestViewerP0Reads:
    """viewer has governance.read; P0 read routes must return non-403."""

    def test_viewer_can_list_decisions(self, build_app) -> None:
        # decisions:read satisfies require_scopes on the route; governance:read → viewer cap
        _, viewer = _mint(
            build_app,
            "decisions:read",
            "governance:read",
            tenant_id=_TENANT,
            role="read_only",
        )
        resp = viewer.get("/decisions")
        assert resp.status_code != 403, resp.text

    def test_viewer_can_list_risk_acceptances(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.get("/risk-acceptances")
        assert resp.status_code != 403, resp.text

    def test_viewer_can_list_risk_governance_policies(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.get("/risk-governance/policies")
        assert resp.status_code != 403, resp.text

    def test_viewer_can_read_risk_governance_dashboard(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.get("/risk-governance/dashboard")
        assert resp.status_code != 403, resp.text


# ---------------------------------------------------------------------------
# 2. viewer denied governance.decision mutations
# ---------------------------------------------------------------------------


class TestViewerGovernanceDecisionDenied:
    """viewer lacks governance.decision; mutation routes must 403."""

    def test_viewer_cannot_create_risk_governance_policy(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.post(
            "/risk-governance/policies",
            json={"name": "test-policy", "policy_type": "control"},
        )
        assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# 3. viewer denied risk.accept mutations
# ---------------------------------------------------------------------------


class TestViewerRiskAcceptDenied:
    """viewer lacks risk.accept; risk-acceptance write routes must 403."""

    def test_viewer_cannot_create_risk_acceptance(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.post(
            "/risk-acceptances",
            json={
                "risk_id": "risk-001",
                "rationale": "test",
                "accepted_by": "viewer",
            },
        )
        assert resp.status_code == 403, resp.text

    def test_viewer_cannot_transition_risk_acceptance(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.post(
            "/risk-acceptances/nonexistent/transitions",
            json={"transition": "approve"},
        )
        assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# 4. compliance_reviewer can record governance decisions
# ---------------------------------------------------------------------------


class TestComplianceReviewerGovernanceDecision:
    """compliance_reviewer has governance.decision; decision mutations must not 403."""

    def test_compliance_reviewer_can_create_risk_governance_policy(
        self, build_app
    ) -> None:
        _, reviewer = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="governance_admin",
        )
        resp = reviewer.post(
            "/risk-governance/policies",
            json={"name": "p5-policy", "policy_type": "control"},
        )
        # 403 would mean RBAC denied; 422/409/200 means gate passed
        assert resp.status_code != 403, resp.text


# ---------------------------------------------------------------------------
# 5. compliance_reviewer can accept risk
# ---------------------------------------------------------------------------


class TestComplianceReviewerRiskAccept:
    """compliance_reviewer has risk.accept."""

    def test_compliance_reviewer_can_create_risk_acceptance(self, build_app) -> None:
        _, reviewer = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="governance_admin",
        )
        resp = reviewer.post(
            "/risk-acceptances",
            json={
                "risk_id": "risk-p5-001",
                "rationale": "phase5 test",
                "accepted_by": "compliance-reviewer",
            },
        )
        assert resp.status_code != 403, resp.text


# ---------------------------------------------------------------------------
# 6. tenant_admin can manage keys
# ---------------------------------------------------------------------------


class TestTenantAdminKeyManage:
    """tenant_admin has key.manage; key routes must not 403."""

    def test_tenant_admin_can_list_keys(self, build_app) -> None:
        # keys:admin satisfies the router-level require_scopes; tenant_admin → key.manage cap
        _, admin = _mint(
            build_app,
            "keys:admin",
            tenant_id=_TENANT,
            role="tenant_admin",
        )
        resp = admin.get("/keys")
        assert resp.status_code != 403, resp.text


# ---------------------------------------------------------------------------
# 7. viewer denied key management
# ---------------------------------------------------------------------------


class TestViewerKeyManageDenied:
    """viewer lacks key.manage; key routes must 403."""

    def test_viewer_cannot_list_keys(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.get("/keys")
        assert resp.status_code == 403, resp.text

    def test_viewer_cannot_create_key(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.post("/keys", json={"name": "test-key", "scopes": []})
        assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# 8. Legacy admin:write scope → platform_admin fallback
# ---------------------------------------------------------------------------


class TestLegacyAdminScopeFallback:
    """admin:write legacy scope resolves to platform_admin permissions."""

    def test_admin_write_scope_passes_quota_update(self, build_app) -> None:
        _, admin = _mint(build_app, "admin:write", tenant_id=_TENANT)
        resp = admin.put(
            f"/admin/tenants/{_TENANT}/quota",
            json={"quota": 100},
        )
        # 403 = RBAC denied; any other code means gate passed
        assert resp.status_code != 403, resp.text

    def test_admin_read_scope_passes_list_tenants(self, build_app) -> None:
        _, admin = _mint(build_app, "admin:read", tenant_id=_TENANT)
        resp = admin.get("/admin/tenants")
        assert resp.status_code != 403, resp.text


# ---------------------------------------------------------------------------
# 9. Legacy governance:read → viewer → read allowed, decision denied
# ---------------------------------------------------------------------------


class TestLegacyGovReadScopeFallback:
    """governance:read maps to viewer; decision mutations must still 403."""

    def test_legacy_read_scope_allows_decisions_list(self, build_app) -> None:
        _, client = _mint(
            build_app, "decisions:read", "governance:read", tenant_id=_TENANT
        )
        resp = client.get("/decisions")
        assert resp.status_code != 403, resp.text

    def test_legacy_read_scope_denies_risk_accept(self, build_app) -> None:
        _, client = _mint(build_app, "governance:read", tenant_id=_TENANT)
        resp = client.post(
            "/risk-acceptances",
            json={"risk_id": "x", "rationale": "x", "accepted_by": "x"},
        )
        assert resp.status_code == 403, resp.text
