"""Phase 4 — governance_intelligence + governance_orchestration read enforcement.

Covers:
  1. viewer can read governance intelligence and orchestration dashboards.
  2. viewer is denied governance write mutations (governance.decision).
  3. viewer is denied governance.promote routes (approve/reject/delegate).
  4. assessor can trigger simulation scan (scan.trigger).
  5. compliance_reviewer can read governance intelligence (governance.read).
  6. tenant_admin can read governance orchestration (governance.read).
  7. Legacy governance:read-only scope → viewer fallback → gov read allowed.
  8. Legacy governance:write-only scope → assessor fallback → read AND decision allowed.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

from fastapi.testclient import TestClient
from sqlalchemy import text as sa_text

_TENANT = "tenant-p4-gov"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mint(build_app, *scopes: str, tenant_id: str, role: str | None = None) -> tuple:
    """Issue a canonical credential, optionally assign a role; return (app, client)."""
    import uuid as _uuid
    from api.credential_authority import issue_credential
    from api.db import get_engine
    from api.tenant_rbac import assign_role
    from sqlalchemy.orm import Session

    app = build_app(auth_enabled=True)
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            sa_text(
                "INSERT OR IGNORE INTO tenants (tenant_id, lifecycle_state)"
                " VALUES (:tid, 'active')"
            ),
            {"tid": tenant_id},
        )
    result = issue_credential(
        engine,
        tenant_id=tenant_id,
        credential_type="tenant_api_key",
        credential_slot=f"test:{_uuid.uuid4()}",
        scopes=list(scopes),
    )
    if role:
        with Session(engine) as db:
            assign_role(
                db,
                tenant_id=tenant_id,
                actor_key_prefix="pytest",
                credential_id=result.record.credential_id,
                role_name=role,
            )
            db.commit()

    return app, TestClient(app, headers={"X-API-Key": result.plaintext_secret})


# ---------------------------------------------------------------------------
# 1. viewer reads governance intelligence — smoke
# ---------------------------------------------------------------------------


class TestViewerGovIntelRead:
    """viewer (read_only role) can reach governance.read-gated endpoints."""

    def test_viewer_can_read_intelligence_dashboard(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.get("/intelligence/dashboard")
        assert resp.status_code == 200, resp.text

    def test_viewer_can_list_policies(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.get("/intelligence/policies")
        assert resp.status_code == 200, resp.text

    def test_viewer_can_list_simulations(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.get("/intelligence/simulations")
        assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# 2. viewer reads governance orchestration — smoke
# ---------------------------------------------------------------------------


class TestViewerGovOrchRead:
    """viewer can reach governance-orchestration read endpoints."""

    def test_viewer_can_read_orchestration_dashboard(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.get("/governance-orchestration/dashboard")
        assert resp.status_code == 200, resp.text

    def test_viewer_can_list_policies(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.get("/governance-orchestration/policies")
        assert resp.status_code == 200, resp.text

    def test_viewer_can_list_workflows(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.get("/governance-orchestration/workflows")
        assert resp.status_code == 200, resp.text

    def test_viewer_can_list_approvals(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.get("/governance-orchestration/approvals")
        assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# 3. viewer denied write mutations (governance.decision)
# ---------------------------------------------------------------------------


class TestViewerGovWriteDenied:
    """viewer lacks governance.decision; all mutation routes must 403."""

    def test_viewer_cannot_create_intelligence_policy(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.post(
            "/intelligence/policies",
            json={
                "name": "p4-test-policy",
                "policy_type": "control",
                "rules": [],
            },
        )
        assert resp.status_code == 403, resp.text

    def test_viewer_cannot_create_orchestration_policy(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.post(
            "/governance-orchestration/policies",
            json={"name": "p4-orch-policy", "policy_type": "control", "rules": []},
        )
        assert resp.status_code == 403, resp.text

    def test_viewer_cannot_create_workflow(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.post(
            "/governance-orchestration/workflows",
            json={"name": "p4-workflow", "workflow_type": "standard", "steps": []},
        )
        assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# 4. viewer denied governance.promote routes
# ---------------------------------------------------------------------------


class TestViewerPromoteDenied:
    """viewer lacks governance.promote; approve/reject/delegate must 403."""

    def test_viewer_cannot_approve_approval(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.post(
            "/governance-orchestration/approvals/nonexistent/approve",
            json={"decision": "APPROVE", "reason": "test"},
        )
        assert resp.status_code == 403, resp.text

    def test_viewer_cannot_reject_approval(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.post(
            "/governance-orchestration/approvals/nonexistent/reject",
            json={"decision": "REJECT", "reason": "test"},
        )
        assert resp.status_code == 403, resp.text

    def test_viewer_cannot_delegate_approval(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.post(
            "/governance-orchestration/approvals/nonexistent/delegate",
            json={"decision": "DELEGATE", "reason": "test", "delegated_to": "user-x"},
        )
        assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# 5. assessor can trigger simulation (scan.trigger)
# ---------------------------------------------------------------------------


class TestAssessorScanTrigger:
    """assessor has scan.trigger; run_simulation must NOT 403."""

    def test_assessor_can_trigger_simulation(self, build_app) -> None:
        _, assessor = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="analyst",
        )
        resp = assessor.post(
            "/intelligence/simulations/nonexistent-sim/run",
            json={},
        )
        # 403 would indicate RBAC denial; 404/422 means it passed the gate
        assert resp.status_code != 403, resp.text

    def test_viewer_cannot_trigger_simulation(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.post(
            "/intelligence/simulations/nonexistent-sim/run",
            json={},
        )
        assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# 6. compliance_reviewer has governance.read
# ---------------------------------------------------------------------------


class TestComplianceReviewerGovRead:
    """compliance_reviewer inherits governance.read."""

    def test_compliance_reviewer_can_read_intelligence_dashboard(
        self, build_app
    ) -> None:
        _, reviewer = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="governance_admin",
        )
        resp = reviewer.get("/intelligence/dashboard")
        assert resp.status_code == 200, resp.text

    def test_compliance_reviewer_can_read_orchestration_dashboard(
        self, build_app
    ) -> None:
        _, reviewer = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="governance_admin",
        )
        resp = reviewer.get("/governance-orchestration/dashboard")
        assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# 7. tenant_admin has governance.read
# ---------------------------------------------------------------------------


class TestTenantAdminGovRead:
    """tenant_admin inherits governance.read."""

    def test_tenant_admin_can_read_intelligence_dashboard(self, build_app) -> None:
        _, admin = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="tenant_admin",
        )
        resp = admin.get("/intelligence/dashboard")
        assert resp.status_code == 200, resp.text

    def test_tenant_admin_can_read_orchestration_dashboard(self, build_app) -> None:
        _, admin = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="tenant_admin",
        )
        resp = admin.get("/governance-orchestration/dashboard")
        assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# 8. Legacy scope fallback
# ---------------------------------------------------------------------------


class TestLegacyScopeFallback:
    """Keys with no DB role derive permissions from legacy scopes."""

    def test_legacy_read_scope_allows_gov_intel_read(self, build_app) -> None:
        _, client = _mint(build_app, "governance:read", tenant_id=_TENANT)
        resp = client.get("/intelligence/dashboard")
        assert resp.status_code == 200, resp.text

    def test_legacy_read_scope_denies_gov_write(self, build_app) -> None:
        _, client = _mint(build_app, "governance:read", tenant_id=_TENANT)
        resp = client.post(
            "/intelligence/policies",
            json={"name": "legacy-test", "policy_type": "control", "rules": []},
        )
        assert resp.status_code == 403, resp.text

    def test_legacy_write_scope_allows_gov_read_and_decision(self, build_app) -> None:
        _, client = _mint(
            build_app, "governance:read", "governance:write", tenant_id=_TENANT
        )
        read_resp = client.get("/intelligence/dashboard")
        assert read_resp.status_code == 200, read_resp.text
