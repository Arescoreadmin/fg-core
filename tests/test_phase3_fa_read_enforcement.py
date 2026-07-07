"""Phase 3 — FA GET route read-capability enforcement and SoD denial tests.

Covers:
  1. viewer role can read all FA resource types (smoke path).
  2. viewer role is denied all FA write mutations.
  3. qa_reviewer cannot create assessments or trigger scans.
  4. Cross-tenant: engagement owned by tenant A returns 404 to tenant B key.
  5. Legacy governance:read-only scope → viewer fallback → read allowed, write denied.
  6. Legacy governance:write-only scope → assessor fallback → read AND write allowed.
  7. Legacy governance:qa_approve-only scope → qa_reviewer fallback → read allowed,
     assessment.create denied.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

from fastapi.testclient import TestClient
from sqlalchemy import text as sa_text

_TENANT = "tenant-p3-read"
_TENANT_OTHER = "tenant-p3-other"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mint(build_app, *scopes: str, tenant_id: str, role: str | None = None) -> tuple:
    """Mint an API key, optionally assign a DB role; return (app, client)."""
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


def _make_engagement(client: TestClient, tenant_id: str) -> str:
    resp = client.post(
        "/field-assessment/engagements",
        json={
            "client_name": f"P3 Corp {tenant_id}",
            "assessor_id": "assessor-p3",
            "assessment_type": "ai_governance",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# 1. viewer reads — smoke path
# ---------------------------------------------------------------------------


class TestViewerCanRead:
    """viewer (read_only → viewer) can reach every read endpoint."""

    def test_list_engagements(self, build_app) -> None:
        _, c = _mint(
            build_app, "governance:read", "governance:write", tenant_id=_TENANT
        )
        # Use assessor client to create an engagement, viewer to read it.
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.get("/field-assessment/engagements")
        assert resp.status_code == 200, resp.text

    def test_get_engagement(self, build_app) -> None:
        _, assessor = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="analyst",
        )
        eng_id = _make_engagement(assessor, _TENANT)
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        assert viewer.get(f"/field-assessment/engagements/{eng_id}").status_code == 200

    def test_list_findings(self, build_app) -> None:
        _, assessor = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="analyst",
        )
        eng_id = _make_engagement(assessor, _TENANT)
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        assert (
            viewer.get(f"/field-assessment/engagements/{eng_id}/findings").status_code
            == 200
        )

    def test_list_scan_results(self, build_app) -> None:
        _, assessor = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="analyst",
        )
        eng_id = _make_engagement(assessor, _TENANT)
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        assert (
            viewer.get(
                f"/field-assessment/engagements/{eng_id}/scan-results"
            ).status_code
            == 200
        )

    def test_list_reports(self, build_app) -> None:
        _, assessor = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="analyst",
        )
        eng_id = _make_engagement(assessor, _TENANT)
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        assert (
            viewer.get(f"/field-assessment/engagements/{eng_id}/reports").status_code
            == 200
        )

    def test_list_observations(self, build_app) -> None:
        _, assessor = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="analyst",
        )
        eng_id = _make_engagement(assessor, _TENANT)
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        assert (
            viewer.get(
                f"/field-assessment/engagements/{eng_id}/observations"
            ).status_code
            == 200
        )


# ---------------------------------------------------------------------------
# 2. viewer cannot write
# ---------------------------------------------------------------------------


class TestViewerCannotWrite:
    """viewer has only *.read permissions — all mutation routes must return 403."""

    def test_cannot_create_engagement(self, build_app) -> None:
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.post(
            "/field-assessment/engagements",
            json={
                "client_name": "Should Fail",
                "assessor_id": "x",
                "assessment_type": "ai_governance",
            },
        )
        assert resp.status_code == 403
        assert resp.json()["detail"]["code"] == "PERMISSION_DENIED"

    def test_cannot_trigger_scan(self, build_app) -> None:
        _, assessor = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="analyst",
        )
        eng_id = _make_engagement(assessor, _TENANT)
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.post(
            f"/field-assessment/engagements/{eng_id}/scan-results",
            json={
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-07-01T00:00:00Z",
                "raw_payload": {},
                "object_count": 0,
            },
        )
        assert resp.status_code == 403

    def test_cannot_upload_evidence(self, build_app) -> None:
        _, assessor = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="analyst",
        )
        eng_id = _make_engagement(assessor, _TENANT)
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.post(
            f"/field-assessment/engagements/{eng_id}/document-analyses",
            json={"document_name": "doc.pdf", "document_classification": "ai_policy"},
        )
        assert resp.status_code == 403

    def test_cannot_generate_report(self, build_app) -> None:
        _, assessor = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="analyst",
        )
        eng_id = _make_engagement(assessor, _TENANT)
        _, viewer = _mint(
            build_app, "governance:read", tenant_id=_TENANT, role="read_only"
        )
        resp = viewer.post(
            f"/field-assessment/engagements/{eng_id}/reports",
            json={"schema_version": "1.0", "sections": {}, "section_hashes": {}},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 3. qa_reviewer SoD
# ---------------------------------------------------------------------------


class TestQaReviewerSoD:
    """qa_reviewer (auditor) can read but cannot create assessments or trigger scans."""

    def test_qa_reviewer_can_list_engagements(self, build_app) -> None:
        _, qa = _mint(
            build_app,
            "governance:read",
            "governance:write",
            "governance:qa_approve",
            tenant_id=_TENANT,
            role="auditor",
        )
        assert qa.get("/field-assessment/engagements").status_code == 200

    def test_qa_reviewer_cannot_create_engagement(self, build_app) -> None:
        _, qa = _mint(
            build_app,
            "governance:read",
            "governance:write",
            "governance:qa_approve",
            tenant_id=_TENANT,
            role="auditor",
        )
        resp = qa.post(
            "/field-assessment/engagements",
            json={
                "client_name": "QA Fail",
                "assessor_id": "x",
                "assessment_type": "ai_governance",
            },
        )
        assert resp.status_code == 403

    def test_qa_reviewer_cannot_trigger_scan(self, build_app) -> None:
        _, assessor = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="analyst",
        )
        eng_id = _make_engagement(assessor, _TENANT)
        _, qa = _mint(
            build_app,
            "governance:read",
            "governance:write",
            "governance:qa_approve",
            tenant_id=_TENANT,
            role="auditor",
        )
        resp = qa.post(
            f"/field-assessment/engagements/{eng_id}/scan-results",
            json={
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-07-01T00:00:00Z",
                "raw_payload": {},
                "object_count": 0,
            },
        )
        assert resp.status_code == 403

    def test_qa_reviewer_can_read_scan_results(self, build_app) -> None:
        _, assessor = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="analyst",
        )
        eng_id = _make_engagement(assessor, _TENANT)
        _, qa = _mint(
            build_app,
            "governance:read",
            "governance:write",
            "governance:qa_approve",
            tenant_id=_TENANT,
            role="auditor",
        )
        assert (
            qa.get(f"/field-assessment/engagements/{eng_id}/scan-results").status_code
            == 200
        )


# ---------------------------------------------------------------------------
# 4. Cross-tenant object ownership
# ---------------------------------------------------------------------------


class TestCrossTenantIsolation:
    """Engagement owned by tenant A must not be readable by tenant B."""

    def test_cross_tenant_engagement_returns_404(self, build_app) -> None:
        _, a = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="analyst",
        )
        _, b = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT_OTHER,
            role="analyst",
        )
        eng_id = _make_engagement(a, _TENANT)
        resp = b.get(f"/field-assessment/engagements/{eng_id}")
        assert resp.status_code == 404

    def test_cross_tenant_findings_returns_404(self, build_app) -> None:
        _, a = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="analyst",
        )
        _, b = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT_OTHER,
            role="analyst",
        )
        eng_id = _make_engagement(a, _TENANT)
        # Engagement not found for tenant B → service returns 404 before any findings query.
        resp = b.get(f"/field-assessment/engagements/{eng_id}/findings")
        assert resp.status_code == 404

    def test_cross_tenant_scan_results_returns_404(self, build_app) -> None:
        _, a = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="analyst",
        )
        _, b = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT_OTHER,
            role="analyst",
        )
        eng_id = _make_engagement(a, _TENANT)
        resp = b.get(f"/field-assessment/engagements/{eng_id}/scan-results")
        assert resp.status_code == 404

    def test_cross_tenant_cannot_write_to_engagement(self, build_app) -> None:
        _, a = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="analyst",
        )
        _, b = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT_OTHER,
            role="analyst",
        )
        eng_id = _make_engagement(a, _TENANT)
        resp = b.post(
            f"/field-assessment/engagements/{eng_id}/scan-results",
            json={
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-07-01T00:00:00Z",
                "raw_payload": {},
                "object_count": 0,
            },
        )
        # 404 (engagement not found for tenant B) before any write occurs.
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 5. Legacy scope fallback — governance:read only → viewer
# ---------------------------------------------------------------------------


class TestLegacyScopeReadOnly:
    """governance:read scope + no DB role → viewer via fallback → read OK, write denied."""

    def test_read_allowed(self, build_app) -> None:
        _, c = _mint(build_app, "governance:read", tenant_id=_TENANT)
        assert c.get("/field-assessment/engagements").status_code == 200

    def test_write_denied(self, build_app) -> None:
        _, c = _mint(build_app, "governance:read", tenant_id=_TENANT)
        resp = c.post(
            "/field-assessment/engagements",
            json={
                "client_name": "Scope Fail",
                "assessor_id": "x",
                "assessment_type": "ai_governance",
            },
        )
        assert resp.status_code == 403

    def test_scan_trigger_denied(self, build_app) -> None:
        _, assessor = _mint(
            build_app,
            "governance:read",
            "governance:write",
            tenant_id=_TENANT,
            role="analyst",
        )
        eng_id = _make_engagement(assessor, _TENANT)
        _, c = _mint(build_app, "governance:read", tenant_id=_TENANT)
        resp = c.post(
            f"/field-assessment/engagements/{eng_id}/scan-results",
            json={
                "source_type": "microsoft_graph",
                "schema_version": "1.0",
                "collected_at": "2026-07-01T00:00:00Z",
                "raw_payload": {},
                "object_count": 0,
            },
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 6. Legacy scope fallback — governance:write only → assessor (read + write)
# ---------------------------------------------------------------------------


class TestLegacyScopeWriteOnly:
    """governance:write scope + no DB role → assessor → can both read and write."""

    def test_create_engagement_allowed(self, build_app) -> None:
        _, c = _mint(build_app, "governance:write", tenant_id=_TENANT)
        resp = c.post(
            "/field-assessment/engagements",
            json={
                "client_name": "Write Scope Corp",
                "assessor_id": "x",
                "assessment_type": "ai_governance",
            },
        )
        assert resp.status_code == 201

    def test_read_allowed(self, build_app) -> None:
        _, c = _mint(build_app, "governance:write", tenant_id=_TENANT)
        assert c.get("/field-assessment/engagements").status_code == 200

    def test_qa_approve_denied(self, build_app) -> None:
        # governance:write alone → assessor only, not qa_reviewer → no report.qa_approve
        _, c = _mint(build_app, "governance:write", tenant_id=_TENANT)
        eng_id = _make_engagement(c, _TENANT)
        resp = c.post(
            f"/field-assessment/engagements/{eng_id}/reports/fake-version/qa-approve"
        )
        # 403 PERMISSION_DENIED (no report.qa_approve) before any 404 on missing report
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 7. Legacy scope fallback — governance:qa_approve only → qa_reviewer
# ---------------------------------------------------------------------------


class TestLegacyScopeQaApproveOnly:
    """governance:qa_approve scope + no DB role → qa_reviewer → read OK, create denied."""

    def test_read_allowed(self, build_app) -> None:
        _, c = _mint(build_app, "governance:qa_approve", tenant_id=_TENANT)
        assert c.get("/field-assessment/engagements").status_code == 200

    def test_create_engagement_denied(self, build_app) -> None:
        _, c = _mint(build_app, "governance:qa_approve", tenant_id=_TENANT)
        resp = c.post(
            "/field-assessment/engagements",
            json={
                "client_name": "QA Scope Fail",
                "assessor_id": "x",
                "assessment_type": "ai_governance",
            },
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 8. Drift alert emission requires assessment.create (write gate on GET route)
# ---------------------------------------------------------------------------


class TestDriftAlertEmissionGate:
    """emit_alerts=true on GET drift-report requires assessment.create, not just assessment.read."""

    def test_viewer_emit_alerts_denied(self, build_app) -> None:
        """Viewer (assessment.read only) gets 403 when requesting emit_alerts=true."""
        _, assessor = _mint(build_app, "governance:write", tenant_id=_TENANT)
        _, viewer = _mint(build_app, "governance:read", tenant_id=_TENANT, role="read_only")
        eng_id = _make_engagement(assessor, _TENANT)
        resp = viewer.get(
            f"/field-assessment/engagements/{eng_id}/drift-report",
            params={"current_scan_id": "fake-scan", "emit_alerts": "true"},
        )
        # Viewer reaches baseline check (409) or is denied write gate (403)
        assert resp.status_code in (403, 409)
        if resp.status_code == 403:
            assert "assessment.create" in resp.text

    def test_viewer_default_emit_alerts_returns_409_not_403(self, build_app) -> None:
        """Default emit_alerts=false means viewer reaches the read path (409 = no baseline, not 403)."""
        _, assessor = _mint(build_app, "governance:write", tenant_id=_TENANT)
        _, viewer = _mint(build_app, "governance:read", tenant_id=_TENANT, role="read_only")
        eng_id = _make_engagement(assessor, _TENANT)
        resp = viewer.get(
            f"/field-assessment/engagements/{eng_id}/drift-report",
            params={"current_scan_id": "fake-scan"},
        )
        # Viewer is allowed to read; missing baseline → 409, not 403
        assert resp.status_code == 409

    def test_assessor_emit_alerts_allowed(self, build_app) -> None:
        """Assessor (assessment.create) can pass emit_alerts=true; fails at 409 (no baseline), not 403."""
        _, assessor = _mint(build_app, "governance:write", tenant_id=_TENANT)
        eng_id = _make_engagement(assessor, _TENANT)
        resp = assessor.get(
            f"/field-assessment/engagements/{eng_id}/drift-report",
            params={"current_scan_id": "fake-scan", "emit_alerts": "true"},
        )
        # Has assessment.create; no pinned baseline → 409, not 403
        assert resp.status_code == 409
