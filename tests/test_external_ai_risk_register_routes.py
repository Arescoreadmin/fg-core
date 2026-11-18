"""External AI Risk Register routes (restored after merge 5720043b5 dropped them).

Authority model under test — TENANT-LEVEL only (no engagement assignment exists):
  * assessor (named human) with ai.vendor_governance.execute may run the register;
  * customer tenant_admin may read (oversight) but cannot execute or edit;
  * compliance_reviewer (governance.decision) edits review fields; cannot execute;
  * viewer may read only; API keys and service principals cannot execute or edit;
  * MSP delegation can never confer execution;
  * every route is tenant-scoped (cross-tenant requests see 404).
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests._assurance_actors import HEADER

_TENANT = "tenant-airr-routes-a"
_OTHER = "tenant-airr-routes-b"
_ASSESSOR = "auth0|airr-assessor"


def _human(subject: str, role: str) -> dict[str, str]:
    return {HEADER: f"{subject}|{role}"}


@pytest.fixture()
def app(build_app: Any) -> Any:
    return build_app(auth_enabled=True)


def _client(app: Any, tenant: str, **headers: str) -> TestClient:
    from api.auth_scopes import mint_key

    key = mint_key("governance:read", "governance:write", tenant_id=tenant)
    return TestClient(app, headers={"X-API-Key": key, **headers})


def _engagement(app: Any, tenant: str = _TENANT) -> str:
    resp = _client(app, tenant).post(
        "/field-assessment/engagements",
        json={
            "client_name": "AIRR Corp",
            "assessor_id": "a",
            "assessment_type": "ai_governance",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _seed_ai_tool_discovery(tenant: str, engagement_id: str) -> None:
    from api.db import get_sessionmaker
    from services.field_assessment.connectors.ai_tool_discovery_bridge import (
        import_ai_tool_discovery_scan,
    )

    tool = {
        "tool_name": "Shadow Writer AI",
        "vendor": "Unverified Co",
        "permissions": ["Files.ReadWrite.All", "Mail.Read", "offline_access"],
        "delegated_permissions": ["Files.ReadWrite.All", "Mail.Read", "offline_access"],
        "application_permissions": [],
        "admin_consent": True,
        "consent_type": "AllPrincipals",
        "verified_publisher": False,
        "publisher": "Unverified Co",
        "confidence": "confirmed",
        "service_principal_id": "sp-airr-1",
        "application_id": "app-airr-1",
        "app_id": "app-airr-1",
        "evidence_refs": ["servicePrincipal:sp-airr-1"],
        "risk_indicators": ["unverified_publisher", "sensitive_permissions"],
        "graph_node_id": f"ai_tool:{tenant}:app-airr-1",
    }
    db = get_sessionmaker()()
    try:
        import_ai_tool_discovery_scan(
            db=db,
            tenant_id=tenant,
            engagement_id=engagement_id,
            actor="seed",
            scan_result={
                "scan_completed_at": "2026-11-18T00:00:00Z",
                "tools": [tool],
                "summary": {"discovered": 1},
                "findings": [],
            },
        )
        db.commit()
    finally:
        db.close()


def _run_url(eid: str) -> str:
    return f"/field-assessment/engagements/{eid}/connector-runs/external-ai-risk-register/run"


def _list_url(eid: str) -> str:
    return f"/field-assessment/engagements/{eid}/external-ai-risk-register"


def _scan_audit(tenant: str, eid: str) -> list[Any]:
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaScanAuditEvent

    db = get_sessionmaker()()
    try:
        rows = (
            db.query(FaScanAuditEvent)
            .filter_by(tenant_id=tenant, engagement_id=eid)
            .all()
        )
        db.expunge_all()
        return rows
    finally:
        db.close()


def _seeded_register(app: Any) -> tuple[str, str]:
    eid = _engagement(app)
    _seed_ai_tool_discovery(_TENANT, eid)
    resp = _client(app, _TENANT, **_human(_ASSESSOR, "assessor")).post(
        _run_url(eid), json={}
    )
    assert resp.status_code == 200, resp.text
    items = (
        _client(app, _TENANT, **_human(_ASSESSOR, "assessor"))
        .get(_list_url(eid))
        .json()["items"]
    )
    assert items
    return eid, items[0]["risk_id"]


# ── Permission model ───────────────────────────────────────────────────────


def test_execute_permission_is_registered_and_scoped_to_assessor() -> None:
    from api.actor_context import ALL_PERMISSIONS, ROLE_PERMISSIONS
    from api.msp_authority import MSP_DELEGABLE_PERMISSIONS

    perm = "ai.vendor_governance.execute"
    assert perm in ALL_PERMISSIONS
    holders = {r for r, perms in ROLE_PERMISSIONS.items() if perm in perms}
    assert holders == {"assessor", "platform_admin"}
    # Never a customer-admin power, and never delegable to an MSP.
    assert perm not in ROLE_PERMISSIONS["tenant_admin"]
    assert perm not in MSP_DELEGABLE_PERMISSIONS


def test_customer_admin_keeps_oversight_permissions() -> None:
    from api.actor_context import ROLE_PERMISSIONS

    admin = ROLE_PERMISSIONS["tenant_admin"]
    for perm in (
        "assessment.read",
        "governance.read",
        "governance.promote",
        "scan.consent.approve",
    ):
        assert perm in admin


# ── Run ────────────────────────────────────────────────────────────────────


def test_assessor_runs_register_with_named_human_audit(app: Any) -> None:
    eid = _engagement(app)
    _seed_ai_tool_discovery(_TENANT, eid)
    resp = _client(app, _TENANT, **_human(_ASSESSOR, "assessor")).post(
        _run_url(eid), json={}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "complete" and body["risks_imported"] == 1

    events = {(e.event_type, e.actor) for e in _scan_audit(_TENANT, eid)}
    assert ("scan.initiated", _ASSESSOR) in events
    assert ("scan.completed", _ASSESSOR) in events


def test_run_is_idempotent(app: Any) -> None:
    eid, _ = _seeded_register(app)
    again = _client(app, _TENANT, **_human(_ASSESSOR, "assessor")).post(
        _run_url(eid), json={}
    )
    assert again.status_code == 200
    items = (
        _client(app, _TENANT, **_human(_ASSESSOR, "assessor"))
        .get(_list_url(eid))
        .json()
    )
    assert items["total"] == 1


@pytest.mark.parametrize(
    "role", ["tenant_admin", "viewer", "compliance_reviewer", "qa_reviewer"]
)
def test_non_assessor_roles_cannot_execute(app: Any, role: str) -> None:
    eid = _engagement(app)
    _seed_ai_tool_discovery(_TENANT, eid)
    resp = _client(app, _TENANT, **_human(f"auth0|airr-{role}", role)).post(
        _run_url(eid), json={}
    )
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["code"] == "PERMISSION_DENIED"
    assert not [
        e
        for e in _scan_audit(_TENANT, eid)
        if e.scanner_type == "external_ai_risk_register"
    ]


def test_api_key_without_named_human_cannot_execute(app: Any) -> None:
    eid = _engagement(app)
    _seed_ai_tool_discovery(_TENANT, eid)
    resp = _client(app, _TENANT).post(_run_url(eid), json={})
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["code"] == "NAMED_HUMAN_REQUIRED"


def test_run_requires_ai_tool_discovery(app: Any) -> None:
    eid = _engagement(app)
    resp = _client(app, _TENANT, **_human(_ASSESSOR, "assessor")).post(
        _run_url(eid), json={}
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "NO_AI_TOOL_DISCOVERY_SCAN"


def test_run_rejects_unknown_body_fields(app: Any) -> None:
    eid = _engagement(app)
    _seed_ai_tool_discovery(_TENANT, eid)
    resp = _client(app, _TENANT, **_human(_ASSESSOR, "assessor")).post(
        _run_url(eid), json={"tenant_id": _OTHER}
    )
    assert resp.status_code == 422


# ── Tenant isolation ───────────────────────────────────────────────────────


def test_other_tenant_assessor_cannot_run_read_or_edit(app: Any) -> None:
    eid, risk_id = _seeded_register(app)
    other = _client(app, _OTHER, **_human("auth0|airr-other-assessor", "assessor"))
    assert other.post(_run_url(eid), json={}).status_code == 404
    assert other.get(_list_url(eid)).status_code == 404
    reviewer = _client(
        app, _OTHER, **_human("auth0|airr-other-cr", "compliance_reviewer")
    )
    resp = reviewer.patch(
        f"{_list_url(eid)}/{risk_id}", json={"review_status": "closed"}
    )
    assert resp.status_code == 404


# ── List (oversight) ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "role", ["tenant_admin", "viewer", "assessor", "compliance_reviewer"]
)
def test_tenant_roles_can_read_register(app: Any, role: str) -> None:
    eid, _ = _seeded_register(app)
    resp = _client(app, _TENANT, **_human(f"auth0|airr-read-{role}", role)).get(
        _list_url(eid)
    )
    assert resp.status_code == 200
    assert resp.json()["total"] == 1


def test_list_unknown_engagement_is_404(app: Any) -> None:
    resp = _client(app, _TENANT, **_human(_ASSESSOR, "assessor")).get(
        _list_url("missing")
    )
    assert resp.status_code == 404


# ── PATCH (governance review) ──────────────────────────────────────────────


def test_compliance_reviewer_updates_review_fields_with_audit(app: Any) -> None:
    eid, risk_id = _seeded_register(app)
    reviewer = _client(app, _TENANT, **_human("auth0|airr-cr", "compliance_reviewer"))
    resp = reviewer.patch(
        f"{_list_url(eid)}/{risk_id}",
        json={
            "review_status": "under_review",
            "risk_owner": "CISO",
            "owner_type": "Security",
        },
    )
    assert resp.status_code == 200, resp.text
    row = resp.json()
    assert row["review_status"] == "under_review" and row["owner_type"] == "Security"
    assert row["last_reviewed_at"]

    audit = (
        _client(app, _TENANT)
        .get(f"/field-assessment/engagements/{eid}/audit-events")
        .json()
    )
    events = audit.get("items", audit) if isinstance(audit, dict) else audit
    updated = [e for e in events if e["event_type"] == "risk_record.updated"]
    assert updated and updated[-1]["actor"] == "auth0|airr-cr"
    assert updated[-1]["payload"]["changed_fields"] == [
        "owner_type",
        "review_status",
        "risk_owner",
    ]


@pytest.mark.parametrize("role", ["assessor", "tenant_admin", "viewer"])
def test_non_reviewer_roles_cannot_edit(app: Any, role: str) -> None:
    eid, risk_id = _seeded_register(app)
    resp = _client(app, _TENANT, **_human(f"auth0|airr-edit-{role}", role)).patch(
        f"{_list_url(eid)}/{risk_id}", json={"review_status": "closed"}
    )
    assert resp.status_code == 403


def test_patch_rejects_immutable_and_invalid_values(app: Any) -> None:
    eid, risk_id = _seeded_register(app)
    reviewer = _client(app, _TENANT, **_human("auth0|airr-cr2", "compliance_reviewer"))
    url = f"{_list_url(eid)}/{risk_id}"
    assert reviewer.patch(url, json={"risk_score": "low"}).status_code == 422
    bad = reviewer.patch(url, json={"review_status": "approved-by-me"})
    assert (
        bad.status_code == 422
        and bad.json()["detail"]["code"] == "INVALID_REVIEW_STATUS"
    )
    bad = reviewer.patch(url, json={"vendor_review_status": "fine"})
    assert (
        bad.status_code == 422
        and bad.json()["detail"]["code"] == "INVALID_VENDOR_REVIEW_STATUS"
    )


def test_patch_unknown_risk_is_404(app: Any) -> None:
    eid, _ = _seeded_register(app)
    reviewer = _client(app, _TENANT, **_human("auth0|airr-cr3", "compliance_reviewer"))
    resp = reviewer.patch(
        f"{_list_url(eid)}/does-not-exist", json={"review_status": "closed"}
    )
    assert resp.status_code == 404
