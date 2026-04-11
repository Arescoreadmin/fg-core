"""
Regression tests for Task 1.4: export path tenant isolation and audit logging.

Proves:
- Export without tenant context fails when auth-derived binding is absent
- Cross-tenant export fails (tenant-scoped key cannot retrieve other-tenant data)
- Export event is recorded in the audit chain with tenant_id, actor_id, and trace_id
"""

from __future__ import annotations

import uuid
from typing import cast

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models import SecurityAuditLog


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _suffix() -> str:
    return uuid.uuid4().hex[:8]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    """Minimal app client with auth enabled and unique DB."""
    db_path = str(tmp_path / "export-isolation.db")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_API_KEY", "")

    from api.db import init_db, reset_engine_cache
    from api.main import build_app

    reset_engine_cache()
    init_db(sqlite_path=db_path)
    app = build_app()
    return TestClient(app)


# ---------------------------------------------------------------------------
# admin audit export (/admin/audit/export) — cross-tenant + missing tenant
# ---------------------------------------------------------------------------


def test_admin_audit_export_cross_tenant_fails(app_client: TestClient) -> None:
    """Tenant-scoped key cannot export another tenant's audit events."""
    suffix = _suffix()
    tenant_a = f"export-iso-a-{suffix}"
    tenant_b = f"export-iso-b-{suffix}"
    key_a = mint_key("audit:read", tenant_id=tenant_a)

    resp = app_client.post(
        "/admin/audit/export",
        headers={"X-API-Key": key_a},
        json={"tenant_id": tenant_b, "format": "json"},
    )
    assert resp.status_code in {403, 400}, (
        f"expected 403/400 for cross-tenant export, got {resp.status_code}"
    )


def test_admin_audit_export_missing_tenant_context_fails(
    app_client: TestClient,
) -> None:
    """Unscoped key without explicit tenant_id must be rejected (400)."""
    unscoped_key = mint_key("audit:read", tenant_id=None)

    resp = app_client.post(
        "/admin/audit/export",
        headers={"X-API-Key": unscoped_key},
        json={"format": "json"},
    )
    assert resp.status_code == 400, (
        f"unscoped key without tenant_id should be rejected with 400, got {resp.status_code}"
    )


def test_admin_audit_export_emits_audit_event_with_tenant_and_actor(
    app_client: TestClient,
) -> None:
    """Successful admin audit export records a SecurityAuditLog entry with tenant_id and actor."""
    suffix = _suffix()
    tenant = f"export-log-{suffix}"
    key = mint_key("audit:read", tenant_id=tenant)

    resp = app_client.post(
        "/admin/audit/export",
        headers={"X-API-Key": key},
        json={"format": "json"},
    )
    # May be 200 (scoped key uses auth tenant implicitly) or an empty stream
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text}"

    engine = get_engine()
    with Session(engine) as session:
        row = session.execute(
            select(SecurityAuditLog)
            .where(SecurityAuditLog.event_type == "admin_action")
            .where(SecurityAuditLog.reason == "admin_audit_export")
            .where(SecurityAuditLog.tenant_id == tenant)
            .order_by(SecurityAuditLog.id.desc())
        ).scalar_one_or_none()

    assert row is not None, "audit event for admin_audit_export must be recorded"
    assert row.tenant_id == tenant, "audit event must record the correct tenant_id"
    details = row.details_json or {}
    assert details.get("actor_id"), "audit event must record actor_id"
    assert details.get("correlation_id") or row.request_id, (
        "audit event must record trace_id (correlation_id or request_id)"
    )


# ---------------------------------------------------------------------------
# audit bundle export (/audit/export) — missing tenant context
# ---------------------------------------------------------------------------


def test_audit_bundle_export_missing_tenant_context_fails(
    app_client: TestClient,
) -> None:
    """GET /audit/export without a bound tenant (no auth) must be rejected."""
    # No API key → 401 (auth missing entirely)
    resp = app_client.get(
        "/audit/export",
        params={"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z"},
    )
    assert resp.status_code in {401, 403, 400}, (
        f"unauthenticated export must be rejected, got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# Audit ordering: failed export must NOT produce a success audit record
# ---------------------------------------------------------------------------


def test_admin_audit_export_invalid_status_filter_no_success_record(
    app_client: TestClient,
) -> None:
    """Invalid status filter (400) must not write a success audit event."""
    suffix = _suffix()
    tenant = f"export-order-{suffix}"
    key = mint_key("audit:read", tenant_id=tenant)

    resp = app_client.post(
        "/admin/audit/export",
        headers={"X-API-Key": key},
        json={"format": "json", "status": "INVALID_STATUS"},
    )
    assert resp.status_code == 400

    engine = get_engine()
    with Session(engine) as session:
        row = session.execute(
            select(SecurityAuditLog)
            .where(SecurityAuditLog.event_type == "admin_action")
            .where(SecurityAuditLog.reason == "admin_audit_export")
            .where(SecurityAuditLog.tenant_id == tenant)
            .order_by(SecurityAuditLog.id.desc())
        ).scalar_one_or_none()

    assert row is None, (
        "failed export request (400) must not produce a success audit record"
    )


def test_audit_bundle_export_chain_failure_no_success_record(
    tmp_path, monkeypatch
) -> None:
    """Broken chain (409) must not produce a success audit record."""
    from types import SimpleNamespace

    from api.audit import audit_export
    from api.db import init_db, reset_engine_cache
    from api.db_models import SecurityAuditLog
    from api.security_audit import reset_auditor
    from fastapi import HTTPException
    from services.audit_engine.engine import AuditEngine, InvariantResult
    from sqlalchemy.orm import Session

    db_path = str(tmp_path / "chain-fail-audit.db")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv(
        "FG_AUDIT_HMAC_KEY_CURRENT", "api-audit-key-api-audit-key-api-0000"
    )
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", "ak-api")
    monkeypatch.setenv("FG_AUDIT_TENANT_ID", "tenant-chain")
    reset_engine_cache()
    reset_auditor()
    init_db(sqlite_path=db_path)

    eng = AuditEngine()
    monkeypatch.setattr(
        eng, "_invariants", lambda: [InvariantResult("s", "pass", "ok")]
    )
    eng.run_cycle("light")
    # Rotate key so chain verification fails
    monkeypatch.setenv(
        "FG_AUDIT_HMAC_KEY_CURRENT", "different-key-different-key-diff-0000"
    )
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", "ak-new")
    monkeypatch.delenv("FG_AUDIT_HMAC_KEY_PREV", raising=False)
    monkeypatch.setattr("api.audit.AuditEngine", lambda: eng)

    class DummyReq:
        state = SimpleNamespace(
            tenant_id="tenant-chain",
            tenant_is_key_bound=True,
            auth=SimpleNamespace(key_prefix="test-key-chain", scopes={"audit:export"}),
            request_id="test-req-chain-order-001",
        )
        app = SimpleNamespace(openapi=lambda: {"openapi": "3.1.0"})
        headers: dict = {}
        client = None
        method = "GET"
        url = SimpleNamespace(path="/audit/export")

    with pytest.raises(HTTPException) as exc:
        audit_export(
            cast(Request, DummyReq()), "1970-01-01T00:00:00Z", "9999-12-31T23:59:59Z"
        )
    assert exc.value.status_code == 409

    from api.db import get_engine as _get_engine

    with Session(_get_engine()) as session:
        row = session.execute(
            select(SecurityAuditLog)
            .where(SecurityAuditLog.event_type == "admin_action")
            .where(SecurityAuditLog.reason == "audit_bundle_export")
        ).scalar_one_or_none()

    assert row is None, (
        "failed export (chain broken / 409) must not produce a success audit record"
    )


def test_audit_exam_export_cross_tenant_fails(tmp_path, monkeypatch) -> None:
    """AuditEngine.export_exam_bundle rejects a wrong-tenant request (engine layer)."""
    from api.db import init_db, reset_engine_cache
    from services.audit_engine.engine import AuditEngine, AuditTamperDetected

    db_path = str(tmp_path / "exam-export-iso.db")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_CURRENT", "test-audit-key-test-audit-key-te")
    monkeypatch.setenv("FG_AUDIT_HMAC_KEY_ID_CURRENT", "ak-test")
    reset_engine_cache()
    init_db(sqlite_path=db_path)

    engine = AuditEngine()
    exam_id = engine.create_exam(
        tenant_id="tenant-x",
        name="cross-tenant-proof",
        window_start="2026-01-01T00:00:00Z",
        window_end="2026-01-02T00:00:00Z",
    )

    with pytest.raises(AuditTamperDetected):
        engine.export_exam_bundle(exam_id=exam_id, app_openapi={}, tenant_id="tenant-y")
