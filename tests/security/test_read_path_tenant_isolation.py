"""
Regression tests proving cross-tenant read isolation on tenant-scoped read paths.

Invariant: a tenant-scoped key must never receive another tenant's data from any
read endpoint, even when the other tenant's data exists in the database.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models import DecisionRecord, SecurityAuditLog


def _seed_decision(session: Session, *, tenant_id: str, event_id: str) -> None:
    session.add(
        DecisionRecord(
            tenant_id=tenant_id,
            source="unit-test",
            event_id=event_id,
            event_type="auth.bruteforce",
            threat_level="low",
            anomaly_score=0.1,
            ai_adversarial_score=0.0,
            pq_fallback=False,
            rules_triggered_json=[],
            decision_diff_json=None,
            request_json={"timestamp": datetime.now(timezone.utc).isoformat()},
            response_json={"decision": "allow"},
        )
    )


def _entry_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def test_decisions_tenant_read_isolation(build_app) -> None:
    """GET /decisions returns only the authenticated tenant's records.

    Seeds decisions for two tenants; confirms tenant-a key sees only
    tenant-a data and never tenant-b data.
    """
    suffix = uuid.uuid4().hex[:8]
    tenant_a = f"isolation-read-a-{suffix}"
    tenant_b = f"isolation-read-b-{suffix}"
    evt_a = f"evt-read-a-{suffix}"
    evt_b = f"evt-read-b-{suffix}"

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key_a = mint_key("decisions:read", tenant_id=tenant_a)

    engine = get_engine()
    with Session(engine) as session:
        _seed_decision(session, tenant_id=tenant_a, event_id=evt_a)
        _seed_decision(session, tenant_id=tenant_b, event_id=evt_b)
        session.commit()

    resp = client.get("/decisions", headers={"X-API-Key": key_a})
    assert resp.status_code == 200
    items = resp.json()["items"]
    event_ids = [item["event_id"] for item in items]
    assert evt_a in event_ids, "tenant-a's own decision must be returned"
    assert evt_b not in event_ids, "tenant-b's decision must not be returned"
    assert all(item["tenant_id"] == tenant_a for item in items), (
        "all returned decisions must belong to the authenticated tenant"
    )


def test_audit_search_tenant_read_isolation(build_app) -> None:
    """GET /admin/audit/search returns only the authenticated tenant's audit events.

    Seeds audit log entries for two tenants; confirms tenant-a key sees only
    tenant-a events and never tenant-b events.
    """
    suffix = uuid.uuid4().hex[:8]
    tenant_a = f"isolation-audit-a-{suffix}"
    tenant_b = f"isolation-audit-b-{suffix}"

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key_a = mint_key("audit:read", tenant_id=tenant_a)

    engine = get_engine()
    with Session(engine) as session:
        now = datetime.now(timezone.utc)
        session.add(
            SecurityAuditLog(
                event_type="auth_success",
                event_category="security",
                severity="info",
                tenant_id=tenant_a,
                success=True,
                created_at=now,
                chain_id=tenant_a,
                prev_hash="GENESIS",
                entry_hash=_entry_hash(f"audit-a-{suffix}"),
            )
        )
        session.add(
            SecurityAuditLog(
                event_type="auth_success",
                event_category="security",
                severity="info",
                tenant_id=tenant_b,
                success=True,
                created_at=now,
                chain_id=tenant_b,
                prev_hash="GENESIS",
                entry_hash=_entry_hash(f"audit-b-{suffix}"),
            )
        )
        session.commit()

    resp = client.get("/admin/audit/search", headers={"X-API-Key": key_a})
    assert resp.status_code == 200
    items = resp.json()["items"]
    returned_tenants = {item["tenant_id"] for item in items}
    assert tenant_b not in returned_tenants, (
        "tenant-b's audit events must not be returned to tenant-a"
    )
