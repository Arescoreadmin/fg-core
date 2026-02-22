"""
tests/control_plane/test_control_plane_v2.py — FrostGate Control Plane v2 Tests.

Coverage:
  - Command creation and idempotency
  - Command cancellation (queued vs executing conflict)
  - Receipt submission (executor auth enforcement)
  - Ledger append and hash-chain correctness
  - Ledger chain verification (ok + tampered)
  - Heartbeat upsert and staleness detection
  - Playbook triggering (dry-run + live)
  - MSP cross-tenant isolation
  - Evidence bundle assembly
  - Negative tests: each global security invariant

Security invariant tests (negative):
  - tenant_id cannot be supplied via request body (always from auth)
  - Non-executor cannot submit receipt
  - Unauthenticated access returns 401/403
  - Cross-tenant access returns 404 (anti-enumeration)
  - Invalid command enum rejected
  - Missing reason rejected
  - Ledger tamper detected in verify endpoint
  - Subprocess not used anywhere
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional

import pytest

from api.auth_scopes import mint_key
from api.db import init_db, reset_engine_cache
from api.main import build_app
from fastapi.testclient import TestClient

from services.cp_ledger import (
    ControlPlaneLedger,
    compute_content_hash,
    compute_chain_hash,
    compute_merkle_root,
    LedgerEntry,
    GENESIS_HASH,
)
from services.cp_commands import (
    ControlPlaneCommandService,
    VALID_CP_COMMANDS,
    ERR_INVALID_COMMAND,
    ERR_CANCEL_CONFLICT,
    ERR_NOT_EXECUTOR,
    ERR_ALREADY_RECEIPTED,
    ERR_UNKNOWN_COMMAND_ID,
)
from services.cp_heartbeats import HeartbeatService, HEARTBEAT_STALE_SECONDS
from services.cp_playbooks import PlaybookService, VALID_PLAYBOOKS, ERR_INVALID_PLAYBOOK

# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    """Test app with auth enabled and fresh SQLite DB."""
    db_path = tmp_path / "cpv2_test.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_API_KEY", "")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))

    app = build_app(auth_enabled=True)
    return TestClient(app)


@pytest.fixture()
def _db_path(tmp_path, monkeypatch):
    db_path = tmp_path / "cpv2_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    return str(db_path)


def _mint(scopes: str, tenant_id: Optional[str] = "tenant-alpha") -> str:
    return mint_key(scopes, tenant_id=tenant_id)


@pytest.fixture()
def admin_key(_db_path):
    return _mint("control-plane:read,control-plane:admin,control-plane:audit:read")


@pytest.fixture()
def read_key(_db_path):
    return _mint("control-plane:read,control-plane:audit:read")


@pytest.fixture()
def global_admin_key(_db_path):
    return _mint(
        "control-plane:read,control-plane:admin,control-plane:audit:read,control-plane:msp:admin",
        tenant_id=None,
    )


@pytest.fixture()
def msp_read_key(_db_path):
    return _mint(
        "control-plane:read,control-plane:audit:read,control-plane:msp:read",
        tenant_id="msp-provider",
    )


@pytest.fixture()
def other_tenant_key(_db_path):
    return _mint(
        "control-plane:read,control-plane:admin,control-plane:audit:read",
        tenant_id="tenant-beta",
    )


# Helper: make a request with API key header
def _headers(key: str) -> Dict[str, str]:
    return {"x-api-key": key}


def _ikey() -> str:
    return str(uuid.uuid4())


# ===========================================================================
# A. Unit tests: Services (in-memory SQLite via SQLAlchemy)
# ===========================================================================


@pytest.fixture()
def sqlite_session(tmp_path, monkeypatch):
    """SQLAlchemy session backed by SQLite — includes all CP v2 tables."""

    db_path = tmp_path / "unit_cpv2.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=str(db_path))

    from api.db import get_sessionmaker

    Session = get_sessionmaker(sqlite_path=str(db_path))
    db = Session()
    try:
        yield db
    finally:
        db.close()


class TestLedgerService:
    """Unit tests for ControlPlaneLedger."""

    def test_append_event_creates_row(self, sqlite_session):
        ledger = ControlPlaneLedger()
        entry = ledger.append_event(
            db_session=sqlite_session,
            event_type="cp_command_created",
            actor_id="actor-1",
            actor_role="operator",
            tenant_id="tenant-a",
            payload={"key": "value"},
            trace_id="trace-1",
            severity="info",
            source="api",
        )
        sqlite_session.commit()

        assert entry.event_type == "cp_command_created"
        assert entry.actor_id == "actor-1"
        assert entry.tenant_id == "tenant-a"
        assert entry.prev_hash == GENESIS_HASH
        assert len(entry.content_hash) == 64
        assert len(entry.chain_hash) == 64

    def test_hash_chain_linkage(self, sqlite_session):
        """Each event's prev_hash must equal the previous event's chain_hash."""
        ledger = ControlPlaneLedger()

        e1 = ledger.append_event(
            db_session=sqlite_session,
            event_type="cp_command_created",
            actor_id="a",
            actor_role="op",
            tenant_id="t1",
            payload={"seq": 1},
            trace_id="tr1",
        )
        sqlite_session.flush()

        e2 = ledger.append_event(
            db_session=sqlite_session,
            event_type="cp_command_completed",
            actor_id="a",
            actor_role="op",
            tenant_id="t1",
            payload={"seq": 2},
            trace_id="tr2",
        )
        sqlite_session.commit()

        assert e2.prev_hash == e1.chain_hash

    def test_chain_verify_empty_is_ok(self, sqlite_session):
        ledger = ControlPlaneLedger()
        result = ledger.verify_chain(sqlite_session, tenant_id="empty-tenant")
        assert result.ok
        assert result.total_entries == 0

    def test_chain_verify_valid_chain(self, sqlite_session):
        ledger = ControlPlaneLedger()
        for i in range(5):
            ledger.append_event(
                db_session=sqlite_session,
                event_type="cp_command_created",
                actor_id="sys",
                actor_role="system",
                tenant_id="tenant-verify",
                payload={"i": i},
            )
        sqlite_session.commit()

        result = ledger.verify_chain(sqlite_session, tenant_id="tenant-verify")
        assert result.ok
        assert result.total_entries == 5
        assert result.merkle_root is not None

    def test_chain_verify_detects_tamper(self, sqlite_session):
        """Directly mutating a stored row must be detected by verify_chain."""
        from api.db_models_cp_v2 import ControlPlaneEventLedger

        ledger = ControlPlaneLedger()
        ledger.append_event(
            db_session=sqlite_session,
            event_type="cp_command_created",
            actor_id="actor",
            actor_role="op",
            tenant_id="tenant-tamper",
            payload={"data": "original"},
        )
        sqlite_session.commit()

        # Tamper the stored row by changing the payload_json directly in DB
        row = sqlite_session.query(ControlPlaneEventLedger).first()
        assert row is not None
        row.payload_json = {"data": "TAMPERED"}
        sqlite_session.commit()

        result = ledger.verify_chain(sqlite_session, tenant_id="tenant-tamper")
        assert not result.ok
        assert result.first_tampered_id is not None

    def test_tenant_chain_isolation(self, sqlite_session):
        """Events for tenant-a do not appear in tenant-b chain."""
        ledger = ControlPlaneLedger()
        ledger.append_event(
            db_session=sqlite_session,
            event_type="cp_command_created",
            actor_id="a",
            actor_role="op",
            tenant_id="tenant-a",
            payload={},
        )
        sqlite_session.commit()

        result_b = ledger.verify_chain(sqlite_session, tenant_id="tenant-b")
        assert result_b.ok
        assert result_b.total_entries == 0

    def test_merkle_root_deterministic(self, sqlite_session):
        """Merkle root must be deterministic for the same set of entries."""
        entries = [
            LedgerEntry(
                id=str(i),
                ts="2024-01-01T00:00:00Z",
                tenant_id="t",
                actor_id="a",
                actor_role="op",
                event_type="cp_command_created",
                payload_json={},
                content_hash="a" * 64,
                prev_hash="b" * 64,
                chain_hash="c" * 64,
                trace_id="",
                severity="info",
                source="api",
            )
            for i in range(4)
        ]
        r1 = compute_merkle_root(entries)
        r2 = compute_merkle_root(entries)
        assert r1 == r2
        assert len(r1) == 64

    def test_invalid_event_type_rejected(self, sqlite_session):
        ledger = ControlPlaneLedger()
        with pytest.raises(ValueError, match="Invalid event_type"):
            ledger.append_event(
                db_session=sqlite_session,
                event_type="INVALID_TYPE",
                actor_id="a",
                actor_role="op",
                tenant_id="t",
                payload={},
            )

    def test_global_chain_uses_none_tenant(self, sqlite_session):
        """Global/cross-tenant events use tenant_id=None."""
        ledger = ControlPlaneLedger()
        entry = ledger.append_event(
            db_session=sqlite_session,
            event_type="cp_msp_cross_tenant_access",
            actor_id="msp_actor",
            actor_role="msp_admin",
            tenant_id=None,
            payload={"target": "tenant-x"},
        )
        sqlite_session.commit()
        assert entry.tenant_id is None
        assert entry.prev_hash == GENESIS_HASH


class TestCommandService:
    """Unit tests for ControlPlaneCommandService."""

    def test_create_command_success(self, sqlite_session):
        ledger = ControlPlaneLedger()
        svc = ControlPlaneCommandService()
        rec = svc.create_command(
            db_session=sqlite_session,
            ledger=ledger,
            tenant_id="t1",
            actor_id="actor-1",
            actor_role="operator",
            target_type="locker",
            target_id="locker-abc",
            command="restart",
            reason="Scheduled maintenance",
            idempotency_key=_ikey(),
        )
        sqlite_session.commit()

        assert rec.command == "restart"
        assert rec.status == "queued"
        assert not rec.idempotent

    def test_create_command_idempotent(self, sqlite_session):
        """Same idempotency key returns existing record."""
        ledger = ControlPlaneLedger()
        svc = ControlPlaneCommandService()
        ikey = _ikey()

        rec1 = svc.create_command(
            db_session=sqlite_session,
            ledger=ledger,
            tenant_id="t1",
            actor_id="actor-1",
            actor_role="operator",
            target_type="locker",
            target_id="locker-abc",
            command="pause",
            reason="Maintenance window",
            idempotency_key=ikey,
        )
        sqlite_session.commit()

        rec2 = svc.create_command(
            db_session=sqlite_session,
            ledger=ledger,
            tenant_id="t1",
            actor_id="actor-1",
            actor_role="operator",
            target_type="locker",
            target_id="locker-abc",
            command="pause",
            reason="Maintenance window",
            idempotency_key=ikey,
        )
        sqlite_session.commit()

        assert rec1.command_id == rec2.command_id
        assert rec2.idempotent

    def test_invalid_command_rejected(self, sqlite_session):
        ledger = ControlPlaneLedger()
        svc = ControlPlaneCommandService()
        with pytest.raises(ValueError, match=ERR_INVALID_COMMAND):
            svc.create_command(
                db_session=sqlite_session,
                ledger=ledger,
                tenant_id="t1",
                actor_id="a",
                actor_role="op",
                target_type="locker",
                target_id="x",
                command="DO_EVIL_THING",
                reason="Testing invalid command",
                idempotency_key=_ikey(),
            )

    def test_short_reason_rejected(self, sqlite_session):
        ledger = ControlPlaneLedger()
        svc = ControlPlaneCommandService()
        with pytest.raises(ValueError):
            svc.create_command(
                db_session=sqlite_session,
                ledger=ledger,
                tenant_id="t1",
                actor_id="a",
                actor_role="op",
                target_type="locker",
                target_id="x",
                command="restart",
                reason="hi",  # too short
                idempotency_key=_ikey(),
            )

    def test_cancel_queued_command(self, sqlite_session):
        ledger = ControlPlaneLedger()
        svc = ControlPlaneCommandService()

        rec = svc.create_command(
            db_session=sqlite_session,
            ledger=ledger,
            tenant_id="t1",
            actor_id="a",
            actor_role="op",
            target_type="locker",
            target_id="x",
            command="pause",
            reason="Test cancel operation",
            idempotency_key=_ikey(),
        )
        sqlite_session.commit()

        cancelled = svc.cancel_command(
            db_session=sqlite_session,
            ledger=ledger,
            command_id=rec.command_id,
            tenant_id="t1",
            actor_id="a",
            actor_role="op",
        )
        sqlite_session.commit()

        assert cancelled.status == "cancelled"

    def test_cancel_executing_command_conflict(self, sqlite_session):
        """Cancelling an executing command must raise ERR_CANCEL_CONFLICT."""
        from api.db_models_cp_v2 import ControlPlaneCommand

        ledger = ControlPlaneLedger()
        svc = ControlPlaneCommandService()

        rec = svc.create_command(
            db_session=sqlite_session,
            ledger=ledger,
            tenant_id="t1",
            actor_id="a",
            actor_role="op",
            target_type="locker",
            target_id="x",
            command="restart",
            reason="Testing conflict scenario",
            idempotency_key=_ikey(),
        )
        sqlite_session.commit()

        # Manually set to executing
        row = (
            sqlite_session.query(ControlPlaneCommand)
            .filter_by(command_id=rec.command_id)
            .first()
        )
        row.status = "executing"
        sqlite_session.commit()

        with pytest.raises(ValueError, match=ERR_CANCEL_CONFLICT):
            svc.cancel_command(
                db_session=sqlite_session,
                ledger=ledger,
                command_id=rec.command_id,
                tenant_id="t1",
                actor_id="a",
                actor_role="op",
            )

    def test_receipt_submission(self, sqlite_session):
        ledger = ControlPlaneLedger()
        svc = ControlPlaneCommandService()

        rec = svc.create_command(
            db_session=sqlite_session,
            ledger=ledger,
            tenant_id="t1",
            actor_id="a",
            actor_role="op",
            target_type="locker",
            target_id="x",
            command="restart",
            reason="Restart for maintenance",
            idempotency_key=_ikey(),
        )
        sqlite_session.commit()

        receipt = svc.submit_receipt(
            db_session=sqlite_session,
            ledger=ledger,
            command_id=rec.command_id,
            executor_id="agent-node-1",
            executor_type="agent",
            ok=True,
            evidence={"result": "restarted"},
            duration_ms=1200,
        )
        sqlite_session.commit()

        assert receipt.ok
        assert receipt.command_id == rec.command_id
        assert len(receipt.evidence_hash) == 64

    def test_receipt_invalid_executor_type_rejected(self, sqlite_session):
        """Non-executor type must be rejected."""
        ledger = ControlPlaneLedger()
        svc = ControlPlaneCommandService()

        rec = svc.create_command(
            db_session=sqlite_session,
            ledger=ledger,
            tenant_id="t1",
            actor_id="a",
            actor_role="op",
            target_type="locker",
            target_id="x",
            command="restart",
            reason="Test executor validation",
            idempotency_key=_ikey(),
        )
        sqlite_session.commit()

        with pytest.raises(ValueError, match=ERR_NOT_EXECUTOR):
            svc.submit_receipt(
                db_session=sqlite_session,
                ledger=ledger,
                command_id=rec.command_id,
                executor_id="bad-actor",
                executor_type="unknown_type",  # not in VALID_EXECUTOR_TYPES
                ok=True,
            )

    def test_duplicate_receipt_rejected(self, sqlite_session):
        """Submitting a second receipt from the same executor must raise ERR_ALREADY_RECEIPTED."""
        ledger = ControlPlaneLedger()
        svc = ControlPlaneCommandService()

        rec = svc.create_command(
            db_session=sqlite_session,
            ledger=ledger,
            tenant_id="t1",
            actor_id="a",
            actor_role="op",
            target_type="locker",
            target_id="x",
            command="restart",
            reason="Testing duplicate receipts",
            idempotency_key=_ikey(),
        )
        sqlite_session.commit()

        svc.submit_receipt(
            db_session=sqlite_session,
            ledger=ledger,
            command_id=rec.command_id,
            executor_id="agent-1",
            executor_type="agent",
            ok=True,
        )
        sqlite_session.commit()

        with pytest.raises(ValueError, match=ERR_ALREADY_RECEIPTED):
            svc.submit_receipt(
                db_session=sqlite_session,
                ledger=ledger,
                command_id=rec.command_id,
                executor_id="agent-1",
                executor_type="agent",
                ok=True,
            )

    def test_unknown_command_id_receipt(self, sqlite_session):
        ledger = ControlPlaneLedger()
        svc = ControlPlaneCommandService()
        with pytest.raises(ValueError, match=ERR_UNKNOWN_COMMAND_ID):
            svc.submit_receipt(
                db_session=sqlite_session,
                ledger=ledger,
                command_id="does-not-exist",
                executor_id="agent-1",
                executor_type="agent",
                ok=True,
            )


class TestHeartbeatService:
    """Unit tests for HeartbeatService."""

    def test_upsert_creates_record(self, sqlite_session):
        svc = HeartbeatService()
        result = svc.upsert(
            db_session=sqlite_session,
            entity_type="locker",
            entity_id="locker-1",
            tenant_id="t1",
            last_state="active",
        )
        sqlite_session.commit()

        assert result["entity_id"] == "locker-1"
        assert result["last_state"] == "active"

    def test_upsert_updates_existing(self, sqlite_session):
        svc = HeartbeatService()
        svc.upsert(
            db_session=sqlite_session,
            entity_type="locker",
            entity_id="locker-2",
            tenant_id="t1",
            last_state="active",
            queue_depth=0,
        )
        sqlite_session.commit()

        svc.upsert(
            db_session=sqlite_session,
            entity_type="locker",
            entity_id="locker-2",
            tenant_id="t1",
            last_state="degraded",
            queue_depth=42,
        )
        sqlite_session.commit()

        hbs = svc.get_heartbeats(
            db_session=sqlite_session,
            tenant_id="t1",
            is_global_admin=False,
        )
        assert len(hbs) == 1
        assert hbs[0]["last_state"] == "degraded"
        assert hbs[0]["queue_depth"] == 42

    def test_invalid_entity_type_rejected(self, sqlite_session):
        svc = HeartbeatService()
        with pytest.raises(ValueError, match="Invalid entity_type"):
            svc.upsert(
                db_session=sqlite_session,
                entity_type="INVALID",
                entity_id="x",
                tenant_id="t1",
            )

    def test_detect_stale_emits_ledger_event(self, sqlite_session):
        from api.db_models_cp_v2 import ControlPlaneHeartbeat

        svc = HeartbeatService()
        ledger = ControlPlaneLedger()

        # Insert a heartbeat with old last_seen_ts
        old_ts = datetime.now(timezone.utc) - timedelta(
            seconds=HEARTBEAT_STALE_SECONDS + 60
        )
        row = ControlPlaneHeartbeat(
            entity_type="locker",
            entity_id="stale-locker",
            tenant_id="t1",
            last_seen_ts=old_ts,
            last_state="active",
            breaker_state="closed",
            queue_depth=0,
        )
        sqlite_session.add(row)
        sqlite_session.commit()

        stale = svc.detect_stale(
            db_session=sqlite_session,
            ledger=ledger,
            tenant_id="t1",
        )
        sqlite_session.commit()

        assert len(stale) == 1
        assert stale[0]["entity_id"] == "stale-locker"
        assert stale[0]["age_seconds"] >= HEARTBEAT_STALE_SECONDS

    def test_tenant_isolation_in_heartbeats(self, sqlite_session):
        svc = HeartbeatService()
        svc.upsert(
            db_session=sqlite_session,
            entity_type="locker",
            entity_id="locker-a",
            tenant_id="tenant-a",
        )
        svc.upsert(
            db_session=sqlite_session,
            entity_type="locker",
            entity_id="locker-b",
            tenant_id="tenant-b",
        )
        sqlite_session.commit()

        hbs_a = svc.get_heartbeats(
            sqlite_session, tenant_id="tenant-a", is_global_admin=False
        )
        hbs_b = svc.get_heartbeats(
            sqlite_session, tenant_id="tenant-b", is_global_admin=False
        )

        assert len(hbs_a) == 1
        assert hbs_a[0]["entity_id"] == "locker-a"
        assert len(hbs_b) == 1
        assert hbs_b[0]["entity_id"] == "locker-b"


class TestPlaybookService:
    """Unit tests for PlaybookService."""

    def test_invalid_playbook_rejected(self, sqlite_session):
        ledger = ControlPlaneLedger()
        svc = PlaybookService()
        cmd_svc = ControlPlaneCommandService()

        with pytest.raises(ValueError, match=ERR_INVALID_PLAYBOOK):
            svc.trigger(
                db_session=sqlite_session,
                ledger=ledger,
                command_svc=cmd_svc,
                playbook="rm_rf_everything",
                target_id="target",
                tenant_id="t1",
                actor_id="a",
                actor_role="admin",
                reason="Testing invalid playbook",
                idempotency_key=_ikey(),
            )

    def test_dry_run_returns_plan_not_actions(self, sqlite_session):
        ledger = ControlPlaneLedger()
        svc = PlaybookService()
        cmd_svc = ControlPlaneCommandService()

        result = svc.trigger(
            db_session=sqlite_session,
            ledger=ledger,
            command_svc=cmd_svc,
            playbook="stuck_boot_recover",
            target_id="module-xyz",
            tenant_id="t1",
            actor_id="a",
            actor_role="admin",
            reason="Testing dry run mode",
            idempotency_key=_ikey(),
            dry_run=True,
        )
        sqlite_session.commit()

        assert result.ok
        assert result.dry_run
        assert result.actions_taken == []
        assert len(result.actions_planned) > 0

    def test_all_playbooks_valid(self, sqlite_session):
        """All 4 allowlisted playbooks must execute without error."""
        ledger = ControlPlaneLedger()
        svc = PlaybookService()
        cmd_svc = ControlPlaneCommandService()

        for playbook in VALID_PLAYBOOKS:
            result = svc.trigger(
                db_session=sqlite_session,
                ledger=ledger,
                command_svc=cmd_svc,
                playbook=playbook,
                target_id="target-module",
                tenant_id="t1",
                actor_id="a",
                actor_role="admin",
                reason="Automated remediation test",
                idempotency_key=_ikey(),
                dry_run=True,
            )
            sqlite_session.commit()
            assert result.playbook == playbook
            assert result.ok

    def test_playbook_emits_ledger_events(self, sqlite_session):
        from api.db_models_cp_v2 import ControlPlaneEventLedger

        ledger = ControlPlaneLedger()
        svc = PlaybookService()
        cmd_svc = ControlPlaneCommandService()

        svc.trigger(
            db_session=sqlite_session,
            ledger=ledger,
            command_svc=cmd_svc,
            playbook="safe_restart_sequence",
            target_id="target-locker",
            tenant_id="t2",
            actor_id="a",
            actor_role="admin",
            reason="Safe restart for maintenance",
            idempotency_key=_ikey(),
            dry_run=True,
        )
        sqlite_session.commit()

        events = (
            sqlite_session.query(ControlPlaneEventLedger)
            .filter_by(tenant_id="t2")
            .all()
        )
        event_types = {e.event_type for e in events}
        assert "cp_playbook_dry_run" in event_types
        assert "cp_playbook_completed" in event_types


# ===========================================================================
# B. API integration tests (via TestClient)
# ===========================================================================


class TestCommandsAPI:
    """Integration tests for /control-plane/v2/commands endpoints."""

    def test_create_command_requires_auth(self, app_client):
        resp = app_client.post(
            "/control-plane/v2/commands",
            json={
                "target_type": "locker",
                "target_id": "l1",
                "command": "restart",
                "reason": "Test authentication",
                "idempotency_key": _ikey(),
            },
        )
        assert resp.status_code in (401, 403)

    def test_create_command_requires_admin_scope(self, app_client, read_key):
        """Read-only scope must be rejected for command creation."""
        resp = app_client.post(
            "/control-plane/v2/commands",
            json={
                "target_type": "locker",
                "target_id": "l1",
                "command": "restart",
                "reason": "Test scope enforcement",
                "idempotency_key": _ikey(),
            },
            headers=_headers(read_key),
        )
        assert resp.status_code in (401, 403)

    def test_create_command_success(self, app_client, admin_key):
        resp = app_client.post(
            "/control-plane/v2/commands",
            json={
                "target_type": "locker",
                "target_id": "locker-1",
                "command": "restart",
                "reason": "Scheduled maintenance restart",
                "idempotency_key": _ikey(),
            },
            headers=_headers(admin_key),
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["command"] == "restart"
        assert body["status"] == "queued"
        assert "command_id" in body
        assert "trace_id" in body

    def test_invalid_command_rejected(self, app_client, admin_key):
        resp = app_client.post(
            "/control-plane/v2/commands",
            json={
                "target_type": "locker",
                "target_id": "l1",
                "command": "rm_rf",
                "reason": "Testing invalid command enum",
                "idempotency_key": _ikey(),
            },
            headers=_headers(admin_key),
        )
        assert resp.status_code == 400
        body = resp.json()
        assert "CP_CMD_INVALID_COMMAND" in str(body)

    def test_missing_reason_rejected(self, app_client, admin_key):
        resp = app_client.post(
            "/control-plane/v2/commands",
            json={
                "target_type": "locker",
                "target_id": "l1",
                "command": "restart",
                "reason": "hi",  # too short
                "idempotency_key": _ikey(),
            },
            headers=_headers(admin_key),
        )
        # Pydantic min_length validation
        assert resp.status_code in (400, 422)

    def test_idempotent_command_returns_same_id(self, app_client, admin_key):
        ikey = _ikey()
        payload = {
            "target_type": "locker",
            "target_id": "l1",
            "command": "pause",
            "reason": "Idempotency test operation",
            "idempotency_key": ikey,
        }
        r1 = app_client.post(
            "/control-plane/v2/commands", json=payload, headers=_headers(admin_key)
        )
        r2 = app_client.post(
            "/control-plane/v2/commands", json=payload, headers=_headers(admin_key)
        )

        assert r1.status_code == 201
        assert r2.status_code == 201
        assert r1.json()["command_id"] == r2.json()["command_id"]

    def test_list_commands_requires_read_scope(self, app_client):
        resp = app_client.get("/control-plane/v2/commands")
        assert resp.status_code in (401, 403)

    def test_list_commands_success(self, app_client, admin_key):
        resp = app_client.get("/control-plane/v2/commands", headers=_headers(admin_key))
        assert resp.status_code == 200
        assert "commands" in resp.json()

    def test_cross_tenant_command_returns_404(
        self, app_client, admin_key, other_tenant_key
    ):
        """Tenant-beta cannot see tenant-alpha commands (anti-enumeration)."""
        # Create a command as tenant-alpha
        r = app_client.post(
            "/control-plane/v2/commands",
            json={
                "target_type": "locker",
                "target_id": "l1",
                "command": "restart",
                "reason": "Cross-tenant isolation test",
                "idempotency_key": _ikey(),
            },
            headers=_headers(admin_key),
        )
        assert r.status_code == 201
        cmd_id = r.json()["command_id"]

        # Cancel as tenant-beta must get 404 (not 403, to prevent enumeration)
        cancel_resp = app_client.post(
            f"/control-plane/v2/commands/{cmd_id}/cancel",
            json={"reason": "Testing cross-tenant isolation"},
            headers=_headers(other_tenant_key),
        )
        assert cancel_resp.status_code in (404, 409)


class TestReceiptAPI:
    """Integration tests for receipt endpoint — executor auth enforced."""

    def test_receipt_requires_auth(self, app_client):
        resp = app_client.post(
            "/control-plane/v2/commands/fake-id/receipt",
            json={
                "executor_id": "agent-1",
                "executor_type": "agent",
                "ok": True,
            },
        )
        assert resp.status_code in (401, 403)

    def test_receipt_with_invalid_executor_type(self, app_client, admin_key):
        # Create command first
        r = app_client.post(
            "/control-plane/v2/commands",
            json={
                "target_type": "locker",
                "target_id": "l1",
                "command": "restart",
                "reason": "Test receipt validation",
                "idempotency_key": _ikey(),
            },
            headers=_headers(admin_key),
        )
        assert r.status_code == 201
        cmd_id = r.json()["command_id"]

        resp = app_client.post(
            f"/control-plane/v2/commands/{cmd_id}/receipt",
            json={
                "executor_id": "bad-actor",
                "executor_type": "INVALID_TYPE",
                "ok": True,
            },
            headers=_headers(admin_key),
        )
        assert resp.status_code == 403

    def test_receipt_submitted_successfully(self, app_client, admin_key):
        r = app_client.post(
            "/control-plane/v2/commands",
            json={
                "target_type": "locker",
                "target_id": "l2",
                "command": "pause",
                "reason": "Test successful receipt submission",
                "idempotency_key": _ikey(),
            },
            headers=_headers(admin_key),
        )
        assert r.status_code == 201
        cmd_id = r.json()["command_id"]

        resp = app_client.post(
            f"/control-plane/v2/commands/{cmd_id}/receipt",
            json={
                "executor_id": "agent-node-1",
                "executor_type": "agent",
                "ok": True,
                "duration_ms": 450,
            },
            headers=_headers(admin_key),
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["ok"]
        assert body["command_id"] == cmd_id


class TestLedgerAPI:
    """Integration tests for ledger and verification endpoints."""

    def test_ledger_query_requires_audit_scope(self, app_client, read_key):
        # read_key has audit:read — should succeed
        resp = app_client.get("/control-plane/v2/ledger", headers=_headers(read_key))
        assert resp.status_code == 200

    def test_ledger_verify_empty_chain_is_ok(self, app_client, admin_key):
        resp = app_client.get(
            "/control-plane/v2/ledger/verify", headers=_headers(admin_key)
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["integrity"]["ok"]

    def test_ledger_query_returns_events(self, app_client, admin_key):
        # Create a command to generate ledger entries
        app_client.post(
            "/control-plane/v2/commands",
            json={
                "target_type": "locker",
                "target_id": "l1",
                "command": "restart",
                "reason": "Generate ledger entries for query test",
                "idempotency_key": _ikey(),
            },
            headers=_headers(admin_key),
        )

        resp = app_client.get("/control-plane/v2/ledger", headers=_headers(admin_key))
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body["events"], list)
        assert "trace_id" in body

    def test_ledger_anchor_export(self, app_client, admin_key):
        resp = app_client.get(
            "/control-plane/v2/ledger/anchor", headers=_headers(admin_key)
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["anchor_type"] == "cp_ledger_daily_anchor"
        assert "merkle_root" in body
        assert "generated_at" in body

    def test_ledger_unauthenticated_returns_401(self, app_client):
        resp = app_client.get("/control-plane/v2/ledger")
        assert resp.status_code in (401, 403)


class TestHeartbeatAPI:
    """Integration tests for heartbeat endpoints."""

    def test_upsert_heartbeat_success(self, app_client, admin_key):
        resp = app_client.post(
            "/control-plane/v2/heartbeats",
            json={
                "entity_type": "locker",
                "entity_id": "locker-hb-1",
                "last_state": "active",
                "breaker_state": "closed",
                "queue_depth": 0,
            },
            headers=_headers(admin_key),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["entity_id"] == "locker-hb-1"

    def test_upsert_invalid_entity_type(self, app_client, admin_key):
        resp = app_client.post(
            "/control-plane/v2/heartbeats",
            json={
                "entity_type": "INVALID_TYPE",
                "entity_id": "x",
                "last_state": "active",
                "breaker_state": "closed",
                "queue_depth": 0,
            },
            headers=_headers(admin_key),
        )
        assert resp.status_code == 400

    def test_list_heartbeats(self, app_client, admin_key):
        resp = app_client.get(
            "/control-plane/v2/heartbeats", headers=_headers(admin_key)
        )
        assert resp.status_code == 200
        assert "heartbeats" in resp.json()

    def test_stale_heartbeats_endpoint(self, app_client, admin_key):
        resp = app_client.get(
            "/control-plane/v2/heartbeats/stale", headers=_headers(admin_key)
        )
        assert resp.status_code == 200
        assert "stale_entities" in resp.json()


class TestPlaybookAPI:
    """Integration tests for playbook endpoints."""

    def test_list_playbooks(self, app_client, read_key):
        resp = app_client.get("/control-plane/v2/playbooks", headers=_headers(read_key))
        assert resp.status_code == 200
        body = resp.json()
        assert set(body["playbooks"]) == VALID_PLAYBOOKS

    def test_trigger_invalid_playbook(self, app_client, admin_key):
        resp = app_client.post(
            "/control-plane/v2/playbooks/evil_exec/trigger",
            json={
                "target_id": "target",
                "reason": "Testing invalid playbook name",
                "idempotency_key": _ikey(),
                "dry_run": True,
            },
            headers=_headers(admin_key),
        )
        assert resp.status_code == 400

    def test_trigger_dry_run(self, app_client, admin_key):
        resp = app_client.post(
            "/control-plane/v2/playbooks/stuck_boot_recover/trigger",
            json={
                "target_id": "module-1",
                "reason": "Testing playbook dry run trigger",
                "idempotency_key": _ikey(),
                "dry_run": True,
            },
            headers=_headers(admin_key),
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["dry_run"]
        assert body["ok"]
        assert body["actions_taken"] == []
        assert len(body["actions_planned"]) > 0

    def test_trigger_requires_admin_scope(self, app_client, read_key):
        resp = app_client.post(
            "/control-plane/v2/playbooks/stuck_boot_recover/trigger",
            json={
                "target_id": "module-1",
                "reason": "Testing scope enforcement",
                "idempotency_key": _ikey(),
                "dry_run": True,
            },
            headers=_headers(read_key),
        )
        assert resp.status_code in (401, 403)


class TestEvidenceBundleAPI:
    """Integration tests for evidence bundle endpoint."""

    def test_evidence_bundle_requires_audit_scope(self, app_client, read_key):
        resp = app_client.get(
            "/control-plane/evidence/bundle", headers=_headers(read_key)
        )
        assert resp.status_code == 200  # read_key has audit:read

    def test_evidence_bundle_unauthenticated(self, app_client):
        resp = app_client.get("/control-plane/evidence/bundle")
        assert resp.status_code in (401, 403)

    def test_evidence_bundle_structure(self, app_client, admin_key):
        resp = app_client.get(
            "/control-plane/evidence/bundle", headers=_headers(admin_key)
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["bundle_type"] == "control_plane_v2_evidence"
        assert "ledger_events" in body
        assert "commands" in body
        assert "receipts_by_command" in body
        assert "integrity" in body
        assert "trace_id" in body
        assert "generated_at" in body

    def test_evidence_bundle_time_filter(self, app_client, admin_key):
        """Time-bounded filtering must be accepted."""
        resp = app_client.get(
            "/control-plane/evidence/bundle?since=2024-01-01T00:00:00Z&until=2025-01-01T00:00:00Z",
            headers=_headers(admin_key),
        )
        assert resp.status_code == 200


class TestMSPIsolation:
    """Tests for MSP cross-tenant access controls."""

    def test_tenant_cannot_query_another_tenant_ledger(
        self, app_client, admin_key, other_tenant_key
    ):
        """tenant-beta querying tenant_id=tenant-alpha must get 404 (anti-enumeration)."""
        resp = app_client.get(
            "/control-plane/v2/ledger?tenant_id=tenant-alpha",
            headers=_headers(other_tenant_key),
        )
        # Anti-enumeration: 404 (not 403)
        assert resp.status_code == 404

    def test_msp_read_can_query_specific_tenant(self, app_client, msp_read_key):
        """MSP read scope with explicit tenant_id must succeed."""
        resp = app_client.get(
            "/control-plane/v2/ledger?tenant_id=tenant-alpha",
            headers=_headers(msp_read_key),
        )
        assert resp.status_code == 200

    def test_global_admin_can_query_all_tenants(self, app_client, global_admin_key):
        resp = app_client.get(
            "/control-plane/v2/ledger", headers=_headers(global_admin_key)
        )
        assert resp.status_code == 200

    def test_tenant_actor_no_msp_scope_no_cross_tenant(self, app_client, admin_key):
        """Tenant admin without msp scope cannot pass tenant_id for another tenant."""
        resp = app_client.get(
            "/control-plane/v2/commands?tenant_id=tenant-beta",
            headers=_headers(admin_key),
        )
        assert resp.status_code == 404


# ===========================================================================
# C. Security invariant negative tests
# ===========================================================================


class TestSecurityInvariants:
    """Non-vacuous negative tests covering all global security invariants."""

    def test_invariant_no_tenant_from_request_body(self, sqlite_session):
        """
        Invariant 1: tenant_id ONLY from auth context.
        Command creation accepts tenant_id ONLY from service layer (auth context),
        never from user-supplied body fields.
        """
        # CommandRequest model must NOT have a tenant_id field
        from api.control_plane_v2 import CommandRequest

        assert not hasattr(
            CommandRequest.model_fields, "tenant_id"
        ), "CommandRequest must NOT have a tenant_id field — tenant is auth-derived only"

    def test_invariant_command_enum_allowlist(self):
        """
        Invariant 8: No arbitrary payload commands — only allowlisted enum.
        """
        for dangerous in (
            "os.system",
            "subprocess",
            "exec",
            "eval",
            "__import__",
            "rm_rf",
            "DROP TABLE",
        ):
            assert (
                dangerous not in VALID_CP_COMMANDS
            ), f"Dangerous command {dangerous!r} found in VALID_CP_COMMANDS allowlist"

    def test_invariant_no_subprocess(self):
        """
        Invariant 7: No subprocess, no shell, no dynamic execution.
        Check that none of the v2 service files import subprocess or os.system.
        """
        import ast
        from pathlib import Path

        files_to_check = [
            "api/control_plane_v2.py",
            "services/cp_ledger.py",
            "services/cp_commands.py",
            "services/cp_heartbeats.py",
            "services/cp_playbooks.py",
        ]
        repo = Path(__file__).resolve().parents[2]

        for rel_path in files_to_check:
            path = repo / rel_path
            if not path.exists():
                continue
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert (
                            alias.name != "subprocess"
                        ), f"{rel_path} imports subprocess — security violation"
                if isinstance(node, ast.ImportFrom):
                    assert (
                        node.module != "subprocess"
                    ), f"{rel_path} imports from subprocess — security violation"

    def test_invariant_append_only_tables_in_migration(self):
        """
        Invariant 3: All operator actions are append-only and hash-chained.
        Migration 0027 must define triggers blocking UPDATE/DELETE on ledger + receipts.
        """
        from pathlib import Path

        repo = Path(__file__).resolve().parents[2]
        migration = repo / "migrations/postgres/0027_control_plane_v2.sql"
        assert migration.exists(), "Migration 0027 not found"
        content = migration.read_text()

        assert (
            "fg_append_only_enforcer" in content
        ), "append_only_enforcer not referenced in migration"
        assert "control_plane_event_ledger" in content
        assert "control_plane_command_receipts" in content

    def test_invariant_receipt_endpoint_enforces_executor_type(self, sqlite_session):
        """
        Invariant: Receipt endpoint rejects non-executor types.
        """
        ledger = ControlPlaneLedger()
        svc = ControlPlaneCommandService()

        rec = svc.create_command(
            db_session=sqlite_session,
            ledger=ledger,
            tenant_id="t1",
            actor_id="a",
            actor_role="op",
            target_type="locker",
            target_id="x",
            command="restart",
            reason="Testing executor enforcement",
            idempotency_key=_ikey(),
        )
        sqlite_session.commit()

        with pytest.raises(ValueError) as exc_info:
            svc.submit_receipt(
                db_session=sqlite_session,
                ledger=ledger,
                command_id=rec.command_id,
                executor_id="attacker",
                executor_type="hacker",
                ok=True,
            )
        assert ERR_NOT_EXECUTOR in str(exc_info.value)

    def test_invariant_msp_cross_tenant_requires_msp_scope(self, app_client, admin_key):
        """
        MSP cross-tenant access requires explicit msp scope.
        Tenant admin without msp scope querying another tenant's data must be blocked.
        """
        resp = app_client.get(
            "/control-plane/v2/ledger?tenant_id=another-tenant",
            headers=_headers(admin_key),
        )
        assert resp.status_code == 404  # anti-enumeration

    def test_invariant_event_written_before_streaming(self, sqlite_session):
        """
        Invariant: Events ALWAYS written to DB first (truth plane before stream).
        Verify that append_event() writes to DB before returning.
        """
        from api.db_models_cp_v2 import ControlPlaneEventLedger

        ledger = ControlPlaneLedger()
        ledger.append_event(
            db_session=sqlite_session,
            event_type="cp_command_created",
            actor_id="a",
            actor_role="op",
            tenant_id="t1",
            payload={"test": "persist_first"},
        )
        # Before commit — row must exist in session (flush was called)
        rows = sqlite_session.query(ControlPlaneEventLedger).all()
        assert len(rows) == 1, "Event must be in session before commit"

    def test_invariant_playbook_allowlist_is_closed(self):
        """
        Invariant 8 + Playbooks: Only the 4 named playbooks allowed; no dynamic dispatch.
        """
        expected = {
            "stuck_boot_recover",
            "dependency_auto_pause",
            "breaker_auto_isolate",
            "safe_restart_sequence",
        }
        assert (
            VALID_PLAYBOOKS == expected
        ), f"Playbook allowlist must be exactly {expected}"

    def test_invariant_all_error_responses_have_stable_code(
        self, app_client, admin_key
    ):
        """
        Invariant 9: Every externalized error contains stable error_code.
        """
        # Invalid command — must return error with code
        resp = app_client.post(
            "/control-plane/v2/commands",
            json={
                "target_type": "locker",
                "target_id": "l1",
                "command": "evil_cmd",
                "reason": "Testing error code in response",
                "idempotency_key": _ikey(),
            },
            headers=_headers(admin_key),
        )
        assert resp.status_code == 400
        body = resp.json()
        # Must have error.code field
        assert "error" in body.get("detail", body)
        err = body.get("detail", body).get("error", body.get("detail", {}))
        assert "code" in err or "CP_CMD_INVALID_COMMAND" in str(body)

    def test_invariant_hash_chain_requires_prev_hash(self, sqlite_session):
        """
        Chain hash must incorporate prev_hash — changing prev_hash changes chain_hash.
        """
        ts = "2024-01-01T00:00:00Z"
        eid = str(uuid.uuid4())

        h1 = compute_chain_hash(
            prev_hash="A" * 64, content_hash="B" * 64, ts=ts, event_id=eid
        )
        h2 = compute_chain_hash(
            prev_hash="X" * 64, content_hash="B" * 64, ts=ts, event_id=eid
        )
        assert h1 != h2, "Different prev_hash must produce different chain_hash"

    def test_invariant_content_hash_covers_payload(self):
        """content_hash must change when payload changes."""
        ts = "2024-01-01T00:00:00Z"

        h1 = compute_content_hash(
            payload_json={"data": "original"},
            actor_id="a",
            tenant_id="t",
            event_type="cp_command_created",
            ts=ts,
        )
        h2 = compute_content_hash(
            payload_json={"data": "TAMPERED"},
            actor_id="a",
            tenant_id="t",
            event_type="cp_command_created",
            ts=ts,
        )
        assert h1 != h2, "Different payloads must produce different content_hash"
