"""
R3 Tenant Lifecycle Authority tests.

Covers:
A) State machine validation — ALLOWED_TRANSITIONS is correct and complete
B) execute_transition happy paths (active→suspended, suspended→active, archived→deleted, etc.)
C) execute_transition error paths (invalid transition, tenant not found)
D) Idempotency — same idempotency_key returns existing record without double-write
E) get_transition_history returns records in reverse chronological order
F) Audit record fields are persisted faithfully
"""

from __future__ import annotations

import uuid
from datetime import datetime

import pytest
from sqlalchemy import create_engine, text

from api.tenant_lifecycle import (
    ALLOWED_TRANSITIONS,
    VALID_STATES,
    InvalidTransitionError,
    TenantNotFoundError,
    execute_transition,
    get_transition_history,
)

# ---------------------------------------------------------------------------
# SQLite schema (adapted from migrations 0156 + 0157)
# ---------------------------------------------------------------------------

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id           VARCHAR(128)    PRIMARY KEY,
    display_name        TEXT            NOT NULL,
    lifecycle_state     VARCHAR(32)     NOT NULL DEFAULT 'active',
    created_at          TEXT            NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT            NOT NULL DEFAULT (datetime('now')),
    created_by          TEXT,
    metadata            TEXT            NOT NULL DEFAULT '{}',
    canonical_version   INTEGER         NOT NULL DEFAULT 1,
    last_reconciled_at  TEXT,
    archived_at         TEXT,
    migration_source    VARCHAR(32),
    migration_version   VARCHAR(32)
);

CREATE TABLE IF NOT EXISTS tenant_lifecycle_transitions (
    transition_id       VARCHAR(64)     PRIMARY KEY,
    tenant_id           VARCHAR(128)    NOT NULL,
    from_state          VARCHAR(32)     NOT NULL,
    to_state            VARCHAR(32)     NOT NULL,
    reason              TEXT,
    actor_id            TEXT,
    request_id          TEXT,
    idempotency_key     TEXT            UNIQUE,
    occurred_at         TEXT            NOT NULL DEFAULT (datetime('now'))
);
"""


@pytest.fixture
def engine():
    eng = create_engine("sqlite+pysqlite:///:memory:", future=True)
    with eng.begin() as conn:
        for stmt in _CREATE_SQL.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(text(stmt))
    yield eng
    eng.dispose()


def _insert_tenant(engine, tenant_id: str, state: str = "active") -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, display_name, lifecycle_state) "
                "VALUES (:tid, :name, :state)"
            ),
            {"tid": tenant_id, "name": f"Tenant {tenant_id}", "state": state},
        )


# ---------------------------------------------------------------------------
# A) State machine
# ---------------------------------------------------------------------------


class TestStateMachine:
    def test_valid_states_set(self):
        assert VALID_STATES == frozenset({"active", "suspended", "archived", "deleted"})

    def test_active_can_suspend_or_archive(self):
        assert ALLOWED_TRANSITIONS["active"] == frozenset({"suspended", "archived"})

    def test_suspended_can_activate_or_archive(self):
        assert ALLOWED_TRANSITIONS["suspended"] == frozenset({"active", "archived"})

    def test_archived_can_only_delete(self):
        assert ALLOWED_TRANSITIONS["archived"] == frozenset({"deleted"})

    def test_deleted_is_terminal(self):
        assert ALLOWED_TRANSITIONS["deleted"] == frozenset()

    def test_all_valid_states_have_transition_entries(self):
        for state in VALID_STATES:
            assert state in ALLOWED_TRANSITIONS, (
                f"{state} missing from ALLOWED_TRANSITIONS"
            )


# ---------------------------------------------------------------------------
# B) Happy paths
# ---------------------------------------------------------------------------


class TestExecuteTransitionHappyPaths:
    def test_active_to_suspended(self, engine):
        _insert_tenant(engine, "t1")
        rec = execute_transition(engine, tenant_id="t1", to_state="suspended")
        assert rec.from_state == "active"
        assert rec.to_state == "suspended"
        assert rec.tenant_id == "t1"
        assert isinstance(rec.occurred_at, datetime)

        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT lifecycle_state FROM tenants WHERE tenant_id = 't1'")
            ).fetchone()
        assert row[0] == "suspended"

    def test_suspended_to_active(self, engine):
        _insert_tenant(engine, "t2", state="suspended")
        rec = execute_transition(engine, tenant_id="t2", to_state="active")
        assert rec.from_state == "suspended"
        assert rec.to_state == "active"

    def test_active_to_archived(self, engine):
        _insert_tenant(engine, "t3")
        rec = execute_transition(engine, tenant_id="t3", to_state="archived")
        assert rec.to_state == "archived"

        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT lifecycle_state, archived_at FROM tenants WHERE tenant_id = 't3'"
                )
            ).fetchone()
        assert row[0] == "archived"
        assert row[1] is not None, "archived_at must be set when archiving"

    def test_suspended_to_archived(self, engine):
        _insert_tenant(engine, "t4", state="suspended")
        rec = execute_transition(engine, tenant_id="t4", to_state="archived")
        assert rec.from_state == "suspended"
        assert rec.to_state == "archived"

    def test_archived_to_deleted(self, engine):
        _insert_tenant(engine, "t5", state="archived")
        rec = execute_transition(engine, tenant_id="t5", to_state="deleted")
        assert rec.from_state == "archived"
        assert rec.to_state == "deleted"

    def test_audit_record_written(self, engine):
        _insert_tenant(engine, "t6")
        rec = execute_transition(
            engine,
            tenant_id="t6",
            to_state="suspended",
            reason="billing overdue",
            actor_id="admin-123",
            request_id="req-abc",
        )

        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT from_state, to_state, reason, actor_id, request_id "
                    "FROM tenant_lifecycle_transitions WHERE transition_id = :tid"
                ),
                {"tid": rec.transition_id},
            ).fetchone()

        assert row[0] == "active"
        assert row[1] == "suspended"
        assert row[2] == "billing overdue"
        assert row[3] == "admin-123"
        assert row[4] == "req-abc"

    def test_caller_supplied_transition_id(self, engine):
        _insert_tenant(engine, "t7")
        my_id = str(uuid.uuid4())
        rec = execute_transition(
            engine, tenant_id="t7", to_state="suspended", transition_id=my_id
        )
        assert rec.transition_id == my_id


# ---------------------------------------------------------------------------
# C) Error paths
# ---------------------------------------------------------------------------


class TestExecuteTransitionErrors:
    def test_tenant_not_found(self, engine):
        with pytest.raises(TenantNotFoundError):
            execute_transition(engine, tenant_id="nonexistent", to_state="suspended")

    def test_invalid_state_value(self, engine):
        _insert_tenant(engine, "te1")
        with pytest.raises(ValueError, match="Unknown lifecycle state"):
            execute_transition(engine, tenant_id="te1", to_state="limbo")

    def test_transition_not_allowed_active_to_deleted(self, engine):
        _insert_tenant(engine, "te2")
        with pytest.raises(InvalidTransitionError):
            execute_transition(engine, tenant_id="te2", to_state="deleted")

    def test_transition_not_allowed_archived_to_active(self, engine):
        _insert_tenant(engine, "te3", state="archived")
        with pytest.raises(InvalidTransitionError):
            execute_transition(engine, tenant_id="te3", to_state="active")

    def test_transition_not_allowed_deleted_to_anything(self, engine):
        _insert_tenant(engine, "te4", state="deleted")
        with pytest.raises(InvalidTransitionError):
            execute_transition(engine, tenant_id="te4", to_state="active")

    def test_suspended_to_deleted_not_allowed(self, engine):
        """Must archive before deleting."""
        _insert_tenant(engine, "te5", state="suspended")
        with pytest.raises(InvalidTransitionError):
            execute_transition(engine, tenant_id="te5", to_state="deleted")


# ---------------------------------------------------------------------------
# D) Idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_same_key_returns_existing_record(self, engine):
        _insert_tenant(engine, "ti1")
        key = "idem-key-001"
        rec1 = execute_transition(
            engine, tenant_id="ti1", to_state="suspended", idempotency_key=key
        )
        rec2 = execute_transition(
            engine, tenant_id="ti1", to_state="suspended", idempotency_key=key
        )
        assert rec1.transition_id == rec2.transition_id

    def test_idempotent_call_does_not_double_write(self, engine):
        _insert_tenant(engine, "ti2")
        key = "idem-key-002"
        execute_transition(
            engine, tenant_id="ti2", to_state="suspended", idempotency_key=key
        )
        execute_transition(
            engine, tenant_id="ti2", to_state="suspended", idempotency_key=key
        )

        with engine.connect() as conn:
            count = conn.execute(
                text(
                    "SELECT COUNT(*) FROM tenant_lifecycle_transitions "
                    "WHERE idempotency_key = :key"
                ),
                {"key": key},
            ).fetchone()[0]
        assert count == 1

    def test_different_keys_produce_separate_records(self, engine):
        _insert_tenant(engine, "ti3")
        rec1 = execute_transition(
            engine, tenant_id="ti3", to_state="suspended", idempotency_key="k1"
        )
        # reactivate so second transition is valid
        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE tenants SET lifecycle_state = 'active' WHERE tenant_id = 'ti3'"
                )
            )
        rec2 = execute_transition(
            engine, tenant_id="ti3", to_state="suspended", idempotency_key="k2"
        )
        assert rec1.transition_id != rec2.transition_id


# ---------------------------------------------------------------------------
# E) History
# ---------------------------------------------------------------------------


class TestGetTransitionHistory:
    def test_history_returned_newest_first(self, engine):
        _insert_tenant(engine, "th1")
        execute_transition(engine, tenant_id="th1", to_state="suspended")
        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE tenants SET lifecycle_state = 'active' WHERE tenant_id = 'th1'"
                )
            )
        execute_transition(engine, tenant_id="th1", to_state="suspended")

        history = get_transition_history(engine, "th1")
        assert len(history) == 2
        assert history[0].occurred_at >= history[1].occurred_at

    def test_history_empty_for_unknown_tenant(self, engine):
        history = get_transition_history(engine, "nobody")
        assert history == []

    def test_history_limit_respected(self, engine):
        _insert_tenant(engine, "th2")
        for _ in range(3):
            execute_transition(engine, tenant_id="th2", to_state="suspended")
            # reset directly so the next transition is valid
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE tenants SET lifecycle_state = 'active' WHERE tenant_id = 'th2'"
                    )
                )

        history = get_transition_history(engine, "th2", limit=2)
        assert len(history) == 2
