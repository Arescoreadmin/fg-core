# tests/test_r4_credential_events.py
"""
R4.5 — Credential audit event tests.

Verifies that every credential lifecycle operation emits the correct event to
tenant_credential_events, and that validation telemetry is emitted best-effort.

Schema: full union of tenants + credential_slots + tenant_credentials +
tenant_credential_events.  Argon2id parameters are minimum-cost via monkeypatch.
"""

from __future__ import annotations

from typing import cast


import pytest
from argon2 import PasswordHasher
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

import api.credential_authority as ca
from api.credential_authority import (
    CredentialEventRecord,
    CredentialNotFoundError,
    TenantLifecycleError,
    expire_credentials,
    issue_credential,
    list_credential_events,
    revoke_credential,
    rotate_credential,
    validate_credential,
)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id          VARCHAR(128) PRIMARY KEY,
    display_name       VARCHAR(256) NOT NULL DEFAULT '',
    lifecycle_state    VARCHAR(32)  NOT NULL DEFAULT 'active',
    created_at         TEXT,
    updated_at         TEXT,
    created_by         TEXT,
    metadata           TEXT         NOT NULL DEFAULT '{}',
    canonical_version  INTEGER      NOT NULL DEFAULT 1,
    last_reconciled_at TEXT,
    archived_at        TEXT,
    migration_source   TEXT,
    migration_version  TEXT
);

CREATE TABLE IF NOT EXISTS credential_slots (
    tenant_id           VARCHAR(128) NOT NULL,
    credential_type     VARCHAR(64)  NOT NULL,
    credential_slot     VARCHAR(128) NOT NULL,
    current_generation  INTEGER      NOT NULL DEFAULT 0,
    rotation_policy     VARCHAR(32)  NOT NULL DEFAULT 'immediate',
    max_overlap_count   INTEGER      NOT NULL DEFAULT 1,
    created_at          TEXT,
    updated_at          TEXT,
    PRIMARY KEY (tenant_id, credential_type, credential_slot)
);

CREATE TABLE IF NOT EXISTS tenant_credential_events (
    event_id          VARCHAR(64)  NOT NULL PRIMARY KEY,
    tenant_id         VARCHAR(128) NOT NULL,
    credential_id     VARCHAR(64),
    credential_type   VARCHAR(64),
    credential_slot   VARCHAR(128),
    generation        INTEGER,
    event_type        VARCHAR(64)  NOT NULL,
    actor_id          VARCHAR(256),
    request_id        VARCHAR(128),
    occurred_at       TEXT         NOT NULL,
    outcome           VARCHAR(16)  NOT NULL DEFAULT 'success',
    failure_reason    TEXT,
    metadata          TEXT,
    schema_version    INTEGER      NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS tenant_credentials (
    credential_id               VARCHAR(64)  NOT NULL PRIMARY KEY,
    tenant_id                   VARCHAR(128) NOT NULL,
    credential_type             VARCHAR(64)  NOT NULL,
    credential_slot             VARCHAR(128) NOT NULL,
    generation                  INTEGER      NOT NULL DEFAULT 1,
    lookup_fingerprint          VARCHAR(64)  NOT NULL,
    lookup_key_version          INTEGER      NOT NULL DEFAULT 1,
    secret_prefix               VARCHAR(16)  NOT NULL,
    secret_hash                 TEXT         NOT NULL,
    hash_algorithm              VARCHAR(32)  NOT NULL DEFAULT 'argon2id',
    hash_params                 TEXT         NOT NULL,
    status                      VARCHAR(16)  NOT NULL DEFAULT 'active',
    expires_at                  TEXT,
    issued_at                   TEXT         NOT NULL,
    activated_at                TEXT,
    rotated_at                  TEXT,
    revoked_at                  TEXT,
    replaced_by_credential_id   VARCHAR(64),
    created_by_actor_id         VARCHAR(256),
    request_id                  VARCHAR(128),
    idempotency_key             VARCHAR(256),
    last_used_at                TEXT,
    approximate_use_count       INTEGER      NOT NULL DEFAULT 0,
    scopes_csv                  TEXT,
    metadata                    TEXT,
    schema_version              INTEGER      NOT NULL DEFAULT 1,
    record_hash                 VARCHAR(64),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_tc_slot_generation
    ON tenant_credentials (tenant_id, credential_type, credential_slot, generation);
CREATE INDEX IF NOT EXISTS ix_tc_lookup_fingerprint
    ON tenant_credentials (lookup_fingerprint);
"""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def fast_hasher(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ca, "_HASHER", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    )


@pytest.fixture(autouse=True)
def pepper_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_KEY_PEPPER", "r4.5-test-pepper")


@pytest.fixture()
def engine() -> Engine:
    e = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    with e.begin() as conn:
        for stmt in _SCHEMA.split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(text(stmt))
        conn.execute(
            text("INSERT INTO tenants (tenant_id, display_name) VALUES (:tid, :name)"),
            {"tid": "tenant-alpha", "name": "Alpha"},
        )
        conn.execute(
            text("INSERT INTO tenants (tenant_id, display_name) VALUES (:tid, :name)"),
            {"tid": "tenant-beta", "name": "Beta"},
        )
    return e


def _events(
    engine: Engine, tenant_id: str = "tenant-alpha"
) -> list[CredentialEventRecord]:
    return list_credential_events(engine, tenant_id)


# ---------------------------------------------------------------------------
# A — issued event
# ---------------------------------------------------------------------------


class TestA_IssuedEvent:
    def test_issue_emits_issued_event(self, engine: Engine) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
            actor_id="op-create",
            request_id="req-001",
        )
        evts = _events(engine)
        assert len(evts) == 1
        e = evts[0]
        assert e.event_type == "issued"
        assert e.outcome == "success"
        assert e.tenant_id == "tenant-alpha"
        assert e.credential_id == result.record.credential_id
        assert e.credential_type == "tenant_api_key"
        assert e.credential_slot == "prod"
        assert e.generation == 1
        assert e.actor_id == "op-create"
        assert e.request_id == "req-001"

    def test_issue_event_is_within_transaction(self, engine: Engine) -> None:
        """If the issue fails after event insertion the event is also rolled back."""
        # Force a failure by issuing on the same slot twice (occupied-slot guard).
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        from api.credential_authority import CredentialStateError

        with pytest.raises(CredentialStateError):
            issue_credential(
                engine,
                tenant_id="tenant-alpha",
                credential_type="tenant_api_key",
                credential_slot="prod",
            )
        # Only one event — the failed second issue was rolled back.
        evts = _events(engine)
        assert len(evts) == 1
        assert evts[0].event_type == "issued"

    def test_idempotent_replay_emits_no_new_event(self, engine: Engine) -> None:
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
            idempotency_key="idem-key-1",
        )
        # Replay — idempotency short-circuits before event emission.
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
            idempotency_key="idem-key-1",
        )
        evts = _events(engine)
        assert len(evts) == 1


# ---------------------------------------------------------------------------
# B — rotated event
# ---------------------------------------------------------------------------


class TestB_RotatedEvent:
    def test_rotate_emits_rotated_event(self, engine: Engine) -> None:
        r1 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        r2 = rotate_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
            actor_id="op-rotate",
        )
        evts = list_credential_events(engine, "tenant-alpha", event_type="rotated")
        assert len(evts) == 1
        e = evts[0]
        assert e.event_type == "rotated"
        assert e.credential_id == r2.record.credential_id
        assert e.generation == 2
        assert e.actor_id == "op-rotate"
        assert e.metadata is not None
        assert e.metadata["replaced_credential_id"] == r1.record.credential_id

    def test_rotate_emits_one_rotated_event_per_rotation(self, engine: Engine) -> None:
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        for _ in range(3):
            rotate_credential(
                engine,
                tenant_id="tenant-alpha",
                credential_type="tenant_api_key",
                credential_slot="prod",
            )
        rotated_evts = list_credential_events(
            engine, "tenant-alpha", event_type="rotated"
        )
        assert len(rotated_evts) == 3


# ---------------------------------------------------------------------------
# C — revoked event
# ---------------------------------------------------------------------------


class TestC_RevokedEvent:
    def test_revoke_emits_revoked_event(self, engine: Engine) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        revoke_credential(
            engine,
            credential_id=result.record.credential_id,
            tenant_id="tenant-alpha",
            actor_id="op-revoke",
            reason="security incident",
            request_id="req-rev-1",
        )
        evts = list_credential_events(engine, "tenant-alpha", event_type="revoked")
        assert len(evts) == 1
        e = evts[0]
        assert e.event_type == "revoked"
        assert e.credential_id == result.record.credential_id
        assert e.actor_id == "op-revoke"
        assert e.request_id == "req-rev-1"
        assert e.metadata is not None
        assert e.metadata["reason"] == "security incident"

    def test_idempotent_revoke_emits_no_second_event(self, engine: Engine) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        cid = result.record.credential_id
        revoke_credential(
            engine,
            credential_id=cid,
            tenant_id="tenant-alpha",
            actor_id="op",
            reason="r",
        )
        # Second revoke is idempotent — returns early before event insertion.
        revoke_credential(
            engine,
            credential_id=cid,
            tenant_id="tenant-alpha",
            actor_id="op",
            reason="r",
        )
        evts = list_credential_events(engine, "tenant-alpha", event_type="revoked")
        assert len(evts) == 1


# ---------------------------------------------------------------------------
# D — expired event
# ---------------------------------------------------------------------------


class TestD_ExpiredEvent:
    def test_expire_credentials_emits_expired_events(self, engine: Engine) -> None:
        r1 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="slot-a",
            expires_in_seconds=-1,
        )
        r2 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="slot-b",
            expires_in_seconds=-1,
        )
        count = expire_credentials(engine, tenant_id="tenant-alpha")
        assert count == 2

        evts = list_credential_events(engine, "tenant-alpha", event_type="expired")
        assert len(evts) == 2
        cids = {e.credential_id for e in evts}
        assert r1.record.credential_id in cids
        assert r2.record.credential_id in cids
        for e in evts:
            assert e.outcome == "success"

    def test_expire_already_expired_emits_no_duplicate(self, engine: Engine) -> None:
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="slot-a",
            expires_in_seconds=-1,
        )
        expire_credentials(engine, tenant_id="tenant-alpha")
        expire_credentials(
            engine, tenant_id="tenant-alpha"
        )  # second sweep — no new rows
        evts = list_credential_events(engine, "tenant-alpha", event_type="expired")
        assert len(evts) == 1


# ---------------------------------------------------------------------------
# E — validated event (best-effort)
# ---------------------------------------------------------------------------


class TestE_ValidatedEvent:
    def test_successful_validation_emits_validated(self, engine: Engine) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        validate_credential(engine, cast(str, result.plaintext_secret))

        evts = list_credential_events(engine, "tenant-alpha", event_type="validated")
        assert len(evts) == 1
        e = evts[0]
        assert e.outcome == "success"
        assert e.credential_id == result.record.credential_id
        assert e.failure_reason is None

    def test_event_emission_failure_does_not_block_validation(
        self, engine: Engine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_emit_event_best_effort swallows exceptions — validation still returns."""
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )

        def boom(*a, **kw):
            raise RuntimeError("simulated event store failure")

        # Patch the inner insert helper so _emit_event_best_effort's own
        # exception swallowing is what keeps validation from being blocked.
        monkeypatch.setattr(ca, "_insert_event", boom)
        # Must not raise despite emit failure.
        principal = validate_credential(engine, cast(str, result.plaintext_secret))
        assert principal.tenant_id == "tenant-alpha"


# ---------------------------------------------------------------------------
# F — validation_failed event
# ---------------------------------------------------------------------------


class TestF_ValidationFailedEvent:
    def test_wrong_secret_emits_validation_failed(self, engine: Engine) -> None:
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        with pytest.raises(CredentialNotFoundError):
            validate_credential(engine, "fgk.eyJ0IjoidGVuYW50LWFscGhhIn0.wrongsecret00")

        evts = list_credential_events(
            engine, "tenant-alpha", event_type="validation_failed"
        )
        assert len(evts) == 1
        assert evts[0].outcome == "failure"

    def test_revoked_credential_emits_validation_failed(self, engine: Engine) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        revoke_credential(
            engine,
            credential_id=result.record.credential_id,
            tenant_id="tenant-alpha",
            actor_id="op",
            reason="test",
        )
        with pytest.raises(CredentialNotFoundError):
            validate_credential(engine, cast(str, result.plaintext_secret))

        evts = list_credential_events(
            engine, "tenant-alpha", event_type="validation_failed"
        )
        assert len(evts) == 1
        e = evts[0]
        assert e.failure_reason == "status_revoked"

    def test_expired_credential_emits_validation_failed_expired(
        self, engine: Engine
    ) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
            expires_in_seconds=-1,
        )
        with pytest.raises(CredentialNotFoundError):
            validate_credential(engine, cast(str, result.plaintext_secret))

        evts = list_credential_events(
            engine, "tenant-alpha", event_type="validation_failed"
        )
        assert len(evts) == 1
        assert evts[0].failure_reason == "expired"


# ---------------------------------------------------------------------------
# G — denied_tenant_state event
# ---------------------------------------------------------------------------


class TestG_DeniedTenantStateEvent:
    def test_suspended_tenant_emits_denied_event(self, engine: Engine) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        # Suspend tenant directly.
        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE tenants SET lifecycle_state = 'suspended' "
                    "WHERE tenant_id = 'tenant-alpha'"
                )
            )

        with pytest.raises(TenantLifecycleError):
            validate_credential(engine, cast(str, result.plaintext_secret))

        evts = list_credential_events(
            engine, "tenant-alpha", event_type="denied_tenant_state"
        )
        assert len(evts) == 1
        e = evts[0]
        assert e.outcome == "denied"
        assert e.credential_id == result.record.credential_id


# ---------------------------------------------------------------------------
# H — list_credential_events
# ---------------------------------------------------------------------------


class TestH_ListCredentialEvents:
    def test_returns_newest_first(self, engine: Engine) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        validate_credential(engine, cast(str, result.plaintext_secret))
        validate_credential(engine, cast(str, result.plaintext_secret))

        evts = _events(engine)
        # 1 issued + 2 validated
        assert len(evts) == 3
        assert evts[0].occurred_at >= evts[1].occurred_at

    def test_filter_by_credential_id(self, engine: Engine) -> None:
        r1 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="slot-a",
        )
        r2 = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="slot-b",
        )
        evts = list_credential_events(
            engine, "tenant-alpha", credential_id=r1.record.credential_id
        )
        assert len(evts) == 1
        assert evts[0].credential_id == r1.record.credential_id

        evts2 = list_credential_events(
            engine, "tenant-alpha", credential_id=r2.record.credential_id
        )
        assert len(evts2) == 1
        assert evts2[0].credential_id == r2.record.credential_id

    def test_filter_by_event_type(self, engine: Engine) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        validate_credential(engine, cast(str, result.plaintext_secret))

        issued_evts = list_credential_events(
            engine, "tenant-alpha", event_type="issued"
        )
        assert len(issued_evts) == 1
        validated_evts = list_credential_events(
            engine, "tenant-alpha", event_type="validated"
        )
        assert len(validated_evts) == 1

    def test_limit_respected(self, engine: Engine) -> None:
        result = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        for _ in range(5):
            validate_credential(engine, cast(str, result.plaintext_secret))

        evts = list_credential_events(engine, "tenant-alpha", limit=3)
        assert len(evts) == 3

    def test_event_record_fields_populated(self, engine: Engine) -> None:
        # Slot "prod" — issue then rotate (original becomes rotated, cannot be revoked)
        issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
            actor_id="actor-1",
            request_id="req-1",
        )
        rotate_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
            actor_id="actor-2",
        )
        # Slot "backup" — issue then revoke independently
        backup = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="backup",
            actor_id="actor-1",
        )
        revoke_credential(
            engine,
            credential_id=backup.record.credential_id,
            tenant_id="tenant-alpha",
            actor_id="actor-3",
            reason="cleanup",
        )
        all_evts = _events(engine)
        types = [e.event_type for e in all_evts]
        assert "issued" in types
        assert "rotated" in types
        assert "revoked" in types
        for e in all_evts:
            assert e.event_id
            assert e.tenant_id == "tenant-alpha"
            assert e.occurred_at is not None
            assert e.schema_version == 1


# ---------------------------------------------------------------------------
# I — tenant isolation
# ---------------------------------------------------------------------------


class TestI_TenantIsolation:
    def test_events_isolated_by_tenant(self, engine: Engine) -> None:
        r_a = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        r_b = issue_credential(
            engine,
            tenant_id="tenant-beta",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        validate_credential(engine, cast(str, r_a.plaintext_secret))
        validate_credential(engine, cast(str, r_b.plaintext_secret))

        alpha_evts = list_credential_events(engine, "tenant-alpha")
        beta_evts = list_credential_events(engine, "tenant-beta")

        assert all(e.tenant_id == "tenant-alpha" for e in alpha_evts)
        assert all(e.tenant_id == "tenant-beta" for e in beta_evts)
        assert len(alpha_evts) == 2  # issued + validated
        assert len(beta_evts) == 2

    def test_cross_tenant_credential_id_filter_returns_empty(
        self, engine: Engine
    ) -> None:
        r_a = issue_credential(
            engine,
            tenant_id="tenant-alpha",
            credential_type="tenant_api_key",
            credential_slot="prod",
        )
        # Querying beta with alpha's credential_id returns nothing.
        evts = list_credential_events(
            engine, "tenant-beta", credential_id=r_a.record.credential_id
        )
        assert evts == []
