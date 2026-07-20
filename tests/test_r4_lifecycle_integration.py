# tests/test_r4_lifecycle_integration.py
"""
R4.4 — Cross-authority integration tests.

Proves that the R3 Tenant Lifecycle Authority and the R4 Credential Authority
compose correctly against the same database.  The acceptance criterion:

    execute_transition(tenant_id, "suspended")
    → next validate_credential(...)
    → TenantLifecycleError

and:

    execute_transition(tenant_id, "active")
    → next validate_credential(...)
    → success

with no credential mutation between those calls.

Uses SQLite in-memory with the union schema of both authorities.
Argon2id parameters are set to minimum values via monkeypatch for speed.
"""

from __future__ import annotations

import pytest
from argon2 import PasswordHasher
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

import api.credential_authority as ca
from api.credential_authority import (
    CredentialNotFoundError,
    CredentialPrincipal,
    TenantLifecycleError,
    TenantNotFoundError,
    issue_credential,
    validate_credential,
)
from api.tenant_lifecycle import execute_transition

# ---------------------------------------------------------------------------
# Schema — union of R3 (tenants + transitions) and R4.2 (credentials)
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

CREATE TABLE IF NOT EXISTS tenant_lifecycle_transitions (
    transition_id    VARCHAR(64)  NOT NULL PRIMARY KEY,
    tenant_id        VARCHAR(128) NOT NULL,
    from_state       VARCHAR(32)  NOT NULL,
    to_state         VARCHAR(32)  NOT NULL,
    reason           TEXT,
    actor_id         TEXT,
    request_id       TEXT,
    idempotency_key  TEXT,
    occurred_at      TEXT         NOT NULL,
    transition_hash  VARCHAR(64),
    schema_version   INTEGER      NOT NULL DEFAULT 0
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
    record_hash                 VARCHAR(64)
);
"""

_TENANTS = [
    ("tenant-alpha", "Tenant Alpha"),
    ("tenant-beta", "Tenant Beta"),
]


@pytest.fixture()
def engine() -> Engine:
    e = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    with e.begin() as conn:
        for stmt in _SCHEMA.split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(text(stmt))
        for tid, name in _TENANTS:
            conn.execute(
                text(
                    "INSERT INTO tenants (tenant_id, display_name) VALUES (:tid, :name)"
                ),
                {"tid": tid, "name": name},
            )
    return e


@pytest.fixture(autouse=True)
def fast_hasher(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ca, "_HASHER", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    )


@pytest.fixture(autouse=True)
def pepper_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_KEY_PEPPER", "integration-test-pepper-r4.4")


def _transition(engine: Engine, tenant_id: str, to_state: str) -> None:
    execute_transition(engine, tenant_id=tenant_id, to_state=to_state, actor_id="test")


def _issue(engine: Engine, tenant_id: str = "tenant-alpha", slot: str = "prod"):
    return issue_credential(
        engine,
        tenant_id=tenant_id,
        credential_type="tenant_api_key",
        credential_slot=slot,
    )


# ---------------------------------------------------------------------------
# A — Baseline validation across a shared DB
# ---------------------------------------------------------------------------


class TestA_Baseline:
    def test_active_tenant_validate_succeeds(self, engine: Engine) -> None:
        result = _issue(engine)
        principal = validate_credential(engine, result.plaintext_secret)
        assert isinstance(principal, CredentialPrincipal)
        assert principal.tenant_id == "tenant-alpha"

    def test_unknown_tenant_issue_fails_closed(self, engine: Engine) -> None:
        with pytest.raises(TenantNotFoundError):
            issue_credential(
                engine,
                tenant_id="does-not-exist",
                credential_type="tenant_api_key",
                credential_slot="prod",
            )

    def test_unknown_tenant_validate_fails_closed(self, engine: Engine) -> None:
        """Credential for unknown tenant — fingerprint lookup returns nothing."""
        with pytest.raises(CredentialNotFoundError):
            validate_credential(engine, "fgk.eyJ0IjoiZ2hvc3QifQ.fakesecret")


# ---------------------------------------------------------------------------
# B — Suspend / reactivate cycle
# ---------------------------------------------------------------------------


class TestB_SuspendReactivate:
    def test_suspend_blocks_validation_immediately(self, engine: Engine) -> None:
        result = _issue(engine)
        _transition(engine, "tenant-alpha", "suspended")
        with pytest.raises(TenantLifecycleError):
            validate_credential(engine, result.plaintext_secret)

    def test_reactivate_restores_validation(self, engine: Engine) -> None:
        result = _issue(engine)
        _transition(engine, "tenant-alpha", "suspended")
        _transition(engine, "tenant-alpha", "active")
        principal = validate_credential(engine, result.plaintext_secret)
        assert principal.tenant_id == "tenant-alpha"

    def test_credential_row_unchanged_after_suspend(self, engine: Engine) -> None:
        """Suspension is a tenant-level control — no credential mutation required."""
        result = _issue(engine)
        cid = result.record.credential_id

        _transition(engine, "tenant-alpha", "suspended")

        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT status FROM tenant_credentials WHERE credential_id = :cid"
                ),
                {"cid": cid},
            ).fetchone()
        assert row[0] == "active"

    def test_credential_row_unchanged_after_reactivate(self, engine: Engine) -> None:
        result = _issue(engine)
        cid = result.record.credential_id

        _transition(engine, "tenant-alpha", "suspended")
        _transition(engine, "tenant-alpha", "active")

        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT status FROM tenant_credentials WHERE credential_id = :cid"
                ),
                {"cid": cid},
            ).fetchone()
        assert row[0] == "active"

    def test_tenant_transition_alone_changes_validation_outcome(
        self, engine: Engine
    ) -> None:
        """The only change between the two validate calls is the tenant lifecycle state."""
        result = _issue(engine)

        principal = validate_credential(engine, result.plaintext_secret)
        assert isinstance(principal, CredentialPrincipal)

        _transition(engine, "tenant-alpha", "suspended")

        with pytest.raises(TenantLifecycleError):
            validate_credential(engine, result.plaintext_secret)

        _transition(engine, "tenant-alpha", "active")

        principal2 = validate_credential(engine, result.plaintext_secret)
        assert principal2.credential_id == principal.credential_id

    def test_suspend_blocks_issue(self, engine: Engine) -> None:
        _transition(engine, "tenant-alpha", "suspended")
        with pytest.raises(TenantLifecycleError):
            _issue(engine)

    def test_suspended_allows_revoke(self, engine: Engine) -> None:
        from api.credential_authority import revoke_credential

        result = _issue(engine)
        _transition(engine, "tenant-alpha", "suspended")
        rec = revoke_credential(
            engine,
            credential_id=result.record.credential_id,
            tenant_id="tenant-alpha",
            actor_id="op",
            reason="suspended tenant cleanup",
        )
        assert rec.status == "revoked"


# ---------------------------------------------------------------------------
# C — Archive
# ---------------------------------------------------------------------------


class TestC_Archive:
    def test_archive_blocks_validation(self, engine: Engine) -> None:
        result = _issue(engine)
        _transition(engine, "tenant-alpha", "archived")
        with pytest.raises(TenantLifecycleError):
            validate_credential(engine, result.plaintext_secret)

    def test_archive_blocks_issue(self, engine: Engine) -> None:
        _transition(engine, "tenant-alpha", "archived")
        with pytest.raises(TenantLifecycleError):
            _issue(engine)

    def test_credential_row_unchanged_after_archive(self, engine: Engine) -> None:
        result = _issue(engine)
        cid = result.record.credential_id
        _transition(engine, "tenant-alpha", "archived")
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT status FROM tenant_credentials WHERE credential_id = :cid"
                ),
                {"cid": cid},
            ).fetchone()
        assert row[0] == "active"


# ---------------------------------------------------------------------------
# D — Delete (terminal)
# ---------------------------------------------------------------------------


class TestD_Delete:
    def test_deleted_blocks_validation(self, engine: Engine) -> None:
        result = _issue(engine)
        _transition(engine, "tenant-alpha", "archived")
        _transition(engine, "tenant-alpha", "deleted")
        with pytest.raises(TenantLifecycleError):
            validate_credential(engine, result.plaintext_secret)

    def test_deleted_blocks_issue(self, engine: Engine) -> None:
        _transition(engine, "tenant-alpha", "archived")
        _transition(engine, "tenant-alpha", "deleted")
        with pytest.raises(TenantLifecycleError):
            _issue(engine)


# ---------------------------------------------------------------------------
# E — Tenant isolation (two tenants, same DB)
# ---------------------------------------------------------------------------


class TestE_TenantIsolation:
    def test_suspend_one_tenant_does_not_affect_other(self, engine: Engine) -> None:
        r_alpha = _issue(engine, tenant_id="tenant-alpha", slot="prod")
        r_beta = _issue(engine, tenant_id="tenant-beta", slot="prod")

        _transition(engine, "tenant-alpha", "suspended")

        with pytest.raises(TenantLifecycleError):
            validate_credential(engine, r_alpha.plaintext_secret)

        principal = validate_credential(engine, r_beta.plaintext_secret)
        assert principal.tenant_id == "tenant-beta"
