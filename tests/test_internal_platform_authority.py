"""Internal platform authority bootstrap tests."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

import api.credential_authority as ca
from api.credential_authority import (
    get_credential,
    revoke_credential,
    rotate_credential,
)
from api.internal_platform_authority import (
    CANONICAL_INTERNAL_TENANT_ID,
    OPERATOR_CREDENTIAL_SLOT,
    OPERATOR_CREDENTIAL_TYPE,
    InternalPlatformAuthorityError,
    bootstrap_internal_platform_authority,
    emit_internal_credential_event_if_applicable,
    read_internal_platform_authority_status,
    validate_configured_core_tenant_id,
    validate_operator_authority_record,
)
from api.tenant_repository import TenantRepository

MIGRATION = Path("migrations/postgres/0167_internal_platform_authority_bootstrap.sql")

_SCHEMA = """
CREATE TABLE tenants (
    tenant_id VARCHAR(128) PRIMARY KEY,
    display_name TEXT NOT NULL,
    lifecycle_state VARCHAR(32) NOT NULL DEFAULT 'active',
    tenant_kind VARCHAR(32) NOT NULL DEFAULT 'customer'
        CHECK (tenant_kind IN ('customer', 'internal_platform', 'validation', 'demo')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_by TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    canonical_version INTEGER NOT NULL DEFAULT 1,
    last_reconciled_at TEXT,
    archived_at TEXT,
    migration_source VARCHAR(32),
    migration_version VARCHAR(32)
);

CREATE TABLE credential_slots (
    tenant_id VARCHAR(128) NOT NULL,
    credential_type VARCHAR(64) NOT NULL,
    credential_slot VARCHAR(128) NOT NULL,
    current_generation INTEGER NOT NULL DEFAULT 0,
    rotation_policy VARCHAR(32) NOT NULL DEFAULT 'immediate',
    max_overlap_count INTEGER NOT NULL DEFAULT 1,
    created_at TEXT,
    updated_at TEXT,
    PRIMARY KEY (tenant_id, credential_type, credential_slot)
);

CREATE TABLE tenant_credentials (
    credential_id VARCHAR(64) NOT NULL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    credential_type VARCHAR(64) NOT NULL,
    credential_slot VARCHAR(128) NOT NULL,
    generation INTEGER NOT NULL DEFAULT 1,
    lookup_fingerprint VARCHAR(64) NOT NULL,
    lookup_key_version INTEGER NOT NULL DEFAULT 1,
    secret_prefix VARCHAR(16) NOT NULL,
    secret_hash TEXT NOT NULL,
    hash_algorithm VARCHAR(32) NOT NULL DEFAULT 'argon2id',
    hash_params TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    expires_at TEXT,
    issued_at TEXT NOT NULL,
    activated_at TEXT,
    rotated_at TEXT,
    revoked_at TEXT,
    replaced_by_credential_id VARCHAR(64),
    created_by_actor_id VARCHAR(256),
    request_id VARCHAR(128),
    idempotency_key VARCHAR(256),
    last_used_at TEXT,
    approximate_use_count INTEGER NOT NULL DEFAULT 0,
    scopes_csv TEXT,
    metadata TEXT,
    schema_version INTEGER NOT NULL DEFAULT 1,
    record_hash VARCHAR(64),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE UNIQUE INDEX ix_tc_slot_generation
    ON tenant_credentials (tenant_id, credential_type, credential_slot, generation);
CREATE INDEX ix_tc_lookup_fingerprint
    ON tenant_credentials (lookup_fingerprint);

CREATE TABLE tenant_credential_events (
    event_id VARCHAR(64) NOT NULL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    credential_id VARCHAR(64),
    credential_type VARCHAR(64),
    credential_slot VARCHAR(128),
    generation INTEGER,
    event_type VARCHAR(64) NOT NULL,
    actor_id VARCHAR(256),
    request_id VARCHAR(128),
    occurred_at TEXT NOT NULL,
    outcome VARCHAR(16) NOT NULL DEFAULT 'success',
    failure_reason TEXT,
    metadata TEXT,
    schema_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE internal_platform_authority_events (
    event_id VARCHAR(64) NOT NULL PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    actor_id VARCHAR(256) NOT NULL,
    service_id VARCHAR(128) NOT NULL,
    target_tenant_id VARCHAR(128) NOT NULL,
    authority_tenant_id VARCHAR(128),
    credential_id VARCHAR(64),
    credential_type VARCHAR(64),
    credential_slot VARCHAR(128),
    generation INTEGER,
    request_id VARCHAR(128),
    occurred_at TEXT NOT NULL,
    outcome VARCHAR(16) NOT NULL DEFAULT 'success',
    failure_reason TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    schema_version INTEGER NOT NULL DEFAULT 1
);
"""


@pytest.fixture(autouse=True)
def fast_hasher(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ca, "_HASHER", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    )
    monkeypatch.setenv("FG_KEY_PEPPER", "internal-platform-test-pepper")


@pytest.fixture()
def engine() -> Generator[Engine, None, None]:
    eng = create_engine("sqlite+pysqlite:///:memory:", future=True)
    with eng.begin() as conn:
        for stmt in _SCHEMA.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(text(stmt))
    yield eng
    eng.dispose()


def _events(engine: Engine) -> list[tuple[str, str, str | None]]:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT event_type, target_tenant_id, request_id "
                "FROM internal_platform_authority_events ORDER BY occurred_at, event_type"
            )
        ).fetchall()
    return [
        (str(row[0]), str(row[1]), None if row[2] is None else str(row[2]))
        for row in rows
    ]


def test_bootstrap_creates_once_and_issues_operator_credential_once(
    engine: Engine,
) -> None:
    first = bootstrap_internal_platform_authority(engine, request_id="req-1")
    second = bootstrap_internal_platform_authority(engine, request_id="req-2")

    assert first.tenant_id == CANONICAL_INTERNAL_TENANT_ID
    assert first.tenant_kind == "internal_platform"
    assert first.lifecycle_state == "active"
    assert first.authority_version == 1
    assert first.bootstrap_status == "created"
    assert first.credential_issued is True
    assert second.bootstrap_status == "reused"
    assert second.credential_issued is False
    assert not hasattr(first, "plaintext_secret")

    with engine.connect() as conn:
        tenants = conn.execute(text("SELECT COUNT(*) FROM tenants")).scalar_one()
        credentials = conn.execute(
            text("SELECT COUNT(*) FROM tenant_credentials")
        ).scalar_one()
        slot = conn.execute(
            text(
                "SELECT current_generation FROM credential_slots "
                "WHERE tenant_id=:tenant_id AND credential_type=:credential_type "
                "AND credential_slot=:credential_slot"
            ),
            {
                "tenant_id": CANONICAL_INTERNAL_TENANT_ID,
                "credential_type": OPERATOR_CREDENTIAL_TYPE,
                "credential_slot": OPERATOR_CREDENTIAL_SLOT,
            },
        ).fetchone()
    assert tenants == 1
    assert credentials == 1
    assert slot is not None
    assert slot[0] == 1

    event_types = [event[0] for event in _events(engine)]
    assert "bootstrap_created" in event_types
    assert "bootstrap_reused" in event_types
    assert "credential_issued" in event_types
    assert "credential_reused" in event_types


def test_bootstrap_reuses_existing_internal_platform_tenant(engine: Engine) -> None:
    repo = TenantRepository(engine)
    repo.create(
        "existing-internal",
        "Existing Internal",
        tenant_kind="internal_platform",
        allow_internal_platform=True,
        metadata={"authority_version": 7},
    )

    status = bootstrap_internal_platform_authority(engine, request_id="req-existing")

    assert status.tenant_id == "existing-internal"
    assert status.authority_version == 7
    assert status.bootstrap_status == "reused"
    with engine.connect() as conn:
        tenant_ids = [
            row[0] for row in conn.execute(text("SELECT tenant_id FROM tenants"))
        ]
    assert tenant_ids == ["existing-internal"]


def test_bootstrap_rejects_canonical_customer_conflict(engine: Engine) -> None:
    TenantRepository(engine).create(CANONICAL_INTERNAL_TENANT_ID, "Customer Collision")

    with pytest.raises(InternalPlatformAuthorityError) as exc:
        bootstrap_internal_platform_authority(engine)

    assert exc.value.code == "CANONICAL_INTERNAL_AUTHORITY_CONFLICT"


@pytest.mark.parametrize("kind", ["customer", "demo", "validation"])
def test_non_internal_kinds_rejected_for_operator_authority(
    engine: Engine, kind: str
) -> None:
    record = TenantRepository(engine).create(
        f"tenant-{kind}", kind.title(), tenant_kind=kind
    )

    with pytest.raises(InternalPlatformAuthorityError) as exc:
        validate_operator_authority_record(record)

    assert exc.value.code == "OPERATOR_TENANT_NOT_ALLOWED"


def test_internal_platform_accepted_for_operator_authority(engine: Engine) -> None:
    record = TenantRepository(engine).create(
        "internal-a",
        "Internal A",
        tenant_kind="internal_platform",
        allow_internal_platform=True,
    )
    validate_operator_authority_record(record)


def test_suspended_internal_platform_rejected(engine: Engine) -> None:
    repo = TenantRepository(engine)
    repo.create(
        "internal-a",
        "Internal A",
        tenant_kind="internal_platform",
        allow_internal_platform=True,
    )
    record = repo.set_lifecycle_state("internal-a", "suspended")

    with pytest.raises(InternalPlatformAuthorityError):
        validate_operator_authority_record(record)


@pytest.mark.parametrize(
    ("env_value", "code"),
    [
        (None, "CORE_TENANT_ID_MISSING"),
        ("", "CORE_TENANT_ID_MISSING"),
        ("default", "CORE_TENANT_ID_INVALID"),
        ("bad tenant", "CORE_TENANT_ID_INVALID"),
        ("ghost", "OPERATOR_TENANT_NOT_FOUND"),
    ],
)
def test_configured_core_tenant_id_fails_closed_for_invalid_values(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    env_value: str | None,
    code: str,
) -> None:
    bootstrap_internal_platform_authority(engine)
    if env_value is None:
        monkeypatch.delenv("CORE_TENANT_ID", raising=False)
    else:
        monkeypatch.setenv("CORE_TENANT_ID", env_value)

    with pytest.raises(InternalPlatformAuthorityError) as exc:
        validate_configured_core_tenant_id(engine, request_id="req-invalid")

    assert exc.value.code == code
    assert any(event[0] == "authority_denied" for event in _events(engine))


@pytest.mark.parametrize("kind", ["customer", "demo", "validation"])
def test_configured_core_tenant_id_rejects_non_internal_existing_tenants(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    TenantRepository(engine).create(f"tenant-{kind}", kind.title(), tenant_kind=kind)
    monkeypatch.setenv("CORE_TENANT_ID", f"tenant-{kind}")

    with pytest.raises(InternalPlatformAuthorityError) as exc:
        validate_configured_core_tenant_id(engine, request_id="req-kind")

    assert exc.value.code == "OPERATOR_TENANT_NOT_ALLOWED"


def test_configured_core_tenant_id_accepts_internal_platform(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bootstrap_internal_platform_authority(engine)
    monkeypatch.setenv("CORE_TENANT_ID", CANONICAL_INTERNAL_TENANT_ID)

    record = validate_configured_core_tenant_id(engine, request_id="req-valid")

    assert record.tenant_id == CANONICAL_INTERNAL_TENANT_ID
    assert any(event[0] == "authority_validated" for event in _events(engine))


def test_read_status_never_exposes_credential_secret(engine: Engine) -> None:
    bootstrap_internal_platform_authority(engine)

    status = read_internal_platform_authority_status(engine).safe_dict()

    assert status["authority_exists"] is True
    assert status["credential_status"] == "active"
    assert "plaintext_secret" not in status
    assert "secret" not in status


def test_internal_credential_rotation_and_revocation_are_audited(
    engine: Engine,
) -> None:
    status = bootstrap_internal_platform_authority(engine)
    assert status.credential_id is not None

    rotated = rotate_credential(
        engine,
        tenant_id=CANONICAL_INTERNAL_TENANT_ID,
        credential_type=OPERATOR_CREDENTIAL_TYPE,
        credential_slot=OPERATOR_CREDENTIAL_SLOT,
        actor_id="admin-actor",
        request_id="req-rotate",
    )
    emit_internal_credential_event_if_applicable(
        engine,
        tenant_id=CANONICAL_INTERNAL_TENANT_ID,
        event_type="credential_rotated",
        actor_id="admin-actor",
        request_id="req-rotate",
        credential_id=rotated.record.credential_id,
        credential_type=rotated.record.credential_type,
        credential_slot=rotated.record.credential_slot,
        generation=rotated.record.generation,
    )

    revoked = revoke_credential(
        engine,
        credential_id=rotated.record.credential_id,
        tenant_id=CANONICAL_INTERNAL_TENANT_ID,
        actor_id="admin-actor",
        reason="test revocation",
        request_id="req-revoke",
    )
    emit_internal_credential_event_if_applicable(
        engine,
        tenant_id=CANONICAL_INTERNAL_TENANT_ID,
        event_type="credential_revoked",
        actor_id="admin-actor",
        request_id="req-revoke",
        credential_id=revoked.credential_id,
        credential_type=revoked.credential_type,
        credential_slot=revoked.credential_slot,
        generation=revoked.generation,
    )

    assert (
        get_credential(
            engine, revoked.credential_id, CANONICAL_INTERNAL_TENANT_ID
        ).status
        == "revoked"
    )
    event_types = [event[0] for event in _events(engine)]
    assert "credential_rotated" in event_types
    assert "credential_revoked" in event_types
    assert (
        "credential_rotated",
        CANONICAL_INTERNAL_TENANT_ID,
        "req-rotate",
    ) in _events(engine)
    assert (
        "credential_revoked",
        CANONICAL_INTERNAL_TENANT_ID,
        "req-revoke",
    ) in _events(engine)


def test_migration_documents_canonical_internal_bootstrap_without_credentials() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "frostgate-internal" in sql
    assert "tenant_kind = 'internal_platform'" in sql
    assert "uq_tenants_single_internal_platform_authority" in sql
    assert "internal_platform_authority_events" in sql
    assert "00000000-0000-0000-0000-000000000167" in sql
    assert "credential material is created" in sql
    assert "tenant_credentials" not in sql
    assert "tenant_kind LIKE" not in sql
