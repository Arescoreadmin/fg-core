"""Platform service principal tests (PR #586).

Covers:
- Bootstrap: created / reused / conflict / invalid_authority / idempotency
- Authority binding: internal_platform accepted, customer/demo/validation/unknown rejected
- Lifecycle: active / suspended / resumed / revoked fail-closed behavior
- Credential: issued once, rotation succeeds, revocation, no raw secret in status
- Authentication: active passes, suspended/revoked denied
- Authorization: explicit permission grants, missing permission denied
- Audit events: all lifecycle and auth events emitted; no secrets in metadata
- Security invariants:
  - principal_kind enforced
  - PSP cannot be created for customer tenant
  - No raw secret in status or audit records
  - Duplicate canonical PSP impossible
  - Revocation is irreversible
  - Target tenant authorization enforced: explicit non-empty target required,
      nonexistent target fails closed, suspended/archived target denied,
      authority tenant cannot be used as target
- Permission registry: ALL_PERMISSIONS contains all PSP permissions
- Migration: documents canonical stable_key, PSP table, no credentials in SQL
"""

from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

import api.credential_authority as ca
from api.actor_context import ALL_PERMISSIONS
from api.platform_service_principal import (
    CANONICAL_PSP_STABLE_KEY,
    PLATFORM_SERVICE_DEFAULT_PERMISSIONS,
    PSP_CREDENTIAL_SLOT,
    PSP_PRINCIPAL_KIND,
    PlatformServicePrincipalError,
    authenticate_service_principal,
    authorize_service_principal,
    bootstrap_platform_service_principal,
    read_service_principal_status,
    resume_service_principal,
    revoke_service_principal,
    rotate_service_principal_credential,
    suspend_service_principal,
)
from api.tenant_repository import TenantRepository

MIGRATION = Path("migrations/postgres/0168_platform_service_principal.sql")

# ── SQLite in-memory fixture schema ─────────────────────────────────────────

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

CREATE TABLE platform_service_principals (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    stable_key VARCHAR(128) NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    authority_tenant_id VARCHAR(128) NOT NULL,
    principal_kind VARCHAR(32) NOT NULL DEFAULT 'platform_service',
    lifecycle_state VARCHAR(32) NOT NULL DEFAULT 'active',
    authority_version INTEGER NOT NULL DEFAULT 1,
    credential_slot VARCHAR(128) NOT NULL,
    credential_type VARCHAR(64) NOT NULL DEFAULT 'tenant_api_key',
    granted_permissions TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    activated_at TEXT,
    suspended_at TEXT,
    revoked_at TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    schema_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE platform_service_principal_events (
    event_id VARCHAR(64) NOT NULL PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    service_principal_id VARCHAR(64),
    stable_key VARCHAR(128),
    actor_id VARCHAR(256) NOT NULL,
    service_id VARCHAR(128) NOT NULL,
    authority_tenant_id VARCHAR(128),
    target_tenant_id VARCHAR(128),
    credential_id VARCHAR(64),
    credential_type VARCHAR(64),
    credential_slot VARCHAR(128),
    generation INTEGER,
    request_id VARCHAR(128),
    permission VARCHAR(128),
    outcome VARCHAR(16) NOT NULL DEFAULT 'success',
    failure_reason TEXT,
    occurred_at TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    schema_version INTEGER NOT NULL DEFAULT 1
);
"""


@pytest.fixture(autouse=True)
def fast_hasher(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ca, "_HASHER", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    )
    monkeypatch.setenv("FG_KEY_PEPPER", "psp-test-pepper-2026")


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


@pytest.fixture()
def engine_with_authority(engine: Engine) -> Engine:
    """Engine pre-seeded with a canonical internal_platform tenant."""
    TenantRepository(engine).create(
        "frostgate-internal",
        "FrostGate Internal Platform",
        tenant_kind="internal_platform",
        allow_internal_platform=True,
    )
    return engine


@pytest.fixture()
def engine_with_targets(engine_with_authority: Engine) -> Engine:
    """Authority engine plus active customer tenants for authorization tests."""
    repo = TenantRepository(engine_with_authority)
    for tid, name in [
        ("customer-x", "Customer X"),
        ("target-tenant-abc", "Target Tenant ABC"),
        ("any-tenant", "Any Tenant"),
    ]:
        repo.create(tid, name, tenant_kind="customer")
    return engine_with_authority


# ── Helpers ──────────────────────────────────────────────────────────────────


def _psp_events(engine: Engine) -> list[tuple[str, str, str | None]]:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT event_type, stable_key, request_id "
                "FROM platform_service_principal_events ORDER BY occurred_at, event_type"
            )
        ).fetchall()
    return [(str(r[0]), str(r[1]), None if r[2] is None else str(r[2])) for r in rows]


def _event_types(engine: Engine) -> list[str]:
    return [e[0] for e in _psp_events(engine)]


def _psp_row(engine: Engine) -> dict | None:
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT id, stable_key, lifecycle_state, authority_tenant_id, "
                "principal_kind, granted_permissions FROM platform_service_principals "
                "WHERE stable_key = :sk"
            ),
            {"sk": CANONICAL_PSP_STABLE_KEY},
        ).fetchone()
    if row is None:
        return None
    return {
        "id": str(row[0]),
        "stable_key": str(row[1]),
        "lifecycle_state": str(row[2]),
        "authority_tenant_id": str(row[3]),
        "principal_kind": str(row[4]),
        "granted_permissions": json.loads(row[5] or "[]"),
    }


# ── Bootstrap tests ──────────────────────────────────────────────────────────


def test_bootstrap_creates_canonical_psp_once(engine_with_authority: Engine) -> None:
    result = bootstrap_platform_service_principal(
        engine_with_authority, request_id="req-1"
    )

    assert result.status == "created"
    assert result.stable_key == CANONICAL_PSP_STABLE_KEY
    assert result.authority_tenant_id == "frostgate-internal"
    assert result.lifecycle_state == "active"
    assert result.credential_issued is True
    assert result.error_code is None

    row = _psp_row(engine_with_authority)
    assert row is not None
    assert row["stable_key"] == CANONICAL_PSP_STABLE_KEY
    assert row["lifecycle_state"] == "active"
    assert row["principal_kind"] == PSP_PRINCIPAL_KIND

    with engine_with_authority.connect() as conn:
        psp_count = conn.execute(
            text("SELECT COUNT(*) FROM platform_service_principals")
        ).scalar_one()
        cred_count = conn.execute(
            text("SELECT COUNT(*) FROM tenant_credentials")
        ).scalar_one()
    assert psp_count == 1
    assert cred_count == 1

    assert "bootstrap_created" in _event_types(engine_with_authority)
    assert "credential_issued" in _event_types(engine_with_authority)


def test_second_bootstrap_reuses_existing_psp(engine_with_authority: Engine) -> None:
    first = bootstrap_platform_service_principal(engine_with_authority)
    second = bootstrap_platform_service_principal(engine_with_authority)

    assert first.status == "created"
    assert second.status == "reused"
    assert second.credential_issued is False

    with engine_with_authority.connect() as conn:
        psp_count = conn.execute(
            text("SELECT COUNT(*) FROM platform_service_principals")
        ).scalar_one()
        cred_count = conn.execute(
            text("SELECT COUNT(*) FROM tenant_credentials")
        ).scalar_one()
    assert psp_count == 1
    assert cred_count == 1

    assert "bootstrap_reused" in _event_types(engine_with_authority)


def test_bootstrap_is_idempotent_across_many_calls(
    engine_with_authority: Engine,
) -> None:
    for _ in range(5):
        result = bootstrap_platform_service_principal(engine_with_authority)
        assert result.status in ("created", "reused")

    with engine_with_authority.connect() as conn:
        count = conn.execute(
            text("SELECT COUNT(*) FROM platform_service_principals")
        ).scalar_one()
    assert count == 1


def test_bootstrap_fails_closed_when_no_internal_authority(engine: Engine) -> None:
    result = bootstrap_platform_service_principal(engine)

    assert result.status == "invalid_authority"
    assert result.error_code == "INTERNAL_AUTHORITY_MISSING"
    assert result.credential_issued is False
    assert "invalid_authority_binding" in _event_types(engine)


def test_bootstrap_fails_closed_when_authority_suspended(engine: Engine) -> None:
    repo = TenantRepository(engine)
    repo.create(
        "frostgate-internal",
        "FrostGate Internal",
        tenant_kind="internal_platform",
        allow_internal_platform=True,
    )
    repo.set_lifecycle_state("frostgate-internal", "suspended")

    result = bootstrap_platform_service_principal(engine)

    assert result.status == "invalid_authority"
    assert result.error_code is not None


def test_bootstrap_fails_closed_for_customer_authority(engine: Engine) -> None:
    TenantRepository(engine).create("customer-a", "Customer A", tenant_kind="customer")

    result = bootstrap_platform_service_principal(engine)

    assert result.status == "invalid_authority"


def test_bootstrap_conflict_when_psp_bound_to_different_authority(
    engine: Engine,
) -> None:
    repo = TenantRepository(engine)
    repo.create(
        "authority-1",
        "Authority 1",
        tenant_kind="internal_platform",
        allow_internal_platform=True,
    )
    first = bootstrap_platform_service_principal(engine)
    assert first.status == "created"
    # PSP is now bound to authority-1

    # Simulate authority rotation: demote authority-1, promote authority-2
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE tenants SET tenant_kind = 'validation' WHERE tenant_id = 'authority-1'"
            )
        )
    repo.create(
        "authority-2",
        "Authority 2",
        tenant_kind="internal_platform",
        allow_internal_platform=True,
    )
    # Now the single internal_platform tenant is authority-2,
    # but the PSP.authority_tenant_id is still "authority-1" → conflict

    result = bootstrap_platform_service_principal(engine)

    assert result.status == "conflict"
    assert result.error_code == "AUTHORITY_BINDING_MISMATCH"
    assert "bootstrap_conflict" in _event_types(engine)


# ── Authority binding tests ───────────────────────────────────────────────────


@pytest.mark.parametrize("kind", ["customer", "demo", "validation"])
def test_bootstrap_rejects_non_internal_authority(engine: Engine, kind: str) -> None:
    TenantRepository(engine).create(f"tenant-{kind}", kind.title(), tenant_kind=kind)

    result = bootstrap_platform_service_principal(engine)

    assert result.status == "invalid_authority"
    assert result.credential_issued is False


def test_bootstrap_internal_platform_accepted(engine_with_authority: Engine) -> None:
    result = bootstrap_platform_service_principal(engine_with_authority)

    assert result.status == "created"
    assert result.authority_tenant_id == "frostgate-internal"


def test_bootstrap_missing_tenant_fails_closed(engine: Engine) -> None:
    result = bootstrap_platform_service_principal(engine)

    assert result.status == "invalid_authority"
    assert result.error_code == "INTERNAL_AUTHORITY_MISSING"


# ── Credential tests ──────────────────────────────────────────────────────────


def test_credential_issued_once_at_bootstrap(engine_with_authority: Engine) -> None:
    result = bootstrap_platform_service_principal(engine_with_authority)

    assert result.credential_issued is True

    with engine_with_authority.connect() as conn:
        count = conn.execute(
            text(
                "SELECT COUNT(*) FROM tenant_credentials WHERE credential_slot = :slot"
            ),
            {"slot": PSP_CREDENTIAL_SLOT},
        ).scalar_one()
    assert count == 1


def test_read_status_never_exposes_raw_secret(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_authority)

    status = read_service_principal_status(engine_with_authority)
    d = status.safe_dict()

    assert "plaintext_secret" not in d
    assert "secret" not in d
    assert d["credential_status"] == "active"
    assert d["credential_id"] is not None


def test_rotation_succeeds_and_invalidates_prior_credential(
    engine_with_authority: Engine,
) -> None:
    result = bootstrap_platform_service_principal(engine_with_authority)
    original_cred_id = result.credential_id
    assert original_cred_id is not None

    status = rotate_service_principal_credential(
        engine_with_authority, actor_id="admin", request_id="req-rotate"
    )

    assert status.credential_status == "active"
    assert status.credential_generation == 2
    assert "credential_rotated" in _event_types(engine_with_authority)

    # Prior credential should now be rotated/inactive
    from api.credential_authority import get_credential

    old_cred = get_credential(
        engine_with_authority, original_cred_id, "frostgate-internal"
    )
    assert old_cred.status != "active"


def test_rotation_on_revoked_principal_fails_closed(
    engine_with_authority: Engine,
) -> None:
    bootstrap_platform_service_principal(engine_with_authority)
    revoke_service_principal(engine_with_authority, actor_id="admin")

    with pytest.raises(PlatformServicePrincipalError) as exc:
        rotate_service_principal_credential(engine_with_authority, actor_id="admin")

    assert exc.value.code == "SERVICE_PRINCIPAL_REVOKED"


def test_revoke_also_revokes_credential(engine_with_authority: Engine) -> None:
    result = bootstrap_platform_service_principal(engine_with_authority)
    cred_id = result.credential_id
    assert cred_id is not None

    revoke_service_principal(engine_with_authority, actor_id="admin")

    from api.credential_authority import get_credential

    cred = get_credential(engine_with_authority, cred_id, "frostgate-internal")
    assert cred.status == "revoked"


def test_no_raw_secret_in_audit_events(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_authority)
    rotate_service_principal_credential(engine_with_authority, actor_id="admin")

    with engine_with_authority.connect() as conn:
        rows = conn.execute(
            text("SELECT metadata FROM platform_service_principal_events")
        ).fetchall()

    for row in rows:
        meta_str = str(row[0] or "")
        assert "secret" not in meta_str.lower() or "plaintext_exposed" in meta_str


# ── Lifecycle tests ───────────────────────────────────────────────────────────


def test_active_principal_authenticates(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_authority)

    auth = authenticate_service_principal(
        engine_with_authority, actor_id="workload", request_id="req-auth"
    )

    assert auth.authenticated is True
    assert auth.denial_code is None
    assert "authentication_success" in _event_types(engine_with_authority)


def test_suspended_principal_denied(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_authority)
    suspend_service_principal(engine_with_authority, actor_id="admin")

    auth = authenticate_service_principal(engine_with_authority, actor_id="workload")

    assert auth.authenticated is False
    assert auth.denial_code == "SERVICE_PRINCIPAL_SUSPENDED"
    assert "authentication_failure" in _event_types(engine_with_authority)


def test_revoked_principal_denied(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_authority)
    revoke_service_principal(engine_with_authority, actor_id="admin")

    auth = authenticate_service_principal(engine_with_authority, actor_id="workload")

    assert auth.authenticated is False
    assert auth.denial_code == "SERVICE_PRINCIPAL_REVOKED"


def test_suspended_then_resumed_authenticates(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_authority)
    suspend_service_principal(engine_with_authority, actor_id="admin")
    resume_service_principal(engine_with_authority, actor_id="admin")

    auth = authenticate_service_principal(engine_with_authority, actor_id="workload")

    assert auth.authenticated is True
    event_list = _event_types(engine_with_authority)
    assert "principal_suspended" in event_list
    assert "principal_resumed" in event_list


def test_revoked_principal_cannot_be_suspended(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_authority)
    revoke_service_principal(engine_with_authority, actor_id="admin")

    with pytest.raises(PlatformServicePrincipalError) as exc:
        suspend_service_principal(engine_with_authority, actor_id="admin")

    assert exc.value.code == "SERVICE_PRINCIPAL_REVOKED"


def test_revoked_principal_cannot_be_resumed(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_authority)
    revoke_service_principal(engine_with_authority, actor_id="admin")

    with pytest.raises(PlatformServicePrincipalError) as exc:
        resume_service_principal(engine_with_authority, actor_id="admin")

    assert exc.value.code == "SERVICE_PRINCIPAL_REVOKED"


def test_suspend_already_suspended_fails_closed(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_authority)
    suspend_service_principal(engine_with_authority, actor_id="admin")

    with pytest.raises(PlatformServicePrincipalError) as exc:
        suspend_service_principal(engine_with_authority, actor_id="admin")

    assert exc.value.code == "SERVICE_PRINCIPAL_ALREADY_SUSPENDED"


def test_revoke_already_revoked_fails_closed(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_authority)
    revoke_service_principal(engine_with_authority, actor_id="admin")

    with pytest.raises(PlatformServicePrincipalError) as exc:
        revoke_service_principal(engine_with_authority, actor_id="admin")

    assert exc.value.code == "SERVICE_PRINCIPAL_ALREADY_REVOKED"


def test_resume_active_principal_is_no_op(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_authority)

    status = resume_service_principal(engine_with_authority, actor_id="admin")

    assert status.lifecycle_state == "active"


# ── Authorization tests ───────────────────────────────────────────────────────


def test_granted_permission_allowed(engine_with_targets: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_targets)

    result = authorize_service_principal(
        engine_with_targets,
        actor_id="workload",
        permission="platform.tenants.read",
        target_tenant_id="customer-x",
    )

    assert result.allowed is True
    assert result.denial_code is None
    assert "authorization_allowed" in _event_types(engine_with_targets)


def test_missing_permission_denied(engine_with_targets: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_targets)

    result = authorize_service_principal(
        engine_with_targets,
        actor_id="workload",
        permission="assessment.create",
        target_tenant_id="customer-x",
    )

    assert result.allowed is False
    assert result.denial_code == "PERMISSION_NOT_GRANTED"
    assert "authorization_denied" in _event_types(engine_with_targets)


def test_suspended_principal_authorization_denied(
    engine_with_targets: Engine,
) -> None:
    bootstrap_platform_service_principal(engine_with_targets)
    suspend_service_principal(engine_with_targets, actor_id="admin")

    result = authorize_service_principal(
        engine_with_targets,
        actor_id="workload",
        permission="platform.tenants.read",
        target_tenant_id="customer-x",
    )

    assert result.allowed is False


def test_authorization_records_target_tenant(engine_with_targets: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_targets)

    authorize_service_principal(
        engine_with_targets,
        actor_id="workload",
        permission="platform.tenants.read",
        target_tenant_id="target-tenant-abc",
        request_id="req-authz",
    )

    with engine_with_targets.connect() as conn:
        row = conn.execute(
            text(
                "SELECT target_tenant_id, permission, request_id "
                "FROM platform_service_principal_events "
                "WHERE event_type = 'authorization_allowed'"
            )
        ).fetchone()

    assert row is not None
    assert str(row[0]) == "target-tenant-abc"
    assert str(row[1]) == "platform.tenants.read"
    assert str(row[2]) == "req-authz"


def test_psp_is_not_global_superuser(engine_with_targets: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_targets)

    # Permissions not in PLATFORM_SERVICE_DEFAULT_PERMISSIONS must be denied
    non_psp_permissions = [
        "assessment.create",
        "finding.approve",
        "governance.decision",
        "risk.accept",
        "exception.grant",
        "key.manage",
    ]
    for perm in non_psp_permissions:
        result = authorize_service_principal(
            engine_with_targets,
            actor_id="workload",
            permission=perm,
            target_tenant_id="any-tenant",
        )
        assert result.allowed is False, f"PSP should not have permission: {perm}"


# ── Status tests ──────────────────────────────────────────────────────────────


def test_read_status_before_bootstrap_returns_not_exists(engine: Engine) -> None:
    status = read_service_principal_status(engine)

    assert status.exists is False
    assert status.id is None
    assert status.lifecycle_state is None
    assert status.credential_id is None


def test_read_status_after_bootstrap_shows_active(
    engine_with_authority: Engine,
) -> None:
    bootstrap_platform_service_principal(engine_with_authority)

    status = read_service_principal_status(engine_with_authority)

    assert status.exists is True
    assert status.lifecycle_state == "active"
    assert status.stable_key == CANONICAL_PSP_STABLE_KEY
    assert status.principal_kind == PSP_PRINCIPAL_KIND
    assert status.authority_tenant_id == "frostgate-internal"
    assert status.credential_status == "active"
    assert status.credential_generation >= 1


def test_status_contains_granted_permissions(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_authority)

    status = read_service_principal_status(engine_with_authority)

    assert set(status.granted_permissions) == PLATFORM_SERVICE_DEFAULT_PERMISSIONS


# ── Audit event tests ─────────────────────────────────────────────────────────


def test_bootstrap_created_event_emitted(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(
        engine_with_authority, request_id="req-bootstrap"
    )

    events = _psp_events(engine_with_authority)
    event_map = {e[0]: e for e in events}

    assert "bootstrap_created" in event_map
    assert "credential_issued" in event_map


def test_bootstrap_reused_event_emitted(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_authority, request_id="r1")
    bootstrap_platform_service_principal(engine_with_authority, request_id="r2")

    assert "bootstrap_reused" in _event_types(engine_with_authority)


def test_authentication_events_audited(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_authority)

    authenticate_service_principal(
        engine_with_authority, actor_id="workload", request_id="req-auth"
    )

    events = _psp_events(engine_with_authority)
    event_map = {e[0]: e for e in events}
    assert "authentication_success" in event_map
    assert event_map["authentication_success"][2] == "req-auth"


def test_lifecycle_events_audited(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_authority)
    suspend_service_principal(
        engine_with_authority, actor_id="admin", request_id="req-suspend"
    )
    resume_service_principal(
        engine_with_authority, actor_id="admin", request_id="req-resume"
    )
    revoke_service_principal(
        engine_with_authority, actor_id="admin", request_id="req-revoke"
    )

    event_list = _event_types(engine_with_authority)
    assert "principal_suspended" in event_list
    assert "principal_resumed" in event_list
    assert "principal_revoked" in event_list
    assert "credential_revoked" in event_list


def test_audit_events_never_contain_raw_secrets(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(engine_with_authority)
    rotate_service_principal_credential(engine_with_authority, actor_id="admin")

    with engine_with_authority.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT metadata, failure_reason FROM platform_service_principal_events"
            )
        ).fetchall()

    forbidden_patterns = ["fgk.", "secret=", "password=", "plaintext"]
    for row in rows:
        for field_val in row:
            lowered = str(field_val or "").lower()
            for pat in forbidden_patterns:
                if pat == "plaintext":
                    assert "plaintext_secret" not in lowered
                else:
                    assert pat not in lowered, (
                        f"Forbidden pattern {pat!r} found in audit event: {field_val!r}"
                    )


def test_request_id_propagated_in_events(engine_with_authority: Engine) -> None:
    bootstrap_platform_service_principal(
        engine_with_authority, request_id="req-bootstrap-001"
    )

    with engine_with_authority.connect() as conn:
        count = conn.execute(
            text(
                "SELECT COUNT(*) FROM platform_service_principal_events "
                "WHERE request_id = 'req-bootstrap-001'"
            )
        ).scalar_one()

    assert count >= 1


# ── Security invariant tests ──────────────────────────────────────────────────


def test_duplicate_canonical_psp_impossible(engine_with_authority: Engine) -> None:
    """stable_key UNIQUE constraint prevents duplicate PSPs."""
    bootstrap_platform_service_principal(engine_with_authority)

    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        with engine_with_authority.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO platform_service_principals "
                    "(id, stable_key, display_name, authority_tenant_id, "
                    "principal_kind, lifecycle_state, authority_version, "
                    "credential_slot, credential_type, granted_permissions) "
                    "VALUES ('dup-id', :sk, 'Dup', 'frostgate-internal', "
                    "'platform_service', 'active', 1, :slot, 'tenant_api_key', '[]')"
                ),
                {"sk": CANONICAL_PSP_STABLE_KEY, "slot": PSP_CREDENTIAL_SLOT},
            )


def test_psp_not_created_for_customer_tenant(engine: Engine) -> None:
    TenantRepository(engine).create("customer-a", "Customer A")

    result = bootstrap_platform_service_principal(engine)

    assert result.status == "invalid_authority"

    with engine.connect() as conn:
        count = conn.execute(
            text("SELECT COUNT(*) FROM platform_service_principals")
        ).scalar_one()
    assert count == 0


def test_authentication_fails_when_no_psp_bootstrapped(engine: Engine) -> None:
    auth = authenticate_service_principal(engine, actor_id="workload")

    assert auth.authenticated is False
    assert auth.denial_code == "SERVICE_PRINCIPAL_NOT_FOUND"


# ── Permission registry tests ─────────────────────────────────────────────────


def test_all_psp_permissions_in_all_permissions_registry() -> None:
    missing = PLATFORM_SERVICE_DEFAULT_PERMISSIONS - ALL_PERMISSIONS
    assert not missing, (
        f"PSP permissions missing from ALL_PERMISSIONS: {sorted(missing)}"
    )


def test_platform_service_permissions_explicit_not_wildcard() -> None:
    assert "platform.admin" not in PLATFORM_SERVICE_DEFAULT_PERMISSIONS, (
        "PSP must not be granted platform.admin (global superuser); "
        "use explicit PSP permissions only"
    )


def test_psp_does_not_grant_customer_permissions() -> None:
    customer_permissions = {
        "assessment.create",
        "finding.approve",
        "governance.decision",
        "risk.accept",
        "exception.grant",
        "bundle.approve",
        "report.qa_approve",
    }
    overlap = PLATFORM_SERVICE_DEFAULT_PERMISSIONS & customer_permissions
    assert not overlap, f"PSP granted customer-facing permissions: {sorted(overlap)}"


# ── Migration tests ───────────────────────────────────────────────────────────


def test_migration_0168_documents_canonical_stable_key() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "frostgate-platform-service" in sql or "stable_key" in sql


def test_migration_creates_psp_table() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "platform_service_principals" in sql
    assert "platform_service_principal_events" in sql


def test_migration_has_no_credential_material() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "fgk." not in sql
    assert "INSERT INTO tenant_credentials" not in sql
    assert "INSERT INTO platform_service_principals" not in sql


def test_migration_has_append_only_trigger() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "pspe_prevent_mutation" in sql
    assert "restrict_violation" in sql


def test_migration_has_unique_stable_key_constraint() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "uq_psp_stable_key" in sql
    assert "uq_psp_authority_kind_active" in sql


def test_migration_is_replay_safe() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "IF NOT EXISTS" in sql or "CREATE TABLE IF NOT EXISTS" in sql


def test_migration_documents_pr_context() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "PR #586" in sql or "586" in sql
    assert (
        "credential material is created" in sql.lower()
        or "no credential" in sql.lower()
    )


def test_migration_documents_identity_continuity() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "uq_psp_stable_key" in sql
    # Non-partial uniqueness index enforces identity continuity
    assert (
        "lifecycle_state"
        not in sql.split("uq_psp_stable_key")[1].split("uq_psp_authority_kind_active")[
            0
        ]
    )


# ── platform.admin route-access permission tests ─────────────────────────────


def test_platform_admin_permission_exists_in_registry() -> None:
    """platform.admin must be a registered permission so routes are reachable."""
    from api.actor_context import ALL_PERMISSIONS

    assert "platform.admin" in ALL_PERMISSIONS, (
        "platform.admin missing from ALL_PERMISSIONS — PSP admin routes are unreachable"
    )


def test_psp_actor_lacks_platform_admin() -> None:
    """PSP permissions do not include platform.admin — PSP cannot self-administer."""
    from api.actor_context import ActorContext

    psp_actor = ActorContext(
        subject="system:psp",
        email="",
        name="Platform Service Principal",
        permissions=frozenset(PLATFORM_SERVICE_DEFAULT_PERMISSIONS),
        roles=[],
        auth_source="api_key",
        tenant_id="frostgate-internal",
    )
    assert not psp_actor.has_permission("platform.admin"), (
        "PSP actor must not hold platform.admin — self-administration is prohibited"
    )


def test_human_operator_actor_can_hold_platform_admin() -> None:
    """An internal operator ActorContext with platform.admin can reach admin routes."""
    from api.actor_context import ActorContext

    operator_actor = ActorContext(
        subject="operator@frostgate.io",
        email="operator@frostgate.io",
        name="Internal Operator",
        permissions=frozenset(["platform.admin"]),
        roles=["internal_operator"],
        auth_source="oidc_auth0",
        tenant_id="frostgate-internal",
    )
    assert operator_actor.has_permission("platform.admin")


def test_customer_actor_lacks_platform_admin() -> None:
    """Customer tenant actor does not have platform.admin."""
    from api.actor_context import ActorContext

    customer_actor = ActorContext(
        subject="customer-user@example.com",
        email="customer-user@example.com",
        name="Customer",
        permissions=frozenset(["assessment.create", "finding.view"]),
        roles=["client_user"],
        auth_source="oidc_auth0",
        tenant_id="customer-a",
    )
    assert not customer_actor.has_permission("platform.admin")


def test_require_permission_denies_missing_platform_admin() -> None:
    """require_permission('platform.admin') raises 403 for actors without it."""
    from fastapi import HTTPException

    from api.auth_dispatch import require_permission
    from api.actor_context import ActorContext

    psp_actor = ActorContext(
        subject="system:psp",
        email="",
        name="PSP",
        permissions=frozenset(PLATFORM_SERVICE_DEFAULT_PERMISSIONS),
        roles=[],
        auth_source="api_key",
        tenant_id="frostgate-internal",
    )
    dep = require_permission("platform.admin")
    with pytest.raises(HTTPException) as exc_info:
        dep(psp_actor)
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail["code"] == "PERMISSION_DENIED"


# ── Target-tenant authorization enforcement tests ─────────────────────────────


def test_psp_permission_does_not_bypass_target_tenant_authorization(
    engine_with_authority: Engine,
) -> None:
    """platform.tenants.operate does not bypass target-tenant enforcement.

    A nonexistent target tenant must be denied even when the PSP holds the
    required permission — the PSP cannot operate on tenants that don't exist.
    """
    bootstrap_platform_service_principal(engine_with_authority)

    result = authorize_service_principal(
        engine_with_authority,
        actor_id="workload",
        permission="platform.tenants.operate",
        target_tenant_id="nonexistent-customer",
    )

    assert result.allowed is False
    assert result.denial_code in ("TARGET_TENANT_NOT_FOUND", "TARGET_TENANT_NOT_ACTIVE")


def test_psp_authorization_requires_explicit_target_tenant(
    engine_with_authority: Engine,
) -> None:
    """authorize_service_principal denies when target_tenant_id is None."""
    bootstrap_platform_service_principal(engine_with_authority)

    result = authorize_service_principal(
        engine_with_authority,
        actor_id="workload",
        permission="platform.tenants.read",
        target_tenant_id=None,
    )

    assert result.allowed is False
    assert result.denial_code == "TARGET_TENANT_REQUIRED"


def test_psp_authorization_denies_empty_target_tenant(
    engine_with_authority: Engine,
) -> None:
    """authorize_service_principal denies when target_tenant_id is empty string."""
    bootstrap_platform_service_principal(engine_with_authority)

    result = authorize_service_principal(
        engine_with_authority,
        actor_id="workload",
        permission="platform.tenants.read",
        target_tenant_id="",
    )

    assert result.allowed is False
    assert result.denial_code == "TARGET_TENANT_REQUIRED"


def test_psp_authority_tenant_cannot_be_target_tenant(
    engine_with_authority: Engine,
) -> None:
    """The platform authority tenant cannot be used as target_tenant_id.

    Prevents authority_tenant_id from silently becoming the target, which
    would allow the PSP to issue operations against its own authority tenant.
    """
    bootstrap_platform_service_principal(engine_with_authority)

    result = authorize_service_principal(
        engine_with_authority,
        actor_id="workload",
        permission="platform.tenants.read",
        target_tenant_id="frostgate-internal",
    )

    assert result.allowed is False
    assert result.denial_code == "AUTHORITY_TENANT_CANNOT_BE_TARGET"


def test_psp_authorization_denied_for_suspended_target_tenant(
    engine_with_authority: Engine,
) -> None:
    """Suspended target tenant is denied — PSP must not operate on suspended tenants."""
    repo = TenantRepository(engine_with_authority)
    repo.create("suspended-customer", "Suspended Customer", tenant_kind="customer")
    repo.set_lifecycle_state("suspended-customer", "suspended")
    bootstrap_platform_service_principal(engine_with_authority)

    result = authorize_service_principal(
        engine_with_authority,
        actor_id="workload",
        permission="platform.tenants.read",
        target_tenant_id="suspended-customer",
    )

    assert result.allowed is False
    assert result.denial_code is not None
    assert (
        "SUSPENDED" in result.denial_code
        or "NOT_ACTIVE" in result.denial_code
        or result.denial_code == "TARGET_TENANT_SUSPENDED"
    )


def test_psp_authorization_denied_for_archived_target_tenant(
    engine_with_authority: Engine,
) -> None:
    """Archived target tenant is denied."""
    repo = TenantRepository(engine_with_authority)
    repo.create("archived-customer", "Archived Customer", tenant_kind="customer")
    repo.set_lifecycle_state("archived-customer", "archived")
    bootstrap_platform_service_principal(engine_with_authority)

    result = authorize_service_principal(
        engine_with_authority,
        actor_id="workload",
        permission="platform.tenants.read",
        target_tenant_id="archived-customer",
    )

    assert result.allowed is False
    assert result.denial_code is not None


# ── Concurrent bootstrap (race condition) tests ───────────────────────────────


def test_concurrent_bootstrap_race_returns_reused(
    engine_with_authority: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IntegrityError from concurrent INSERT is resolved to 'reused', not 'conflict'.

    Simulates the concurrent race: _fetch_by_stable_key returns None on first
    call (as if the PSP didn't exist yet), causing bootstrap to attempt INSERT.
    Since another concurrent bootstrapper already created the PSP, the INSERT
    raises IntegrityError.  The new code reloads the existing record, validates
    the authority binding matches, and returns 'reused' — not 'conflict'.
    Note: Postgres partial unique index behavior and row locking are exercised
    only in the full Postgres integration test suite (requires live Postgres).
    """
    import api.platform_service_principal as psp_mod

    # Pre-create the PSP (simulates the winner of the concurrent race).
    first = bootstrap_platform_service_principal(engine_with_authority)
    assert first.status == "created"

    original_fetch = psp_mod._fetch_by_stable_key
    call_count = [0]

    def patched_fetch(conn: object, stable_key: str) -> object:
        call_count[0] += 1
        if call_count[0] == 1:
            # Pretend PSP doesn't exist → bootstrap will attempt INSERT
            return None
        # Subsequent calls (reload after IntegrityError) return the real record
        return original_fetch(conn, stable_key)  # type: ignore[arg-type]

    monkeypatch.setattr(psp_mod, "_fetch_by_stable_key", patched_fetch)

    result = bootstrap_platform_service_principal(engine_with_authority)

    # Must be "reused" — not "conflict" — because the existing PSP matches the authority
    assert result.status == "reused", (
        f"Expected 'reused' after concurrent race, got {result.status!r}. "
        "IntegrityError from a concurrent same-authority bootstrap must resolve to reused."
    )
    assert result.credential_issued is False


# ── Credential rotation atomicity tests ──────────────────────────────────────


def test_rotation_no_two_active_credentials(engine_with_authority: Engine) -> None:
    """After rotation exactly one active credential exists for the PSP slot."""
    bootstrap_platform_service_principal(engine_with_authority)
    rotate_service_principal_credential(engine_with_authority, actor_id="admin")

    with engine_with_authority.connect() as conn:
        active_count = conn.execute(
            text(
                "SELECT COUNT(*) FROM tenant_credentials "
                "WHERE credential_slot = :slot AND status = 'active'"
            ),
            {"slot": PSP_CREDENTIAL_SLOT},
        ).scalar_one()

    assert active_count == 1, (
        f"Expected exactly 1 active credential after rotation, found {active_count}"
    )


def test_rotation_old_credential_no_longer_active(
    engine_with_authority: Engine,
) -> None:
    """Old credential transitions out of 'active' after rotation."""
    result = bootstrap_platform_service_principal(engine_with_authority)
    old_cred_id = result.credential_id
    assert old_cred_id is not None

    rotate_service_principal_credential(engine_with_authority, actor_id="admin")

    with engine_with_authority.connect() as conn:
        old_status = conn.execute(
            text("SELECT status FROM tenant_credentials WHERE credential_id = :id"),
            {"id": old_cred_id},
        ).scalar_one()

    assert old_status != "active", (
        f"Old credential {old_cred_id!r} is still active after rotation"
    )


def test_rotation_response_contains_no_raw_secret(
    engine_with_authority: Engine,
) -> None:
    """rotate_service_principal_credential returns no secret material."""
    bootstrap_platform_service_principal(engine_with_authority)
    status = rotate_service_principal_credential(
        engine_with_authority, actor_id="admin"
    )
    d = status.safe_dict()

    forbidden_keys = {
        "secret",
        "raw_secret",
        "plaintext_secret",
        "credential_value",
        "api_key",
        "token",
        "password",
        "secret_hash",
        "lookup_fingerprint",
    }
    for key in d:
        assert key not in forbidden_keys, (
            f"Forbidden field {key!r} found in rotation response"
        )
    for val in d.values():
        if isinstance(val, str):
            assert "fgk." not in val, (
                f"Raw key material (fgk. prefix) found in rotation response value: {val!r}"
            )


# ── Route-level secret scanning tests ────────────────────────────────────────


_SECRET_FIELD_NAMES = {
    "secret",
    "raw_secret",
    "plaintext_secret",
    "credential_value",
    "api_key",
    "token",
    "password",
    "secret_hash",
    "lookup_fingerprint",
}


def _assert_no_secrets_in_dict(d: dict, label: str) -> None:
    for key in d:
        assert key not in _SECRET_FIELD_NAMES, (
            f"[{label}] Forbidden field {key!r} in response"
        )
    for val in d.values():
        if isinstance(val, str):
            assert "fgk." not in val, (
                f"[{label}] Raw key material in value for field containing: {val!r}"
            )
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    assert "fgk." not in item


def test_get_status_response_contains_no_secrets(engine_with_authority: Engine) -> None:
    """GET /system/service-principal response body contains no secret material."""
    bootstrap_platform_service_principal(engine_with_authority)
    status = read_service_principal_status(engine_with_authority)
    _assert_no_secrets_in_dict(status.safe_dict(), "GET status")


def test_rotate_response_contains_no_secrets(engine_with_authority: Engine) -> None:
    """POST /system/service-principal/rotate response body contains no secret material."""
    bootstrap_platform_service_principal(engine_with_authority)
    status = rotate_service_principal_credential(
        engine_with_authority, actor_id="admin"
    )
    _assert_no_secrets_in_dict(status.safe_dict(), "rotate response")


def test_lifecycle_responses_contain_no_secrets(engine_with_authority: Engine) -> None:
    """Suspend/resume lifecycle response bodies contain no secret material."""
    bootstrap_platform_service_principal(engine_with_authority)
    suspend_status = suspend_service_principal(engine_with_authority, actor_id="admin")
    _assert_no_secrets_in_dict(suspend_status.safe_dict(), "suspend response")
    resume_status = resume_service_principal(engine_with_authority, actor_id="admin")
    _assert_no_secrets_in_dict(resume_status.safe_dict(), "resume response")


def test_audit_events_no_secret_fields(engine_with_authority: Engine) -> None:
    """Audit events never contain any secret field names or key material."""
    bootstrap_platform_service_principal(engine_with_authority)
    rotate_service_principal_credential(engine_with_authority, actor_id="admin")

    with engine_with_authority.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT event_type, metadata, failure_reason, actor_id, service_id "
                "FROM platform_service_principal_events"
            )
        ).fetchall()

    for row in rows:
        for field_val in row:
            s = str(field_val or "").lower()
            for forbidden in ("fgk.", "raw_secret", "plaintext_secret"):
                assert forbidden not in s, (
                    f"Forbidden pattern {forbidden!r} in audit event field: {field_val!r}"
                )
            # Check that metadata JSON doesn't contain forbidden keys
            if field_val and isinstance(field_val, str) and field_val.startswith("{"):
                try:
                    parsed = json.loads(field_val)
                    for k in parsed:
                        assert k not in _SECRET_FIELD_NAMES, (
                            f"Secret field {k!r} found in audit event metadata"
                        )
                except (ValueError, TypeError):
                    pass
