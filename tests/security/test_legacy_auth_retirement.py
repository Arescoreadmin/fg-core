"""R4.9 — Legacy api_keys authority retirement regression tests.

Two invariants proved here:

  LA-1  Non-fgk key on Postgres returns key_not_found — the R4.8 Postgres guard
        holds and has not been regressed by R4.9 cleanup.

  LA-2  Canonical credential issued via credential_authority validates correctly —
        the R4.9 cleanup did not break the canonical issuance/validation path.

Neither test requires a live Postgres connection. LA-1 exercises the early-return
branch in resolution.py by simulating the Postgres environment via env-var patch.
LA-2 uses an in-memory SQLite engine with the tenant_credentials schema to prove
the credential authority layer works end-to-end.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Minimal schema for LA-2 (must match what credential_authority expects)
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

_TENANT = "r4-9-la-tenant-01"


@pytest.fixture
def mem_engine():
    from sqlalchemy import create_engine, text

    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    with engine.begin() as conn:
        for stmt in _SCHEMA.split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(text(stmt))
    return engine


# ---------------------------------------------------------------------------
# LA-1: Non-fgk key on Postgres returns key_not_found
# ---------------------------------------------------------------------------


def test_la1_postgres_legacy_key_returns_key_not_found(monkeypatch):
    """Non-fgk key on Postgres hits the R4.8 early-return guard → key_not_found."""
    monkeypatch.setenv("FG_DB_BACKEND", "postgres")
    monkeypatch.setenv("FG_ENV", "test")

    from api.auth_scopes.resolution import verify_api_key_detailed

    result = verify_api_key_detailed(raw="legacyprefix.sometoken.somesecret")

    assert not result.valid, "legacy key must not authenticate on Postgres"
    assert result.reason == "key_not_found", (
        f"expected key_not_found, got: {result.reason!r} — "
        "R4.8 Postgres guard may have been regressed"
    )


# ---------------------------------------------------------------------------
# LA-2: Canonical credential issued via authority validates correctly
# ---------------------------------------------------------------------------


def test_la2_canonical_credential_issues_and_validates(mem_engine, monkeypatch):
    """issue_credential → validate_credential round-trip proves authority path intact."""
    monkeypatch.setenv("FG_ENV", "test")

    from sqlalchemy import text

    from api.credential_authority import issue_credential, validate_credential

    with mem_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, lifecycle_state) VALUES (:tid, 'active')"
            ),
            {"tid": _TENANT},
        )

    result = issue_credential(
        mem_engine,
        tenant_id=_TENANT,
        credential_type="tenant_api_key",
        credential_slot="default",
        actor_id="test-actor",
        request_id="la2-req-01",
        idempotency_key="la2-idem-01",
    )

    assert result.plaintext_secret is not None, "issued credential must have a secret"
    assert result.plaintext_secret.startswith("fgk."), (
        f"canonical credential must start with fgk., got: {result.plaintext_secret[:12]!r}"
    )

    from api.credential_authority import CredentialNotFoundError

    try:
        principal = validate_credential(
            mem_engine,
            raw_key=result.plaintext_secret,
            credential_type="tenant_api_key",
        )
    except CredentialNotFoundError as exc:
        raise AssertionError(
            f"canonical credential must validate; got CredentialNotFoundError: {exc}"
        ) from exc

    assert principal.tenant_id == _TENANT
