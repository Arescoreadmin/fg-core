"""PR-AUTH-001 — Principal + ExternalIdentity foundation tests.

All tests run against SQLite in-memory using the canonical schema for
fg_principals and fg_external_identities (migrations 0179 + 0180).

Coverage groups:
  A — Schema invariants (source-level)
  B — create_principal: happy path and type validation
  C — bind_external_identity: happy path and duplicate rejection
  D — resolve_external_identity: found, not found, inactive principal
  E — touch_external_identity_seen: best-effort update
  F — Cross-table invariant: principal cannot be deleted while binding exists
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

import api.principal_authority as pa
from api.principal_authority import (
    ExternalIdentityRecord,
    PrincipalRecord,
    bind_external_identity,
    create_principal,
    resolve_external_identity,
    touch_external_identity_seen,
)

# ---------------------------------------------------------------------------
# SQLite schema (mirrors migrations 0179 + 0180)
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS fg_principals (
    id                TEXT        PRIMARY KEY,
    display_name      TEXT,
    primary_email     TEXT,
    principal_type    TEXT        NOT NULL DEFAULT 'human',
    lifecycle_state   TEXT        NOT NULL DEFAULT 'active',
    mfa_verified      INTEGER     NOT NULL DEFAULT 0,
    authority_version INTEGER     NOT NULL DEFAULT 1,
    created_at        TEXT        NOT NULL,
    updated_at        TEXT        NOT NULL
);

CREATE TABLE IF NOT EXISTS fg_external_identities (
    id               TEXT        PRIMARY KEY,
    principal_id     TEXT        NOT NULL REFERENCES fg_principals(id),
    provider         TEXT        NOT NULL,
    provider_issuer  TEXT        NOT NULL,
    provider_subject TEXT        NOT NULL,
    provider_email   TEXT,
    created_at       TEXT        NOT NULL,
    last_seen_at     TEXT,
    UNIQUE (provider, provider_issuer, provider_subject)
);
"""


def _setup_schema(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("PRAGMA foreign_keys = ON"))
        for stmt in _SCHEMA.split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(text(stmt))


@pytest.fixture()
def engine() -> Engine:
    eng = create_engine("sqlite:///:memory:", echo=False)
    _setup_schema(eng)

    @__import__("sqlalchemy").event.listens_for(eng, "connect")
    def _fk_on(dbapi_con, _rec):
        dbapi_con.execute("PRAGMA foreign_keys = ON")

    return eng


# ---------------------------------------------------------------------------
# A — Schema invariants (source-level)
# ---------------------------------------------------------------------------

_PA_SRC = (
    __import__("pathlib").Path("api/principal_authority.py").read_text(encoding="utf-8")
)
_MODELS_SRC = (
    __import__("pathlib").Path("api/db_models_principal.py").read_text(encoding="utf-8")
)


def test_A1_principal_authority_module_exists() -> None:
    assert "def create_principal(" in _PA_SRC
    assert "def bind_external_identity(" in _PA_SRC
    assert "def resolve_external_identity(" in _PA_SRC


def test_A2_valid_providers_constant_matches_schema() -> None:
    assert "auth0" in pa._VALID_PROVIDERS
    assert "entra" in pa._VALID_PROVIDERS
    assert "okta" in pa._VALID_PROVIDERS
    assert "saml" in pa._VALID_PROVIDERS
    assert "oidc_generic" in pa._VALID_PROVIDERS


def test_A3_orm_models_present() -> None:
    assert "class FgPrincipal(Base):" in _MODELS_SRC
    assert "class FgExternalIdentity(Base):" in _MODELS_SRC
    assert "uq_fg_external_identities_binding" in _MODELS_SRC


def test_A4_no_rls_in_migrations() -> None:
    """fg_principals and fg_external_identities have no RLS."""
    m179 = (
        __import__("pathlib")
        .Path("migrations/postgres/0179_fg_principals.sql")
        .read_text(encoding="utf-8")
    )
    m180 = (
        __import__("pathlib")
        .Path("migrations/postgres/0180_fg_external_identities.sql")
        .read_text(encoding="utf-8")
    )
    assert "ENABLE ROW LEVEL SECURITY" not in m179
    assert "ENABLE ROW LEVEL SECURITY" not in m180


def test_A5_db_py_registers_principal_models() -> None:
    db_src = __import__("pathlib").Path("api/db.py").read_text(encoding="utf-8")
    assert "db_models_principal" in db_src


# ---------------------------------------------------------------------------
# B — create_principal
# ---------------------------------------------------------------------------


def test_B1_create_principal_returns_record(engine: Engine) -> None:
    with engine.begin() as conn:
        p = create_principal(
            conn, display_name="Alice", primary_email="alice@example.com"
        )
    assert isinstance(p, PrincipalRecord)
    assert p.principal_type == "human"
    assert p.lifecycle_state == "active"
    assert p.authority_version == 1
    assert p.mfa_verified is False
    assert p.primary_email == "alice@example.com"
    assert p.display_name == "Alice"


def test_B2_create_principal_persists_to_db(engine: Engine) -> None:
    with engine.begin() as conn:
        p = create_principal(conn, primary_email="bob@example.com")
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT id, lifecycle_state FROM fg_principals WHERE id = :id"),
            {"id": p.id},
        ).fetchone()
    assert row is not None
    assert row.lifecycle_state == "active"


def test_B3_create_principal_null_optional_fields(engine: Engine) -> None:
    with engine.begin() as conn:
        p = create_principal(conn)
    assert p.display_name is None
    assert p.primary_email is None


def test_B4_create_principal_rejects_non_human_type(engine: Engine) -> None:
    with engine.begin() as conn:
        with pytest.raises(ValueError, match="Unsupported principal_type"):
            create_principal(conn, principal_type="service")


def test_B5_create_principal_ids_are_unique(engine: Engine) -> None:
    with engine.begin() as conn:
        p1 = create_principal(conn)
        p2 = create_principal(conn)
    assert p1.id != p2.id


# ---------------------------------------------------------------------------
# C — bind_external_identity
# ---------------------------------------------------------------------------


def test_C1_bind_external_identity_returns_record(engine: Engine) -> None:
    with engine.begin() as conn:
        p = create_principal(conn)
        ei = bind_external_identity(
            conn,
            principal_id=p.id,
            provider="auth0",
            provider_issuer="https://example.auth0.com/",
            provider_subject="auth0|abc123",
            provider_email="alice@example.com",
        )
    assert isinstance(ei, ExternalIdentityRecord)
    assert ei.principal_id == p.id
    assert ei.provider == "auth0"
    assert ei.provider_email == "alice@example.com"


def test_C2_bind_external_identity_persists(engine: Engine) -> None:
    with engine.begin() as conn:
        p = create_principal(conn)
        ei = bind_external_identity(
            conn,
            principal_id=p.id,
            provider="auth0",
            provider_issuer="https://example.auth0.com/",
            provider_subject="auth0|abc123",
        )
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT principal_id FROM fg_external_identities WHERE id = :id"),
            {"id": ei.id},
        ).fetchone()
    assert row.principal_id == p.id


def test_C3_global_uniqueness_constraint_enforced(engine: Engine) -> None:
    """The same IdP identity cannot be bound to two principals."""
    with engine.begin() as conn:
        p1 = create_principal(conn)
        p2 = create_principal(conn)
        bind_external_identity(
            conn,
            principal_id=p1.id,
            provider="auth0",
            provider_issuer="https://example.auth0.com/",
            provider_subject="auth0|same-sub",
        )
        with pytest.raises(Exception):
            bind_external_identity(
                conn,
                principal_id=p2.id,
                provider="auth0",
                provider_issuer="https://example.auth0.com/",
                provider_subject="auth0|same-sub",
            )


def test_C4_different_providers_same_subject_allowed(engine: Engine) -> None:
    """Different providers with the same subject string are distinct identities."""
    with engine.begin() as conn:
        p1 = create_principal(conn)
        p2 = create_principal(conn)
        ei1 = bind_external_identity(
            conn,
            principal_id=p1.id,
            provider="auth0",
            provider_issuer="https://example.auth0.com/",
            provider_subject="sub-001",
        )
        ei2 = bind_external_identity(
            conn,
            principal_id=p2.id,
            provider="entra",
            provider_issuer="https://login.microsoftonline.com/tenant/",
            provider_subject="sub-001",
        )
    assert ei1.id != ei2.id


def test_C5_invalid_provider_rejected(engine: Engine) -> None:
    with engine.begin() as conn:
        p = create_principal(conn)
        with pytest.raises(ValueError, match="Unknown provider"):
            bind_external_identity(
                conn,
                principal_id=p.id,
                provider="unknown_idp",
                provider_issuer="https://example.com/",
                provider_subject="sub",
            )


# ---------------------------------------------------------------------------
# D — resolve_external_identity
# ---------------------------------------------------------------------------


def test_D1_resolve_returns_records_for_active_principal(engine: Engine) -> None:
    with engine.begin() as conn:
        p = create_principal(conn, display_name="Carol")
        bind_external_identity(
            conn,
            principal_id=p.id,
            provider="auth0",
            provider_issuer="https://example.auth0.com/",
            provider_subject="auth0|carol",
        )
    with engine.connect() as conn:
        result = resolve_external_identity(
            conn,
            provider="auth0",
            provider_issuer="https://example.auth0.com/",
            provider_subject="auth0|carol",
        )
    assert result is not None
    ei, principal = result
    assert principal.id == p.id
    assert principal.lifecycle_state == "active"
    assert ei.provider == "auth0"


def test_D2_resolve_returns_none_for_unknown_identity(engine: Engine) -> None:
    with engine.connect() as conn:
        result = resolve_external_identity(
            conn,
            provider="auth0",
            provider_issuer="https://example.auth0.com/",
            provider_subject="auth0|ghost",
        )
    assert result is None


def test_D3_suspended_principal_returns_none(engine: Engine) -> None:
    """Inactive principal at any lifecycle state → DENY (authority graph invariant)."""
    with engine.begin() as conn:
        p = create_principal(conn)
        bind_external_identity(
            conn,
            principal_id=p.id,
            provider="auth0",
            provider_issuer="https://example.auth0.com/",
            provider_subject="auth0|suspended",
        )
        conn.execute(
            text(
                "UPDATE fg_principals SET lifecycle_state = 'suspended' WHERE id = :id"
            ),
            {"id": p.id},
        )
    with engine.connect() as conn:
        result = resolve_external_identity(
            conn,
            provider="auth0",
            provider_issuer="https://example.auth0.com/",
            provider_subject="auth0|suspended",
        )
    assert result is None


def test_D4_resolve_rejects_invalid_provider(engine: Engine) -> None:
    with engine.connect() as conn:
        with pytest.raises(ValueError, match="Unknown provider"):
            resolve_external_identity(
                conn,
                provider="bad_provider",
                provider_issuer="https://x.com/",
                provider_subject="sub",
            )


# ---------------------------------------------------------------------------
# E — touch_external_identity_seen
# ---------------------------------------------------------------------------


def test_E1_touch_updates_last_seen_at(engine: Engine) -> None:
    with engine.begin() as conn:
        p = create_principal(conn)
        bind_external_identity(
            conn,
            principal_id=p.id,
            provider="auth0",
            provider_issuer="https://example.auth0.com/",
            provider_subject="auth0|touch-me",
        )
    with engine.begin() as conn:
        touch_external_identity_seen(
            conn,
            provider="auth0",
            provider_issuer="https://example.auth0.com/",
            provider_subject="auth0|touch-me",
        )
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT last_seen_at FROM fg_external_identities"
                " WHERE provider_subject = 'auth0|touch-me'"
            )
        ).fetchone()
    assert row.last_seen_at is not None


def test_E2_touch_nonexistent_does_not_raise(engine: Engine) -> None:
    with engine.begin() as conn:
        touch_external_identity_seen(
            conn,
            provider="auth0",
            provider_issuer="https://example.auth0.com/",
            provider_subject="auth0|nobody",
        )


# ---------------------------------------------------------------------------
# F — Cross-table invariant
# ---------------------------------------------------------------------------


def test_F1_principal_cannot_be_deleted_while_binding_exists(
    engine: Engine,
) -> None:
    with engine.begin() as conn:
        p = create_principal(conn)
        bind_external_identity(
            conn,
            principal_id=p.id,
            provider="auth0",
            provider_issuer="https://example.auth0.com/",
            provider_subject="auth0|protected",
        )
    with engine.begin() as conn:
        with pytest.raises(Exception):
            conn.execute(
                text("DELETE FROM fg_principals WHERE id = :id"),
                {"id": p.id},
            )
