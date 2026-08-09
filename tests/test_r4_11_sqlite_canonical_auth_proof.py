"""R4.11 step-1 proof: canonical fgk.* auth + RBAC works in SQLite via real init_db.

Verifies the _is_postgres gate removal in resolution.py does not break the
canonical credential path and that the full chain works on SQLite:

  issue_credential() → tenant_credentials write
  resolve_key()      → tenant_credentials read (not api_keys)
  get_credential_role() → tenant_credential_roles read

All through the real init_db / get_engine() flow, not a custom in-memory schema.
"""

from __future__ import annotations

import os
import tempfile
from unittest.mock import patch

import pytest

from api.credential_authority import issue_credential
from api.auth_scopes.resolution import verify_api_key_detailed
from api.auth_scopes.definitions import AuthResult
from api.tenant_rbac import assign_role, get_credential_role


@pytest.fixture()
def sqlite_env(tmp_path, monkeypatch):
    """Spin up a real SQLite db via init_db and point the app at it."""
    db_path = str(tmp_path / "proof.db")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_DB_BACKEND", "sqlite")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("FG_DB_URL", raising=False)

    # Import after env is set so engine cache picks up the new path.
    from api.db import reset_engine_cache, get_engine, init_db

    reset_engine_cache()
    init_db(sqlite_path=db_path)
    engine = get_engine()

    # Seed a tenant row so credential issuance and RLS-equivalent checks pass.
    from sqlalchemy import text
    with engine.begin() as conn:
        conn.execute(
            text("INSERT OR IGNORE INTO tenants (tenant_id, lifecycle_state) VALUES (:tid, 'active')"),
            {"tid": "proof-tenant"},
        )

    yield engine

    reset_engine_cache()


def test_canonical_issue_and_resolve(sqlite_env, monkeypatch):
    """Full chain: issue → resolve → no api_keys read."""
    engine = sqlite_env
    monkeypatch.setenv("FG_KEY_PEPPER", "r4-11-proof-pepper")

    result = issue_credential(
        engine,
        tenant_id="proof-tenant",
        credential_type="tenant_api_key",
        credential_slot="proof:v1",
    )
    assert result.plaintext_secret is not None
    raw_key = result.plaintext_secret

    # Resolve through the real resolution path.
    auth = verify_api_key_detailed(raw=raw_key, required_scopes=None)

    assert isinstance(auth, AuthResult)
    assert auth.valid, f"Expected valid=True, got reason={auth.reason!r}"
    assert auth.reason == "canonical_validated"
    assert auth.tenant_id == "proof-tenant"
    assert auth.credential_id is not None


def test_canonical_rbac_resolve(sqlite_env, monkeypatch):
    """Role assigned in tenant_credential_roles is readable after canonical auth."""
    from sqlalchemy.orm import Session
    engine = sqlite_env
    monkeypatch.setenv("FG_KEY_PEPPER", "r4-11-proof-pepper")

    result = issue_credential(
        engine,
        tenant_id="proof-tenant",
        credential_type="tenant_api_key",
        credential_slot="proof-rbac:v1",
    )
    cred_id = result.record.credential_id

    with Session(engine) as session:
        assign_role(
            session,
            tenant_id="proof-tenant",
            actor_key_prefix="pytest",
            credential_id=cred_id,
            role_name="analyst",
        )
        session.commit()

        role = get_credential_role(session, tenant_id="proof-tenant", credential_id=cred_id)

    assert role == "analyst"


def test_no_api_keys_read_during_canonical_auth(sqlite_env, monkeypatch):
    """Canonical resolution must not touch api_keys table."""
    from sqlalchemy import event as sa_event

    engine = sqlite_env
    monkeypatch.setenv("FG_KEY_PEPPER", "r4-11-proof-pepper")

    result = issue_credential(
        engine,
        tenant_id="proof-tenant",
        credential_type="tenant_api_key",
        credential_slot="proof-nokeys:v1",
    )
    raw_key = result.plaintext_secret

    # Use a SQLAlchemy execution event so the listener fires on the already-open
    # engine pool connection — reliable regardless of connection reuse.
    api_keys_reads: list[str] = []

    def _before_exec(conn, cursor, statement, parameters, context, executemany):
        if "api_keys" in statement.lower():
            api_keys_reads.append(statement.strip()[:120])

    sa_event.listen(engine, "before_cursor_execute", _before_exec)
    try:
        auth = verify_api_key_detailed(raw=raw_key, required_scopes=None)
    finally:
        sa_event.remove(engine, "before_cursor_execute", _before_exec)

    assert auth.valid, f"Auth failed: {auth.reason}"
    assert api_keys_reads == [], (
        "Canonical auth unexpectedly read api_keys:\n" + "\n".join(api_keys_reads)
    )
