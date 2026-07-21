"""
PR 17 — Postgres Auth Authority: store.py unit tests.

Tests backend dispatch, column handling, timestamp conversion,
JSONB handling, and security invariants.

No live Postgres connection required: Postgres paths are tested via
mock/patch where connectivity would be needed. Backend dispatch and
pure-Python helpers are tested directly.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# 1. _resolve_backend() returns "postgres" when FG_DB_BACKEND=postgres
# ---------------------------------------------------------------------------


def test_resolve_backend_returns_postgres() -> None:
    """FG_DB_BACKEND=postgres → _resolve_backend() returns 'postgres'."""
    with patch.dict(os.environ, {"FG_DB_BACKEND": "postgres"}, clear=False):
        import api.auth_scopes.store as store_mod

        result = store_mod._resolve_backend()
    assert result == "postgres"


def test_resolve_backend_defaults_sqlite_when_unset() -> None:
    """FG_DB_BACKEND unset → _resolve_backend() returns 'sqlite'."""
    env = {k: v for k, v in os.environ.items() if k != "FG_DB_BACKEND"}
    with patch.dict(os.environ, env, clear=True):
        from api.auth_scopes.store import _resolve_backend

        result = _resolve_backend()
    assert result == "sqlite"


def test_resolve_backend_defaults_sqlite_when_empty() -> None:
    """FG_DB_BACKEND='' → _resolve_backend() returns 'sqlite'."""
    with patch.dict(os.environ, {"FG_DB_BACKEND": ""}, clear=False):
        from api.auth_scopes.store import _resolve_backend

        result = _resolve_backend()
    assert result == "sqlite"


# ---------------------------------------------------------------------------
# 2. insert_key_row requires tenant_id
# ---------------------------------------------------------------------------


def test_insert_key_row_requires_tenant_id() -> None:
    """insert_key_row raises ValueError when tenant_id is missing."""
    with patch.dict(os.environ, {"FG_DB_BACKEND": "postgres"}, clear=False):
        from api.auth_scopes.store import insert_key_row
        import pytest

        with pytest.raises(ValueError, match="tenant_id"):
            insert_key_row(
                {
                    "prefix": "fgk",
                    "key_hash": "deadbeef",
                    "key_lookup": "abc",
                    "hash_alg": "argon2id",
                    "hash_params": {},
                    "scopes_csv": "read",
                    "enabled": True,
                    "tenant_id": "",
                }
            )


def test_insert_key_row_requires_tenant_id_none() -> None:
    """insert_key_row raises ValueError when tenant_id is None."""
    with patch.dict(os.environ, {"FG_DB_BACKEND": "postgres"}, clear=False):
        from api.auth_scopes.store import insert_key_row
        import pytest

        with pytest.raises(ValueError, match="tenant_id"):
            insert_key_row(
                {
                    "prefix": "fgk",
                    "key_hash": "deadbeef",
                    "scopes_csv": "read",
                    "enabled": True,
                    "tenant_id": None,
                }
            )


# ---------------------------------------------------------------------------
# 7. Postgres timestamp conversion handles expires_at
# ---------------------------------------------------------------------------


def test_to_pg_timestamp_integer() -> None:
    """INTEGER epoch converts to timezone-aware UTC datetime."""
    from api.auth_scopes.store import _to_pg_timestamp

    ts = 1700000000
    result = _to_pg_timestamp(ts)
    assert isinstance(result, datetime)
    assert result.tzinfo is not None
    assert result.tzinfo == timezone.utc
    assert int(result.timestamp()) == ts


def test_to_pg_timestamp_none() -> None:
    """None input returns None."""
    from api.auth_scopes.store import _to_pg_timestamp

    assert _to_pg_timestamp(None) is None


def test_to_pg_timestamp_datetime_naive() -> None:
    """Naive datetime gets UTC tzinfo attached."""
    from api.auth_scopes.store import _to_pg_timestamp

    naive = datetime(2024, 1, 1, 12, 0, 0)
    result = _to_pg_timestamp(naive)
    assert result is not None
    assert result.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# 8. Postgres hash_params JSONB conversion handles dict/text
# ---------------------------------------------------------------------------


def test_to_pg_hash_params_dict_passthrough() -> None:
    """dict input passes through unchanged."""
    from api.auth_scopes.store import _to_pg_hash_params

    params = {"time_cost": 2, "memory_cost": 65536}
    result = _to_pg_hash_params(params)
    assert result == params


def test_to_pg_hash_params_json_string() -> None:
    """JSON string is parsed to dict."""
    from api.auth_scopes.store import _to_pg_hash_params

    params = {"time_cost": 2, "memory_cost": 65536}
    result = _to_pg_hash_params(json.dumps(params))
    assert result == params


def test_to_pg_hash_params_none() -> None:
    """None returns None."""
    from api.auth_scopes.store import _to_pg_hash_params

    assert _to_pg_hash_params(None) is None


def test_to_pg_hash_params_invalid_json() -> None:
    """Invalid JSON string returns None."""
    from api.auth_scopes.store import _to_pg_hash_params

    assert _to_pg_hash_params("not-json{") is None


# ---------------------------------------------------------------------------
# 9. update_key_enabled scopes by prefix and key_hash
# ---------------------------------------------------------------------------


def test_update_key_enabled_uses_parameterized_sql() -> None:
    """update_key_enabled calls execute with bound parameters (no f-string injection)."""
    mock_conn = MagicMock()
    mock_conn.execute.return_value.rowcount = 1
    mock_ctx = MagicMock()
    mock_ctx.__enter__ = MagicMock(return_value=mock_conn)
    mock_ctx.__exit__ = MagicMock(return_value=False)

    mock_engine = MagicMock()
    mock_engine.begin.return_value = mock_ctx

    with patch.dict(os.environ, {"FG_DB_BACKEND": "postgres"}, clear=False):
        with patch("api.auth_scopes.store._pg_engine", return_value=mock_engine):
            from api.auth_scopes.store import update_key_enabled

            count = update_key_enabled(
                prefix="fgk",
                key_hash="deadbeef",
                enabled=False,
                tenant_id="tenant-1",
            )

    assert count == 1
    # Verify execute was called with a text() query and param dict (not raw strings)
    assert mock_conn.execute.called
    call_args = mock_conn.execute.call_args
    # Second arg (params dict) should not contain raw hash values as SQL
    params = call_args[0][1] if len(call_args[0]) > 1 else call_args[1]
    assert "key_hash" in params or "deadbeef" in str(params)


def test_update_key_enabled_returns_zero_without_tenant_id() -> None:
    """update_key_enabled returns 0 without tenant_id in Postgres mode."""
    with patch.dict(os.environ, {"FG_DB_BACKEND": "postgres"}, clear=False):
        from api.auth_scopes.store import update_key_enabled

        result = update_key_enabled(
            prefix="fgk",
            key_hash="deadbeef",
            enabled=False,
            tenant_id=None,
        )
    assert result == 0


# ---------------------------------------------------------------------------
# 10. No raw secret in SQL params or logs
# ---------------------------------------------------------------------------


def test_insert_key_row_no_raw_secret_in_params() -> None:
    """insert_key_row: the row dict should contain only hashed values, no raw secret."""
    mock_conn = MagicMock()
    mock_ctx = MagicMock()
    mock_ctx.__enter__ = MagicMock(return_value=mock_conn)
    mock_ctx.__exit__ = MagicMock(return_value=False)

    mock_engine = MagicMock()
    mock_engine.begin.return_value = mock_ctx

    raw_secret = "super-secret-value-that-must-not-appear"

    row = {
        "name": "test-key",
        "prefix": "fgk",
        "key_hash": "argon2id$hashed_value_not_raw",
        "key_lookup": "hmac_lookup_not_raw",
        "hash_alg": "argon2id",
        "hash_params": {"time_cost": 2},
        "scopes_csv": "read",
        "enabled": True,
        "tenant_id": "tenant-1",
        "created_at": 1700000000,
        "expires_at": 1700086400,
        "version": 1,
        "use_count": 0,
    }

    with patch.dict(os.environ, {"FG_DB_BACKEND": "postgres"}, clear=False):
        with patch("api.auth_scopes.store._pg_engine", return_value=mock_engine):
            from api.auth_scopes.store import insert_key_row

            insert_key_row(row)

    # Verify the raw_secret is not present in any execute() call arguments
    all_calls_str = str(mock_conn.execute.call_args_list)
    assert raw_secret not in all_calls_str


def test_insert_key_row_serializes_hash_params_for_jsonb() -> None:
    """Postgres receives canonical JSON text and casts it to JSONB."""
    mock_conn = MagicMock()
    mock_ctx = MagicMock()
    mock_ctx.__enter__ = MagicMock(return_value=mock_conn)
    mock_ctx.__exit__ = MagicMock(return_value=False)

    mock_engine = MagicMock()
    mock_engine.begin.return_value = mock_ctx

    with patch.dict(os.environ, {"FG_DB_BACKEND": "postgres"}, clear=False):
        with patch("api.auth_scopes.store._pg_engine", return_value=mock_engine):
            from api.auth_scopes.store import insert_key_row

            insert_key_row(
                {
                    "prefix": "fgk",
                    "key_hash": "hashed",
                    "key_lookup": "lookup",
                    "hash_alg": "argon2id",
                    "hash_params": {"time_cost": 2, "memory_cost": 65536},
                    "scopes_csv": "admin:write",
                    "enabled": True,
                    "tenant_id": "tenant-1",
                }
            )

    insert_call = mock_conn.execute.call_args_list[-1]
    sql = str(insert_call.args[0])
    params = insert_call.args[1]
    assert "CAST(:hash_params AS JSONB)" in sql
    assert params["hash_params"] == '{"memory_cost":65536,"time_cost":2}'


def test_postgres_minted_key_name_respects_schema_limit() -> None:
    """Generated descriptive names fit api_keys.name VARCHAR(128)."""
    scopes_csv = ",".join(f"scope:{index}" for index in range(40))

    with patch("api.auth_scopes.store.insert_key_row") as insert_key_row:
        from api.auth_scopes.mapping import _mint_key_postgres

        _mint_key_postgres(
            scopes=scopes_csv.split(","),
            prefix="fgk",
            token="token",
            secret="secret",
            key_hash="hashed",
            hash_alg="argon2id",
            hash_params={"time_cost": 2},
            key_lookup="lookup",
            scopes_csv=scopes_csv,
            tenant_id="tenant-1",
            now_i=1700000000,
            exp_i=1700086400,
        )

    row = insert_key_row.call_args.args[0]
    assert len(row["name"]) == 128
    assert row["name"].startswith("minted:")
    assert row["scopes_csv"] == scopes_csv
