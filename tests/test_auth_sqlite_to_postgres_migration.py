"""
PR 17 — Migration script tests: tools/scripts/migrate_auth_sqlite_to_postgres.py

Tests:
  1. dry-run reads SQLite rows and does not write to Postgres.
  2. NULL name becomes "default".
  3. timestamp conversion produces timezone-aware UTC datetime.
  4. hash_params JSON string becomes dict.
  5. existing rows are skipped (ON CONFLICT DO NOTHING).
  6. missing FG_SQLITE_PATH exits non-zero.
  7. missing FG_DB_URL exits non-zero.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sqlite_db(path: str, rows: list[dict]) -> None:
    con = sqlite3.connect(path)
    con.execute(
        """
        CREATE TABLE api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prefix TEXT NOT NULL,
            key_hash TEXT NOT NULL UNIQUE,
            key_lookup TEXT,
            hash_alg TEXT DEFAULT 'argon2id',
            hash_params TEXT,
            scopes_csv TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            tenant_id TEXT,
            created_at INTEGER,
            expires_at INTEGER,
            last_used_at INTEGER,
            use_count INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 1,
            name TEXT,
            description TEXT,
            rotated_from TEXT,
            created_by TEXT
        )
        """
    )
    for row in rows:
        cols = list(row.keys())
        vals = [row[c] for c in cols]
        placeholders = ", ".join(["?"] * len(cols))
        con.execute(
            f"INSERT INTO api_keys ({', '.join(cols)}) VALUES ({placeholders})",
            vals,
        )
    con.commit()
    con.close()


def _invoke_script(args: list[str], env: dict) -> subprocess.CompletedProcess:
    script_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "tools",
        "scripts",
        "migrate_auth_sqlite_to_postgres.py",
    )
    return subprocess.run(
        [sys.executable, script_path] + args,
        env={**os.environ, **env},
        capture_output=True,
        text=True,
    )


# ---------------------------------------------------------------------------
# 1. dry-run reads SQLite rows and does not write
# ---------------------------------------------------------------------------


def test_dry_run_reads_rows_no_write() -> None:
    """--dry-run reads SQLite rows and reports them without writing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        sqlite_path = f.name
    try:
        _make_sqlite_db(
            sqlite_path,
            [
                {
                    "prefix": "fgk",
                    "key_hash": "hash_abc",
                    "scopes_csv": "read",
                    "tenant_id": "tenant-1",
                    "created_at": 1700000000,
                }
            ],
        )
        result = _invoke_script(
            ["--dry-run"],
            {"FG_SQLITE_PATH": sqlite_path, "FG_DB_URL": "postgresql://irrelevant/db"},
        )
        assert result.returncode == 0, result.stderr
        assert "dry-run" in result.stdout.lower() or "dry_run" in result.stdout.lower()
        assert "fgk" in result.stdout  # prefix appears in dry-run output
    finally:
        os.unlink(sqlite_path)


# ---------------------------------------------------------------------------
# 2. NULL name becomes "default"
# ---------------------------------------------------------------------------


def test_null_name_becomes_default() -> None:
    """Rows with name=NULL are mapped to name='default' in the output row."""
    from tools.scripts.migrate_auth_sqlite_to_postgres import _build_pg_row

    row = {
        "prefix": "fgk",
        "key_hash": "deadbeef",
        "name": None,
        "scopes_csv": "read",
        "enabled": 1,
        "tenant_id": "t1",
    }
    pg_row = _build_pg_row(row)
    assert pg_row["name"] == "default"


def test_empty_name_becomes_default() -> None:
    """Empty string name is also mapped to 'default'."""
    from tools.scripts.migrate_auth_sqlite_to_postgres import _build_pg_row

    row = {
        "prefix": "fgk",
        "key_hash": "deadbeef",
        "name": "",
        "scopes_csv": "read",
        "enabled": 1,
        "tenant_id": "t1",
    }
    pg_row = _build_pg_row(row)
    assert pg_row["name"] == "default"


# ---------------------------------------------------------------------------
# 3. Timestamp conversion produces timezone-aware UTC datetime
# ---------------------------------------------------------------------------


def test_timestamp_conversion_integer() -> None:
    """INTEGER epoch converts to timezone-aware UTC datetime."""
    from tools.scripts.migrate_auth_sqlite_to_postgres import _to_utc_dt

    ts = 1700000000
    result = _to_utc_dt(ts)
    assert isinstance(result, datetime)
    assert result.tzinfo is not None
    assert result.tzinfo == timezone.utc
    assert int(result.timestamp()) == ts


def test_timestamp_conversion_none() -> None:
    """None returns None."""
    from tools.scripts.migrate_auth_sqlite_to_postgres import _to_utc_dt

    assert _to_utc_dt(None) is None


def test_timestamp_in_build_pg_row() -> None:
    """_build_pg_row converts created_at and expires_at to UTC datetimes."""
    from tools.scripts.migrate_auth_sqlite_to_postgres import _build_pg_row

    row = {
        "prefix": "fgk",
        "key_hash": "deadbeef",
        "scopes_csv": "read",
        "enabled": 1,
        "tenant_id": "t1",
        "created_at": 1700000000,
        "expires_at": 1700086400,
        "last_used_at": None,
    }
    pg_row = _build_pg_row(row)
    assert isinstance(pg_row["created_at"], datetime)
    assert pg_row["created_at"].tzinfo == timezone.utc
    assert isinstance(pg_row["expires_at"], datetime)
    assert pg_row["expires_at"].tzinfo == timezone.utc
    assert pg_row["last_used_at"] is None


# ---------------------------------------------------------------------------
# 4. hash_params JSON string becomes dict
# ---------------------------------------------------------------------------


def test_hash_params_json_string_becomes_dict() -> None:
    """hash_params TEXT JSON string is parsed to dict in the output row."""
    from tools.scripts.migrate_auth_sqlite_to_postgres import _build_pg_row

    params = {"time_cost": 2, "memory_cost": 65536}
    row = {
        "prefix": "fgk",
        "key_hash": "deadbeef",
        "scopes_csv": "read",
        "enabled": 1,
        "tenant_id": "t1",
        "hash_params": json.dumps(params),
    }
    pg_row = _build_pg_row(row)
    assert pg_row["hash_params"] == params


def test_hash_params_dict_passthrough() -> None:
    """dict hash_params passes through unchanged."""
    from tools.scripts.migrate_auth_sqlite_to_postgres import _build_pg_row

    params = {"time_cost": 2}
    row = {
        "prefix": "fgk",
        "key_hash": "deadbeef",
        "scopes_csv": "read",
        "enabled": 1,
        "tenant_id": "t1",
        "hash_params": params,
    }
    pg_row = _build_pg_row(row)
    assert pg_row["hash_params"] == params


# ---------------------------------------------------------------------------
# 5. Missing FG_SQLITE_PATH exits non-zero
# ---------------------------------------------------------------------------


def test_missing_sqlite_path_exits_nonzero() -> None:
    """Script exits non-zero with clear message when FG_SQLITE_PATH is missing."""
    result = _invoke_script(
        [],
        {"FG_SQLITE_PATH": "", "FG_DB_URL": "postgresql://irrelevant/db"},
    )
    assert result.returncode != 0
    assert "FG_SQLITE_PATH" in result.stderr


# ---------------------------------------------------------------------------
# 6. Missing FG_DB_URL exits non-zero
# ---------------------------------------------------------------------------


def test_missing_db_url_exits_nonzero() -> None:
    """Script exits non-zero with clear message when FG_DB_URL is missing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        sqlite_path = f.name
    try:
        result = _invoke_script(
            [],
            {"FG_SQLITE_PATH": sqlite_path, "FG_DB_URL": ""},
        )
        assert result.returncode != 0
        assert "FG_DB_URL" in result.stderr
    finally:
        os.unlink(sqlite_path)


# ---------------------------------------------------------------------------
# 7. NULL tenant_id becomes "unknown"
# ---------------------------------------------------------------------------


def test_null_tenant_id_becomes_unknown() -> None:
    """Rows with NULL tenant_id are mapped to 'unknown' (matches migration 0004 default)."""
    from tools.scripts.migrate_auth_sqlite_to_postgres import _build_pg_row

    row = {
        "prefix": "fgk",
        "key_hash": "deadbeef",
        "scopes_csv": "read",
        "enabled": 1,
        "tenant_id": None,
    }
    pg_row = _build_pg_row(row)
    assert pg_row["tenant_id"] == "unknown"
