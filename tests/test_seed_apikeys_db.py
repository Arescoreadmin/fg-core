from __future__ import annotations

import sqlite3

from scripts import seed_apikeys_db as seed_keys


def _create_api_keys_schema(path: str) -> None:
    con = sqlite3.connect(path)
    try:
        con.execute(
            """
            CREATE TABLE api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                scopes_csv TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        con.commit()
    finally:
        con.close()


def test_upsert_key_inserts_name_and_required_columns(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "seed-keys.db"
    _create_api_keys_schema(str(db_path))

    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setattr(seed_keys, "init_db", lambda: None)

    seed_keys.upsert_key(
        "seedauditgwkey0_000000000000",
        "audit:read,audit:export",
    )

    con = sqlite3.connect(str(db_path))
    try:
        row = con.execute(
            "SELECT name, prefix, key_hash, scopes_csv, enabled, created_at "
            "FROM api_keys WHERE prefix=?",
            ("seedauditgwkey0_",),
        ).fetchone()
    finally:
        con.close()

    assert row is not None
    assert row[0] == "seed:seedauditgwkey0_"
    assert row[1] == "seedauditgwkey0_"
    assert row[2]
    assert row[3] == "audit:read,audit:export"
    assert row[4] == 1
    assert isinstance(row[5], int)


def test_upsert_key_is_idempotent_for_same_key(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "seed-keys-idempotent.db"
    _create_api_keys_schema(str(db_path))

    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setattr(seed_keys, "init_db", lambda: None)

    raw = "seedadmin_primary_key_000000000000"
    scopes = "decisions:read,defend:write,ingest:write"

    seed_keys.upsert_key(raw, scopes)
    seed_keys.upsert_key(raw, scopes)

    con = sqlite3.connect(str(db_path))
    try:
        count = con.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]
    finally:
        con.close()

    assert count == 1
