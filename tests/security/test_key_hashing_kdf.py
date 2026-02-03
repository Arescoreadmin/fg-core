from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import time

from api.auth_scopes import mint_key, verify_api_key_detailed
from api.db import init_db


def _b64url(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def test_new_keys_use_argon2(tmp_path, monkeypatch):
    db_path = str(tmp_path / "keys.db")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_KEY_PEPPER", "test-pepper")
    init_db(sqlite_path=db_path)

    mint_key("stats:read", ttl_seconds=3600, tenant_id="tenant-a")

    con = sqlite3.connect(db_path)
    try:
        row = con.execute(
            "SELECT key_hash, hash_alg, hash_params, key_lookup FROM api_keys LIMIT 1"
        ).fetchone()
    finally:
        con.close()

    assert row is not None
    key_hash, hash_alg, hash_params, key_lookup = row
    assert hash_alg == "argon2id"
    assert key_hash.startswith("$argon2")
    assert key_lookup
    assert hash_params


def test_legacy_sha256_key_is_upgraded(tmp_path, monkeypatch):
    db_path = str(tmp_path / "legacy.db")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_KEY_PEPPER", "test-pepper")
    init_db(sqlite_path=db_path)

    secret = "legacy-secret"
    token = _b64url(
        {
            "scopes": ["stats:read"],
            "tenant_id": "tenant-a",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
    )
    raw_key = f"fgk.{token}.{secret}"
    legacy_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO api_keys (name, prefix, key_hash, scopes_csv, enabled, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("legacy", "fgk", legacy_hash, "stats:read", 1, "tenant-a"),
        )
        con.commit()
    finally:
        con.close()

    result = verify_api_key_detailed(raw=raw_key, required_scopes=None)
    assert result.valid is True

    con = sqlite3.connect(db_path)
    try:
        row = con.execute(
            "SELECT key_hash, hash_alg, key_lookup FROM api_keys WHERE prefix=? LIMIT 1",
            ("fgk",),
        ).fetchone()
    finally:
        con.close()

    assert row is not None
    upgraded_hash, hash_alg, key_lookup = row
    assert hash_alg == "argon2id"
    assert upgraded_hash.startswith("$argon2")
    assert key_lookup
