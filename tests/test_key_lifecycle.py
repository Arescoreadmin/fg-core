"""
Tests for API key lifecycle enforcement.

Covers:
- Expired keys fail (both token and DB expiration)
- use_count increments on successful auth
- last_used_at updates on successful auth
- Canary token detection triggers audit event
"""

import sqlite3
import time

import pytest

from api.auth_scopes import (
    mint_key,
    rotate_api_key_by_prefix,
    verify_api_key_detailed,
    verify_api_key_raw,
)
from api.db import init_db, reset_engine_cache
from api.tripwires import CANARY_KEY_PREFIX


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    """Create a fresh database for testing."""
    db_path = str(tmp_path / "test_lifecycle.db")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_API_KEY", "")  # Disable global key
    reset_engine_cache()
    init_db(sqlite_path=db_path)
    return db_path


class TestExpiredKeys:
    """Test that expired keys fail authentication."""

    def test_expired_key_from_token_payload_fails(self, fresh_db, monkeypatch):
        """Keys with expired token payload should fail."""
        # Mint a key that's already expired (negative TTL hack via past timestamp)
        past_time = int(time.time()) - 3600  # 1 hour ago
        key = mint_key("read", ttl_seconds=1, now=past_time)  # Expired 1 hour ago

        result = verify_api_key_detailed(raw=key)
        assert not result.valid
        assert "expired" in result.reason

    def test_key_with_db_expires_at_fails(self, fresh_db, monkeypatch):
        """Keys with expired DB expires_at should fail."""
        # Mint a valid key first
        key = mint_key("read", ttl_seconds=86400)  # 24 hours

        # Manually set expires_at to past in DB
        parts = key.split(".")
        prefix = parts[0]
        secret = parts[-1]
        import hashlib

        key_hash = hashlib.sha256(secret.encode()).hexdigest()

        con = sqlite3.connect(fresh_db)
        try:
            # Update expires_at to past timestamp
            past_ts = int(time.time()) - 3600
            con.execute(
                "UPDATE api_keys SET expires_at = ? WHERE prefix = ? AND key_hash = ?",
                (past_ts, prefix, key_hash),
            )
            con.commit()
        finally:
            con.close()

        result = verify_api_key_detailed(raw=key)
        assert not result.valid
        assert "expired" in result.reason

    def test_non_expired_key_succeeds(self, fresh_db):
        """Keys that aren't expired should succeed."""
        key = mint_key("read", ttl_seconds=86400)  # 24 hours from now
        result = verify_api_key_detailed(raw=key)
        assert result.valid


class TestUsageTracking:
    """Test that key usage is tracked."""

    def test_use_count_increments_on_auth(self, fresh_db):
        """use_count should increment on successful auth."""
        key = mint_key("read", ttl_seconds=86400)

        # Get initial use_count
        parts = key.split(".")
        prefix = parts[0]
        secret = parts[-1]
        import hashlib

        key_hash = hashlib.sha256(secret.encode()).hexdigest()

        con = sqlite3.connect(fresh_db)
        try:
            row = con.execute(
                "SELECT use_count FROM api_keys WHERE prefix = ? AND key_hash = ?",
                (prefix, key_hash),
            ).fetchone()
            initial_count = row[0] if row else 0
        finally:
            con.close()

        # Auth multiple times
        for _ in range(3):
            result = verify_api_key_detailed(raw=key)
            assert result.valid

        # Check use_count increased
        con = sqlite3.connect(fresh_db)
        try:
            row = con.execute(
                "SELECT use_count FROM api_keys WHERE prefix = ? AND key_hash = ?",
                (prefix, key_hash),
            ).fetchone()
            final_count = row[0] if row else 0
        finally:
            con.close()

        assert final_count == initial_count + 3

    def test_last_used_at_updates_on_auth(self, fresh_db):
        """last_used_at should update on successful auth."""
        key = mint_key("read", ttl_seconds=86400)

        parts = key.split(".")
        prefix = parts[0]
        secret = parts[-1]
        import hashlib

        key_hash = hashlib.sha256(secret.encode()).hexdigest()

        before_auth = int(time.time())

        # Auth
        result = verify_api_key_detailed(raw=key)
        assert result.valid

        # Check last_used_at updated
        con = sqlite3.connect(fresh_db)
        try:
            row = con.execute(
                "SELECT last_used_at FROM api_keys WHERE prefix = ? AND key_hash = ?",
                (prefix, key_hash),
            ).fetchone()
            after = row[0] if row else None
        finally:
            con.close()

        assert after is not None
        assert after >= before_auth

    def test_verify_api_key_raw_tracks_usage(self, fresh_db):
        """verify_api_key_raw should update usage stats on success."""
        key = mint_key("read", ttl_seconds=86400)

        parts = key.split(".")
        prefix = parts[0]
        secret = parts[-1]
        import hashlib

        key_hash = hashlib.sha256(secret.encode()).hexdigest()

        verify_api_key_raw(raw=key)

        con = sqlite3.connect(fresh_db)
        try:
            row = con.execute(
                "SELECT use_count, last_used_at FROM api_keys WHERE prefix = ? AND key_hash = ?",
                (prefix, key_hash),
            ).fetchone()
            use_count, last_used_at = row if row else (0, None)
        finally:
            con.close()

        assert use_count == 1
        assert last_used_at is not None


class TestKeyRotation:
    """Test key rotation behavior."""

    def test_rotate_invalidates_prior(self, fresh_db):
        """Rotating a key should revoke the old key."""
        key = mint_key("read", ttl_seconds=86400)
        prefix = key.split(".")[0]

        pre_rotate = verify_api_key_detailed(raw=key)
        assert pre_rotate.valid

        result = rotate_api_key_by_prefix(prefix, ttl_seconds=3600)
        new_key = result["new_key"]

        new_result = verify_api_key_detailed(raw=new_key)
        assert new_result.valid

        old_result = verify_api_key_detailed(raw=key)
        assert not old_result.valid


class TestCanaryTokenDetection:
    """Test that canary tokens are detected."""

    def test_canary_prefix_triggers_detection(self, fresh_db, monkeypatch, caplog):
        """Keys with canary prefix should trigger detection and fail auth."""
        import logging

        caplog.set_level(logging.WARNING)

        # Create a fake canary key in the DB (include version and use_count for schema)
        canary_prefix = f"{CANARY_KEY_PREFIX}test1234"
        canary_hash = "a" * 64

        con = sqlite3.connect(fresh_db)
        try:
            con.execute(
                "INSERT INTO api_keys (name, prefix, key_hash, scopes_csv, enabled, version, use_count) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("CANARY", canary_prefix, canary_hash, "", 1, 1, 0),
            )
            con.commit()
        finally:
            con.close()

        # Try to auth with a key that has canary prefix
        fake_key = f"{canary_prefix}.token.secret"
        result = verify_api_key_detailed(raw=fake_key)

        assert not result.valid
        assert result.reason == "canary_token"

    def test_normal_key_does_not_trigger_canary(self, fresh_db):
        """Normal keys should not trigger canary detection."""
        key = mint_key("read", ttl_seconds=86400)
        result = verify_api_key_detailed(raw=key)

        assert result.valid
        assert result.reason != "canary_token"


class TestAuthResult:
    """Test AuthResult class behavior."""

    def test_missing_key_detection(self, fresh_db):
        """AuthResult should correctly identify missing keys."""
        result = verify_api_key_detailed(raw="")
        assert not result.valid
        assert result.is_missing_key
        assert not result.is_invalid_key

    def test_invalid_key_detection(self, fresh_db):
        """AuthResult should correctly identify invalid keys."""
        result = verify_api_key_detailed(raw="invalid_key_that_does_not_exist")
        assert not result.valid
        assert not result.is_missing_key
        assert result.is_invalid_key

    def test_valid_key_detection(self, fresh_db):
        """AuthResult should correctly identify valid keys."""
        key = mint_key("read", ttl_seconds=86400)
        result = verify_api_key_detailed(raw=key)
        assert result.valid
        assert not result.is_missing_key
        assert not result.is_invalid_key
