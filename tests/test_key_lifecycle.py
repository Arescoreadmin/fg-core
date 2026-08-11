"""
Tests for API key lifecycle enforcement — canonical credential authority.

R4.11: Migrated from legacy api_keys-based mint_key to canonical issue_credential.

Covers:
- Expired credentials fail
- Valid credentials succeed
- Canary token detection triggers audit event
"""

import pytest

from api.auth_scopes import (
    mint_key,
    verify_api_key_detailed,
    verify_api_key_raw,
)
from api.credential_authority import issue_credential
from api.db import get_engine, init_db, reset_engine_cache, ensure_tenant_canonical_row
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


@pytest.fixture
def fresh_engine(fresh_db):
    return get_engine()


class TestExpiredKeys:
    """Test that expired credentials fail authentication."""

    def test_expired_credential_fails(self, fresh_db, fresh_engine):
        """Credentials issued with expires_in_seconds=1 and manually expired should fail auth."""
        from sqlalchemy import text as _text

        ensure_tenant_canonical_row(fresh_db, "tenant-test")
        result = issue_credential(
            fresh_engine,
            tenant_id="tenant-test",
            credential_type="tenant_api_key",
            credential_slot="test-expired:v1",
            expires_in_seconds=1,
        )
        key = result.plaintext_secret

        # Force-expire by setting expires_at in the past
        with fresh_engine.begin() as conn:
            conn.execute(
                _text(
                    "UPDATE tenant_credentials SET expires_at = '2000-01-01T00:00:00+00:00'"
                    " WHERE credential_id = :cid"
                ),
                {"cid": result.record.credential_id},
            )

        auth = verify_api_key_detailed(raw=key)
        # Canonical path: expired credentials are refused
        assert not auth.valid

    def test_valid_credential_succeeds(self, fresh_db, fresh_engine):
        """Credentials without expiry should succeed."""
        key = mint_key("read", ttl_seconds=86400, tenant_id="tenant-test")
        result = verify_api_key_detailed(raw=key)
        assert result.valid

    def test_non_expired_key_succeeds(self, fresh_db):
        """Keys that aren't expired should succeed."""
        key = mint_key("read", ttl_seconds=86400)
        result = verify_api_key_detailed(raw=key)
        assert result.valid

    def test_mint_key_respects_requested_ttl(self, fresh_db, fresh_engine):
        """mint_key(ttl_seconds=...) forwards expiry to credential authority."""
        from datetime import datetime, timezone

        from api.credential_authority import validate_credential
        from sqlalchemy import text as _text

        key = mint_key("read", ttl_seconds=3600, tenant_id="tenant-test")
        principal = validate_credential(fresh_engine, key)
        with fresh_engine.connect() as conn:
            expires_at = conn.execute(
                _text(
                    "SELECT expires_at FROM tenant_credentials "
                    "WHERE credential_id = :cid"
                ),
                {"cid": principal.credential_id},
            ).scalar_one()

        expires_dt = datetime.fromisoformat(str(expires_at))
        delta = expires_dt - datetime.now(timezone.utc)
        assert 3500 <= delta.total_seconds() <= 3700

    def test_mint_key_seeds_default_active_config(self, fresh_db, fresh_engine):
        """mint_key preserves the SQLite test shim's default config side effect."""
        from sqlalchemy import text as _text

        mint_key("ingest:write", tenant_id="tenant-config-default")

        with fresh_engine.connect() as conn:
            active_hash = conn.execute(
                _text(
                    "SELECT active_config_hash FROM tenant_config_active "
                    "WHERE tenant_id = :tenant_id"
                ),
                {"tenant_id": "tenant-config-default"},
            ).scalar_one()
            config_hash = conn.execute(
                _text(
                    "SELECT config_hash FROM config_versions "
                    "WHERE tenant_id = :tenant_id"
                ),
                {"tenant_id": "tenant-config-default"},
            ).scalar_one()

        assert active_hash == config_hash


class TestKeyRotation:
    """Test key rotation behavior."""


class TestCanaryTokenDetection:
    """Test that canary tokens are detected."""

    def test_canary_prefix_triggers_detection(self, fresh_db, monkeypatch, caplog):
        """Keys with canary prefix should trigger detection and fail auth."""
        import logging

        caplog.set_level(logging.WARNING)

        # A fake canary key — must start with CANARY_KEY_PREFIX
        canary_prefix = f"{CANARY_KEY_PREFIX}test1234"
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

    def test_verify_api_key_raw_succeeds(self, fresh_db):
        """verify_api_key_raw should return True for valid keys."""
        key = mint_key("read", ttl_seconds=86400)
        assert verify_api_key_raw(raw=key) is True

    def test_mint_key_allows_unscoped_keys(self, fresh_db):
        """mint_key should allow keys with a tenant_id."""
        key = mint_key("read", ttl_seconds=86400, tenant_id="tenant-test")
        result = verify_api_key_detailed(raw=key)
        assert result.valid
        assert result.tenant_id == "tenant-test"
