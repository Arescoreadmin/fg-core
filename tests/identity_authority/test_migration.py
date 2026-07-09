"""tests/identity_authority/test_migration.py — Legacy session migration tests."""

from __future__ import annotations

import time

import pytest

from tests.identity_authority.conftest import _build_legacy_token


@pytest.fixture
def migrator(monkeypatch):
    monkeypatch.setenv("PORTAL_PASSWORD", "test-portal-password")
    monkeypatch.setenv("FG_SESSION_SECRET", "test-fg-secret-32-bytes-exactly!!")
    from api.identity_authority.migration import LegacySessionMigrator

    return LegacySessionMigrator()


def _make_token(secret: str, **overrides) -> str:
    now = int(time.time())
    payload = {
        "sub": "portal-user@acme.com",
        "email": "portal-user@acme.com",
        "tid": "tenant-acme",
        "roles": ["viewer"],
        "iat": now,
        "exp": now + 3600,
        "sid": "legacy-sid-001",
        **overrides,
    }
    return _build_legacy_token(payload, secret)


def test_migrate_valid_portal_token(migrator):
    token = _make_token("test-portal-password")
    payload = migrator.migrate(token)
    assert payload.subject == "portal-user@acme.com"
    assert payload.email == "portal-user@acme.com"
    assert payload.tenant_id == "tenant-acme"
    assert payload.roles == ["viewer"]
    assert payload.legacy_format == "portal_v1"


def test_migrate_valid_fg_session_secret(migrator):
    token = _make_token("test-fg-secret-32-bytes-exactly!!")
    payload = migrator.migrate(token)
    assert payload.legacy_format == "admin_gw_v1"
    assert payload.subject == "portal-user@acme.com"


def test_migrate_expired_portal_token_raises(migrator):
    from api.identity_authority.migration import LegacyMigrationError

    token = _make_token("test-portal-password", exp=int(time.time()) - 100)
    with pytest.raises((LegacyMigrationError, ValueError)):
        migrator.migrate(token)


def test_migrate_unknown_format_raises(migrator):
    from api.identity_authority.migration import LegacyMigrationError

    with pytest.raises(LegacyMigrationError) as exc_info:
        migrator.migrate("totally.invalid.garbage.token.here")
    assert exc_info.value.code == "UNKNOWN_FORMAT"


def test_migrate_wrong_secret_raises(migrator):
    from api.identity_authority.migration import LegacyMigrationError

    token = _make_token("wrong-secret-entirely")
    with pytest.raises(LegacyMigrationError):
        migrator.migrate(token)


def test_build_identity_from_legacy(migrator):
    token = _make_token("test-portal-password")
    payload = migrator.migrate(token)
    identity = migrator.build_identity_from_legacy(payload)
    assert identity.subject == "portal-user@acme.com"
    assert identity.identity_type == "human"
    assert identity.tenant_binding is not None
    assert identity.tenant_binding.tenant_id == "tenant-acme"
    assert "viewer" in identity.tenant_binding.roles


def test_build_identity_no_tenant(migrator):
    now = int(time.time())
    payload_dict = {
        "sub": "no-tenant@acme.com",
        "email": "no-tenant@acme.com",
        "iat": now,
        "exp": now + 3600,
    }
    token = _build_legacy_token(payload_dict, "test-portal-password")
    payload = migrator.migrate(token)
    identity = migrator.build_identity_from_legacy(payload)
    assert identity.tenant_binding is None
