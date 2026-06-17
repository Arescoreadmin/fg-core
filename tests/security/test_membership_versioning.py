"""P1.1 Membership Versioning + Immediate Session Revocation — security test suite.

Test matrix (15 tests):
  MembershipVersionService (MV-1 through MV-3):
    MV-1  bump_version increments membership_version in DB
    MV-2  bump_version returns the new version value
    MV-3  bump_version on non-existent membership raises ValueError

  IdentityPrincipal versioning (MV-4 through MV-6):
    MV-4  IdentityPrincipal carries membership_version from DB
    MV-5  resolve() reads membership_version; reflects bumped value
    MV-6  resolve() defaults membership_version to 1 when DB column is NULL

  Admin gateway Session serialization (MV-7 through MV-8):
    MV-7  Session.to_dict() serializes membership_version
    MV-8  Session.from_dict() round-trips membership_version

  Portal scope named-user path (MV-9 through MV-12):
    MV-9  portal_scope: named-user allowed when version matches
    MV-10 portal_scope: named-user denied SESSION_REVOKED_VERSION_MISMATCH on stale version
    MV-11 portal_scope: named-user denied MEMBERSHIP_INACTIVE when active=False
    MV-12 portal_scope: falls back to PORTAL_SESSION_REQUIRED when no membership headers

  Core API /portal/identity/login (MV-13 through MV-14):
    MV-13 /portal/identity/login response includes membership_version field
    MV-14 /portal/identity/login membership_version matches DB value after bump

  Service account path (MV-15):
    MV-15 API key actor passes through without membership_version check
"""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import get_sessionmaker, init_db, reset_engine_cache
from api.db_models import TenantUser
from api.main import build_app
from services.identity_resolver import (
    IdentityPrincipal,
    IdentityResolver,
    membership_version_svc,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str = "mv"):
    db_path = str(tmp_path / f"{name}.db")
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    reset_engine_cache()
    init_db(sqlite_path=db_path)
    return get_sessionmaker(sqlite_path=db_path)()


def _user(
    db,
    *,
    tenant_id: str = "tenant-a",
    email: str = "alice@example.com",
    role: str = "assessor",
    active: bool = True,
    binding_status: str = "bound",
    provider: str = "auth0",
    issuer: str = "https://example.auth0.com/",
    subject: str = "auth0|user-1",
    membership_version: int = 1,
) -> TenantUser:
    user = TenantUser(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        email=email,
        display_name=email,
        role=role,
        active=active,
        identity_type="human",
        identity_provider=provider,
        identity_issuer=issuer,
        identity_subject=subject,
        identity_email=email,
        identity_email_verified=True,
        identity_binding_status=binding_status,
        membership_version=membership_version,
    )
    db.add(user)
    db.commit()
    return user


def _setup_portal_client(tmp_path: Path, monkeypatch) -> tuple[TestClient, str, str]:
    _make_db(tmp_path, monkeypatch, "mv_portal")
    monkeypatch.setenv("FG_AUTH0_DOMAIN", "test.auth0.com")
    key = mint_key("governance:read", "governance:write", tenant_id="tenant-a")
    app = build_app()
    client = TestClient(app, raise_server_exceptions=True)
    return client, key, "tenant-a"


# ---------------------------------------------------------------------------
# MV-1: bump_version increments membership_version in DB
# ---------------------------------------------------------------------------


def test_mv1_bump_version_increments_db(tmp_path, monkeypatch):
    """MV-1: bump_version() writes membership_version + 1 to the DB row."""
    db = _make_db(tmp_path, monkeypatch, "mv1")
    user = _user(db, membership_version=1)

    membership_version_svc.bump_version(
        db, membership_id=user.id, tenant_id="tenant-a", reason="test"
    )
    db.commit()

    db.expire(user)
    db.refresh(user)
    assert user.membership_version == 2

    db.close()
    reset_engine_cache()


# ---------------------------------------------------------------------------
# MV-2: bump_version returns the new version value
# ---------------------------------------------------------------------------


def test_mv2_bump_version_returns_new_value(tmp_path, monkeypatch):
    """MV-2: bump_version() returns the incremented version."""
    db = _make_db(tmp_path, monkeypatch, "mv2")
    user = _user(db, membership_version=5)

    new_v = membership_version_svc.bump_version(
        db, membership_id=user.id, tenant_id="tenant-a", reason="test"
    )
    assert new_v == 6

    db.close()
    reset_engine_cache()


# ---------------------------------------------------------------------------
# MV-3: bump_version on missing membership raises ValueError
# ---------------------------------------------------------------------------


def test_mv3_bump_version_missing_membership_raises(tmp_path, monkeypatch):
    """MV-3: bump_version() raises ValueError when the row does not exist."""
    db = _make_db(tmp_path, monkeypatch, "mv3")

    with pytest.raises(ValueError, match="no row for"):
        membership_version_svc.bump_version(
            db,
            membership_id="does-not-exist",
            tenant_id="tenant-a",
            reason="test",
        )

    db.close()
    reset_engine_cache()


# ---------------------------------------------------------------------------
# MV-4: IdentityPrincipal carries membership_version from DB
# ---------------------------------------------------------------------------


def test_mv4_identity_principal_has_membership_version(tmp_path, monkeypatch):
    """MV-4: IdentityPrincipal.membership_version is populated from the DB row."""
    db = _make_db(tmp_path, monkeypatch, "mv4")
    _user(db, subject="auth0|mv4", membership_version=3)

    principal = IdentityResolver().resolve(
        db,
        provider="auth0",
        issuer="https://example.auth0.com/",
        subject="auth0|mv4",
        tenant_id="tenant-a",
    )
    assert principal is not None
    assert isinstance(principal, IdentityPrincipal)
    assert principal.membership_version == 3

    db.close()
    reset_engine_cache()


# ---------------------------------------------------------------------------
# MV-5: resolve() reads membership_version; reflects bumped value
# ---------------------------------------------------------------------------


def test_mv5_resolve_reflects_bumped_version(tmp_path, monkeypatch):
    """MV-5: resolve() returns the current membership_version, including after a bump."""
    db = _make_db(tmp_path, monkeypatch, "mv5")
    user = _user(db, subject="auth0|mv5", membership_version=1)

    membership_version_svc.bump_version(
        db, membership_id=user.id, tenant_id="tenant-a", reason="role-change"
    )
    db.commit()

    principal = IdentityResolver().resolve(
        db,
        provider="auth0",
        issuer="https://example.auth0.com/",
        subject="auth0|mv5",
        tenant_id="tenant-a",
    )
    assert principal is not None
    assert principal.membership_version == 2

    db.close()
    reset_engine_cache()


# ---------------------------------------------------------------------------
# MV-6: resolve() defaults membership_version to 1 when DB column is NULL
# ---------------------------------------------------------------------------


def test_mv6_resolve_defaults_version_to_1_when_null():
    """MV-6: resolve() defaults membership_version=1 when the row returns NULL.

    The NOT NULL constraint prevents NULL in production; this tests the defensive
    fallback in resolve() for pre-migration rows or direct DB patches.
    """
    from unittest.mock import MagicMock

    fake_row = MagicMock()
    fake_row.active = True
    fake_row.tenant_id = "tenant-a"
    fake_row.id = "m-null"
    fake_row.role = "assessor"
    fake_row.identity_subject = "auth0|mv6"
    fake_row.identity_issuer = "https://example.auth0.com/"
    fake_row.identity_provider = "auth0"
    fake_row.identity_email = "alice@example.com"
    fake_row.email = "alice@example.com"
    fake_row.identity_binding_status = "bound"
    fake_row.membership_version = None  # simulates pre-migration NULL

    fake_result = MagicMock()
    fake_result.one_or_none.return_value = fake_row

    fake_db = MagicMock()
    fake_db.execute.return_value = fake_result

    principal = IdentityResolver().resolve(
        fake_db,
        provider="auth0",
        issuer="https://example.auth0.com/",
        subject="auth0|mv6",
    )
    assert principal is not None
    assert principal.membership_version == 1


# ---------------------------------------------------------------------------
# MV-7: Session.to_dict() serializes membership_version
# ---------------------------------------------------------------------------


def test_mv7_session_to_dict_includes_membership_version():
    """MV-7: Session.to_dict() includes membership_version."""
    import time

    from admin_gateway.auth.session import Session

    session = Session(
        user_id="u1",
        membership_id="m1",
        membership_version=7,
        tenant_id="tenant-a",
        tenant_governed=True,
        expires_at=time.time() + 3600,
    )
    d = session.to_dict()
    assert d["membership_version"] == 7


# ---------------------------------------------------------------------------
# MV-8: Session.from_dict() round-trips membership_version
# ---------------------------------------------------------------------------


def test_mv8_session_from_dict_restores_membership_version():
    """MV-8: Session.from_dict() restores membership_version from serialized state."""
    import time

    from admin_gateway.auth.session import Session

    data = {
        "user_id": "u1",
        "membership_id": "m1",
        "membership_version": 42,
        "tenant_id": "tenant-a",
        "tenant_governed": True,
        "created_at": time.time(),
        "expires_at": time.time() + 3600,
    }
    session = Session.from_dict(data)
    assert session.membership_version == 42


# ---------------------------------------------------------------------------
# MV-9: portal_scope named-user allowed when version matches
# ---------------------------------------------------------------------------


def test_mv9_portal_scope_named_user_allowed_on_version_match(tmp_path, monkeypatch):
    """MV-9: PortalClientScopeMiddleware passes named-user request when version matches."""
    db = _make_db(tmp_path, monkeypatch, "mv9")
    user = _user(db, subject="auth0|mv9", membership_version=2, tenant_id="tenant-a")

    monkeypatch.setenv("FG_AUTH0_DOMAIN", "test.auth0.com")
    api_key = mint_key("governance:read", tenant_id="tenant-a")
    db.commit()

    app = build_app()
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get(
        "/field-assessment/engagements/eng-999",
        headers={
            "X-API-Key": api_key,
            "X-Tenant-ID": "tenant-a",
            "X-Portal-Source": "client-portal",
            "X-FG-Membership-ID": user.id,
            "X-FG-Membership-Version": "2",
        },
    )
    # Middleware passes; core handler returns 404 (no such engagement) — not 403
    assert resp.status_code != 403, f"expected middleware pass, got: {resp.json()}"

    db.close()
    reset_engine_cache()


# ---------------------------------------------------------------------------
# MV-10: portal_scope named-user denied on version mismatch
# ---------------------------------------------------------------------------


def test_mv10_portal_scope_named_user_denied_on_version_mismatch(tmp_path, monkeypatch):
    """MV-10: PortalClientScopeMiddleware returns SESSION_REVOKED_VERSION_MISMATCH."""
    db = _make_db(tmp_path, monkeypatch, "mv10")
    user = _user(db, subject="auth0|mv10", membership_version=3, tenant_id="tenant-a")

    monkeypatch.setenv("FG_AUTH0_DOMAIN", "test.auth0.com")
    api_key = mint_key("governance:read", tenant_id="tenant-a")
    db.commit()

    app = build_app()
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get(
        "/field-assessment/engagements/eng-999",
        headers={
            "X-API-Key": api_key,
            "X-Tenant-ID": "tenant-a",
            "X-Portal-Source": "client-portal",
            "X-FG-Membership-ID": user.id,
            "X-FG-Membership-Version": "1",  # stale — DB has 3
        },
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body["code"] == "SESSION_REVOKED_VERSION_MISMATCH"

    db.close()
    reset_engine_cache()


# ---------------------------------------------------------------------------
# MV-11: portal_scope named-user denied when membership inactive
# ---------------------------------------------------------------------------


def test_mv11_portal_scope_named_user_denied_on_inactive(tmp_path, monkeypatch):
    """MV-11: PortalClientScopeMiddleware returns MEMBERSHIP_INACTIVE for active=False."""
    db = _make_db(tmp_path, monkeypatch, "mv11")
    user = _user(
        db,
        subject="auth0|mv11",
        membership_version=1,
        active=False,
        tenant_id="tenant-a",
    )

    monkeypatch.setenv("FG_AUTH0_DOMAIN", "test.auth0.com")
    api_key = mint_key("governance:read", tenant_id="tenant-a")
    db.commit()

    app = build_app()
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get(
        "/field-assessment/engagements/eng-999",
        headers={
            "X-API-Key": api_key,
            "X-Tenant-ID": "tenant-a",
            "X-Portal-Source": "client-portal",
            "X-FG-Membership-ID": user.id,
            "X-FG-Membership-Version": "1",
        },
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body["code"] == "MEMBERSHIP_INACTIVE"

    db.close()
    reset_engine_cache()


# ---------------------------------------------------------------------------
# MV-12: portal_scope falls back to PORTAL_SESSION_REQUIRED without membership headers
# ---------------------------------------------------------------------------


def test_mv12_portal_scope_no_membership_headers_requires_grant_session(
    tmp_path, monkeypatch
):
    """MV-12: Without membership headers portal_scope falls through to grant-session path."""
    db = _make_db(tmp_path, monkeypatch, "mv12")
    monkeypatch.setenv("FG_AUTH0_DOMAIN", "test.auth0.com")
    api_key = mint_key("governance:read", tenant_id="tenant-a")
    db.commit()

    app = build_app()
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get(
        "/field-assessment/engagements/eng-999",
        headers={
            "X-API-Key": api_key,
            "X-Tenant-ID": "tenant-a",
            "X-Portal-Source": "client-portal",
            # No X-FG-Membership-* headers, no X-FG-Portal-Session
        },
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body["code"] == "PORTAL_SESSION_REQUIRED"

    db.close()
    reset_engine_cache()


# ---------------------------------------------------------------------------
# MV-13: /portal/identity/login response includes membership_version
# ---------------------------------------------------------------------------


def test_mv13_portal_identity_login_returns_membership_version(tmp_path, monkeypatch):
    """MV-13: POST /portal/identity/login response includes membership_version."""
    client, api_key, tenant_id = _setup_portal_client(tmp_path, monkeypatch)
    # _setup_portal_client already called _make_db which set FG_SQLITE_PATH
    db = get_sessionmaker()()
    _user(
        db,
        subject="auth0|mv13",
        tenant_id=tenant_id,
        membership_version=4,
        issuer="https://test.auth0.com/",  # must match FG_AUTH0_DOMAIN
    )
    db.commit()

    fake_actor = MagicMock()
    fake_actor.subject = "auth0|mv13"
    fake_actor.tenant_id = tenant_id

    with patch("api.portal.validate_auth0_token", return_value=fake_actor):
        resp = client.post(
            "/portal/identity/login",
            json={"access_token": "fake-jwt"},
            headers={"X-API-Key": api_key, "X-Tenant-ID": tenant_id},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert "membership_version" in body
    assert isinstance(body["membership_version"], int)

    db.close()
    reset_engine_cache()


# ---------------------------------------------------------------------------
# MV-14: membership_version in /portal/identity/login matches DB value after bump
# ---------------------------------------------------------------------------


def test_mv14_portal_identity_login_version_matches_db(tmp_path, monkeypatch):
    """MV-14: membership_version in login response reflects the live DB value."""
    db = _make_db(tmp_path, monkeypatch, "mv14")
    monkeypatch.setenv("FG_AUTH0_DOMAIN", "test.auth0.com")
    api_key = mint_key("governance:read", tenant_id="tenant-a")
    user = _user(
        db,
        subject="auth0|mv14",
        tenant_id="tenant-a",
        membership_version=1,
        issuer="https://test.auth0.com/",  # must match FG_AUTH0_DOMAIN
    )

    # Bump the version before login
    membership_version_svc.bump_version(
        db, membership_id=user.id, tenant_id="tenant-a", reason="role-change"
    )
    db.commit()

    app = build_app()
    client = TestClient(app, raise_server_exceptions=True)

    fake_actor = MagicMock()
    fake_actor.subject = "auth0|mv14"
    fake_actor.tenant_id = "tenant-a"

    with patch("api.portal.validate_auth0_token", return_value=fake_actor):
        resp = client.post(
            "/portal/identity/login",
            json={"access_token": "fake-jwt"},
            headers={"X-API-Key": api_key, "X-Tenant-ID": "tenant-a"},
        )

    assert resp.status_code == 200
    assert resp.json()["membership_version"] == 2

    db.close()
    reset_engine_cache()


# ---------------------------------------------------------------------------
# MV-15: API key actor unaffected by membership_version
# ---------------------------------------------------------------------------


def test_mv15_api_key_actor_no_version_check(tmp_path, monkeypatch):
    """MV-15: Service accounts (api_key auth_source) reach handlers without version check."""
    db = _make_db(tmp_path, monkeypatch, "mv15")
    monkeypatch.setenv("FG_AUTH0_DOMAIN", "test.auth0.com")
    # Key with no membership — pure service account
    api_key = mint_key("governance:read", tenant_id="tenant-a")
    db.commit()

    app = build_app()
    client = TestClient(app, raise_server_exceptions=True)

    # Governance:read-gated endpoint with no portal source — should not trigger version check
    resp = client.get(
        "/portal/me",
        headers={
            "X-API-Key": api_key,
            "X-Tenant-ID": "tenant-a",
        },
    )
    # 403 from missing portal session is expected — NOT a version-related error
    assert resp.status_code == 403
    body = resp.json()
    assert body.get("detail", {}).get("code") != "SESSION_REVOKED"
    assert body.get("detail", {}).get("code") != "SESSION_REVOKED_VERSION_MISMATCH"

    db.close()
    reset_engine_cache()
