"""tests/identity_authority/test_session_authority.py — Session lifecycle tests."""

from __future__ import annotations

import time

import pytest


@pytest.fixture
def authority(monkeypatch):
    monkeypatch.setenv("FG_SESSION_SECRET", "test-secret-32-bytes-exactly!!!!")
    monkeypatch.delenv("FG_REDIS_URL", raising=False)
    from api.identity_authority.session_authority import SessionAuthority

    return SessionAuthority()


def test_create_and_validate_session(authority):
    token = authority.create_session(
        subject="user|abc",
        email="a@b.com",
        tenant_id="t1",
        provider="auth0",
    )
    ctx = authority.validate_session(token.token)
    assert ctx.subject == "user|abc"
    assert ctx.email == "a@b.com"
    assert ctx.tenant_id == "t1"
    assert ctx.provider == "auth0"
    assert ctx.revoked is False


def test_session_contains_mfa_flag(authority):
    token = authority.create_session(
        subject="user|mfa",
        email="mfa@test.com",
        tenant_id=None,
        mfa_verified=True,
    )
    ctx = authority.validate_session(token.token)
    assert ctx.mfa_verified is True


def test_revoke_session(authority):
    from api.identity_authority.session_authority import SessionRevokedError

    token = authority.create_session(
        subject="user|rev", email="r@r.com", tenant_id=None
    )
    authority.revoke_session(token.session_id)

    with pytest.raises(SessionRevokedError):
        authority.validate_session(token.token)


def test_invalid_signature_raises(authority):
    from api.identity_authority.session_authority import SessionInvalidError

    token = authority.create_session(subject="u", email="u@u.com", tenant_id=None)
    tampered = token.token[:-4] + "xxxx"
    with pytest.raises(SessionInvalidError):
        authority.validate_session(tampered)


def test_malformed_token_raises(authority):
    from api.identity_authority.session_authority import SessionInvalidError

    with pytest.raises(SessionInvalidError):
        authority.validate_session("not.a.valid.token.at.all")


def test_expired_session_raises(authority, monkeypatch):
    from api.identity_authority.session_authority import SessionExpiredError

    token = authority.create_session(subject="u", email="u@u.com", tenant_id=None)
    # Fast-forward time past expiry by patching the token's exp field directly
    now_plus = int(time.time()) + 999999
    monkeypatch.setattr(
        "api.identity_authority.session_authority.time",
        type(
            "_t",
            (),
            {"time": staticmethod(lambda: now_plus), "monotonic": time.monotonic},
        )(),
    )
    with pytest.raises(SessionExpiredError):
        authority.validate_session(token.token)


def test_refresh_session_revokes_old(authority, monkeypatch):
    from api.identity_authority.session_authority import (
        SessionRevokedError,
    )

    # Create a session with a very short absolute TTL so we can enter the refresh window
    # without also exceeding the idle timeout.
    import api.identity_authority.session_authority as _sa_mod

    monkeypatch.setattr(_sa_mod, "SESSION_TTL_SECONDS", 3600)
    monkeypatch.setattr(_sa_mod, "IDLE_TIMEOUT_SECONDS", 3600)
    monkeypatch.setattr(_sa_mod, "REFRESH_WINDOW_SECONDS", 1800)

    token = authority.create_session(subject="u", email="u@u.com", tenant_id=None)
    # Move into the refresh window (last 30 min of a 1h TTL)
    offset = 3600 - 1800 + 60  # 1861 seconds: just inside the refresh window
    now_plus = int(time.time()) + offset
    monkeypatch.setattr(
        "api.identity_authority.session_authority.time",
        type(
            "_t",
            (),
            {"time": staticmethod(lambda: now_plus), "monotonic": time.monotonic},
        )(),
    )
    new_token = authority.refresh_session(token.token)
    assert new_token.token != token.token

    with pytest.raises(SessionRevokedError):
        authority.validate_session(token.token)


def test_revoke_all_for_subject(authority):
    from api.identity_authority.session_authority import SessionRevokedError

    t1 = authority.create_session(subject="u|multi", email="m@m.com", tenant_id=None)
    t2 = authority.create_session(subject="u|multi", email="m@m.com", tenant_id=None)
    count = authority.revoke_all_for_subject("u|multi", [t1.session_id, t2.session_id])
    assert count == 2

    with pytest.raises(SessionRevokedError):
        authority.validate_session(t1.token)
    with pytest.raises(SessionRevokedError):
        authority.validate_session(t2.token)


def test_extract_session_id(authority):
    token = authority.create_session(subject="u", email="u@u.com", tenant_id=None)
    sid = authority.extract_session_id(token.token)
    assert sid == token.session_id


def test_extract_session_id_from_bad_token_returns_none(authority):
    assert authority.extract_session_id("garbage") is None
