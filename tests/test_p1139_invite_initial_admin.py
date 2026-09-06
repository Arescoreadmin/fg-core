"""
P-113.9B — invite-initial-admin — proof matrix.

Test matrix:
  I-01  admin_unset → creates user + invitation, email skipped (no key) → 200 {"action": "invited"}
  I-02  admin_unbound + valid pending invite + same email → resends (rotates token)
  I-03  admin_unbound + expired invite + same email → creates new invite
  I-04  admin_unbound + no invite + same email → creates new invite
  I-05  admin bound, same email → 200 {"action": "noop", "reason": "already_bound"}
  I-06  admin bound, different email → 409 ADMIN_EMAIL_MISMATCH
  I-07  admin unbound, different email → 409 ADMIN_EMAIL_MISMATCH
  I-08  email delivery failure → 503 INVITE_EMAIL_FAILED, DB unchanged
  I-09  non-platform actor → 403
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterator
from unittest import mock

import pytest
from sqlalchemy import text
from starlette.testclient import TestClient

from api.auth_scopes import mint_key

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app(build_app, monkeypatch):
    monkeypatch.setenv("FG_RL_BACKEND", "memory")
    return build_app(auth_enabled=True, api_key="")


@pytest.fixture
def client(app) -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


@pytest.fixture
def engine(app):
    from api.db import get_engine

    return get_engine()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tid() -> str:
    return f"p1139ia-{uuid.uuid4().hex[:8]}"


def _platform_headers(tenant_id: str) -> dict[str, str]:
    key = mint_key("admin:read", "admin:write", tenant_id=tenant_id)
    return {"x-api-key": key}


def _non_platform_headers(tenant_id: str) -> dict[str, str]:
    """Scoped key with no platform.admin permission."""
    key = mint_key("admin:read", tenant_id=tenant_id)
    return {"x-api-key": key}


def _ensure_tenant(engine, tenant_id: str, lifecycle_state: str = "active") -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenants "
                "(tenant_id, tenant_kind, lifecycle_state, display_name) "
                "VALUES (:tid, 'customer', :lc, :dn)"
            ),
            {"tid": tenant_id, "lc": lifecycle_state, "dn": f"Tenant {tenant_id[:8]}"},
        )


def _seed_principal(engine, principal_id: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO fg_principals "
                "(id, principal_type, lifecycle_state, mfa_verified, "
                "authority_version, created_at, updated_at) "
                "VALUES (:id, 'human', 'active', 0, 1, :now, :now)"
            ),
            {"id": principal_id, "now": _now_iso()},
        )


def _seed_admin_user(
    engine,
    tenant_id: str,
    email: str,
    *,
    binding_status: str = "unbound",
    principal_id: str | None = None,
) -> str:
    """Insert an active tenant_admin row. Returns user_id."""
    user_id = str(uuid.uuid4())
    if principal_id:
        _seed_principal(engine, principal_id)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenant_users "
                "(id, tenant_id, email, display_name, role, active, "
                "identity_binding_status, principal_id, created_at, updated_at) "
                "VALUES (:id, :t, :e, :dn, 'tenant_admin', 1, :bs, :pid, :now, :now)"
            ),
            {
                "id": user_id,
                "t": tenant_id,
                "e": email,
                "dn": email,
                "bs": binding_status,
                "pid": principal_id,
                "now": _now_iso(),
            },
        )
    return user_id


def _seed_invitation(
    engine,
    tenant_id: str,
    user_id: str,
    email: str,
    *,
    status: str = "pending",
    expires_delta: timedelta | None = None,
    fingerprint: str | None = None,
) -> str:
    """Insert a tenant_invitation row. Returns invitation_id."""
    from api.identity.workforce_token import generate

    raw, fp = generate()
    if fingerprint is None:
        fingerprint = fp
    inv_id = str(uuid.uuid4())
    if expires_delta is None:
        expires_delta = timedelta(hours=72)
    expires_at = datetime.now(timezone.utc) + expires_delta
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenant_invitations "
                "(id, tenant_id, membership_id, email, normalized_email, role, status, "
                "identity_mode_at_invite, expires_at, acceptance_token_hash, created_at, updated_at) "
                "VALUES (:id, :tid, :uid, :email, :ne, 'tenant_admin', :status, 'managed', "
                ":exp, :fp, :now, :now)"
            ),
            {
                "id": inv_id,
                "tid": tenant_id,
                "uid": user_id,
                "email": email,
                "ne": email.lower(),
                "status": status,
                "exp": expires_at.isoformat(),
                "fp": fingerprint,
                "now": _now_iso(),
            },
        )
    return inv_id, fp


def _get_admin_rows(engine, tenant_id: str) -> list:
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT id, email, identity_binding_status FROM tenant_users "
                "WHERE tenant_id = :t AND role = 'tenant_admin'"
            ),
            {"t": tenant_id},
        ).fetchall()


def _get_invitation_fp(engine, inv_id: str) -> str | None:
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT acceptance_token_hash FROM tenant_invitations WHERE id = :id"),
            {"id": inv_id},
        ).fetchone()
    return row[0] if row else None


# ---------------------------------------------------------------------------
# I-01: admin_unset → creates user + invitation → 200 {"action": "invited"}
# ---------------------------------------------------------------------------


class TestInviteInitialAdminUnset:
    def test_i01_admin_unset_creates_user_and_invitation(self, client, engine, monkeypatch):
        monkeypatch.delenv("FG_RESEND_API_KEY", raising=False)
        tid = _tid()
        _ensure_tenant(engine, tid)

        r = client.post(
            f"/admin/tenants/{tid}/invite-initial-admin",
            headers=_platform_headers(tid),
            json={"email": "first@example.com", "display_name": "First Admin"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["action"] == "invited"
        assert body["email"] == "first@example.com"
        assert body["invitation_sent"] is True

        # Verify tenant_user row created
        admins = _get_admin_rows(engine, tid)
        assert len(admins) == 1
        assert admins[0][1] == "first@example.com"
        assert admins[0][2] == "unbound"

        # Verify invitation row created
        with engine.connect() as conn:
            inv = conn.execute(
                text(
                    "SELECT status, acceptance_token_hash FROM tenant_invitations "
                    "WHERE tenant_id = :t AND role = 'tenant_admin'"
                ),
                {"t": tid},
            ).fetchone()
        assert inv is not None
        assert inv[0] == "pending"
        assert inv[1] is not None

    def test_i01_display_name_defaults_to_email(self, client, engine, monkeypatch):
        monkeypatch.delenv("FG_RESEND_API_KEY", raising=False)
        tid = _tid()
        _ensure_tenant(engine, tid)

        r = client.post(
            f"/admin/tenants/{tid}/invite-initial-admin",
            headers=_platform_headers(tid),
            json={"email": "nodisplay@example.com"},
        )
        assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# I-02: admin_unbound + valid invite → rotates token
# ---------------------------------------------------------------------------


class TestInviteInitialAdminUnboundValidInvite:
    def test_i02_rotates_token_old_fp_gone(self, client, engine, monkeypatch):
        monkeypatch.delenv("FG_RESEND_API_KEY", raising=False)
        tid = _tid()
        _ensure_tenant(engine, tid)
        user_id = _seed_admin_user(engine, tid, "admin@example.com")
        inv_id, old_fp = _seed_invitation(engine, tid, user_id, "admin@example.com")

        r = client.post(
            f"/admin/tenants/{tid}/invite-initial-admin",
            headers=_platform_headers(tid),
            json={"email": "admin@example.com"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["action"] == "resent"
        assert body["invitation_sent"] is True

        # Old fingerprint must be replaced
        new_fp = _get_invitation_fp(engine, inv_id)
        assert new_fp is not None
        assert new_fp != old_fp

    def test_i02_same_invitation_id(self, client, engine, monkeypatch):
        """Resend reuses the same invitation row (rotates in-place)."""
        monkeypatch.delenv("FG_RESEND_API_KEY", raising=False)
        tid = _tid()
        _ensure_tenant(engine, tid)
        user_id = _seed_admin_user(engine, tid, "admin2@example.com")
        inv_id, _ = _seed_invitation(engine, tid, user_id, "admin2@example.com")

        r = client.post(
            f"/admin/tenants/{tid}/invite-initial-admin",
            headers=_platform_headers(tid),
            json={"email": "admin2@example.com"},
        )
        assert r.status_code == 200, r.text

        # Only one invitation row should exist
        with engine.connect() as conn:
            count = conn.execute(
                text("SELECT COUNT(*) FROM tenant_invitations WHERE tenant_id = :t AND role = 'tenant_admin'"),
                {"t": tid},
            ).scalar()
        assert count == 1


# ---------------------------------------------------------------------------
# I-03: admin_unbound + expired invite → rotated in-place (lineage preserved)
# ---------------------------------------------------------------------------


class TestInviteInitialAdminUnboundExpiredInvite:
    def test_i03_expired_invite_rotated_in_place(self, client, engine, monkeypatch):
        """Expired invitations are revivable — same row, new token, extended expiry."""
        monkeypatch.delenv("FG_RESEND_API_KEY", raising=False)
        tid = _tid()
        _ensure_tenant(engine, tid)
        user_id = _seed_admin_user(engine, tid, "admin3@example.com")
        inv_id, old_fp = _seed_invitation(
            engine, tid, user_id, "admin3@example.com",
            expires_delta=timedelta(hours=-1),
        )

        r = client.post(
            f"/admin/tenants/{tid}/invite-initial-admin",
            headers=_platform_headers(tid),
            json={"email": "admin3@example.com"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["action"] == "resent"
        assert body["invitation_sent"] is True

        # Same invitation row — lineage preserved, no duplicate paperwork
        with engine.connect() as conn:
            count = conn.execute(
                text("SELECT COUNT(*) FROM tenant_invitations WHERE tenant_id = :t AND role = 'tenant_admin'"),
                {"t": tid},
            ).scalar()
        assert count == 1

        # Fingerprint changed — old token is dead
        new_fp = _get_invitation_fp(engine, inv_id)
        assert new_fp is not None
        assert new_fp != old_fp

        # Status restored to pending, expires_at extended into the future
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT status, expires_at FROM tenant_invitations WHERE id = :id"),
                {"id": inv_id},
            ).fetchone()
        assert row[0] == "pending"
        exp = row[1]
        if isinstance(exp, str):
            exp = datetime.fromisoformat(exp)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        assert exp > datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# I-04: admin_unbound + no invite → creates new invite
# ---------------------------------------------------------------------------


class TestInviteInitialAdminUnboundNoInvite:
    def test_i04_no_invite_creates_one(self, client, engine, monkeypatch):
        monkeypatch.delenv("FG_RESEND_API_KEY", raising=False)
        tid = _tid()
        _ensure_tenant(engine, tid)
        # Seed an admin user (like old bootstrap-admin), but no invitation row
        _seed_admin_user(engine, tid, "legacy@example.com")

        r = client.post(
            f"/admin/tenants/{tid}/invite-initial-admin",
            headers=_platform_headers(tid),
            json={"email": "legacy@example.com"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["action"] == "invited"
        assert body["invitation_sent"] is True

        with engine.connect() as conn:
            inv = conn.execute(
                text(
                    "SELECT status FROM tenant_invitations WHERE tenant_id = :t AND role = 'tenant_admin'"
                ),
                {"t": tid},
            ).fetchone()
        assert inv is not None
        assert inv[0] == "pending"


# ---------------------------------------------------------------------------
# I-05: admin bound, same email → noop
# ---------------------------------------------------------------------------


class TestInviteInitialAdminBoundSameEmail:
    def test_i05_bound_same_email_noop(self, client, engine, monkeypatch):
        monkeypatch.delenv("FG_RESEND_API_KEY", raising=False)
        tid = _tid()
        _ensure_tenant(engine, tid)
        pid = str(uuid.uuid4())
        _seed_admin_user(
            engine, tid, "bound@example.com",
            binding_status="bound", principal_id=pid,
        )

        r = client.post(
            f"/admin/tenants/{tid}/invite-initial-admin",
            headers=_platform_headers(tid),
            json={"email": "bound@example.com"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["action"] == "noop"
        assert body["reason"] == "already_bound"

        # No new invitation rows created
        with engine.connect() as conn:
            count = conn.execute(
                text("SELECT COUNT(*) FROM tenant_invitations WHERE tenant_id = :t"), {"t": tid}
            ).scalar()
        assert count == 0


# ---------------------------------------------------------------------------
# I-06: admin bound, different email → 409
# ---------------------------------------------------------------------------


class TestInviteInitialAdminBoundDifferentEmail:
    def test_i06_bound_different_email_409(self, client, engine, monkeypatch):
        monkeypatch.delenv("FG_RESEND_API_KEY", raising=False)
        tid = _tid()
        _ensure_tenant(engine, tid)
        pid = str(uuid.uuid4())
        _seed_admin_user(
            engine, tid, "existing@example.com",
            binding_status="bound", principal_id=pid,
        )

        r = client.post(
            f"/admin/tenants/{tid}/invite-initial-admin",
            headers=_platform_headers(tid),
            json={"email": "other@example.com"},
        )
        assert r.status_code == 409, r.text
        body = r.json()
        assert body["detail"]["code"] == "ADMIN_EMAIL_MISMATCH"


# ---------------------------------------------------------------------------
# I-07: admin unbound, different email → 409
# ---------------------------------------------------------------------------


class TestInviteInitialAdminUnboundDifferentEmail:
    def test_i07_unbound_different_email_409(self, client, engine, monkeypatch):
        monkeypatch.delenv("FG_RESEND_API_KEY", raising=False)
        tid = _tid()
        _ensure_tenant(engine, tid)
        _seed_admin_user(engine, tid, "assigned@example.com")

        r = client.post(
            f"/admin/tenants/{tid}/invite-initial-admin",
            headers=_platform_headers(tid),
            json={"email": "intruder@example.com"},
        )
        assert r.status_code == 409, r.text
        body = r.json()
        assert body["detail"]["code"] == "ADMIN_EMAIL_MISMATCH"


# ---------------------------------------------------------------------------
# I-08: email delivery failure → 503, DB unchanged
# ---------------------------------------------------------------------------


class TestInviteInitialAdminEmailFailure:
    def test_i08_delivery_failure_503_db_unchanged(self, client, engine, monkeypatch):
        tid = _tid()
        _ensure_tenant(engine, tid)

        from api.notifications.email import EmailDeliveryResult

        with mock.patch(
            "api.tenant_admin.send_portal_invitation",
            return_value=EmailDeliveryResult(state="failed", error_code="RESEND_ERROR"),
        ):
            r = client.post(
                f"/admin/tenants/{tid}/invite-initial-admin",
                headers=_platform_headers(tid),
                json={"email": "fail@example.com"},
            )

        assert r.status_code == 503, r.text
        body = r.json()
        assert body["detail"]["code"] == "INVITE_EMAIL_FAILED"

        # No user or invitation rows were committed
        admins = _get_admin_rows(engine, tid)
        assert len(admins) == 0

        with engine.connect() as conn:
            count = conn.execute(
                text("SELECT COUNT(*) FROM tenant_invitations WHERE tenant_id = :t"), {"t": tid}
            ).scalar()
        assert count == 0

    def test_i08_unbound_resend_failure_old_token_preserved(self, client, engine, monkeypatch):
        """Email failure during resend must leave the original invitation fingerprint intact."""
        tid = _tid()
        _ensure_tenant(engine, tid)
        user_id = _seed_admin_user(engine, tid, "stable@example.com")
        inv_id, original_fp = _seed_invitation(engine, tid, user_id, "stable@example.com")

        from api.notifications.email import EmailDeliveryResult

        with mock.patch(
            "api.tenant_admin.send_portal_invitation",
            return_value=EmailDeliveryResult(state="failed", error_code="RESEND_ERROR"),
        ):
            r = client.post(
                f"/admin/tenants/{tid}/invite-initial-admin",
                headers=_platform_headers(tid),
                json={"email": "stable@example.com"},
            )

        assert r.status_code == 503, r.text
        # Original fingerprint must still be in DB
        fp_after = _get_invitation_fp(engine, inv_id)
        assert fp_after == original_fp


# ---------------------------------------------------------------------------
# I-09: non-platform actor → 403
# ---------------------------------------------------------------------------


class TestInviteInitialAdminNonPlatform:
    def test_i09_non_platform_denied(self, client, engine, monkeypatch):
        monkeypatch.delenv("FG_RESEND_API_KEY", raising=False)
        tid = _tid()
        _ensure_tenant(engine, tid)

        r = client.post(
            f"/admin/tenants/{tid}/invite-initial-admin",
            headers=_non_platform_headers(tid),
            json={"email": "nope@example.com"},
        )
        assert r.status_code == 403, r.text
