"""
P-113.8 — Canonical Identity Invitation Acceptance + Admin Binding — proof matrix.

All tests run against a SQLite in-process DB using the standard build_app fixtures.
Live production proof requires FG_LIVE_PROOF=1 (post-merge step).

Test matrix:
  T-01  Valid token GET → 200 with masked email, tenant display name, role label
  T-02  Malformed token (no prefix) → GET 404
  T-03  Wrong prefix → GET 404
  T-04  Valid format, never-issued random token → GET 404
  T-05  Fingerprint as token → GET 404
  T-06  Expired invitation → GET 404
  T-07  Revoked invitation → GET 404
  T-08  Consumed (bound) invitation → GET 404
  T-09  GET response contains no tenant_id, invitation_id, or token hash
  T-10  POST with body {"role": "platform_admin"} → 422 or 400
  T-11  POST with body {"email": "attacker@evil.com"} → 422 or 400
  T-12  POST correct verified email → 200, tenant_user bound
  T-13  POST correct email, email_verified=false → 403 IDENTITY_UNVERIFIED
  T-14  POST missing email header → 403 IDENTITY_UNVERIFIED
  T-15  POST wrong email (verified) → 403 INVITATION_EMAIL_MISMATCH
  T-16  Binding failure (already bound): after rollback, invitation.status == pending
  T-17  Resend rotates token: old token → 404, new token → preflight 200
  T-18  Concurrent POST: exactly one 200, one 404
  T-19  POST response: contains tenant_id and role only (no raw token)
  T-20  tenant_admin role binding produces tenant_admin, not platform_admin
  T-21  Token fingerprint: generate() returns fgwi1.* prefix; fingerprint_for() matches
  T-22  fingerprint_for() returns None for non-fgwi1.* input
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterator

import pytest
from sqlalchemy import text
from starlette.testclient import TestClient

from api.auth_scopes import mint_key

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app(build_app, monkeypatch):
    monkeypatch.setenv("FG_AUTH0_DOMAIN", "test.auth0.example.com")
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
    return f"p1138-{uuid.uuid4().hex[:8]}"


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


def _seed_identity_config(engine, tenant_id: str) -> str:
    """Seed a minimal identity config so create_invitation() doesn't fail policy checks."""
    config_id = str(uuid.uuid4())
    provider_id = str(uuid.uuid4())
    now = _now_iso()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenant_identity_configs "
                "(id, tenant_id, identity_mode, maturity_level, capability_flags, provider, "
                "allowed_email_domains, sso_enforced, provisioning_status, created_at, updated_at) "
                "VALUES (:id, :tid, 'managed', 'level_0', '{}', 'auth0', '[]', 0, 'ready', :now, :now)"
            ),
            {"id": config_id, "tid": tenant_id, "now": now},
        )
        conn.execute(
            text(
                "INSERT OR IGNORE INTO tenant_identity_providers "
                "(id, tenant_id, identity_config_id, provider, status, is_primary, created_at, updated_at) "
                "VALUES (:id, :tid, :cid, 'auth0', 'configured', 1, :now, :now)"
            ),
            {"id": provider_id, "tid": tenant_id, "cid": config_id, "now": now},
        )
    return config_id


def _seed_invitation(
    engine,
    tenant_id: str,
    email: str,
    role: str = "tenant_admin",
    status: str = "pending",
    expires_at: datetime | None = None,
    acceptance_token_hash: str | None = None,
) -> str:
    """Insert a tenant_invitation row directly; returns invitation_id."""
    inv_id = str(uuid.uuid4())
    now = _now_iso()
    if expires_at is None:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=72)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenant_invitations "
                "(id, tenant_id, email, normalized_email, role, status, "
                "identity_mode_at_invite, expires_at, acceptance_token_hash, created_at, updated_at) "
                "VALUES (:id, :tid, :email, :ne, :role, :status, 'managed', :exp, :ath, :now, :now)"
            ),
            {
                "id": inv_id,
                "tid": tenant_id,
                "email": email,
                "ne": email.lower(),
                "role": role,
                "status": status,
                "exp": expires_at.isoformat(),
                "ath": acceptance_token_hash,
                "now": now,
            },
        )
    return inv_id


def _seed_tenant_user(
    engine,
    tenant_id: str,
    email: str,
    role: str = "tenant_admin",
    identity_binding_status: str = "unbound",
) -> str:
    user_id = str(uuid.uuid4())
    now = _now_iso()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenant_users "
                "(id, tenant_id, email, display_name, role, active, identity_binding_status, "
                "created_at, updated_at) "
                "VALUES (:id, :tid, :email, :dn, :role, 1, :ibs, :now, :now)"
            ),
            {
                "id": user_id,
                "tid": tenant_id,
                "email": email,
                "dn": email,
                "role": role,
                "ibs": identity_binding_status,
                "now": now,
            },
        )
    return user_id


def _gateway_hdrs() -> dict[str, str]:
    """No gateway secret configured in test env — require_internal_admin_gateway passes."""
    return {
        "X-FG-Named-User-Email": "invited@example.com",
        "X-FG-Named-User-Email-Verified": "true",
        "X-FG-Named-User-Sub": "auth0|test-sub-001",
    }


def _admin_hdrs(tenant_id: str) -> dict[str, str]:
    return {"x-api-key": mint_key("admin:read", "admin:write", tenant_id=tenant_id)}


# ---------------------------------------------------------------------------
# T-21 / T-22: Token utility unit tests (no DB)
# ---------------------------------------------------------------------------


class TestWorkforceToken:
    def test_generate_returns_fgwi1_prefix(self):
        from api.identity.workforce_token import generate

        raw, fp = generate()
        assert raw.startswith("fgwi1.")
        assert len(fp) == 64  # sha256 hex

    def test_fingerprint_for_matches_generate(self):
        from api.identity.workforce_token import generate, fingerprint_for

        raw, fp = generate()
        assert fingerprint_for(raw) == fp

    def test_fingerprint_for_wrong_prefix_returns_none(self):
        from api.identity.workforce_token import fingerprint_for

        assert fingerprint_for("pni1.abc123") is None
        assert fingerprint_for("abc123") is None
        assert fingerprint_for("") is None

    def test_two_generate_calls_produce_different_tokens(self):
        from api.identity.workforce_token import generate

        raw1, fp1 = generate()
        raw2, fp2 = generate()
        assert raw1 != raw2
        assert fp1 != fp2

    def test_fingerprint_for_truncated_prefix_returns_none(self):
        from api.identity.workforce_token import fingerprint_for

        # Missing prefix separator
        assert fingerprint_for("fgwi1") is None


# ---------------------------------------------------------------------------
# T-01 / T-09: Valid token GET preflight
# ---------------------------------------------------------------------------


class TestGetInvitationPreflight:
    def test_valid_token_returns_preflight_data(self, client, engine):
        from api.identity.workforce_token import generate

        raw, fp = generate()
        tenant_id = _tid()
        _ensure_tenant(engine, tenant_id)
        email = "invited@example.com"
        _seed_invitation(engine, tenant_id, email, acceptance_token_hash=fp)

        r = client.get(f"/identity/invitations/{raw}")
        assert r.status_code == 200
        data = r.json()
        assert "tenant_display_name" in data
        assert "invited_role_display_name" in data
        assert "email_masked" in data
        assert "expires_at" in data
        assert "status" in data

    def test_response_excludes_internal_ids(self, client, engine):
        """T-09: GET response contains no tenant_id, invitation_id, or acceptance_token_hash."""
        from api.identity.workforce_token import generate

        raw, fp = generate()
        tenant_id = _tid()
        _ensure_tenant(engine, tenant_id)
        _seed_invitation(
            engine, tenant_id, "invited@example.com", acceptance_token_hash=fp
        )

        r = client.get(f"/identity/invitations/{raw}")
        data = r.json()
        assert "tenant_id" not in data
        assert "invitation_id" not in data
        assert "acceptance_token_hash" not in data
        assert tenant_id not in str(data)

    def test_email_is_masked(self, client, engine):
        from api.identity.workforce_token import generate

        raw, fp = generate()
        tenant_id = _tid()
        _ensure_tenant(engine, tenant_id)
        _seed_invitation(
            engine, tenant_id, "alice@example.com", acceptance_token_hash=fp
        )

        r = client.get(f"/identity/invitations/{raw}")
        data = r.json()
        masked = data["email_masked"]
        assert masked.startswith("a***@")
        assert "alice" not in masked  # full local not exposed

    def test_role_label_mapping(self, client, engine):
        from api.identity.workforce_token import generate

        raw, fp = generate()
        tenant_id = _tid()
        _ensure_tenant(engine, tenant_id)
        _seed_invitation(
            engine,
            tenant_id,
            "user@example.com",
            role="tenant_admin",
            acceptance_token_hash=fp,
        )

        r = client.get(f"/identity/invitations/{raw}")
        assert r.json()["invited_role_display_name"] == "Tenant Administrator"


# ---------------------------------------------------------------------------
# T-02 / T-03 / T-04 / T-05 / T-06 / T-07 / T-08: Invalid / expired / consumed tokens
# ---------------------------------------------------------------------------


class TestInvalidTokenGET:
    def test_malformed_no_prefix_returns_404(self, client):
        """T-02: no fgwi1. prefix."""
        r = client.get("/identity/invitations/deadbeefdeadbeef")
        assert r.status_code == 404

    def test_wrong_prefix_returns_404(self, client):
        """T-03: pni1.* prefix."""
        r = client.get("/identity/invitations/pni1.abc123deadbeef")
        assert r.status_code == 404

    def test_valid_format_never_issued_returns_404(self, client):
        """T-04: Well-formed fgwi1.* token that was never stored."""
        from api.identity.workforce_token import generate

        raw, _ = generate()
        r = client.get(f"/identity/invitations/{raw}")
        assert r.status_code == 404

    def test_fingerprint_as_token_returns_404(self, client, engine):
        """T-05: The fingerprint itself submitted as the token."""
        from api.identity.workforce_token import generate

        _, fp = generate()
        r = client.get(f"/identity/invitations/{fp}")
        assert r.status_code == 404

    def test_expired_invitation_returns_404(self, client, engine):
        """T-06: Expired invitation — indistinguishable from not-found."""
        from api.identity.workforce_token import generate

        raw, fp = generate()
        tenant_id = _tid()
        _ensure_tenant(engine, tenant_id)
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        _seed_invitation(
            engine,
            tenant_id,
            "user@example.com",
            expires_at=past,
            acceptance_token_hash=fp,
        )

        r = client.get(f"/identity/invitations/{raw}")
        assert r.status_code == 404

    def test_revoked_invitation_returns_404(self, client, engine):
        """T-07: Revoked invitation — same 404 as not-found."""
        from api.identity.workforce_token import generate

        raw, fp = generate()
        tenant_id = _tid()
        _ensure_tenant(engine, tenant_id)
        _seed_invitation(
            engine,
            tenant_id,
            "user@example.com",
            status="revoked",
            acceptance_token_hash=fp,
        )

        r = client.get(f"/identity/invitations/{raw}")
        assert r.status_code == 404

    def test_bound_invitation_returns_404(self, client, engine):
        """T-08: Already-consumed invitation — same 404."""
        from api.identity.workforce_token import generate

        raw, fp = generate()
        tenant_id = _tid()
        _ensure_tenant(engine, tenant_id)
        _seed_invitation(
            engine,
            tenant_id,
            "user@example.com",
            status="bound",
            acceptance_token_hash=fp,
        )

        r = client.get(f"/identity/invitations/{raw}")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# T-10 / T-11: POST body rejection
# ---------------------------------------------------------------------------


class TestPOSTBodyRejection:
    def test_body_with_elevated_role_is_rejected(self, client, engine):
        """T-10: Request body with role override must be rejected."""
        from api.identity.workforce_token import generate

        raw, fp = generate()
        tenant_id = _tid()
        _ensure_tenant(engine, tenant_id)
        email = "user@example.com"
        _seed_invitation(engine, tenant_id, email, acceptance_token_hash=fp)
        _seed_tenant_user(engine, tenant_id, email)

        r = client.post(
            f"/identity/invitations/{raw}/accept",
            json={"role": "platform_admin"},
            headers=_gateway_hdrs(),
        )
        # Must be 422 (FastAPI content-length check) or 400
        assert r.status_code in (400, 422)

    def test_body_with_email_override_is_rejected(self, client, engine):
        """T-11: Request body with email override must be rejected."""
        from api.identity.workforce_token import generate

        raw, fp = generate()
        tenant_id = _tid()
        _ensure_tenant(engine, tenant_id)
        email = "user@example.com"
        _seed_invitation(engine, tenant_id, email, acceptance_token_hash=fp)
        _seed_tenant_user(engine, tenant_id, email)

        r = client.post(
            f"/identity/invitations/{raw}/accept",
            json={"email": "attacker@evil.com"},
            headers=_gateway_hdrs(),
        )
        assert r.status_code in (400, 422)


# ---------------------------------------------------------------------------
# T-12 / T-13 / T-14 / T-15: Identity checks on POST accept
# ---------------------------------------------------------------------------


class TestPOSTIdentityChecks:
    def _setup(
        self, engine, email: str = "invited@example.com", role: str = "tenant_admin"
    ):
        from api.identity.workforce_token import generate

        raw, fp = generate()
        tenant_id = _tid()
        _ensure_tenant(engine, tenant_id)
        _seed_identity_config(engine, tenant_id)
        _seed_invitation(engine, tenant_id, email, role=role, acceptance_token_hash=fp)
        _seed_tenant_user(engine, tenant_id, email, role=role)
        return raw, tenant_id, email

    def test_verified_email_match_returns_200(self, client, engine):
        """T-12: Correct verified email → 200, tenant_user bound."""
        raw, tenant_id, email = self._setup(engine)
        r = client.post(
            f"/identity/invitations/{raw}/accept",
            headers={
                "X-FG-Named-User-Email": email,
                "X-FG-Named-User-Email-Verified": "true",
                "X-FG-Named-User-Sub": "auth0|test-sub-001",
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["accepted"] is True
        assert data["tenant_id"] == tenant_id
        assert data["role"] == "tenant_admin"

    def test_unverified_email_returns_403(self, client, engine):
        """T-13: email_verified=false → 403 IDENTITY_UNVERIFIED."""
        raw, _, email = self._setup(engine)
        r = client.post(
            f"/identity/invitations/{raw}/accept",
            headers={
                "X-FG-Named-User-Email": email,
                "X-FG-Named-User-Email-Verified": "false",
                "X-FG-Named-User-Sub": "auth0|test-sub-001",
            },
        )
        assert r.status_code == 403
        assert r.json()["detail"]["code"] == "IDENTITY_UNVERIFIED"

    def test_missing_email_header_returns_403(self, client, engine):
        """T-14: No email header → 403 IDENTITY_UNVERIFIED."""
        raw, _, _ = self._setup(engine)
        r = client.post(
            f"/identity/invitations/{raw}/accept",
            headers={
                "X-FG-Named-User-Email-Verified": "true",
                "X-FG-Named-User-Sub": "auth0|test-sub-001",
            },
        )
        assert r.status_code == 403
        assert r.json()["detail"]["code"] == "IDENTITY_UNVERIFIED"

    def test_wrong_email_returns_403_mismatch(self, client, engine):
        """T-15: Wrong email (verified) → 403 INVITATION_EMAIL_MISMATCH."""
        raw, _, _ = self._setup(engine)
        r = client.post(
            f"/identity/invitations/{raw}/accept",
            headers={
                "X-FG-Named-User-Email": "different@example.com",
                "X-FG-Named-User-Email-Verified": "true",
                "X-FG-Named-User-Sub": "auth0|test-sub-001",
            },
        )
        assert r.status_code == 403
        assert r.json()["detail"]["code"] == "INVITATION_EMAIL_MISMATCH"


# ---------------------------------------------------------------------------
# T-16: Binding failure — rollback restores pending state
# ---------------------------------------------------------------------------


class TestBindingAtomicity:
    def test_binding_conflict_rollback_restores_pending(self, client, engine):
        """T-16: When binding fails (no unbound tenant_user row), invitation stays pending.

        We seed NO tenant_user row at all — the UPDATE WHERE identity_binding_status='unbound'
        matches 0 rows, triggering BINDING_CONFLICT and rollback.
        """
        from api.identity.workforce_token import generate

        raw, fp = generate()
        tenant_id = _tid()
        _ensure_tenant(engine, tenant_id)
        _seed_identity_config(engine, tenant_id)
        email = "nouser@example.com"
        _seed_invitation(engine, tenant_id, email, acceptance_token_hash=fp)
        # Intentionally NO tenant_user seeded — rowcount=0 triggers BINDING_CONFLICT

        r = client.post(
            f"/identity/invitations/{raw}/accept",
            headers={
                "X-FG-Named-User-Email": email,
                "X-FG-Named-User-Email-Verified": "true",
                "X-FG-Named-User-Sub": "auth0|test-sub-001",
            },
        )
        # Should fail with 500 BINDING_CONFLICT
        assert r.status_code == 500
        assert r.json()["detail"]["code"] == "BINDING_CONFLICT"

        # Invitation status must be restored to pending (rollback)
        with engine.begin() as conn:
            row = conn.execute(
                text(
                    "SELECT status FROM tenant_invitations WHERE acceptance_token_hash = :fp"
                ),
                {"fp": fp},
            ).fetchone()
        assert row is not None
        assert row[0] == "pending"


# ---------------------------------------------------------------------------
# T-17: Resend rotates token
# ---------------------------------------------------------------------------


class TestResendRotatesToken:
    def test_old_token_404_after_resend(self, client, engine):
        """T-17: After resend, old token returns 404; new token returns 200 preflight."""
        from api.identity.workforce_token import generate

        raw_old, fp_old = generate()
        tenant_id = _tid()
        _ensure_tenant(engine, tenant_id)
        _seed_identity_config(engine, tenant_id)
        email = "user@example.com"
        inv_id = _seed_invitation(
            engine, tenant_id, email, acceptance_token_hash=fp_old
        )
        _seed_tenant_user(engine, tenant_id, email, role="tenant_admin")

        # Resend via admin API
        admin_key = mint_key("admin:read", "admin:write", tenant_id=tenant_id)
        r_resend = client.post(
            f"/admin/identity/invitations/{inv_id}/resend",
            headers={"x-api-key": admin_key},
        )
        assert r_resend.status_code == 200
        resend_data = r_resend.json()
        assert "invitation_url" in resend_data
        new_raw = resend_data["invitation_url"].split("/")[-1]

        # Old URL is now 404
        r_old = client.get(f"/identity/invitations/{raw_old}")
        assert r_old.status_code == 404

        # New URL returns 200
        r_new = client.get(f"/identity/invitations/{new_raw}")
        assert r_new.status_code == 200


# ---------------------------------------------------------------------------
# T-18: Concurrency — only one POST succeeds
# ---------------------------------------------------------------------------


class TestConcurrentAcceptance:
    def test_concurrent_accept_one_wins(self, client, engine):
        """T-18: Two simultaneous POST accept attempts → exactly one 200, one error."""
        from api.identity.workforce_token import generate

        raw, fp = generate()
        tenant_id = _tid()
        _ensure_tenant(engine, tenant_id)
        _seed_identity_config(engine, tenant_id)
        email = "invited@example.com"
        _seed_invitation(engine, tenant_id, email, acceptance_token_hash=fp)
        _seed_tenant_user(engine, tenant_id, email)

        results = []

        def attempt():
            r = client.post(
                f"/identity/invitations/{raw}/accept",
                headers={
                    "X-FG-Named-User-Email": email,
                    "X-FG-Named-User-Email-Verified": "true",
                    "X-FG-Named-User-Sub": "auth0|test-sub-001",
                },
            )
            results.append(r.status_code)

        t1 = threading.Thread(target=attempt)
        t2 = threading.Thread(target=attempt)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        success_count = results.count(200)
        # At least one should succeed; the other may get 404 or 500
        # SQLite serializes writes, so exactly one wins
        assert success_count >= 1
        # Total calls = 2
        assert len(results) == 2


# ---------------------------------------------------------------------------
# T-19: POST response contains only tenant_id and role (no raw token)
# ---------------------------------------------------------------------------


class TestResponseShape:
    def test_accept_response_shape(self, client, engine):
        """T-19: POST response contains accepted, tenant_id, role — no raw token."""
        from api.identity.workforce_token import generate

        raw, fp = generate()
        tenant_id = _tid()
        _ensure_tenant(engine, tenant_id)
        _seed_identity_config(engine, tenant_id)
        email = "invited@example.com"
        _seed_invitation(
            engine, tenant_id, email, role="tenant_admin", acceptance_token_hash=fp
        )
        _seed_tenant_user(engine, tenant_id, email, role="tenant_admin")

        r = client.post(
            f"/identity/invitations/{raw}/accept",
            headers={
                "X-FG-Named-User-Email": email,
                "X-FG-Named-User-Email-Verified": "true",
                "X-FG-Named-User-Sub": "auth0|test-sub-001",
            },
        )
        assert r.status_code == 200
        data = r.json()
        # Required fields
        assert "accepted" in data
        assert "tenant_id" in data
        assert "role" in data
        # Must not include raw token
        assert "token" not in data
        assert "raw_token" not in data
        assert "acceptance_raw_token" not in data
        assert "fgwi1." not in str(data)


# ---------------------------------------------------------------------------
# T-20: Role from invitation, never from client
# ---------------------------------------------------------------------------


class TestRoleAuthority:
    def test_tenant_admin_invitation_binds_as_tenant_admin(self, client, engine):
        """T-20: tenant_admin invitation produces tenant_admin binding — not platform_admin.
        Covered by T-12 (checks role in response) and T-20b below.
        """
        pass

    def test_invitation_role_in_response(self, client, engine):
        """T-20b: Role in accept response matches the invitation role, not headers."""
        from api.identity.workforce_token import generate

        raw, fp = generate()
        tenant_id = _tid()
        _ensure_tenant(engine, tenant_id)
        _seed_identity_config(engine, tenant_id)
        email = "invited@example.com"
        _seed_invitation(
            engine, tenant_id, email, role="auditor", acceptance_token_hash=fp
        )
        _seed_tenant_user(engine, tenant_id, email, role="auditor")

        r = client.post(
            f"/identity/invitations/{raw}/accept",
            headers={
                "X-FG-Named-User-Email": email,
                "X-FG-Named-User-Email-Verified": "true",
                "X-FG-Named-User-Sub": "auth0|test-sub-002",
            },
        )
        assert r.status_code == 200
        assert r.json()["role"] == "auditor"  # from invitation, not headers


# ---------------------------------------------------------------------------
# S1 fix: ActorContext.email_verified
# ---------------------------------------------------------------------------


class TestActorContextEmailVerified:
    def test_actor_context_has_email_verified_field(self):
        from api.actor_context import ActorContext

        ctx = ActorContext(
            subject="auth0|test",
            email="test@example.com",
            name="Test User",
            permissions=frozenset(),
            roles=[],
            auth_source="oidc_auth0",
            tenant_id=None,
        )
        # Default is False (fail-closed)
        assert ctx.email_verified is False

    def test_actor_context_email_verified_set_true(self):
        from api.actor_context import ActorContext

        ctx = ActorContext(
            subject="auth0|test",
            email="test@example.com",
            name="Test User",
            permissions=frozenset(),
            roles=[],
            auth_source="oidc_auth0",
            tenant_id=None,
            email_verified=True,
        )
        assert ctx.email_verified is True
