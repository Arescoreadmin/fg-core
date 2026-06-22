"""tests/test_c7_portal_grants.py — C7 Portal Grant Model Hardening test suite.

Covers all 15 mandatory security control layers:
  L1  Argon2id hashing — plaintext never stored, hash never exposed
  L2  Authentication — correct secret accepted, wrong secret rejected
  L3  Grant expiry — expired grants rejected at authentication time
  L4  Revocation — revoked grants/sessions rejected immediately
  L5  Rotation — old secret invalidated, new secret functional
  L6  Server-derived identity — portal identity from DB, not caller headers
  L7  Replay protection — revoked sessions fail validation and middleware
  L8  Audit trail — lifecycle events written for create/use/deny/revoke/rotate
  L9  Wrong-tenant protection — cross-tenant sessions denied
  L10 Wrong-engagement protection — valid session, wrong engagement denied
  L11 Evidence boundary — middleware enforces per-engagement scope on sub-resources
  L12 Rate limiting — IP limit (10/15min) enforced
  L13 Session management — TTL enforced, server-side revocation works
  L14 Portal scope middleware — X-FG-Portal-Session required; no query-param auth
  L15 No plaintext — grant_hash never appears in any API response
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT_ID = "tenant-c7-test"
_TENANT_B_ID = "tenant-c7-b"

_ENGAGEMENT_BODY = {
    "client_name": "Apex Corp",
    "assessor_id": "assessor-c7",
    "assessment_type": "ai_governance",
}
_ENGAGEMENT_B_BODY = {
    "client_name": "Beta Corp",
    "assessor_id": "assessor-c7",
    "assessment_type": "ai_governance",
}

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_rate_limits():
    """Reset in-memory rate limit buckets before and after each test."""
    import services.portal_grant_service as _svc

    _svc._rl_buckets.clear()
    yield
    _svc._rl_buckets.clear()


@pytest.fixture()
def client(build_app: object) -> TestClient:
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def portal_client(build_app: object) -> TestClient:
    """Portal-origin client; X-FG-Portal-Session added per-request."""
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    return TestClient(
        app, headers={"X-API-Key": key, "X-Portal-Source": "client-portal"}
    )


@pytest.fixture()
def client_b(build_app: object) -> TestClient:
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_B_ID)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def portal_client_b(build_app: object) -> TestClient:
    from api.auth_scopes import mint_key

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_B_ID)
    return TestClient(
        app, headers={"X-API-Key": key, "X-Portal-Source": "client-portal"}
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_engagement(c: TestClient, body: dict | None = None) -> dict:
    resp = c.post("/field-assessment/engagements", json=body or _ENGAGEMENT_BODY)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _create_grant(c: TestClient, eng_id: str, ttl_days: int = 14) -> dict:
    resp = c.post(
        f"/field-assessment/engagements/{eng_id}/portal-grants",
        json={"ttl_days": ttl_days},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _authenticate(c: TestClient, secret: str) -> tuple[int, dict]:
    resp = c.post("/portal/authenticate", json={"secret": secret})
    return resp.status_code, resp.json()


# ---------------------------------------------------------------------------
# L1 — Argon2id hashing: no plaintext in storage or responses
# ---------------------------------------------------------------------------


def test_l1_create_response_has_raw_secret_not_hash(client: TestClient) -> None:
    """raw_secret is returned once in CreatePortalGrantResponse; grant_hash is never present."""
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    assert "raw_secret" in data
    assert len(data["raw_secret"]) >= 40
    assert "grant_hash" not in data
    assert "grant_hash" not in data.get("grant", {})


def test_l1_raw_secret_is_not_argon2_string(client: TestClient) -> None:
    """The returned raw_secret is a random token, not an Argon2id hash string."""
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    assert not data["raw_secret"].startswith("$argon2")


def test_l15_list_grants_never_exposes_hash_or_secret(client: TestClient) -> None:
    """GET /portal-grants never exposes grant_hash or raw_secret."""
    eng = _create_engagement(client)
    _create_grant(client, eng["id"])
    resp = client.get(f"/field-assessment/engagements/{eng['id']}/portal-grants")
    assert resp.status_code == 200
    for g in resp.json():
        assert "grant_hash" not in g
        assert "raw_secret" not in g


def test_l15_rotate_response_exposes_new_secret_not_hash(client: TestClient) -> None:
    """RotatePortalGrantResponse has raw_secret; grant_hash is absent."""
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    resp = client.post(
        f"/field-assessment/engagements/{eng['id']}/portal-grants/{data['grant']['id']}/rotate"
    )
    assert resp.status_code == 200
    rot = resp.json()
    assert "raw_secret" in rot
    assert not rot["raw_secret"].startswith("$argon2")
    assert "grant_hash" not in rot
    assert "grant_hash" not in rot.get("grant", {})


def test_l15_engagement_response_has_no_client_access_code(client: TestClient) -> None:
    """EngagementResponse no longer exposes the legacy client_access_code field."""
    eng = _create_engagement(client)
    resp = client.get(f"/field-assessment/engagements/{eng['id']}")
    assert resp.status_code == 200
    assert "client_access_code" not in resp.json()


def test_l15_list_engagements_no_client_access_code(client: TestClient) -> None:
    _create_engagement(client)
    resp = client.get("/field-assessment/engagements")
    assert resp.status_code == 200
    for eng in resp.json().get("items", []):
        assert "client_access_code" not in eng


# ---------------------------------------------------------------------------
# L2 — Authentication correctness
# ---------------------------------------------------------------------------


def test_l2_authenticate_correct_secret_succeeds(client: TestClient) -> None:
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    code, result = _authenticate(client, data["raw_secret"])
    assert code == 200
    assert result["session_id"]
    assert result["client_id"] == "Apex Corp"
    assert eng["id"] in result["engagement_ids"]


def test_l2_authenticate_wrong_secret_returns_401(client: TestClient) -> None:
    eng = _create_engagement(client)
    _create_grant(client, eng["id"])
    code, _ = _authenticate(client, "not-the-right-secret-at-all")
    assert code == 401


def test_l2_authenticate_no_grants_returns_401(client: TestClient) -> None:
    _create_engagement(client)
    code, _ = _authenticate(client, "any-secret")
    assert code == 401


def test_l2_session_id_is_64_hex_chars(client: TestClient) -> None:
    """Session IDs are 32-byte hex tokens (64 chars = 256-bit entropy)."""
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    code, result = _authenticate(client, data["raw_secret"])
    assert code == 200
    sid = result["session_id"]
    assert len(sid) == 64
    assert all(c in "0123456789abcdef" for c in sid)


# ---------------------------------------------------------------------------
# L3 — Grant expiry
# ---------------------------------------------------------------------------


def test_l3_expired_grant_cannot_authenticate(build_app: object) -> None:
    """Expired grant (expires_at in the past) is rejected at authenticate time."""
    from api.auth_scopes import mint_key
    from api.db import get_sessionmaker
    from api.db_models_portal import PortalGrant
    from sqlalchemy import select

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    c = TestClient(app, headers={"X-API-Key": key})

    eng = _create_engagement(c)
    data = _create_grant(c, eng["id"])
    raw_secret = data["raw_secret"]

    SM = get_sessionmaker()
    with SM() as db:
        grant = db.execute(
            select(PortalGrant).where(PortalGrant.id == data["grant"]["id"])
        ).scalar_one()
        grant.expires_at = "2020-01-01T00:00:00+00:00"
        db.commit()

    code, _ = _authenticate(c, raw_secret)
    assert code == 401


def test_l3_expired_grant_blocks_middleware_access(build_app: object) -> None:
    """Middleware re-validates grant per request; expired grant denies access mid-session."""
    from api.auth_scopes import mint_key
    from api.db import get_sessionmaker
    from api.db_models_portal import PortalGrant
    from sqlalchemy import select

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    c = TestClient(app, headers={"X-API-Key": key})
    portal = TestClient(
        app, headers={"X-API-Key": key, "X-Portal-Source": "client-portal"}
    )

    eng = _create_engagement(c)
    data = _create_grant(c, eng["id"])
    auth = c.post("/portal/authenticate", json={"secret": data["raw_secret"]}).json()
    session_id = auth["session_id"]

    SM = get_sessionmaker()
    with SM() as db:
        grant = db.execute(
            select(PortalGrant).where(PortalGrant.id == data["grant"]["id"])
        ).scalar_one()
        grant.expires_at = "2020-01-01T00:00:00+00:00"
        db.commit()

    resp = portal.get(
        f"/field-assessment/engagements/{eng['id']}",
        headers={"X-FG-Portal-Session": session_id},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# L4 — Revocation
# ---------------------------------------------------------------------------


def test_l4_revoked_grant_cannot_authenticate(client: TestClient) -> None:
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    grant_id = data["grant"]["id"]
    raw_secret = data["raw_secret"]

    resp = client.delete(
        f"/field-assessment/engagements/{eng['id']}/portal-grants/{grant_id}"
    )
    assert resp.status_code == 204

    code, _ = _authenticate(client, raw_secret)
    assert code == 401


def test_l4_revoked_grant_shows_revoked_status(client: TestClient) -> None:
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    grant_id = data["grant"]["id"]

    client.delete(f"/field-assessment/engagements/{eng['id']}/portal-grants/{grant_id}")

    resp = client.get(f"/field-assessment/engagements/{eng['id']}/portal-grants")
    revoked = next(g for g in resp.json() if g["id"] == grant_id)
    assert revoked["status"] == "revoked"
    assert revoked["revoked_at"] is not None


def test_l4_revoke_nonexistent_grant_returns_404(client: TestClient) -> None:
    eng = _create_engagement(client)
    resp = client.delete(
        f"/field-assessment/engagements/{eng['id']}/portal-grants/nonexistent-grant-id"
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# L5 — Rotation
# ---------------------------------------------------------------------------


def test_l5_rotation_invalidates_old_secret(client: TestClient) -> None:
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    grant_id = data["grant"]["id"]
    old_secret = data["raw_secret"]

    resp = client.post(
        f"/field-assessment/engagements/{eng['id']}/portal-grants/{grant_id}/rotate"
    )
    assert resp.status_code == 200

    code, _ = _authenticate(client, old_secret)
    assert code == 401


def test_l5_rotation_new_secret_authenticates(client: TestClient) -> None:
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    grant_id = data["grant"]["id"]

    rot = client.post(
        f"/field-assessment/engagements/{eng['id']}/portal-grants/{grant_id}/rotate"
    ).json()

    code, result = _authenticate(client, rot["raw_secret"])
    assert code == 200
    assert eng["id"] in result["engagement_ids"]


def test_l5_rotation_increments_counter(client: TestClient) -> None:
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    assert data["grant"]["rotation_counter"] == 0

    rot = client.post(
        f"/field-assessment/engagements/{eng['id']}/portal-grants/{data['grant']['id']}/rotate"
    ).json()
    assert rot["grant"]["rotation_counter"] == 1


def test_l5_rotation_of_nonexistent_grant_returns_404(client: TestClient) -> None:
    eng = _create_engagement(client)
    resp = client.post(
        f"/field-assessment/engagements/{eng['id']}/portal-grants/no-such-grant/rotate"
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# L6 — Server-derived identity
# ---------------------------------------------------------------------------


def test_l6_portal_me_returns_server_derived_client_id(client: TestClient) -> None:
    """GET /portal/me returns client_id from DB — not from any caller-supplied header."""
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    auth = client.post(
        "/portal/authenticate", json={"secret": data["raw_secret"]}
    ).json()

    resp = client.get("/portal/me", headers={"X-FG-Portal-Session": auth["session_id"]})
    assert resp.status_code == 200
    me = resp.json()
    assert me["client_id"] == "Apex Corp"
    assert eng["id"] in me["engagement_ids"]


def test_l6_portal_client_id_not_overridable_via_header(
    portal_client: TestClient, client: TestClient
) -> None:
    """Portal client_id is derived from the session DB record — a spoofed header has no effect."""
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    auth = client.post(
        "/portal/authenticate", json={"secret": data["raw_secret"]}
    ).json()
    session_id = auth["session_id"]

    # Passing X-Portal-Client-ID (hypothetical spoofing header) has no effect
    resp = portal_client.get(
        f"/field-assessment/engagements/{eng['id']}",
        headers={
            "X-FG-Portal-Session": session_id,
            "X-Portal-Client-ID": "evil-client-override",
        },
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# L7 — Replay protection
# ---------------------------------------------------------------------------


def test_l7_revoked_session_denied_by_middleware(
    portal_client: TestClient, client: TestClient
) -> None:
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    auth = client.post(
        "/portal/authenticate", json={"secret": data["raw_secret"]}
    ).json()
    session_id = auth["session_id"]

    resp = portal_client.get(
        f"/field-assessment/engagements/{eng['id']}",
        headers={"X-FG-Portal-Session": session_id},
    )
    assert resp.status_code == 200

    client.delete(f"/portal/sessions/{session_id}")

    resp = portal_client.get(
        f"/field-assessment/engagements/{eng['id']}",
        headers={"X-FG-Portal-Session": session_id},
    )
    assert resp.status_code == 403


def test_l7_portal_me_fails_after_session_revocation(client: TestClient) -> None:
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    auth = client.post(
        "/portal/authenticate", json={"secret": data["raw_secret"]}
    ).json()
    session_id = auth["session_id"]

    assert (
        client.get(
            "/portal/me", headers={"X-FG-Portal-Session": session_id}
        ).status_code
        == 200
    )

    client.delete(f"/portal/sessions/{session_id}")

    assert (
        client.get(
            "/portal/me", headers={"X-FG-Portal-Session": session_id}
        ).status_code
        == 403
    )


# ---------------------------------------------------------------------------
# L8 — Audit trail
# ---------------------------------------------------------------------------


def test_l8_audit_event_on_grant_creation(build_app: object) -> None:
    from api.auth_scopes import mint_key
    from api.db import get_sessionmaker
    from api.db_models_portal import PortalGrantAuditEvent
    from sqlalchemy import select

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    c = TestClient(app, headers={"X-API-Key": key})

    eng = _create_engagement(c)
    data = _create_grant(c, eng["id"])

    SM = get_sessionmaker()
    with SM() as db:
        events = (
            db.execute(
                select(PortalGrantAuditEvent).where(
                    PortalGrantAuditEvent.grant_id == data["grant"]["id"],
                    PortalGrantAuditEvent.event_type == "grant.created",
                )
            )
            .scalars()
            .all()
        )
    assert len(events) >= 1


def test_l8_audit_event_on_authentication(build_app: object) -> None:
    from api.auth_scopes import mint_key
    from api.db import get_sessionmaker
    from api.db_models_portal import PortalGrantAuditEvent
    from sqlalchemy import select

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    c = TestClient(app, headers={"X-API-Key": key})

    eng = _create_engagement(c)
    data = _create_grant(c, eng["id"])
    c.post("/portal/authenticate", json={"secret": data["raw_secret"]})

    SM = get_sessionmaker()
    with SM() as db:
        events = (
            db.execute(
                select(PortalGrantAuditEvent).where(
                    PortalGrantAuditEvent.event_type == "grant.used",
                    PortalGrantAuditEvent.tenant_id == _TENANT_ID,
                )
            )
            .scalars()
            .all()
        )
    assert len(events) >= 1


def test_l8_audit_event_on_auth_denial(build_app: object) -> None:
    from api.auth_scopes import mint_key
    from api.db import get_sessionmaker
    from api.db_models_portal import PortalGrantAuditEvent
    from sqlalchemy import select

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    c = TestClient(app, headers={"X-API-Key": key})

    _create_engagement(c)
    c.post("/portal/authenticate", json={"secret": "bad-secret"})

    SM = get_sessionmaker()
    with SM() as db:
        events = (
            db.execute(
                select(PortalGrantAuditEvent).where(
                    PortalGrantAuditEvent.event_type == "grant.denied",
                    PortalGrantAuditEvent.tenant_id == _TENANT_ID,
                )
            )
            .scalars()
            .all()
        )
    assert len(events) >= 1


def test_l8_audit_event_on_revocation(build_app: object) -> None:
    from api.auth_scopes import mint_key
    from api.db import get_sessionmaker
    from api.db_models_portal import PortalGrantAuditEvent
    from sqlalchemy import select

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    c = TestClient(app, headers={"X-API-Key": key})

    eng = _create_engagement(c)
    data = _create_grant(c, eng["id"])
    grant_id = data["grant"]["id"]
    c.delete(f"/field-assessment/engagements/{eng['id']}/portal-grants/{grant_id}")

    SM = get_sessionmaker()
    with SM() as db:
        events = (
            db.execute(
                select(PortalGrantAuditEvent).where(
                    PortalGrantAuditEvent.grant_id == grant_id,
                    PortalGrantAuditEvent.event_type == "grant.revoked",
                )
            )
            .scalars()
            .all()
        )
    assert len(events) >= 1


def test_l8_audit_event_on_rotation(build_app: object) -> None:
    from api.auth_scopes import mint_key
    from api.db import get_sessionmaker
    from api.db_models_portal import PortalGrantAuditEvent
    from sqlalchemy import select

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    c = TestClient(app, headers={"X-API-Key": key})

    eng = _create_engagement(c)
    data = _create_grant(c, eng["id"])
    grant_id = data["grant"]["id"]
    c.post(f"/field-assessment/engagements/{eng['id']}/portal-grants/{grant_id}/rotate")

    SM = get_sessionmaker()
    with SM() as db:
        events = (
            db.execute(
                select(PortalGrantAuditEvent).where(
                    PortalGrantAuditEvent.grant_id == grant_id,
                    PortalGrantAuditEvent.event_type == "grant.rotated",
                )
            )
            .scalars()
            .all()
        )
    assert len(events) >= 1


# ---------------------------------------------------------------------------
# L9 — Wrong-tenant protection
# ---------------------------------------------------------------------------


def test_l9_cross_tenant_session_denied(
    portal_client_b: TestClient,
    client: TestClient,
    client_b: TestClient,
) -> None:
    """Session minted for tenant A cannot access tenant B's engagement endpoints."""
    eng_a = _create_engagement(client)
    data_a = _create_grant(client, eng_a["id"])
    auth_a = client.post(
        "/portal/authenticate", json={"secret": data_a["raw_secret"]}
    ).json()
    session_a = auth_a["session_id"]

    eng_b = _create_engagement(client_b)

    resp = portal_client_b.get(
        f"/field-assessment/engagements/{eng_b['id']}",
        headers={"X-FG-Portal-Session": session_a},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# L10 — Wrong-engagement protection
# ---------------------------------------------------------------------------


def test_l10_wrong_engagement_denied(
    portal_client: TestClient, client: TestClient
) -> None:
    """Valid session but no grant for the requested engagement → PORTAL_ENGAGEMENT_ACCESS_DENIED."""
    eng1 = _create_engagement(client)
    eng2 = _create_engagement(client, _ENGAGEMENT_B_BODY)

    data = _create_grant(client, eng1["id"])
    auth = client.post(
        "/portal/authenticate", json={"secret": data["raw_secret"]}
    ).json()
    session_id = auth["session_id"]

    resp = portal_client.get(
        f"/field-assessment/engagements/{eng1['id']}",
        headers={"X-FG-Portal-Session": session_id},
    )
    assert resp.status_code == 200

    resp = portal_client.get(
        f"/field-assessment/engagements/{eng2['id']}",
        headers={"X-FG-Portal-Session": session_id},
    )
    assert resp.status_code == 403
    assert resp.json()["code"] == "PORTAL_ENGAGEMENT_ACCESS_DENIED"


def test_l10_same_client_multiple_engagements_all_accessible(
    portal_client: TestClient, client: TestClient
) -> None:
    """Session grants access to all engagements with active grants for the same client."""
    body = {
        "client_name": "Multi Corp",
        "assessor_id": "a1",
        "assessment_type": "ai_governance",
    }
    eng1 = _create_engagement(client, body)
    eng2 = _create_engagement(client, body)

    data1 = _create_grant(client, eng1["id"])
    _create_grant(client, eng2["id"])

    auth = client.post(
        "/portal/authenticate", json={"secret": data1["raw_secret"]}
    ).json()
    assert eng1["id"] in auth["engagement_ids"]
    assert eng2["id"] in auth["engagement_ids"]


# ---------------------------------------------------------------------------
# L11 — Evidence boundary
# ---------------------------------------------------------------------------


def test_l11_middleware_blocks_sub_resource_wrong_engagement(
    portal_client: TestClient, client: TestClient
) -> None:
    """/findings sub-resource is also gated per engagement."""
    eng1 = _create_engagement(client)
    eng2 = _create_engagement(client, _ENGAGEMENT_B_BODY)
    data = _create_grant(client, eng1["id"])
    auth = client.post(
        "/portal/authenticate", json={"secret": data["raw_secret"]}
    ).json()
    session_id = auth["session_id"]

    resp = portal_client.get(
        f"/field-assessment/engagements/{eng2['id']}/findings",
        headers={"X-FG-Portal-Session": session_id},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# L12 — Rate limiting
# ---------------------------------------------------------------------------


def test_l12_rate_limited_after_10_ip_attempts(client: TestClient) -> None:
    """After 10 failed authentication attempts from the same IP, the 11th is 429."""
    eng = _create_engagement(client)
    _create_grant(client, eng["id"])

    for _ in range(10):
        resp = client.post("/portal/authenticate", json={"secret": "bad-secret"})
        assert resp.status_code == 401

    resp = client.post("/portal/authenticate", json={"secret": "bad-secret"})
    assert resp.status_code == 429


# ---------------------------------------------------------------------------
# L13 — Session TTL and management
# ---------------------------------------------------------------------------


def test_l13_expired_session_denied_by_middleware(build_app: object) -> None:
    from api.auth_scopes import mint_key
    from api.db import get_sessionmaker
    from api.db_models_portal import PortalGrantSession
    from sqlalchemy import select

    app = build_app(auth_enabled=True)  # type: ignore[operator]
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_ID)
    c = TestClient(app, headers={"X-API-Key": key})
    portal = TestClient(
        app, headers={"X-API-Key": key, "X-Portal-Source": "client-portal"}
    )

    eng = _create_engagement(c)
    data = _create_grant(c, eng["id"])
    auth = c.post("/portal/authenticate", json={"secret": data["raw_secret"]}).json()
    session_id = auth["session_id"]

    SM = get_sessionmaker()
    with SM() as db:
        session_row = db.execute(
            select(PortalGrantSession).where(PortalGrantSession.id == session_id)
        ).scalar_one()
        session_row.expires_at = "2020-01-01T00:00:00+00:00"
        db.commit()

    resp = portal.get(
        f"/field-assessment/engagements/{eng['id']}",
        headers={"X-FG-Portal-Session": session_id},
    )
    assert resp.status_code == 403


def test_l13_session_has_correct_client_id(client: TestClient) -> None:
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    code, result = _authenticate(client, data["raw_secret"])
    assert code == 200
    assert result["client_id"] == "Apex Corp"
    assert result["expires_at"]


def test_l13_logout_revokes_session(client: TestClient) -> None:
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    auth = client.post(
        "/portal/authenticate", json={"secret": data["raw_secret"]}
    ).json()
    session_id = auth["session_id"]

    assert (
        client.get(
            "/portal/me", headers={"X-FG-Portal-Session": session_id}
        ).status_code
        == 200
    )

    resp = client.delete(f"/portal/sessions/{session_id}")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    assert (
        client.get(
            "/portal/me", headers={"X-FG-Portal-Session": session_id}
        ).status_code
        == 403
    )


# ---------------------------------------------------------------------------
# L14 — Portal scope middleware behavior
# ---------------------------------------------------------------------------


def test_l14_middleware_requires_session_header(
    portal_client: TestClient, client: TestClient
) -> None:
    """X-Portal-Source without X-FG-Portal-Session returns 403 PORTAL_SESSION_REQUIRED."""
    eng = _create_engagement(client)
    resp = portal_client.get(f"/field-assessment/engagements/{eng['id']}")
    assert resp.status_code == 403
    assert resp.json()["code"] == "PORTAL_SESSION_REQUIRED"


def test_l14_middleware_rejects_invalid_session(
    portal_client: TestClient, client: TestClient
) -> None:
    eng = _create_engagement(client)
    resp = portal_client.get(
        f"/field-assessment/engagements/{eng['id']}",
        headers={"X-FG-Portal-Session": "totally-fake-session-id"},
    )
    assert resp.status_code == 403


def test_l14_no_portal_source_bypasses_guard(client: TestClient) -> None:
    """Operator requests (no X-Portal-Source) pass through without a session."""
    eng = _create_engagement(client)
    resp = client.get(f"/field-assessment/engagements/{eng['id']}")
    assert resp.status_code == 200


def test_l14_portal_me_requires_session_header(client: TestClient) -> None:
    resp = client.get("/portal/me")
    assert resp.status_code == 403


def test_l14_portal_me_invalid_session_returns_403(client: TestClient) -> None:
    resp = client.get("/portal/me", headers={"X-FG-Portal-Session": "fake-session-id"})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Portal grant management routes — contract tests
# ---------------------------------------------------------------------------


def test_create_grant_for_nonexistent_engagement_returns_404(
    client: TestClient,
) -> None:
    resp = client.post(
        "/field-assessment/engagements/nonexistent-id/portal-grants",
        json={"ttl_days": 14},
    )
    assert resp.status_code == 404


def test_create_multiple_grants_same_engagement(client: TestClient) -> None:
    eng = _create_engagement(client)
    data1 = _create_grant(client, eng["id"])
    data2 = _create_grant(client, eng["id"])
    assert data1["grant"]["id"] != data2["grant"]["id"]
    assert data1["raw_secret"] != data2["raw_secret"]


def test_list_grants_shows_all(client: TestClient) -> None:
    eng = _create_engagement(client)
    _create_grant(client, eng["id"])
    _create_grant(client, eng["id"])
    resp = client.get(f"/field-assessment/engagements/{eng['id']}/portal-grants")
    assert resp.status_code == 200
    assert len(resp.json()) >= 2


def test_grant_response_contains_expected_fields(client: TestClient) -> None:
    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"])
    g = data["grant"]
    assert g["status"] == "active"
    assert g["engagement_id"] == eng["id"]
    assert g["client_id"] == "Apex Corp"
    assert g["rotation_counter"] == 0
    assert g["expires_at"]
    assert g["created_at"]
    assert g.get("revoked_at") is None


def test_custom_ttl_grant_expiry_is_honoured(client: TestClient) -> None:
    from datetime import datetime, timedelta, timezone

    eng = _create_engagement(client)
    data = _create_grant(client, eng["id"], ttl_days=7)
    expires = datetime.fromisoformat(data["grant"]["expires_at"].replace("Z", "+00:00"))
    diff = expires - datetime.now(timezone.utc)
    assert timedelta(days=6) <= diff <= timedelta(days=8)
