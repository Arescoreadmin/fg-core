"""IDENTITY-ACCEPT-002: retire caller-attributed workforce acceptance."""

from __future__ import annotations

from starlette.testclient import TestClient

from api.auth_scopes import mint_key


def _routes(app):
    return {route.path for route in app.routes if hasattr(route, "path")}


def _admin_client(build_app) -> TestClient:
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key("admin:read", "admin:write", tenant_id="identity-accept-002")
    return TestClient(app, headers={"x-api-key": key})


def test_legacy_route_is_removed_and_canonical_route_remains(build_app):
    app = build_app(auth_enabled=True, api_key="")
    routes = _routes(app)
    assert "/identity/invitations/accept" not in routes
    assert "/identity/invitations/{token}/accept" in routes


def test_legacy_public_exact_path_is_not_restored():
    from api.security.public_paths import PUBLIC_PATHS_EXACT, PUBLIC_PATHS_PREFIX

    assert "/identity/invitations/accept" not in PUBLIC_PATHS_EXACT
    assert "/identity/invitations/" in PUBLIC_PATHS_PREFIX


def test_legacy_endpoint_cannot_mutate_or_bind(build_app):
    with _admin_client(build_app) as client:
        invitation = client.post(
            "/identity/admin/users/invite", json={"email": "accept-002@example.com"}
        )
        assert invitation.status_code == 201
        subject = invitation.json()["subject"]

        response = client.post(
            "/identity/invitations/accept",
            json={
                "token": invitation.json()["invitation_token"],
                "accepted_by": "forged",
            },
        )
        assert response.status_code in (404, 405)
        assert "INVITATION" not in response.text
        assert "accepted" not in response.text.lower()

        state = client.get(f"/identity/admin/users/{subject}")
        assert state.status_code == 200
        assert state.json()["lifecycle_state"] == "INVITED"
        assert state.json().get("identity_binding_status") in (None, "unbound")


def test_unauthenticated_legacy_request_does_not_disclose_token_state(build_app):
    app = build_app(auth_enabled=True, api_key="")
    with TestClient(app) as client:
        response = client.post(
            "/identity/invitations/accept",
            json={"token": "fgwi1.synthetic", "accepted_by": "forged"},
        )
    assert response.status_code in (401, 404, 405)
    assert "INVITATION" not in response.text
    assert "accepted" not in response.text.lower()


def test_no_alternate_legacy_workforce_mutation_authority(build_app):
    with _admin_client(build_app) as client:
        response = client.post(
            "/workforce/users/accept-invite",
            json={"token": "fgwi1.synthetic", "accepted_by": "forged"},
        )
    assert response.status_code == 410
    assert response.json()["detail"]["code"] == "LEGACY_INVITE_ENDPOINT_REMOVED"


def test_canonical_acceptance_requires_verified_named_user(build_app, monkeypatch):
    from tests.test_p1138_invitation_acceptance import (
        _ensure_tenant,
        _seed_identity_config,
        _seed_invitation,
        _seed_tenant_user,
    )
    from api.identity.workforce_token import generate
    from api.db import get_engine

    monkeypatch.setenv("FG_AUTH0_DOMAIN", "test.auth0.example.com")
    app = build_app(auth_enabled=True, api_key="")
    engine = get_engine()
    raw, fingerprint = generate()
    tenant_id = "identity-accept-002-canonical"
    _ensure_tenant(engine, tenant_id)
    _seed_identity_config(engine, tenant_id)
    _seed_invitation(
        engine, tenant_id, "accept-002@example.com", acceptance_token_hash=fingerprint
    )
    _seed_tenant_user(engine, tenant_id, "accept-002@example.com")

    with TestClient(app) as client:
        unverified = client.post(
            f"/identity/invitations/{raw}/accept",
            headers={
                "X-FG-Named-User-Email": "accept-002@example.com",
                "X-FG-Named-User-Email-Verified": "false",
                "X-FG-Named-User-Sub": "auth0|accept-002",
            },
        )
        assert unverified.status_code == 403
        assert unverified.json()["detail"]["code"] == "IDENTITY_UNVERIFIED"

        mismatch = client.post(
            f"/identity/invitations/{raw}/accept",
            headers={
                "X-FG-Named-User-Email": "wrong@example.com",
                "X-FG-Named-User-Email-Verified": "true",
                "X-FG-Named-User-Sub": "auth0|accept-002",
            },
        )
        assert mismatch.status_code == 403
        assert mismatch.json()["detail"]["code"] == "INVITATION_EMAIL_MISMATCH"
