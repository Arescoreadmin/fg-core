"""Tests for identity administration REST routes using TestClient.

Uses auth_enabled=True with mint_key() to get a tenant-scoped API key.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")
os.environ.setdefault("FG_API_KEY", "ci-test-key-00000000000000000000000000000000")
os.environ.setdefault("FG_KEY_PEPPER", "ci-test-pepper")

import pytest
from starlette.testclient import TestClient

from api.auth_scopes import mint_key
from api.identity_administration.services import reset_admin_services
from api.identity_governance.services import reset_services

TENANT = "tenant-routes-test-001"


@pytest.fixture(autouse=True)
def _reset_singletons() -> None:
    reset_services()
    reset_admin_services()


@pytest.fixture
def client(build_app) -> TestClient:
    app = build_app(auth_enabled=True, api_key="")
    key = mint_key(
        "governance:read",
        "governance:write",
        "admin:read",
        "admin:write",
        tenant_id=TENANT,
        ttl_seconds=3600,
    )
    return TestClient(app, headers={"x-api-key": key})


class TestInviteUser:
    def test_invite_returns_201(self, client: TestClient) -> None:
        resp = client.post(
            "/identity/admin/users/invite",
            json={"email": "new@example.com", "expiry_days": 7},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "invitation_token" in data
        assert "invitation_id" in data
        assert data["lifecycle_state"] == "INVITED"


class TestListUsers:
    def test_list_returns_200(self, client: TestClient) -> None:
        resp = client.get("/identity/admin/users")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data

    def test_list_shows_invited_user(self, client: TestClient) -> None:
        client.post(
            "/identity/admin/users/invite",
            json={"email": "listed@example.com"},
        )
        resp = client.get("/identity/admin/users")
        assert resp.status_code == 200
        items = resp.json()["items"]
        emails = [i["email"] for i in items]
        assert "listed@example.com" in emails


class TestLifecycleTransition:
    def test_patch_lifecycle_returns_200(self, client: TestClient) -> None:
        invite_resp = client.post(
            "/identity/admin/users/invite",
            json={"email": "lifecycle@example.com"},
        )
        assert invite_resp.status_code == 201
        subject = invite_resp.json()["subject"]

        # Transition to INVITATION_SENT (valid from INVITED)
        resp = client.patch(
            f"/identity/admin/users/{subject}/lifecycle",
            json={"target_state": "INVITATION_SENT", "reason": "email sent"},
        )
        assert resp.status_code == 200
        assert resp.json()["lifecycle_state"] == "INVITATION_SENT"

    def test_invalid_transition_returns_400(self, client: TestClient) -> None:
        invite_resp = client.post(
            "/identity/admin/users/invite",
            json={"email": "badtransition@example.com"},
        )
        subject = invite_resp.json()["subject"]
        resp = client.patch(
            f"/identity/admin/users/{subject}/lifecycle",
            json={"target_state": "ACTIVE", "reason": "bad"},
        )
        # INVITED → ACTIVE is not valid; should be 400
        assert resp.status_code == 400


class TestInvitationRevoke:
    def test_delete_invitation_returns_204(self, client: TestClient) -> None:
        invite_resp = client.post(
            "/identity/admin/users/invite",
            json={"email": "revoke@example.com"},
        )
        invitation_id = invite_resp.json()["invitation_id"]
        resp = client.delete(f"/identity/admin/invitations/{invitation_id}")
        assert resp.status_code == 204


class TestAcceptInvitation:
    def test_accept_with_valid_token_returns_200(self, client: TestClient) -> None:
        invite_resp = client.post(
            "/identity/admin/users/invite",
            json={"email": "accept@example.com"},
        )
        token = invite_resp.json()["invitation_token"]
        # Accept endpoint is public — no auth headers needed
        resp = client.post(
            "/identity/invitations/accept",
            json={"token": token, "accepted_by": "user-subject-001"},
            headers=dict[
                str, str
            ](),  # override default key headers for public endpoint
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ACCEPTED"


class TestOwnProfile:
    def test_get_me_returns_404_if_no_profile(self, client: TestClient) -> None:
        # The minted key's subject won't have an identity record
        resp = client.get("/identity/me")
        # 404 because no identity record was created for the API key subject
        assert resp.status_code == 404


class TestDeleteUser:
    def test_delete_invited_user_returns_204(self, client: TestClient) -> None:
        invite_resp = client.post(
            "/identity/admin/users/invite",
            json={"email": "delete-me@example.com"},
        )
        subject = invite_resp.json()["subject"]
        resp = client.delete(f"/identity/admin/users/{subject}")
        assert resp.status_code == 204

    def test_delete_missing_user_returns_404(self, client: TestClient) -> None:
        resp = client.delete("/identity/admin/users/no-such-subject-xyz")
        assert resp.status_code == 404


class TestAcceptInvitationTransitionsLifecycle:
    def test_accept_transitions_identity_to_accepted(self, client: TestClient) -> None:
        invite_resp = client.post(
            "/identity/admin/users/invite",
            json={"email": "lifecycle-accept@example.com"},
        )
        assert invite_resp.status_code == 201
        data = invite_resp.json()
        token = data["invitation_token"]
        subject = data["subject"]

        resp = client.post(
            "/identity/invitations/accept",
            json={"token": token, "accepted_by": subject},
            headers=dict[str, str](),
        )
        assert resp.status_code == 200

        # Identity must now be in ACCEPTED state.
        identity_resp = client.get(f"/identity/admin/users/{subject}")
        assert identity_resp.status_code == 200
        assert identity_resp.json()["lifecycle_state"] == "ACCEPTED"


class TestDeviceOwnershipEnforcement:
    def test_device_trust_returns_403_for_wrong_subject(
        self, client: TestClient
    ) -> None:
        from api.identity_governance.services import get_services

        # Register device under alice; try to revoke it via bob's path.
        gov = get_services()
        device = gov.device_registry.register_device(
            subject="alice-subject",
            tenant_id=TENANT,
            fingerprint_hash="fpr-alice",
            user_agent_hash="ua-alice",
            ip_metadata="",
        )
        resp = client.patch(
            f"/identity/admin/users/bob-subject/devices/{device.device_id}",
            json={"action": "revoke", "reason": "test"},
        )
        assert resp.status_code == 403


class TestGroups:
    def test_list_admin_groups_returns_200(self, client: TestClient) -> None:
        resp = client.get("/identity/admin/groups")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_create_group_returns_201(self, client: TestClient) -> None:
        resp = client.post(
            "/identity/admin/groups",
            json={"name": "TestGroup", "description": "A test group"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "TestGroup"
        assert "group_id" in data
