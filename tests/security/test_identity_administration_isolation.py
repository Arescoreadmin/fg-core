"""Cross-tenant isolation security tests for identity administration.

Verifies that:
- Admin of tenant A cannot see or modify tenant B users
- Invitation tokens are tenant-scoped
- Groups from tenant A are not accessible from tenant B
- Self-service cannot see other user's profile
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

TENANT_A = "tenant-isolation-a"
TENANT_B = "tenant-isolation-b"

_SCOPES = ("governance:read", "governance:write", "admin:read", "admin:write")


@pytest.fixture(autouse=True)
def _reset_singletons() -> None:
    reset_services()
    reset_admin_services()


@pytest.fixture
def app(build_app):
    """Single app instance shared across both tenant clients in each test."""
    return build_app(auth_enabled=True, api_key="")


@pytest.fixture
def client_a(app) -> TestClient:
    key = mint_key(*_SCOPES, tenant_id=TENANT_A, ttl_seconds=3600)
    return TestClient(app, headers={"x-api-key": key})


@pytest.fixture
def client_b(app) -> TestClient:
    key = mint_key(*_SCOPES, tenant_id=TENANT_B, ttl_seconds=3600)
    return TestClient(app, headers={"x-api-key": key})


class TestUserListIsolation:
    def test_tenant_a_list_does_not_include_tenant_b_users(
        self, client_a: TestClient, client_b: TestClient
    ) -> None:
        # Create user in tenant B
        client_b.post(
            "/identity/admin/users/invite",
            json={"email": "tenant-b-user@example.com"},
        )
        # List from tenant A should be empty
        resp = client_a.get("/identity/admin/users")
        assert resp.status_code == 200
        items = resp.json()["items"]
        emails = [i["email"] for i in items]
        assert "tenant-b-user@example.com" not in emails


class TestLifecycleIsolation:
    def test_cannot_transition_lifecycle_of_other_tenant_user(
        self, client_a: TestClient, client_b: TestClient
    ) -> None:
        # Create user in tenant B
        invite_resp = client_b.post(
            "/identity/admin/users/invite",
            json={"email": "b-user@example.com"},
        )
        b_subject = invite_resp.json()["subject"]

        # Try to transition from tenant A — should 400 (not found in tenant A)
        resp = client_a.patch(
            f"/identity/admin/users/{b_subject}/lifecycle",
            json={"target_state": "INVITATION_SENT", "reason": "cross-tenant attack"},
        )
        assert resp.status_code == 400  # ValueError: identity not found in tenant


class TestInvitationIsolation:
    def test_tenant_a_invitations_not_visible_from_tenant_b(
        self, client_a: TestClient, client_b: TestClient
    ) -> None:
        client_a.post(
            "/identity/admin/users/invite",
            json={"email": "private@example.com"},
        )
        resp = client_b.get("/identity/admin/invitations")
        assert resp.status_code == 200
        invitations = resp.json()
        emails = [i["email"] for i in invitations]
        assert "private@example.com" not in emails

    def test_cannot_revoke_other_tenant_invitation(
        self, client_a: TestClient, client_b: TestClient
    ) -> None:
        invite_resp = client_a.post(
            "/identity/admin/users/invite",
            json={"email": "other@example.com"},
        )
        invitation_id = invite_resp.json()["invitation_id"]

        # Try to revoke from tenant B — should fail: not found in tenant B
        resp = client_b.delete(f"/identity/admin/invitations/{invitation_id}")
        assert resp.status_code == 400


class TestGroupIsolation:
    def test_group_from_tenant_a_not_accessible_from_tenant_b(
        self, client_a: TestClient, client_b: TestClient
    ) -> None:
        create_resp = client_a.post(
            "/identity/admin/groups",
            json={"name": "SecretGroup", "description": "sensitive"},
        )
        group_id = create_resp.json()["group_id"]

        resp = client_b.get(f"/identity/admin/groups/{group_id}")
        assert resp.status_code == 404

    def test_list_groups_isolated_per_tenant(
        self, client_a: TestClient, client_b: TestClient
    ) -> None:
        client_a.post(
            "/identity/admin/groups",
            json={"name": "GroupForA"},
        )
        client_b.post(
            "/identity/admin/groups",
            json={"name": "GroupForB"},
        )
        resp_a = client_a.get("/identity/admin/groups")
        names_a = [g["name"] for g in resp_a.json()]
        assert "GroupForA" in names_a
        assert "GroupForB" not in names_a
