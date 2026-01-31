from api.auth_scopes import mint_key
import pytest
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


@pytest.mark.smoke
def test_feed_live_requires_auth():
    r = client.get("/feed/live?limit=5")
    assert r.status_code == 401


@pytest.mark.smoke
def test_feed_live_returns_items_with_auth():
    # P0 Security Fix: tenant_id is now required
    test_tenant = "pytest-tenant"
    key = mint_key("feed:read", tenant_id=test_tenant)

    r = client.get(f"/feed/live?limit=5&tenant_id={test_tenant}", headers={"X-API-Key": key})
    assert r.status_code == 200
    body = r.json()
    assert "items" in body
    assert isinstance(body["items"], list)
    if body["items"]:
        item = body["items"][0]
        for k in (
            "decision_id",
            "timestamp",
            "severity",
            "title",
            "summary",
            "action_taken",
            "confidence",
        ):
            assert k in item
