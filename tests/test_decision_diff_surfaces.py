import pytest
import os
from fastapi.testclient import TestClient

from api.main import app
from api.auth_scopes import mint_key


client = TestClient(app)


@pytest.mark.smoke
def test_decision_diff_exposed_in_decisions_and_feed():
    # P0 Security Fix: Use consistent tenant for isolation
    test_tenant = "pytest-tenant"

    # generate two decisions with same (tenant/source/event_type) to create a diff
    payload = {
        "event_type": "auth_attempt",
        "source": "pytest",
        "tenant_id": test_tenant,
        "metadata": {"source_ip": "1.2.3.4", "username": "alice", "failed_attempts": 1},
    }

    r1 = client.post(
        "/defend", json=payload, headers={"x-api-key": os.environ["FG_API_KEY"]}
    )
    assert r1.status_code in (200, 201), r1.text

    payload["metadata"]["failed_attempts"] = 10
    r2 = client.post(
        "/defend", json=payload, headers={"x-api-key": os.environ["FG_API_KEY"]}
    )
    assert r2.status_code in (200, 201), r2.text

    # decisions list should include decision_diff (P0: tenant_id required)
    key_dec = mint_key("decisions:read", tenant_id=test_tenant)
    dl = client.get(f"/decisions?limit=5&tenant_id={test_tenant}", headers={"X-API-Key": key_dec})
    assert dl.status_code == 200, dl.text
    data = dl.json()
    items = data.get("items") or data.get("results") or []
    assert isinstance(items, list) and len(items) >= 1
    assert "decision_diff" in items[0]

    # feed live should include decision_diff too (P0: tenant_id required)
    key_feed = mint_key("feed:read", tenant_id=test_tenant)
    fl = client.get(f"/feed/live?limit=5&tenant_id={test_tenant}", headers={"X-API-Key": key_feed})
    assert fl.status_code == 200, fl.text
    fdata = fl.json()
    fitems = fdata.get("items") or fdata.get("results") or []
    assert isinstance(fitems, list) and len(fitems) >= 1
    assert "decision_diff" in fitems[0]
