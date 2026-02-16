import os
import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from api.main import app


os.environ.setdefault("FG_RL_ENABLED", "0")
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

    defend_key = mint_key("defend:write", tenant_id=test_tenant)
    r1 = client.post("/defend", json=payload, headers={"x-api-key": defend_key})
    assert r1.status_code in (200, 201), r1.text

    payload["metadata"]["failed_attempts"] = 10
    r2 = client.post("/defend", json=payload, headers={"x-api-key": defend_key})
    assert r2.status_code in (200, 201), r2.text

    # decisions list should include decision_diff (P0: tenant_id required)
    key_dec = mint_key("decisions:read", tenant_id=test_tenant)
    dl = client.get("/decisions?limit=5", headers={"X-API-Key": key_dec})
    assert dl.status_code == 200, dl.text
    data = dl.json()
    items = data.get("items") or data.get("results") or []
    assert isinstance(items, list) and len(items) >= 1
    assert "decision_diff" in items[0]

    # feed live should include decision_diff too (P0: tenant_id required)
    key_feed = mint_key("feed:read", tenant_id=test_tenant)
    fl = client.get("/feed/live?limit=5", headers={"X-API-Key": key_feed})
    assert fl.status_code == 200, fl.text
    fdata = fl.json()
    fitems = fdata.get("items") or fdata.get("results") or []
    assert isinstance(fitems, list) and len(fitems) >= 1
    assert "decision_diff" in fitems[0]
