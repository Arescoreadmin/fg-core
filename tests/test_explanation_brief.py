import os

import pytest
from fastapi.testclient import TestClient

try:
    from api.main import app
except Exception as e:
    raise RuntimeError(
        "Could not import api.main:app. Adjust import in tests/test_explanation_brief.py"
    ) from e


@pytest.fixture()
def client():
    # Ensures startup/shutdown (lifespan) runs and resources get closed.
    with TestClient(app) as c:
        yield c


def test_defend_returns_explanation_brief(client: TestClient):
    api_key = os.getenv("FG_API_KEY")
    if not api_key:
        pytest.skip("FG_API_KEY not set; skipping API-key protected /defend test")

    payload = {
        "event_type": "auth_attempt",
        "source": "pytest",
        "metadata": {
            "source_ip": "1.2.3.4",
            "username": "alice",
            # include anything your brute-force rule expects if you have one
            "failed_attempts": 10,
        },
    }

    r = client.post("/defend", json=payload, headers={"x-api-key": api_key})
    assert r.status_code in (200, 201), r.text
    data = r.json()

    assert "explanation_brief" in data, data
    assert isinstance(data["explanation_brief"], str)
    assert len(data["explanation_brief"]) > 0
