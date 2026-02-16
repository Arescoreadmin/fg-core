from fastapi.testclient import TestClient

from api.auth_scopes import mint_key

try:
    from api.main import app
except Exception as e:
    raise RuntimeError(
        "Could not import api.main:app. Adjust import in tests/test_explanation_brief.py"
    ) from e


def test_defend_returns_explanation_brief(monkeypatch):
    monkeypatch.setenv("FG_RL_ENABLED", "0")
    api_key = mint_key("defend:write", tenant_id="tenant-explain")

    payload = {
        "tenant_id": "tenant-explain",
        "event_type": "auth_attempt",
        "source": "pytest",
        "metadata": {
            "source_ip": "1.2.3.4",
            "username": "alice",
            # include anything your brute-force rule expects if you have one
            "failed_attempts": 10,
        },
    }

    # IMPORTANT: Use context manager so startup/shutdown runs and resources close.
    with TestClient(app) as client:
        r = client.post("/defend", json=payload, headers={"x-api-key": api_key})

    assert r.status_code in (200, 201), r.text
    data = r.json()

    assert "explanation_brief" in data, data
    assert isinstance(data["explanation_brief"], str)
    assert len(data["explanation_brief"]) > 0
