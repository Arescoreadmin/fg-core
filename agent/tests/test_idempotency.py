import hashlib
import json

import pytest

from agent.app.config import deterministic_event_id


def _legacy_expected():
    payload = {
        "tenant_id": "t",
        "agent_id": "a",
        "event_type": "heartbeat",
        "subject": "s",
        "bucket": "b",
        "features": {"alive": True},
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def test_hmac_v2_requires_key(monkeypatch):
    monkeypatch.setenv("FG_EVENT_ID_MODE", "hmac_v2")
    monkeypatch.delenv("FG_EVENT_ID_KEY_CURRENT", raising=False)
    with pytest.raises(ValueError):
        deterministic_event_id("t", "a", "heartbeat", "s", "b", {"alive": True})


def test_deterministic_event_id_stable(monkeypatch):
    monkeypatch.setenv("FG_EVENT_ID_MODE", "legacy")
    f = {"alive": True}
    a = deterministic_event_id("t", "a", "heartbeat", "s", "b", f)
    b = deterministic_event_id("t", "a", "heartbeat", "s", "b", {"alive": True})
    assert a == b


def test_hmac_v2_changes_under_new_key(monkeypatch):
    monkeypatch.setenv("FG_EVENT_ID_MODE", "hmac_v2")
    monkeypatch.setenv("FG_EVENT_ID_KEY_CURRENT", "k1")
    a = deterministic_event_id("t", "a", "heartbeat", "s", "b", {"alive": True})
    monkeypatch.setenv("FG_EVENT_ID_KEY_CURRENT", "k2")
    b = deterministic_event_id("t", "a", "heartbeat", "s", "b", {"alive": True})
    assert a != b


def test_legacy_mode_unchanged(monkeypatch):
    monkeypatch.setenv("FG_EVENT_ID_MODE", "legacy")
    assert (
        deterministic_event_id("t", "a", "heartbeat", "s", "b", {"alive": True})
        == _legacy_expected()
    )


def test_v2_prefix_format(monkeypatch):
    monkeypatch.setenv("FG_EVENT_ID_MODE", "hmac_v2")
    monkeypatch.setenv("FG_EVENT_ID_KEY_CURRENT", "k1")
    event_id = deterministic_event_id("t", "a", "heartbeat", "s", "b", {"alive": True})
    assert event_id.startswith("ev2_")
    assert len(event_id) == 68
