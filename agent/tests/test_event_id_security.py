import pytest

from agent.app.config import deterministic_event_id


def _args():
    return ("tenant", "agent", "heartbeat", "subject", "100", {"ok": True})


def test_event_id_hmac_requires_key_in_v2_mode(monkeypatch):
    monkeypatch.setenv("FG_EVENT_ID_MODE", "hmac_v2")
    monkeypatch.delenv("FG_EVENT_ID_KEY_CURRENT", raising=False)
    monkeypatch.delenv("FG_EVENT_ID_KEYS", raising=False)
    with pytest.raises(ValueError):
        deterministic_event_id(*_args())


def test_event_id_stable_for_same_payload_and_key(monkeypatch):
    monkeypatch.setenv("FG_EVENT_ID_MODE", "hmac_v2")
    monkeypatch.setenv("FG_EVENT_ID_KEY_CURRENT", "key1")
    assert deterministic_event_id(*_args()) == deterministic_event_id(*_args())


def test_event_id_changes_with_key_rotation(monkeypatch):
    monkeypatch.setenv("FG_EVENT_ID_MODE", "hmac_v2")
    monkeypatch.setenv("FG_EVENT_ID_KEY_CURRENT", "key1")
    first = deterministic_event_id(*_args())
    monkeypatch.setenv("FG_EVENT_ID_KEY_CURRENT", "key2")
    second = deterministic_event_id(*_args())
    assert first != second


def test_legacy_mode_emits_v1_hash(monkeypatch):
    monkeypatch.setenv("FG_EVENT_ID_MODE", "legacy")
    legacy = deterministic_event_id(*_args())
    assert len(legacy) == 64
    assert not legacy.startswith("ev2_")


def test_v2_prefix_format(monkeypatch):
    monkeypatch.setenv("FG_EVENT_ID_MODE", "hmac_v2")
    monkeypatch.setenv("FG_EVENT_ID_KEY_CURRENT", "key1")
    value = deterministic_event_id(*_args())
    assert value.startswith("ev2_")
    assert len(value) == 68


def test_v2_includes_canonicalization_version(monkeypatch):
    import hashlib
    import hmac
    import json

    from agent.app.config import EVENT_ID_CANON_VERSION

    # FG-855-REPAIR-001: the shipped v2 canonical payload carries canon_v=2
    # (EVENT_ID_CANON_VERSION, set in 5125a4522). The former golden used
    # canon_v=1 from a superseded draft (492fae967) and was never updated
    # because agent/tests ran in no CI lane. Pin both the constant and the
    # golden so a canonicalization change must update this test deliberately.
    assert EVENT_ID_CANON_VERSION == 2

    monkeypatch.setenv("FG_EVENT_ID_MODE", "hmac_v2")
    monkeypatch.setenv("FG_EVENT_ID_KEY_CURRENT", "key1")
    payload = {
        "tenant_id": "tenant",
        "agent_id": "agent",
        "event_type": "heartbeat",
        "subject": "subject",
        "bucket": "100",
        "features": {"ok": True},
        "canon_v": 2,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    expected = "ev2_" + hmac.new(b"key1", canonical, hashlib.sha256).hexdigest()
    assert expected == (
        "ev2_27598d1e0ea7b6a93348eb9a4401412b2df99b5fd9fd945e2cb21b0ce6861c3c"
    )
    assert deterministic_event_id(*_args()) == expected
