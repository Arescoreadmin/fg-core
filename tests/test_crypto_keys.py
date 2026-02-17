from __future__ import annotations

import json

import pytest

from services.crypto_keys import load_hmac_keys


def test_keyring_rejects_duplicate_key_id(monkeypatch) -> None:
    payload = {
        "keys": [
            {
                "key_id": "k1",
                "created_at_utc": "2026-01-01T00:00:00Z",
                "key_b64": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
            },
            {
                "key_id": "k1",
                "created_at_utc": "2026-01-02T00:00:00Z",
                "key_b64": "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=",
            },
        ]
    }
    monkeypatch.setenv("FG_AUDIT_HMAC_KEYS_JSON", json.dumps(payload, sort_keys=True))
    with pytest.raises(RuntimeError, match="duplicate key_id"):
        load_hmac_keys("FG_AUDIT")


def test_keyring_rejects_bad_retired_window(monkeypatch) -> None:
    payload = {
        "keys": [
            {
                "key_id": "k1",
                "created_at_utc": "2026-01-02T00:00:00Z",
                "retired_at_utc": "2026-01-01T00:00:00Z",
                "key_b64": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
            }
        ]
    }
    monkeypatch.setenv("FG_AUDIT_HMAC_KEYS_JSON", json.dumps(payload, sort_keys=True))
    with pytest.raises(RuntimeError, match="retired_at_utc"):
        load_hmac_keys("FG_AUDIT")
