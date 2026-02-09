from __future__ import annotations

import time

from api.auth_scopes import (
    AuthResult,
    _b64url_json,
    _decode_token_payload,
    _is_key_expired,
    _parse_scopes_csv,
    _validate_tenant_id,
)


def test_parse_scopes_csv_handles_lists_and_strings():
    assert _parse_scopes_csv(["read", "write", ""]) == {"read", "write"}
    assert _parse_scopes_csv("read, write ,") == {"read", "write"}
    assert _parse_scopes_csv(None) == set()


def test_is_key_expired_with_and_without_exp():
    now = int(time.time())
    assert _is_key_expired({"exp": now - 1}, now=now) is True
    assert _is_key_expired({"exp": now + 5}, now=now) is False
    assert _is_key_expired({"foo": "bar"}, now=now) is False
    assert _is_key_expired(None, now=now) is False


def test_validate_tenant_id_edge_cases():
    assert _validate_tenant_id("tenant_ok") == (True, "")
    assert _validate_tenant_id("tenant-1") == (True, "")
    assert _validate_tenant_id("bad tenant") == (
        False,
        "tenant_id contains invalid characters",
    )
    assert _validate_tenant_id("x" * 129) == (
        False,
        "tenant_id exceeds maximum length",
    )


def test_decode_token_payload_round_trip():
    payload = {"exp": 123, "tenant_id": "tenant-a"}
    token = _b64url_json(payload)
    assert _decode_token_payload(token) == payload


def test_auth_result_reason_helpers():
    missing = AuthResult(valid=False, reason="no_key_provided")
    invalid = AuthResult(valid=False, reason="key_not_found")

    assert missing.is_missing_key is True
    assert missing.is_invalid_key is False
    assert invalid.is_missing_key is False
    assert invalid.is_invalid_key is True
