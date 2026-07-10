"""Tests for machine-readable identity error codes."""

from __future__ import annotations

import pytest

from api.identity_governance.error_codes import (
    IDENTITY_ERROR_MESSAGES,
    IdentityErrorCode,
    error_body,
)


def test_all_values_are_unique_strings() -> None:
    values = [member.value for member in IdentityErrorCode]
    assert len(set(values)) == len(values)
    for v in values:
        assert isinstance(v, str) and v == v.strip() and v.upper() == v


def test_every_code_has_a_message() -> None:
    for member in IdentityErrorCode:
        assert member in IDENTITY_ERROR_MESSAGES, (
            f"{member.name}: missing IDENTITY_ERROR_MESSAGES entry"
        )
        message = IDENTITY_ERROR_MESSAGES[member]
        assert isinstance(message, str) and message
        # Messages must not leak subject/tenant/token content.
        lower = message.lower()
        for forbidden in ("token", "password", "secret", "@", "tenant_id"):
            assert forbidden not in lower, f"leaky message on {member}: {message}"


def test_error_body_shape() -> None:
    body = error_body(IdentityErrorCode.SESSION_REVOKED)
    assert body == {
        "code": "SESSION_REVOKED",
        "message": IDENTITY_ERROR_MESSAGES[IdentityErrorCode.SESSION_REVOKED],
    }


def test_error_body_with_reason() -> None:
    body = error_body(IdentityErrorCode.POLICY_DENIED, reason="identity_state")
    assert body["code"] == "POLICY_DENIED"
    assert body["reason"] == "identity_state"


@pytest.mark.parametrize(
    "expected",
    [
        "IDENTITY_SUSPENDED",
        "IDENTITY_DISABLED",
        "SESSION_EXPIRED",
        "SESSION_REVOKED",
        "DEVICE_REVOKED",
        "DEVICE_COMPROMISED",
        "MFA_STEP_UP_REQUIRED",
        "POLICY_DENIED",
        "PERMISSION_DENIED",
        "CAPABILITY_DENIED",
        "TENANT_MISMATCH",
        "BREAK_GLASS_REQUIRED",
        "BREAK_GLASS_EXPIRED",
    ],
)
def test_expected_codes_present(expected: str) -> None:
    assert IdentityErrorCode(expected).value == expected


def test_string_enum() -> None:
    # str.Enum guarantees direct string comparison works for wire format.
    assert IdentityErrorCode.SESSION_REVOKED == "SESSION_REVOKED"
