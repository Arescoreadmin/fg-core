"""Tests for manifest constants and error classes."""

from __future__ import annotations


from services.connectors.msgraph.manifest import (
    AUTHORIZED_SCOPES,
    AUTHORIZED_SCOPES_SET,
    MAX_PAGES_PER_ENDPOINT,
    MAX_RECORDS_PER_PAGE,
    REQUEST_TIMEOUT_SECONDS,
    SCAN_TOTAL_TIMEOUT_SECONDS,
    AcknowledgmentVerificationError,
    ScanTimeoutError,
    TenantIsolationError,
    UnauthorizedScopeError,
)


def test_authorized_scopes_immutable():
    assert isinstance(AUTHORIZED_SCOPES, tuple)
    assert len(AUTHORIZED_SCOPES) == 7


def test_authorized_scopes_set_matches_tuple():
    assert AUTHORIZED_SCOPES_SET == frozenset(AUTHORIZED_SCOPES)


def test_bounds_are_sane():
    assert MAX_PAGES_PER_ENDPOINT == 10
    assert MAX_RECORDS_PER_PAGE == 999
    assert REQUEST_TIMEOUT_SECONDS == 30
    assert SCAN_TOTAL_TIMEOUT_SECONDS == 900


def test_error_classes_are_exceptions():
    for cls in (
        UnauthorizedScopeError,
        AcknowledgmentVerificationError,
        TenantIsolationError,
        ScanTimeoutError,
    ):
        assert issubclass(cls, Exception)
