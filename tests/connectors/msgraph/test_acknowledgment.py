"""Tests for operator acknowledgment receipt generation and verification."""

from __future__ import annotations


import pytest

from services.connectors.msgraph.acknowledgment import generate_receipt, verify_receipt
from services.connectors.msgraph.manifest import AUTHORIZED_SCOPES


@pytest.fixture(autouse=True)
def set_ack_key(monkeypatch):
    monkeypatch.setenv("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")


def _base_params():
    return dict(
        operator_name="Alice",
        operator_org="Acme Security",
        client_org_name="ACME Corp",
        engagement_id="eng-001",
        scan_authorized_at="2026-01-01T00:00:00+00:00",
    )


def test_generate_receipt_produces_valid_hmac():
    receipt = generate_receipt(**_base_params())
    verify_receipt(receipt)  # raises on failure


def test_receipt_contains_all_authorized_scopes():
    receipt = generate_receipt(**_base_params())
    assert set(receipt.scopes_acknowledged) == set(AUTHORIZED_SCOPES)


def test_tampered_receipt_fails_verification():
    receipt = generate_receipt(**_base_params())
    tampered = receipt.model_copy(update={"operator_name": "Mallory"})
    with pytest.raises(Exception):
        verify_receipt(tampered)


def test_tampered_hmac_fails_verification():
    receipt = generate_receipt(**_base_params())
    tampered = receipt.model_copy(update={"receipt_hmac": "00" * 32})
    with pytest.raises(Exception):
        verify_receipt(tampered)


def test_missing_acknowledgment_key_fails_closed(monkeypatch):
    monkeypatch.delenv("FG_ACKNOWLEDGMENT_KEY", raising=False)
    with pytest.raises(Exception, match="FG_ACKNOWLEDGMENT_KEY is required"):
        generate_receipt(**_base_params())


def test_receipt_is_frozen():
    receipt = generate_receipt(**_base_params())
    with pytest.raises(Exception):
        receipt.operator_name = "changed"  # type: ignore[misc]
