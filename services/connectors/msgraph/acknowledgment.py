"""Operator acknowledgment — HMAC-SHA256 receipt generation and verification.

The receipt is a cryptographic artifact stored in the engagement record
and included in the report appendix as chain of custody evidence.

The signing key is derived from the engagement_id and a FrostGate master
key (FG_ACKNOWLEDGMENT_KEY env var — never hardcoded).

Security invariant: the plaintext signing key is never logged, included in
error messages, or stored anywhere except environment memory.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from services.connectors.msgraph.manifest import (
    AUTHORIZED_SCOPES,
    AcknowledgmentVerificationError,
)
from services.connectors.msgraph.schema.scan_result import AcknowledgmentReceipt

_ENV_KEY = "FG_ACKNOWLEDGMENT_KEY"


def _master_key() -> bytes:
    val = os.environ.get(_ENV_KEY, "")
    if not val:
        raise AcknowledgmentVerificationError(
            "FG_ACKNOWLEDGMENT_KEY is required for operator acknowledgment signing"
        )
    return val.encode("utf-8")


def _derive_signing_key(engagement_id: str) -> bytes:
    """Derive a per-engagement HMAC key from the master key."""
    return hmac.new(
        _master_key(),
        engagement_id.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def _canonical_payload(
    *,
    operator_name: str,
    operator_org: str,
    client_org_name: str,
    scopes_acknowledged: list[str],
    scan_authorized_at: str,
    engagement_id: str,
) -> bytes:
    """Deterministic byte string for HMAC input — field order is fixed."""
    parts = [
        f"operator_name:{operator_name}",
        f"operator_org:{operator_org}",
        f"client_org_name:{client_org_name}",
        f"scopes_acknowledged:{','.join(sorted(scopes_acknowledged))}",
        f"scan_authorized_at:{scan_authorized_at}",
        f"engagement_id:{engagement_id}",
    ]
    return "\n".join(parts).encode("utf-8")


def generate_receipt(
    *,
    operator_name: str,
    operator_org: str,
    client_org_name: str,
    scan_authorized_at: str,
    engagement_id: str,
    scopes_acknowledged: list[str] | None = None,
) -> AcknowledgmentReceipt:
    """Generate a signed operator acknowledgment receipt.

    scopes_acknowledged defaults to the full AUTHORIZED_SCOPES list.
    """
    scopes = list(scopes_acknowledged or AUTHORIZED_SCOPES)
    key = _derive_signing_key(engagement_id)
    payload = _canonical_payload(
        operator_name=operator_name,
        operator_org=operator_org,
        client_org_name=client_org_name,
        scopes_acknowledged=scopes,
        scan_authorized_at=scan_authorized_at,
        engagement_id=engagement_id,
    )
    receipt_hmac = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return AcknowledgmentReceipt(
        operator_name=operator_name,
        operator_org=operator_org,
        client_org_name=client_org_name,
        scopes_acknowledged=scopes,
        scan_authorized_at=scan_authorized_at,
        engagement_id=engagement_id,
        receipt_hmac=receipt_hmac,
    )


def verify_receipt(receipt: AcknowledgmentReceipt) -> None:
    """Verify the receipt HMAC.  Raises AcknowledgmentVerificationError on failure.

    Uses constant-time comparison to prevent timing oracle.
    """
    key = _derive_signing_key(receipt.engagement_id)
    payload = _canonical_payload(
        operator_name=receipt.operator_name,
        operator_org=receipt.operator_org,
        client_org_name=receipt.client_org_name,
        scopes_acknowledged=list(receipt.scopes_acknowledged),
        scan_authorized_at=receipt.scan_authorized_at,
        engagement_id=receipt.engagement_id,
    )
    expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, receipt.receipt_hmac):
        raise AcknowledgmentVerificationError(
            "Operator acknowledgment HMAC verification failed — scan aborted"
        )
