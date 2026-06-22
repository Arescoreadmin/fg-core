"""Public key endpoint for Ed25519 report signature verification."""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, HTTPException

from services.governance.report.signing import ReportSigningKeyError, get_public_key_hex

router = APIRouter(prefix="/signing", tags=["signing"])


@router.get("/public-key")
def get_report_signing_public_key() -> dict:
    """Return the Ed25519 public key used to sign governance reports.

    Verification-only clients can use this key to independently verify
    X-Report-Signature headers on PDF export responses.
    """
    try:
        pub_hex = get_public_key_hex()
    except ReportSigningKeyError:
        raise HTTPException(
            status_code=503,
            detail="Report signing key not configured on this server.",
        )
    key_id = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:16]
    return {
        "algorithm": "ed25519",
        "public_key": pub_hex,
        "key_id": key_id,
        "usage": "report-signing",
        "digest": "sha256",
        "verify_instruction": (
            "Compute SHA-256 of the canonical report JSON string, then verify "
            "the Ed25519 signature against that digest using this public key."
        ),
    }
