# api/webhook_security.py
"""
Webhook Security - HMAC Signature Verification.

Provides secure webhook integration with:
- HMAC-SHA256 request signature verification
- Timestamp validation to prevent replay attacks
- Request body validation
- Configurable tolerance windows
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

log = logging.getLogger("frostgate.webhook")

# =============================================================================
# Configuration
# =============================================================================


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    try:
        return int(v)
    except ValueError:
        return default


def _env_str(name: str, default: str) -> str:
    return os.getenv(name, default).strip()


# Webhook configuration
WEBHOOK_SECRET = _env_str("FG_WEBHOOK_SECRET", "")
WEBHOOK_TIMESTAMP_TOLERANCE = _env_int(
    "FG_WEBHOOK_TIMESTAMP_TOLERANCE", 300
)  # 5 minutes
WEBHOOK_SIGNATURE_HEADER = _env_str("FG_WEBHOOK_SIGNATURE_HEADER", "X-FG-Signature")
WEBHOOK_TIMESTAMP_HEADER = _env_str("FG_WEBHOOK_TIMESTAMP_HEADER", "X-FG-Timestamp")


class SignatureAlgorithm(str, Enum):
    """Supported signature algorithms."""

    HMAC_SHA256 = "sha256"
    HMAC_SHA512 = "sha512"


@dataclass
class SignatureVerificationResult:
    """Result of signature verification."""

    valid: bool
    error: Optional[str] = None
    algorithm: Optional[str] = None


def compute_signature(
    payload: bytes,
    secret: str,
    timestamp: Optional[int] = None,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.HMAC_SHA256,
) -> str:
    """
    Compute HMAC signature for a payload.

    The signature is computed as:
        HMAC(secret, timestamp.payload)

    Including the timestamp prevents replay attacks.
    """
    if timestamp is None:
        timestamp = int(time.time())

    # Create the signed payload: timestamp.body
    signed_payload = f"{timestamp}.".encode() + payload

    if algorithm == SignatureAlgorithm.HMAC_SHA256:
        signature = hmac.new(
            secret.encode("utf-8"),
            signed_payload,
            hashlib.sha256,
        ).hexdigest()
    elif algorithm == SignatureAlgorithm.HMAC_SHA512:
        signature = hmac.new(
            secret.encode("utf-8"),
            signed_payload,
            hashlib.sha512,
        ).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return f"v1={signature}"


def verify_signature(
    payload: bytes,
    signature: str,
    timestamp: int,
    secret: Optional[str] = None,
    tolerance: Optional[int] = None,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.HMAC_SHA256,
) -> SignatureVerificationResult:
    """
    Verify an HMAC signature.

    Args:
        payload: The raw request body
        signature: The signature from the request header
        timestamp: The timestamp from the request header
        secret: The webhook secret (defaults to FG_WEBHOOK_SECRET env)
        tolerance: Maximum age of the request in seconds
        algorithm: Signature algorithm to use

    Returns:
        SignatureVerificationResult with validation status
    """
    secret = secret or WEBHOOK_SECRET
    tolerance = tolerance if tolerance is not None else WEBHOOK_TIMESTAMP_TOLERANCE

    # Check if secret is configured
    if not secret:
        log.warning("Webhook signature verification skipped: no secret configured")
        return SignatureVerificationResult(
            valid=True,
            error="Signature verification disabled (no secret configured)",
            algorithm=algorithm.value,
        )

    # Validate timestamp to prevent replay attacks
    current_time = int(time.time())
    time_diff = abs(current_time - timestamp)

    if time_diff > tolerance:
        log.warning(
            f"Webhook signature failed: timestamp too old/future "
            f"(diff={time_diff}s, tolerance={tolerance}s)"
        )
        return SignatureVerificationResult(
            valid=False,
            error=f"Timestamp outside tolerance window ({time_diff}s > {tolerance}s)",
            algorithm=algorithm.value,
        )

    # Parse signature format (v1=signature)
    if not signature:
        return SignatureVerificationResult(
            valid=False,
            error="Missing signature",
            algorithm=algorithm.value,
        )

    sig_parts = signature.split("=", 1)
    if len(sig_parts) != 2:
        return SignatureVerificationResult(
            valid=False,
            error="Invalid signature format (expected v1=signature)",
            algorithm=algorithm.value,
        )

    version, provided_sig = sig_parts

    if version != "v1":
        return SignatureVerificationResult(
            valid=False,
            error=f"Unsupported signature version: {version}",
            algorithm=algorithm.value,
        )

    # Compute expected signature
    expected = compute_signature(payload, secret, timestamp, algorithm)
    expected_sig = expected.split("=", 1)[1]

    # Constant-time comparison
    if not hmac.compare_digest(provided_sig, expected_sig):
        log.warning("Webhook signature verification failed: signature mismatch")
        return SignatureVerificationResult(
            valid=False,
            error="Signature mismatch",
            algorithm=algorithm.value,
        )

    return SignatureVerificationResult(
        valid=True,
        error=None,
        algorithm=algorithm.value,
    )


def sign_webhook_request(
    payload: bytes,
    secret: Optional[str] = None,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.HMAC_SHA256,
) -> Tuple[str, int]:
    """
    Sign a webhook request for outgoing webhooks.

    Returns (signature, timestamp) to include in headers.
    """
    secret = secret or WEBHOOK_SECRET
    timestamp = int(time.time())

    if not secret:
        raise ValueError("Webhook secret not configured")

    signature = compute_signature(payload, secret, timestamp, algorithm)
    return signature, timestamp


class WebhookVerifier:
    """
    Webhook verifier for FastAPI dependency injection.

    Usage:
        verifier = WebhookVerifier()

        @app.post("/webhook")
        async def webhook(
            request: Request,
            _: None = Depends(verifier.verify),
        ):
            ...
    """

    def __init__(
        self,
        secret: Optional[str] = None,
        tolerance: Optional[int] = None,
        signature_header: Optional[str] = None,
        timestamp_header: Optional[str] = None,
        algorithm: SignatureAlgorithm = SignatureAlgorithm.HMAC_SHA256,
    ):
        self.secret = secret or WEBHOOK_SECRET
        self.tolerance = (
            tolerance if tolerance is not None else WEBHOOK_TIMESTAMP_TOLERANCE
        )
        self.signature_header = signature_header or WEBHOOK_SIGNATURE_HEADER
        self.timestamp_header = timestamp_header or WEBHOOK_TIMESTAMP_HEADER
        self.algorithm = algorithm

    async def verify(self, request) -> SignatureVerificationResult:
        """
        FastAPI dependency to verify webhook signature.

        Raises HTTPException on invalid signature.
        """
        from fastapi import HTTPException

        # Get headers (case-insensitive)
        signature = request.headers.get(self.signature_header)
        timestamp_str = request.headers.get(self.timestamp_header)

        if not signature:
            log.warning(f"Missing webhook signature header: {self.signature_header}")
            raise HTTPException(
                status_code=401,
                detail=f"Missing {self.signature_header} header",
            )

        if not timestamp_str:
            log.warning(f"Missing webhook timestamp header: {self.timestamp_header}")
            raise HTTPException(
                status_code=401,
                detail=f"Missing {self.timestamp_header} header",
            )

        try:
            timestamp = int(timestamp_str)
        except (ValueError, TypeError):
            raise HTTPException(
                status_code=400,
                detail="Invalid timestamp format",
            )

        # Get raw body
        body = await request.body()

        result = verify_signature(
            payload=body,
            signature=signature,
            timestamp=timestamp,
            secret=self.secret,
            tolerance=self.tolerance,
            algorithm=self.algorithm,
        )

        if not result.valid:
            log.warning(f"Webhook signature verification failed: {result.error}")
            raise HTTPException(
                status_code=401,
                detail=result.error or "Invalid signature",
            )

        return result


# Default verifier instance
default_webhook_verifier = WebhookVerifier()


__all__ = [
    "SignatureAlgorithm",
    "SignatureVerificationResult",
    "compute_signature",
    "verify_signature",
    "sign_webhook_request",
    "WebhookVerifier",
    "default_webhook_verifier",
    "WEBHOOK_SIGNATURE_HEADER",
    "WEBHOOK_TIMESTAMP_HEADER",
]
