"""
Signed gateway-to-core internal context.

Protocol:
  - Algorithm: HMAC-SHA256
  - Header:    X-FG-Signed-Context
  - Format:    base64url(canonical_json_payload).<hmac_sha256_hex>
  - Canonical: json.dumps(payload, separators=(",",":"), sort_keys=True)
  - Required payload fields: tenant_id, actor_id, scopes, request_id, trace_id, iat
  - iat: Unix timestamp (int); context is valid for MAX_AGE_SECONDS after iat

Secret: FG_GATEWAY_SIGNING_SECRET env var (required when enforcement is active)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import FrozenSet

HEADER_NAME: str = "X-FG-Signed-Context"
MAX_AGE_SECONDS: int = 60
REQUIRED_FIELDS: frozenset[str] = frozenset(
    {"tenant_id", "actor_id", "scopes", "request_id", "trace_id", "iat"}
)


@dataclass(frozen=True)
class SignedContextPayload:
    tenant_id: str
    actor_id: str
    scopes: FrozenSet[str]
    request_id: str
    trace_id: str
    iat: int


class SignedContextError(Exception):
    """Raised by verify_signed_context on any verification failure."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def get_signing_secret() -> str:
    """Return the configured gateway signing secret (may be empty)."""
    return (os.getenv("FG_GATEWAY_SIGNING_SECRET") or "").strip()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(padded)


def sign_context(payload: dict, secret: str) -> str:
    """
    Sign a context payload dict and return the header value string.

    payload must contain all REQUIRED_FIELDS.
    secret must be non-empty.
    """
    if not secret:
        raise SignedContextError("missing_signing_secret")
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    encoded = _b64url_encode(canonical.encode("utf-8"))
    sig = hmac.new(
        secret.encode("utf-8"), encoded.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{encoded}.{sig}"


def verify_signed_context(
    header_value: str,
    secret: str,
    max_age_seconds: int = MAX_AGE_SECONDS,
) -> SignedContextPayload:
    """
    Verify and decode a signed context header value.

    Raises SignedContextError (with .reason) on ANY failure:
      - missing_signed_context   : header_value is empty
      - missing_signing_secret   : secret is empty
      - malformed_signed_context : wrong number of segments
      - invalid_signature        : HMAC mismatch (constant-time)
      - malformed_payload        : JSON parse failure or not a dict
      - missing_fields           : one or more REQUIRED_FIELDS absent
      - empty_<field>            : required string field is blank
      - invalid_scopes_type      : scopes is not a list
      - invalid_iat              : iat is not an integer
      - future_iat               : iat is more than 5s in the future
      - expired_context          : iat is older than max_age_seconds
    """
    if not header_value:
        raise SignedContextError("missing_signed_context")
    if not secret:
        raise SignedContextError("missing_signing_secret")

    parts = header_value.split(".", 1)
    if len(parts) != 2:
        raise SignedContextError("malformed_signed_context")

    encoded, sig = parts
    expected_sig = hmac.new(
        secret.encode("utf-8"), encoded.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        raise SignedContextError("invalid_signature")

    try:
        raw_json = _b64url_decode(encoded).decode("utf-8")
        payload = json.loads(raw_json)
    except Exception:
        raise SignedContextError("malformed_payload")

    if not isinstance(payload, dict):
        raise SignedContextError("malformed_payload")

    missing = REQUIRED_FIELDS - set(payload.keys())
    if missing:
        raise SignedContextError(f"missing_fields:{','.join(sorted(missing))}")

    tenant_id = str(payload.get("tenant_id") or "").strip()
    actor_id = str(payload.get("actor_id") or "").strip()
    request_id = str(payload.get("request_id") or "").strip()
    trace_id = str(payload.get("trace_id") or "").strip()

    if not tenant_id:
        raise SignedContextError("empty_tenant_id")
    if not actor_id:
        raise SignedContextError("empty_actor_id")
    if not request_id:
        raise SignedContextError("empty_request_id")
    if not trace_id:
        raise SignedContextError("empty_trace_id")

    raw_scopes = payload.get("scopes")
    if not isinstance(raw_scopes, list):
        raise SignedContextError("invalid_scopes_type")
    scopes: FrozenSet[str] = frozenset(
        str(s).strip() for s in raw_scopes if str(s).strip()
    )

    try:
        iat = int(payload["iat"])
    except (TypeError, ValueError, KeyError):
        raise SignedContextError("invalid_iat")

    now = int(time.time())
    if iat > now + 5:
        raise SignedContextError("future_iat")
    if now - iat > max_age_seconds:
        raise SignedContextError("expired_context")

    return SignedContextPayload(
        tenant_id=tenant_id,
        actor_id=actor_id,
        scopes=scopes,
        request_id=request_id,
        trace_id=trace_id,
        iat=iat,
    )
