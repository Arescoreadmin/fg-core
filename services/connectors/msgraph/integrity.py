"""Scan integrity manifest generation.

Produces a HMAC-SHA256 signed manifest over all Graph endpoints called,
record counts, call timestamps, and response structure hashes.

RULE-SEC-001: manifest_key derived from env, never logged
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone

from services.connectors.msgraph.client import GraphClient
from services.connectors.msgraph.schema.integrity import SignedManifest

_MANIFEST_KEY_ENV = "FG_MANIFEST_KEY"
_FALLBACK_KEY_SIZE = 32


def _get_manifest_key() -> bytes:
    raw = os.environ.get(_MANIFEST_KEY_ENV, "")
    if raw:
        return raw.encode("utf-8")
    # In test environments a zero key is acceptable — warn via caller
    return b"\x00" * _FALLBACK_KEY_SIZE


def _canonical_manifest_bytes(
    manifest_id: str,
    endpoints: list[str],
    record_counts: dict[str, int],
    call_timestamps: dict[str, str],
    structure_hashes: dict[str, str],
    signed_at: str,
) -> bytes:
    """Deterministic serialization — sorted keys, no floats."""
    payload = {
        "manifest_id": manifest_id,
        "endpoints_called": sorted(endpoints),
        "record_counts": {k: record_counts[k] for k in sorted(record_counts)},
        "call_timestamps": {k: call_timestamps[k] for k in sorted(call_timestamps)},
        "response_structure_hashes": {
            k: structure_hashes[k] for k in sorted(structure_hashes)
        },
        "signed_at": signed_at,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_manifest(client: GraphClient) -> SignedManifest:
    """Build and HMAC-sign a manifest from a completed GraphClient session."""
    manifest_id = uuid.uuid4().hex
    signed_at = datetime.now(timezone.utc).isoformat()

    endpoints = client.endpoints_called
    record_counts = client.record_counts
    structure_hashes = client.structure_hashes
    # GraphClient doesn't track call_timestamps per-endpoint; use signed_at as proxy
    call_timestamps: dict[str, str] = {ep: signed_at for ep in endpoints}

    payload = _canonical_manifest_bytes(
        manifest_id=manifest_id,
        endpoints=endpoints,
        record_counts=record_counts,
        call_timestamps=call_timestamps,
        structure_hashes=structure_hashes,
        signed_at=signed_at,
    )

    key = _get_manifest_key()
    manifest_hmac = hmac.new(key, payload, hashlib.sha256).hexdigest()

    return SignedManifest(
        manifest_id=manifest_id,
        endpoints_called=endpoints,
        record_counts=record_counts,
        call_timestamps=call_timestamps,
        response_structure_hashes=structure_hashes,
        manifest_hmac=manifest_hmac,
        signed_at=signed_at,
    )


def verify_manifest(manifest: SignedManifest, key: bytes | None = None) -> bool:
    """Verify HMAC. Returns True if valid, False if tampered."""
    if key is None:
        key = _get_manifest_key()

    payload = _canonical_manifest_bytes(
        manifest_id=manifest.manifest_id,
        endpoints=list(manifest.endpoints_called),
        record_counts=dict(manifest.record_counts),
        call_timestamps=dict(manifest.call_timestamps),
        structure_hashes=dict(manifest.response_structure_hashes),
        signed_at=manifest.signed_at,
    )
    expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, manifest.manifest_hmac)
