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
from typing import Any

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
    content_hashes: dict[str, str] | None = None,
) -> bytes:
    """Deterministic serialization — sorted keys, no floats."""
    bound_content_hashes = content_hashes or {}
    payload = {
        "manifest_id": manifest_id,
        "endpoints_called": sorted(endpoints),
        "record_counts": {k: record_counts[k] for k in sorted(record_counts)},
        "call_timestamps": {k: call_timestamps[k] for k in sorted(call_timestamps)},
        "response_structure_hashes": {
            k: structure_hashes[k] for k in sorted(structure_hashes)
        },
        "content_hashes": {
            k: bound_content_hashes[k] for k in sorted(bound_content_hashes)
        },
        "signed_at": signed_at,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _model_dump(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value


def _stable_hash(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def build_content_hashes(
    *,
    findings: list[Any],
    evidence_refs: list[Any],
    analyzer_outputs: dict[str, Any],
) -> dict[str, str]:
    """Hash deterministic connector-derived content bound to the manifest."""
    finding_payload = sorted(
        (_model_dump(item) for item in findings),
        key=lambda item: item.get("finding_id", ""),
    )
    evidence_payload = sorted(
        (_model_dump(item) for item in evidence_refs),
        key=lambda item: item.get("ref_id", ""),
    )
    return {
        "findings_sha256": _stable_hash(finding_payload),
        "evidence_refs_sha256": _stable_hash(evidence_payload),
        "analyzer_outputs_sha256": _stable_hash(analyzer_outputs),
    }


def _sign_manifest(
    *,
    manifest_id: str,
    endpoints: list[str],
    record_counts: dict[str, int],
    call_timestamps: dict[str, str],
    structure_hashes: dict[str, str],
    signed_at: str,
    content_hashes: dict[str, str] | None = None,
    key: bytes | None = None,
) -> str:
    payload = _canonical_manifest_bytes(
        manifest_id=manifest_id,
        endpoints=endpoints,
        record_counts=record_counts,
        call_timestamps=call_timestamps,
        structure_hashes=structure_hashes,
        signed_at=signed_at,
        content_hashes=content_hashes,
    )
    return hmac.new(key or _get_manifest_key(), payload, hashlib.sha256).hexdigest()


def build_manifest(client: GraphClient) -> SignedManifest:
    """Build and HMAC-sign a manifest from a completed GraphClient session."""
    manifest_id = uuid.uuid4().hex
    signed_at = datetime.now(timezone.utc).isoformat()

    endpoints = client.endpoints_called
    record_counts = client.record_counts
    structure_hashes = client.structure_hashes
    # GraphClient doesn't track call_timestamps per-endpoint; use signed_at as proxy
    call_timestamps: dict[str, str] = {ep: signed_at for ep in endpoints}

    manifest_hmac = _sign_manifest(
        manifest_id=manifest_id,
        endpoints=endpoints,
        record_counts=record_counts,
        call_timestamps=call_timestamps,
        structure_hashes=structure_hashes,
        signed_at=signed_at,
    )

    return SignedManifest(
        manifest_id=manifest_id,
        endpoints_called=endpoints,
        record_counts=record_counts,
        call_timestamps=call_timestamps,
        response_structure_hashes=structure_hashes,
        content_hashes={},
        manifest_hmac=manifest_hmac,
        signed_at=signed_at,
    )


def bind_manifest_content(
    manifest: SignedManifest,
    *,
    findings: list[Any],
    evidence_refs: list[Any],
    analyzer_outputs: dict[str, Any],
) -> SignedManifest:
    """Return a manifest re-signed with connector-derived content hashes."""
    content_hashes = build_content_hashes(
        findings=findings,
        evidence_refs=evidence_refs,
        analyzer_outputs=analyzer_outputs,
    )
    manifest_hmac = _sign_manifest(
        manifest_id=manifest.manifest_id,
        endpoints=list(manifest.endpoints_called),
        record_counts=dict(manifest.record_counts),
        call_timestamps=dict(manifest.call_timestamps),
        structure_hashes=dict(manifest.response_structure_hashes),
        signed_at=manifest.signed_at,
        content_hashes=content_hashes,
    )
    return manifest.model_copy(
        update={"content_hashes": content_hashes, "manifest_hmac": manifest_hmac}
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
        content_hashes=dict(manifest.content_hashes),
    )
    expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, manifest.manifest_hmac)
