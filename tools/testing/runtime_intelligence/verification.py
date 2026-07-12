"""Structured manifest verification.

All public functions return a :class:`~.signing.VerificationResult` so
callers can render structured reports and never accidentally treat a bare
``bool`` as "valid".
"""

from __future__ import annotations

import hashlib

from .manifest import (
    ValidationManifest,
    canonical_bytes,
    compute_manifest_hash,
    manifest_to_dict,
)
from .models import RuntimeResult
from .serializer import to_json
from .signing import VerificationResult, verify_signature_bytes


def verify_hash(manifest: ValidationManifest) -> VerificationResult:
    """Recompute the manifest hash from canonical content and compare."""
    d = manifest_to_dict(manifest)
    computed = compute_manifest_hash(d)
    if computed == manifest.manifest_hash:
        return VerificationResult(
            valid=True,
            algorithm="sha256",
            signing_identity="",
            reason="hash matches canonical content",
        )
    return VerificationResult(
        valid=False,
        algorithm="sha256",
        signing_identity="",
        reason="hash mismatch",
        detail=f"expected {computed[:16]}... got {manifest.manifest_hash[:16]}...",
    )


def verify_signature(
    manifest: ValidationManifest, public_key_hex: str
) -> VerificationResult:
    """Verify an Ed25519 signature against the canonical content."""
    if manifest.signature_algorithm == "unsigned" or not manifest.signature:
        return VerificationResult(
            valid=False,
            algorithm="unsigned",
            signing_identity="",
            reason="manifest is unsigned",
        )
    data = canonical_bytes(manifest_to_dict(manifest))
    return verify_signature_bytes(data, manifest.signature, public_key_hex)


def verify_chain(
    manifest: ValidationManifest, previous: ValidationManifest | None
) -> VerificationResult:
    """Verify the manifest's link to its predecessor."""
    if not manifest.previous_manifest_hash:
        return VerificationResult(
            valid=True,
            algorithm="chain",
            signing_identity="",
            reason="chain root (no previous)",
        )
    if previous is None:
        return VerificationResult(
            valid=False,
            algorithm="chain",
            signing_identity="",
            reason="previous manifest required but not provided",
        )
    if manifest.previous_manifest_hash == previous.manifest_hash:
        return VerificationResult(
            valid=True,
            algorithm="chain",
            signing_identity="",
            reason="chain link valid",
        )
    return VerificationResult(
        valid=False,
        algorithm="chain",
        signing_identity="",
        reason="chain mismatch",
        detail=(
            f"expected {previous.manifest_hash[:16]}... got "
            f"{manifest.previous_manifest_hash[:16]}..."
        ),
    )


def verify_runtime(
    manifest: ValidationManifest, result: RuntimeResult
) -> VerificationResult:
    """Verify that ``runtime_result_hash`` matches the provided result."""
    computed = hashlib.sha256(to_json(result).encode("utf-8")).hexdigest()
    if computed == manifest.runtime_result_hash:
        return VerificationResult(
            valid=True,
            algorithm="sha256",
            signing_identity="",
            reason="runtime result hash matches",
        )
    return VerificationResult(
        valid=False,
        algorithm="sha256",
        signing_identity="",
        reason="runtime result hash mismatch",
        detail=f"expected {computed[:16]}... got {manifest.runtime_result_hash[:16]}...",
    )


def verify_manifest(
    manifest: ValidationManifest,
    public_key_hex: str = "",
    previous: ValidationManifest | None = None,
    result: RuntimeResult | None = None,
) -> dict[str, VerificationResult]:
    """Run all applicable verification checks on a manifest.

    The returned dict always contains ``hash``, ``signature``, and ``chain``
    keys. ``runtime`` is included only when ``result`` is supplied.

    Unsigned manifests report the ``signature`` check as ``valid=True`` with
    algorithm ``"unsigned"`` — verification of unsigned legacy manifests is
    intentionally non-fatal so existing artifacts continue to load.
    """
    checks: dict[str, VerificationResult] = {}
    checks["hash"] = verify_hash(manifest)

    if manifest.signature_algorithm == "unsigned" or not manifest.signature:
        checks["signature"] = VerificationResult(
            valid=True,
            algorithm="unsigned",
            signing_identity="",
            reason="unsigned legacy manifest",
        )
    elif public_key_hex:
        checks["signature"] = verify_signature(manifest, public_key_hex)
    else:
        checks["signature"] = VerificationResult(
            valid=False,
            algorithm="ed25519",
            signing_identity=manifest.signing_identity,
            reason="no public key provided for verification",
        )

    checks["chain"] = verify_chain(manifest, previous)

    if result is not None:
        checks["runtime"] = verify_runtime(manifest, result)

    return checks
