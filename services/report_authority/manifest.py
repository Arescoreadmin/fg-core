"""services/report_authority/manifest.py

Immutable report manifest generation. The manifest is a cryptographically
verifiable record of everything that produced the report.
"""

from __future__ import annotations

from typing import Any

from services.report_authority.hashing import compute_canonical_hash
from services.report_authority.metadata import (
    EXPORT_VERSION,
    GENERATOR_VERSION,
    PROVIDER_VERSION,
)

MANIFEST_SCHEMA_VERSION = "1.0"


def build_manifest(
    *,
    report_id: str,
    report_version: str,
    schema_version: str,
    assessment_id: str,
    report_type: str,
    tenant_id: str,
    generation_timestamp: str,
    assessor_id: str,
    sections_included: list[str],
    authority_versions: dict[str, str | None] | None = None,
    transparency_root: str | None = None,
    merkle_root: str | None = None,
) -> dict[str, Any]:
    """Build a deterministic manifest dict.

    Must be called with identical inputs to reproduce the same manifest hashes.
    All mutable fields are normalised (sorted lists, sorted authority_versions)
    before hashing to guarantee bit-identical output regardless of call-site
    insertion order.
    """
    manifest: dict[str, Any] = {
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "report_id": report_id,
        "report_version": report_version,
        "schema_version": schema_version,
        "assessment_id": assessment_id,
        "report_type": report_type,
        "tenant_id": tenant_id,
        "generation_timestamp": generation_timestamp,
        "assessor_id": assessor_id,
        "generator_version": GENERATOR_VERSION,
        "provider_version": PROVIDER_VERSION,
        "export_version": EXPORT_VERSION,
        "sections_included": sorted(sections_included),
        "authority_versions": dict(sorted((authority_versions or {}).items())),
        "transparency_root": transparency_root or "",
        "merkle_root": merkle_root or "",
    }
    sha256, sha512 = compute_canonical_hash(manifest)
    manifest["manifest_hash_sha256"] = sha256
    manifest["manifest_hash_sha512"] = sha512
    return manifest


def verify_manifest(manifest: dict[str, Any]) -> bool:
    """Verify manifest hash integrity. Returns True if the hash is valid."""
    check = {
        k: v
        for k, v in manifest.items()
        if k not in {"manifest_hash_sha256", "manifest_hash_sha512"}
    }
    sha256, _ = compute_canonical_hash(check)
    return sha256 == manifest.get("manifest_hash_sha256", "")
