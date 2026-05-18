"""Deterministic identity derivation for governance report artifacts.

All functions are pure Python: no I/O, no side effects, no randomness, no timestamps.

Identity contract:
  - Replay-equivalent inputs MUST produce replay-equivalent identities.
  - Identities are truncated SHA-256 hex digests of canonical JSON payloads.
  - No timestamp-only identities (timestamps break replay equivalence).
  - No random UUIDs.
  - No insertion-order-dependent serialization (always sort_keys=True).

Finding ID stability:
  Two findings with identical (tenant_id, framework, control_id,
  gap_classification, evidence_state_hash) in any assessment produce the same
  finding_id — enabling stable cross-report references and idempotent ingestion.

Manifest hash guarantee:
  derive_manifest_hash covers ALL deterministic fields in GovernanceReport
  except manifest_hash itself.  Any mutation of deterministic content breaks
  the manifest hash — providing tamper evidence for the artifact.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import GovernanceReport


def _sha256_hex(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def derive_finding_id(
    tenant_id: str,
    framework: str,
    control_id: str,
    gap_classification: str,
    evidence_state_hash: str,
) -> str:
    """Derive a deterministic finding ID from canonical governance inputs.

    Returns the first 16 hex characters of SHA-256(canonical JSON).
    Two findings with identical inputs produce the same finding_id.
    """
    payload = json.dumps(
        {
            "tenant_id": tenant_id,
            "framework": framework,
            "control_id": control_id,
            "gap_classification": gap_classification,
            "evidence_state_hash": evidence_state_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256_hex(payload)[:16]


def derive_remediation_id(
    tenant_id: str,
    control_id: str,
    severity: str,
    priority: str,
) -> str:
    """Derive a deterministic remediation ID from (tenant, control, severity, priority).

    Returns the first 16 hex characters of SHA-256(canonical JSON).
    """
    payload = json.dumps(
        {
            "tenant_id": tenant_id,
            "control_id": control_id,
            "severity": severity,
            "priority": priority,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256_hex(payload)[:16]


def derive_evidence_id(
    source: str,
    classification: str,
    provenance_key: str,
) -> str:
    """Derive a deterministic evidence ID from (source, classification, provenance_key).

    Returns the first 16 hex characters of SHA-256(canonical JSON).
    """
    payload = json.dumps(
        {
            "source": source,
            "classification": classification,
            "provenance_key": provenance_key,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256_hex(payload)[:16]


def derive_manifest_hash(report: "GovernanceReport") -> str:
    """Compute the manifest hash of a GovernanceReport.

    Covers all deterministic fields EXCEPT manifest_hash itself.
    Uses canonical JSON (sorted keys, no whitespace variance).
    Returns full 64-char SHA-256 hex digest.

    The hash is computed in serialization.serialize_for_manifest() — this
    function is a thin wrapper that imports lazily to avoid circular imports.
    """
    from .serialization import serialize_for_manifest

    return _sha256_hex(serialize_for_manifest(report))


def derive_canonical_inputs_hash(
    assessment_id: str,
    evidence_refs: list,
    framework_ids: list[str],
) -> str:
    """Derive a deterministic hash of the canonical inputs for a governance report.

    Covers assessment_id, sorted evidence_ids, and sorted framework_ids.
    Returns full 64-char SHA-256 hex digest.
    """
    evidence_ids = sorted(
        getattr(ref, "evidence_id", str(ref)) for ref in evidence_refs
    )
    payload = json.dumps(
        {
            "assessment_id": assessment_id,
            "evidence_ids": evidence_ids,
            "framework_ids": sorted(framework_ids),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256_hex(payload)


def derive_findings_hash(finding_ids: list[str]) -> str:
    """Derive a deterministic hash of finding IDs (sorted).

    Returns full 64-char SHA-256 hex digest.
    """
    payload = json.dumps(
        sorted(finding_ids),
        separators=(",", ":"),
    )
    return _sha256_hex(payload)
