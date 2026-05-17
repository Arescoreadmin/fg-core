"""Runtime Evidence Collection & Governance Signal Extraction Layer — snapshot builder.

Snapshot construction contract:
  - Signals are sorted by (signal_type.value, governance_source) before hashing
    to produce a deterministic canonical ordering regardless of extraction order.
  - Timestamps (extracted_at, last_verified_at, created_at) are excluded from
    the canonical hash — they are nondeterministic and mutable between runs.
  - Session identifiers (signal_id, extraction_id, snapshot_id, assessment_id)
    are excluded from the canonical hash — they vary between extraction runs
    covering identical governance state.
  - inputs_canonical is the exact JSON string that was hashed and is preserved
    in the snapshot for independent forensic replay.
  - snapshot_hash is SHA-256 over inputs_canonical encoded as UTF-8.
  - All governance state fields (enforcement_enabled, validation_state,
    reason_codes, counts, chain_status, etc.) are included in the hash.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Dict, Optional, Type

from .models import (
    AuditChainSignalSummary,
    GovernanceSignalBody,
    RuntimeEvidenceSnapshot,
    RuntimeGovernanceSignal,
)

_SNAPSHOT_VERSION = "1.0.0"

# Fields excluded from canonical hash (timestamps and session identifiers).
_EXCLUDED_SIGNAL_FIELDS = frozenset(
    {"signal_id", "extraction_id", "extracted_at", "signal_metadata"}
)
_EXCLUDED_SUMMARY_FIELDS_BY_TYPE: Dict[Type[Any], frozenset] = {
    AuditChainSignalSummary: frozenset({"last_verified_at"}),
}


def _summary_to_canonical(summary: GovernanceSignalBody) -> dict[str, Any]:
    """Convert a signal summary to a canonical dict for hashing.

    Timestamps are excluded per the field-level hash exclusion contract in models.py.
    All governance state fields are included.
    """
    excluded = _EXCLUDED_SUMMARY_FIELDS_BY_TYPE.get(type(summary), frozenset())

    result: dict[str, Any] = {}
    for field_name, field_val in summary.__dict__.items():
        if field_name in excluded:
            continue
        if hasattr(field_val, "value"):
            result[field_name] = field_val.value
        else:
            result[field_name] = field_val
    return result


def _signal_to_canonical(signal: RuntimeGovernanceSignal) -> dict[str, Any]:
    """Convert a signal to a canonical dict, excluding nondeterministic fields."""
    return {
        "signal_type": signal.signal_type.value,
        "tenant_id": signal.tenant_id,
        "status": signal.status.value,
        "governance_source": signal.governance_source,
        "extractor_version": signal.extractor_version,
        "signal_summary": _summary_to_canonical(signal.signal_summary),
    }


def compute_snapshot_hash(
    tenant_id: str,
    snapshot_version: str,
    signals: tuple[RuntimeGovernanceSignal, ...],
) -> tuple[str, str]:
    """Compute a deterministic SHA-256 hash over the stable signal content.

    Returns (snapshot_hash, inputs_canonical) where inputs_canonical is the
    exact JSON string that was hashed — preserved for forensic replay.

    Signals are sorted by (signal_type.value, governance_source) before
    serialization to ensure deterministic ordering regardless of input order.
    """
    sorted_signals = sorted(
        signals,
        key=lambda s: (s.signal_type.value, s.governance_source),
    )

    canonical_obj: dict[str, Any] = {
        "tenant_id": tenant_id,
        "snapshot_version": snapshot_version,
        "signals": [_signal_to_canonical(s) for s in sorted_signals],
    }

    inputs_canonical = json.dumps(canonical_obj, sort_keys=True, separators=(",", ":"))
    snapshot_hash = hashlib.sha256(inputs_canonical.encode("utf-8")).hexdigest()
    return snapshot_hash, inputs_canonical


def build_runtime_evidence_snapshot(
    *,
    snapshot_id: str,
    tenant_id: str,
    signals: tuple[RuntimeGovernanceSignal, ...],
    created_at: datetime,
    assessment_id: Optional[str] = None,
) -> RuntimeEvidenceSnapshot:
    """Build an immutable, deterministic runtime evidence snapshot.

    snapshot_hash and inputs_canonical are computed from stable signal content.
    assessment_id is excluded from the hash — it can vary between assessments
    covering the same governance state.

    All signals must be scoped to tenant_id. This function does not enforce
    cross-tenant isolation — callers are responsible for passing only signals
    extracted for the given tenant.
    """
    snapshot_hash, inputs_canonical = compute_snapshot_hash(
        tenant_id=tenant_id,
        snapshot_version=_SNAPSHOT_VERSION,
        signals=signals,
    )

    return RuntimeEvidenceSnapshot(
        snapshot_id=snapshot_id,
        tenant_id=tenant_id,
        snapshot_version=_SNAPSHOT_VERSION,
        signals=signals,
        snapshot_hash=snapshot_hash,
        inputs_canonical=inputs_canonical,
        created_at=created_at,
        assessment_id=assessment_id,
    )
