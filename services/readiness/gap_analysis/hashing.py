"""Enterprise Gap Analysis & Remediation Prioritization Engine — integrity hashing.

Hashing contract:
  - All functions are pure Python: no I/O, no side effects, no randomness.
  - Output is deterministic: identical stable-field state → identical hash.
  - Algorithm is SHA-256. Hash value is hex-encoded.
  - inputs_canonical is the exact JSON string that was hashed.
  - compute_gap_analysis_hash() produces a RemediationIntegrityRecord.
  - replay_gap_analysis_hash() recomputes from a saved inputs_canonical string.
  - verify_gap_analysis_hash() checks a stored record against a live result.

Hash inputs (stable — included):
  result_id, framework_id, framework_version, assessment_id, analysis_version,
  gap_ids (sorted), readiness_blocker_ids (sorted), maturity_blocker_ids (sorted),
  dependency_chain_ids (sorted), gap_classification per gap_id (sorted by gap_id),
  gap_severity per gap_id, scoring_contract_version, maturity_model_version,
  mapping_version, evidence_snapshot_version.

Hash excludes:
  analyzed_at, tenant_id, result_metadata, all extension metadata dicts,
  governance_overrides, policy_exceptions, compensating_controls.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

from .models import GapAnalysisResult, RemediationIntegrityRecord

_HASH_ALGORITHM = "sha256"


def _build_canonical_inputs(result: GapAnalysisResult) -> dict:
    return {
        "result_id": result.result_id,
        "framework_id": result.framework_id,
        "framework_version": result.framework_version,
        "assessment_id": result.assessment_id,
        "analysis_version": result.analysis_version,
        "scoring_contract_version": result.scoring_contract_version,
        "maturity_model_version": result.maturity_model_version,
        "mapping_version": result.mapping_version,
        "evidence_snapshot_version": result.evidence_snapshot_version,
        "gap_ids": sorted(g.gap_id for g in result.gaps),
        "gap_classifications": {
            g.gap_id: g.gap_classification.value
            for g in sorted(result.gaps, key=lambda g: g.gap_id)
        },
        "gap_severities": {
            g.gap_id: g.gap_severity.value
            for g in sorted(result.gaps, key=lambda g: g.gap_id)
        },
        "readiness_blocker_ids": sorted(
            b.blocker_id for b in result.readiness_blockers
        ),
        "maturity_blocker_ids": sorted(b.blocker_id for b in result.maturity_blockers),
        "dependency_chain_ids": sorted(c.chain_id for c in result.dependency_chains),
    }


def compute_gap_analysis_hash(
    result: GapAnalysisResult,
    *,
    computed_at: datetime,
) -> RemediationIntegrityRecord:
    """Compute a deterministic SHA-256 integrity record for a GapAnalysisResult."""
    canonical = _build_canonical_inputs(result)
    inputs_canonical = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    hash_value = hashlib.sha256(inputs_canonical.encode()).hexdigest()
    return RemediationIntegrityRecord(
        record_id=f"integrity::{result.result_id}",
        result_id=result.result_id,
        algorithm=_HASH_ALGORITHM,
        hash_value=hash_value,
        inputs_canonical=inputs_canonical,
        computed_at=computed_at,
        is_replay_safe=True,
    )


def replay_gap_analysis_hash(inputs_canonical: str) -> str:
    """Recompute the SHA-256 hash from a saved inputs_canonical string."""
    return hashlib.sha256(inputs_canonical.encode()).hexdigest()


def verify_gap_analysis_hash(
    result: GapAnalysisResult,
    record: RemediationIntegrityRecord,
) -> bool:
    """Verify a RemediationIntegrityRecord matches the current state of a result.

    Returns True if record.hash_value matches a freshly computed hash.
    Returns False on any mismatch — does not raise.
    """
    canonical = _build_canonical_inputs(result)
    inputs_canonical = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(inputs_canonical.encode()).hexdigest()
    return record.hash_value == expected
