"""Deterministic governance report domain models.

All types are:
  - Pure Python. No I/O. No randomness. No SQLAlchemy.
  - Frozen after construction (immutable, frozen=True).
  - Deterministic: identical inputs → identical canonical form.
  - Tenant-safe: all contexts carry tenant_id.
  - Export-safe: no secrets, raw evidence bodies, provider payloads, prompts, or PHI.

Immutability contract:
  - GovernanceFinding and GovernanceReport use frozen=True dataclasses.
  - AI-generated narrative MUST NOT appear in any frozen field.
  - Finding IDs, manifest hashes, and evidence IDs are derived deterministically.
  - Once is_finalized=True on the DB record, report_json is treated as append-only.

Replay contract:
  - ReplayContract captures all inputs required to reproduce the report.
  - canonical_inputs_hash covers assessment_id, evidence_refs, and framework_ids.
  - manifest_hash covers all deterministic output fields.
  - Matching manifest_hash after re-generation proves replay equivalence.

Schema version contract:
  - schema_version = "1.0" — increment when field semantics change.
  - Deserializers must reject unknown schema_versions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ValidationState(str, Enum):
    """Evidence validation state — explicit; never optimistic."""

    VALIDATED = "validated"
    PENDING = "pending"
    MISSING = "missing"


# ---------------------------------------------------------------------------
# Framework mapping
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FrameworkMapping:
    """Maps a finding to a specific control reference within a compliance framework.

    All fields are deterministic — no LLM inference allowed here.
    """

    framework: str
    control_ref: str
    confidence: float  # 0.0–1.0 explicit mapping confidence


# ---------------------------------------------------------------------------
# Evidence reference
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceRef:
    """Canonical reference to a piece of evidence supporting a finding.

    evidence_id is derived deterministically from (source, classification, provenance_key).
    freshness_days=None means freshness is unknown/not tracked — treated as stale.
    """

    evidence_id: str
    source: str
    validation_state: ValidationState
    classification: str
    provenance: str
    freshness_days: Optional[int] = None


# ---------------------------------------------------------------------------
# Confidence score
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConfidenceScore:
    """Deterministic confidence scoring for a governance report.

    overall = weighted mean:
      0.4 * evidence_completeness
      + 0.3 * evidence_freshness
      + 0.2 * control_coverage
      + 0.1 * (1.0 if reviewer_validated else 0.0)
    scaled by assessment_completion_pct / 100.

    Fails closed: if no evidence → overall = 0.0, reasons = ("no evidence",).
    """

    overall: float
    evidence_completeness: float
    evidence_freshness: float
    control_coverage: float
    reviewer_validated: bool
    degradation_reasons: tuple[str, ...]


# ---------------------------------------------------------------------------
# Remediation entry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RemediationEntry:
    """Deterministic remediation recommendation linked to governance findings.

    remediation_id is derived deterministically from (tenant_id, control_id,
    severity, priority).  No AI prose in any field — only structured data.
    """

    remediation_id: str
    linked_finding_ids: tuple[str, ...]
    linked_controls: tuple[str, ...]
    severity: str
    priority: str
    confidence_impact: float  # expected confidence increase if remediated
    evidence_gaps: tuple[str, ...]
    operational_impact: str


# ---------------------------------------------------------------------------
# Governance finding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GovernanceFinding:
    """A single deterministic governance finding.

    finding_id is derived deterministically from
    (tenant_id, framework, control_id, gap_classification, evidence_state_hash).
    Two identical governance states produce identical finding_ids — enabling
    idempotent submission and stable cross-report references.

    No AI narrative in description — only structured control reference text.
    framework_mappings covers all frameworks the control maps to.
    """

    finding_id: str
    control_id: str
    domain: str
    severity: str
    confidence: float
    evidence_ids: tuple[str, ...]
    framework_mappings: tuple[FrameworkMapping, ...]
    remediation_id: str
    gap_classification: str
    description: str


# ---------------------------------------------------------------------------
# Governance report
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GovernanceReport:
    """The root deterministic governance report artifact.

    report_id is a UUID string (caller-provided or derived).
    generated_at is an ISO-format string, NOT a datetime — keeps serialization stable.
    manifest_hash is computed last from all other deterministic fields.
    schema_version pins the wire format; change it when field semantics change.
    """

    report_id: str
    assessment_id: str
    tenant_id: str
    version: int
    generated_at: str  # ISO string — not datetime
    findings: tuple[GovernanceFinding, ...]
    remediations: tuple[RemediationEntry, ...]
    evidence_appendix: tuple[EvidenceRef, ...]
    framework_summary: dict[str, list[str]]
    confidence: ConfidenceScore
    manifest_hash: str
    schema_version: str = "1.0"


# ---------------------------------------------------------------------------
# Replay contract
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReplayContract:
    """Captures all inputs and outputs required to verify replay equivalence.

    canonical_inputs_hash: SHA-256 of (assessment_id, sorted evidence_ids, sorted framework_ids).
    findings_hash: SHA-256 of canonical JSON of all finding_ids (sorted).
    manifest_hash: matches GovernanceReport.manifest_hash.
    """

    report_id: str
    canonical_inputs_hash: str
    findings_hash: str
    manifest_hash: str
    generated_at: str
    schema_version: str
