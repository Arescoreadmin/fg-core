"""Claim-level epistemic determination authority for governance findings.

Operates at claim/control level — distinct from per-evidence trust
(EvidenceTrustState in services/evidence_authority/models.py) and per-evidence
workflow (EvidenceLifecycleState).  Those operate at evidence granularity; this
module determines what the *body of evidence as a whole* establishes about a
claim or control.

EpistemicState values (priority order — earlier wins on conflict):
  NOT_PROVEN         — no evidence present; claim is unsubstantiated
  CONTRADICTORY      — evidence conflicts internally (same source: VALIDATED +
                       MISSING or PENDING); internal conflict voids determination
  STALE              — evidence exists but none of it is fresh and VALIDATED;
                       re-collection required before a determination can be made
  PARTIALLY_SUPPORTED — some evidence is fresh-VALIDATED; some is still pending,
                        missing, or stale; partial case only
  VERIFIED_DEFICIENT  — all evidence is fresh-VALIDATED but an adverse finding
                        is active; control is evidenced but failing
  VERIFIED_EFFECTIVE  — all evidence is fresh-VALIDATED and no adverse finding
                        is active; claim is fully corroborated

Determinism contract:
  - Pure function: no I/O, no randomness, no side effects.
  - Inputs fully determine output; identical inputs → identical EpistemicDetermination.
  - evidence_refs sorted by evidence_id before processing (order invariance).

Fail-closed invariants:
  - Empty evidence → NOT_PROVEN (never VERIFIED_EFFECTIVE or VERIFIED_DEFICIENT).
  - freshness_days=None (unknown freshness) → treated as stale (fail-closed).
  - CONTRADICTORY is resolved before STALE; contradiction is a more severe condition.
  - No LLM authority over epistemic state: purely algorithmic determination.
  - MISSING refs go to invalid_evidence_ids only, not stale_evidence_ids.

Consumer contract:
  - Call determine_epistemic_state() per finding/claim with its evidence slice.
  - Call assess_report_epistemic_states() to batch-determine for a GovernanceReport.
  - Neither function modifies GovernanceFinding or GovernanceReport (frozen artifacts).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Sequence

from .models import EvidenceRef, GovernanceReport, ValidationState

_METHODOLOGY_VERSION = "1.0"


class EpistemicState(str, Enum):
    """Claim-level epistemic determination states."""

    NOT_PROVEN = "NOT_PROVEN"
    CONTRADICTORY = "CONTRADICTORY"
    STALE = "STALE"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    VERIFIED_DEFICIENT = "VERIFIED_DEFICIENT"
    VERIFIED_EFFECTIVE = "VERIFIED_EFFECTIVE"


@dataclass(frozen=True)
class EpistemicDetermination:
    """Deterministic, immutable epistemic determination for a claim or control.

    All tuple fields are sorted for canonical form (order-invariant replay).
    """

    state: EpistemicState
    reason_codes: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    contradictory_evidence_ids: tuple[str, ...]
    stale_evidence_ids: tuple[str, ...]
    invalid_evidence_ids: tuple[str, ...]
    missing_requirements: tuple[str, ...]
    methodology_version: str


def _is_stale(ref: EvidenceRef, stale_threshold_days: int) -> bool:
    """True when freshness is unknown or exceeds the threshold.

    freshness_days=None is treated as stale (fail-closed — unknown freshness
    cannot be assumed to be current).
    """
    return ref.freshness_days is None or ref.freshness_days > stale_threshold_days


def _is_fresh_validated(ref: EvidenceRef, stale_threshold_days: int) -> bool:
    """True when the ref is VALIDATED and its freshness is known and within threshold."""
    return (
        ref.validation_state == ValidationState.VALIDATED
        and ref.freshness_days is not None
        and ref.freshness_days <= stale_threshold_days
    )


def determine_epistemic_state(
    evidence_refs: Sequence[EvidenceRef],
    has_adverse_finding: bool = False,
    stale_threshold_days: int = 90,
) -> EpistemicDetermination:
    """Determine the epistemic state of a claim from its evidence body.

    Args:
        evidence_refs: All evidence refs bearing on the claim.  May be empty.
        has_adverse_finding: True when an active governance finding exists for
            this claim (domain score < 60).  Converts an otherwise
            VERIFIED_EFFECTIVE determination to VERIFIED_DEFICIENT.
        stale_threshold_days: Number of days after which evidence is considered
            stale.  Defaults to 90 (matches the field assessment decay schedule).

    Returns:
        EpistemicDetermination — frozen, deterministic, replay-safe.

    Invariants:
        - Empty evidence_refs → NOT_PROVEN.
        - freshness_days=None → stale (fail-closed).
        - CONTRADICTORY checked before STALE.
        - MISSING refs classified as invalid, not stale.
    """
    refs = sorted(evidence_refs, key=lambda r: r.evidence_id)
    all_ids = tuple(r.evidence_id for r in refs)

    # ── NOT_PROVEN — no evidence at all ──────────────────────────────────────
    if not refs:
        return EpistemicDetermination(
            state=EpistemicState.NOT_PROVEN,
            reason_codes=("no_evidence",),
            evidence_ids=(),
            contradictory_evidence_ids=(),
            stale_evidence_ids=(),
            invalid_evidence_ids=(),
            missing_requirements=("evidence_required",),
            methodology_version=_METHODOLOGY_VERSION,
        )

    # ── Contradiction detection ───────────────────────────────────────────────
    # A source is contradictory when it has at least one VALIDATED ref AND at
    # least one PENDING or MISSING ref.  Internal conflict from a single source
    # voids any positive determination.
    source_states: dict[str, set[ValidationState]] = {}
    for r in refs:
        source_states.setdefault(r.source, set()).add(r.validation_state)

    contradictory_sources = {
        src
        for src, states in source_states.items()
        if ValidationState.VALIDATED in states
        and (ValidationState.PENDING in states or ValidationState.MISSING in states)
    }
    contradictory_ids = tuple(
        sorted(r.evidence_id for r in refs if r.source in contradictory_sources)
    )

    # ── Classify evidence refs ───────────────────────────────────────────────
    # stale_ids: non-MISSING refs where freshness is unknown or exceeds threshold
    stale_ids = tuple(
        sorted(
            r.evidence_id
            for r in refs
            if r.validation_state != ValidationState.MISSING
            and _is_stale(r, stale_threshold_days)
        )
    )
    # invalid_ids: refs with MISSING validation state (evidence absent entirely)
    invalid_ids = tuple(
        sorted(
            r.evidence_id for r in refs if r.validation_state == ValidationState.MISSING
        )
    )
    # fresh_validated: VALIDATED refs with freshness within threshold
    fresh_validated = [r for r in refs if _is_fresh_validated(r, stale_threshold_days)]

    # ── CONTRADICTORY ─────────────────────────────────────────────────────────
    if contradictory_ids:
        return EpistemicDetermination(
            state=EpistemicState.CONTRADICTORY,
            reason_codes=tuple(
                f"source_conflict:{s}" for s in sorted(contradictory_sources)
            ),
            evidence_ids=all_ids,
            contradictory_evidence_ids=contradictory_ids,
            stale_evidence_ids=stale_ids,
            invalid_evidence_ids=invalid_ids,
            missing_requirements=(),
            methodology_version=_METHODOLOGY_VERSION,
        )

    # ── STALE — evidence exists but none is fresh-validated ──────────────────
    if not fresh_validated:
        reason_codes: list[str] = ["all_evidence_stale"]
        if any(
            r.freshness_days is None
            for r in refs
            if r.validation_state != ValidationState.MISSING
        ):
            reason_codes.append("freshness_unknown")
        return EpistemicDetermination(
            state=EpistemicState.STALE,
            reason_codes=tuple(reason_codes),
            evidence_ids=all_ids,
            contradictory_evidence_ids=(),
            stale_evidence_ids=stale_ids,
            invalid_evidence_ids=invalid_ids,
            missing_requirements=(),
            methodology_version=_METHODOLOGY_VERSION,
        )

    # ── PARTIALLY_SUPPORTED — some fresh-validated, some not ─────────────────
    if len(fresh_validated) < len(refs):
        partial_reasons: list[str] = ["partial_validation"]
        if stale_ids:
            partial_reasons.append(f"stale_refs:{len(stale_ids)}")
        if invalid_ids:
            partial_reasons.append(f"missing_refs:{len(invalid_ids)}")
        unfulfilled = tuple(
            sorted(
                r.evidence_id
                for r in refs
                if r.validation_state
                in (ValidationState.PENDING, ValidationState.MISSING)
            )
        )
        return EpistemicDetermination(
            state=EpistemicState.PARTIALLY_SUPPORTED,
            reason_codes=tuple(partial_reasons),
            evidence_ids=all_ids,
            contradictory_evidence_ids=(),
            stale_evidence_ids=stale_ids,
            invalid_evidence_ids=invalid_ids,
            missing_requirements=unfulfilled,
            methodology_version=_METHODOLOGY_VERSION,
        )

    # ── All refs are fresh-validated ─────────────────────────────────────────
    if has_adverse_finding:
        return EpistemicDetermination(
            state=EpistemicState.VERIFIED_DEFICIENT,
            reason_codes=("adverse_finding_active",),
            evidence_ids=all_ids,
            contradictory_evidence_ids=(),
            stale_evidence_ids=(),
            invalid_evidence_ids=(),
            missing_requirements=(),
            methodology_version=_METHODOLOGY_VERSION,
        )

    return EpistemicDetermination(
        state=EpistemicState.VERIFIED_EFFECTIVE,
        reason_codes=("all_validated_fresh",),
        evidence_ids=all_ids,
        contradictory_evidence_ids=(),
        stale_evidence_ids=(),
        invalid_evidence_ids=(),
        missing_requirements=(),
        methodology_version=_METHODOLOGY_VERSION,
    )


def assess_report_epistemic_states(
    report: GovernanceReport,
    evidence_refs: Sequence[EvidenceRef],
    stale_threshold_days: int = 90,
) -> dict[str, EpistemicDetermination]:
    """Return epistemic determination for each finding in a GovernanceReport.

    Args:
        report: The GovernanceReport to assess.  Not modified.
        evidence_refs: The same evidence refs passed to engine.generate().
        stale_threshold_days: Forwarded to determine_epistemic_state().

    Returns:
        Dict keyed by finding_id.  Every finding in report.findings has an entry.
        Findings without matching evidence produce NOT_PROVEN determinations.

    Note:
        All report findings are adverse (domain score < 60) by engine contract,
        so has_adverse_finding=True for every finding assessed here.
    """
    evidence_by_id = {r.evidence_id: r for r in evidence_refs}
    result: dict[str, EpistemicDetermination] = {}
    for finding in report.findings:
        finding_evidence = [
            evidence_by_id[eid] for eid in finding.evidence_ids if eid in evidence_by_id
        ]
        result[finding.finding_id] = determine_epistemic_state(
            evidence_refs=finding_evidence,
            has_adverse_finding=True,
            stale_threshold_days=stale_threshold_days,
        )
    return result
