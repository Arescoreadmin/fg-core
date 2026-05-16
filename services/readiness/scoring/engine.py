"""Deterministic AI Readiness Assessment Scoring Engine.

Pure Python. No I/O. No SQLAlchemy. No LLMs. No randomness.

Caller loads all data into ScoringInput; engine scores deterministically
and returns a frozen ScoreOutput. The engine never mutates its inputs.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from services.readiness.models import AssessmentOutcome, AssessmentResult
from services.readiness.scoring.models import (
    CompletionState,
    ControlScore,
    DomainScore,
    RemediationFactor,
    RemediationPriority,
    RiskLevel,
    ScoreOutput,
    ScoringInput,
    ThresholdFailure,
)

log = logging.getLogger("frostgate.readiness.scoring.engine")

_SCORE_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Outcome → raw score
# ---------------------------------------------------------------------------

_OUTCOME_SCORES: dict[AssessmentOutcome, float] = {
    AssessmentOutcome.COMPLIANT: 100.0,
    AssessmentOutcome.PARTIALLY_COMPLIANT: 50.0,
    AssessmentOutcome.NON_COMPLIANT: 0.0,
    AssessmentOutcome.NOT_EVALUATED: 0.0,
    AssessmentOutcome.NOT_APPLICABLE: 0.0,  # excluded from scoring
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ScoringError(Exception):
    """Base class for scoring engine errors."""


class InvalidWeightError(ScoringError):
    """A weight in weighting_metadata is negative or non-numeric."""


class ScoringContractMismatchError(ScoringError):
    """The ScoringContract framework_id does not match the assessment framework."""


class TenantIsolationViolation(ScoringError):
    """Results or evidence from a different tenant were loaded."""


class FrameworkMismatchError(ScoringError):
    """Results reference controls that do not belong to the loaded framework."""


class InvalidContractMetadataError(ScoringError):
    """A threshold or metadata value in the ScoringContract is non-numeric or invalid."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_weight(value: object, label: str) -> float:
    """Parse and validate a weight value; raises InvalidWeightError on bad input."""
    try:
        w = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise InvalidWeightError(f"Non-numeric weight for {label!r}: {value!r}")
    if w < 0.0:
        raise InvalidWeightError(f"Negative weight for {label!r}: {w}")
    return w


def _classify_risk(
    score: float,
    *,
    is_complete: bool,
    has_critical_failure: bool,
    has_required_failure: bool,
    no_controls: bool,
) -> RiskLevel:
    if no_controls:
        return RiskLevel.UNKNOWN
    if has_critical_failure or score < 25.0:
        return RiskLevel.CRITICAL
    if score < 50.0 or (not is_complete and has_required_failure):
        return RiskLevel.HIGH
    if score < 75.0:
        return RiskLevel.MODERATE
    if not is_complete:
        # score >=75 but incomplete — cap at MODERATE
        return RiskLevel.MODERATE
    if score < 90.0:
        return RiskLevel.LOW
    return RiskLevel.MINIMAL


def _classify_remediation(
    risk: RiskLevel,
    *,
    has_critical_failure: bool,
    has_required_failure: bool,
) -> RemediationPriority:
    if risk == RiskLevel.CRITICAL or has_critical_failure:
        return RemediationPriority.CRITICAL_IMMEDIATE
    if risk == RiskLevel.HIGH or has_required_failure:
        return RemediationPriority.HIGH_PRIORITY
    if risk == RiskLevel.MODERATE:
        return RemediationPriority.MEDIUM_PRIORITY
    if risk == RiskLevel.LOW:
        return RemediationPriority.LOW_PRIORITY
    if risk == RiskLevel.MINIMAL:
        return RemediationPriority.NOT_REQUIRED
    return RemediationPriority.HIGH_PRIORITY  # UNKNOWN → conservative


def _weighted_average(values: list[tuple[float, float]]) -> float:
    """Return weighted average of (score, weight) pairs. Returns 0.0 if total weight == 0."""
    total_weight = sum(w for _, w in values)
    if total_weight == 0.0:
        return 0.0
    return sum(s * w for s, w in values) / total_weight


def _classify_domain_risk(score: float, threshold_failed: bool) -> RiskLevel:
    if threshold_failed or score < 25.0:
        return RiskLevel.CRITICAL
    if score < 50.0:
        return RiskLevel.HIGH
    if score < 75.0:
        return RiskLevel.MODERATE
    if score < 90.0:
        return RiskLevel.LOW
    return RiskLevel.MINIMAL


# ---------------------------------------------------------------------------
# Public engine
# ---------------------------------------------------------------------------


class ReadinessScoreEngine:
    """Deterministic readiness assessment scoring engine.

    Usage::

        engine = ReadinessScoreEngine()
        output = engine.score(scoring_input)

    The engine is stateless and thread-safe. A single instance may be reused
    across requests. All configuration comes from ScoringInput.scoring_contract.
    """

    def score(self, inp: ScoringInput) -> ScoreOutput:
        """Score the assessment. Returns a frozen ScoreOutput.

        Raises ScoringError subclasses on invalid input (bad weights, tenant
        mismatch, contract mismatch). These are logic errors — callers should
        surface them as 400/422 responses, not 500s.
        """
        self._validate(inp)

        contract_weights = self._parse_weights(inp)
        contract_thresholds = self._parse_thresholds(inp)
        critical_control_ids, required_control_ids = self._parse_required(inp)
        overall_pass_threshold = contract_thresholds.get("overall_pass", 0.0)
        domain_minimums: dict[str, float] = contract_thresholds.get(
            "domain_minimums", {}
        )  # type: ignore[assignment]

        # --- Build result lookup: control_id → most-recent AssessmentResult ---
        result_map = self._build_result_map(inp)

        # --- Build evidence count lookup: control_id → count ---
        evidence_count_map = self._build_evidence_count_map(inp)

        # --- Score each control ---
        control_scores: dict[str, ControlScore] = {}
        for ctrl in inp.controls:
            result: Optional[AssessmentResult] = result_map.get(ctrl.control_id)
            outcome = result.outcome if result else AssessmentOutcome.NOT_EVALUATED
            is_applicable = outcome != AssessmentOutcome.NOT_APPLICABLE
            is_evaluated = (
                result is not None and outcome != AssessmentOutcome.NOT_EVALUATED
            )
            raw_score = _OUTCOME_SCORES[outcome]
            weight = _safe_weight(
                contract_weights.get("controls", {}).get(ctrl.control_id, 1.0),
                f"control:{ctrl.control_id}",
            )
            control_scores[ctrl.control_id] = ControlScore(
                control_id=ctrl.control_id,
                control_identifier=ctrl.control_identifier,
                domain_id=ctrl.domain_id,
                outcome=outcome,
                raw_score=raw_score,
                weight=weight,
                is_evaluated=is_evaluated,
                is_applicable=is_applicable,
                evidence_count=evidence_count_map.get(ctrl.control_id, 0),
            )

        # --- Aggregate domain scores ---
        domain_scores: dict[str, DomainScore] = {}
        for domain in inp.domains:
            d_controls = [
                cs for cs in control_scores.values() if cs.domain_id == domain.domain_id
            ]
            applicable = [cs for cs in d_controls if cs.is_applicable]
            evaluated = [cs for cs in applicable if cs.is_evaluated]
            missing = [cs for cs in applicable if not cs.is_evaluated]
            incomplete = [
                cs
                for cs in applicable
                if cs.outcome == AssessmentOutcome.PARTIALLY_COMPLIANT
            ]
            failed = [
                cs for cs in applicable if cs.outcome == AssessmentOutcome.NON_COMPLIANT
            ]

            raw_score = _weighted_average(
                [(cs.raw_score, cs.weight) for cs in applicable]
            )
            normalized_score = round(raw_score / 100.0, 6)
            completion_pct = (
                (len(evaluated) / len(applicable) * 100.0) if applicable else 0.0
            )
            domain_weight = _safe_weight(
                contract_weights.get("domains", {}).get(domain.domain_id, 1.0),
                f"domain:{domain.domain_id}",
            )
            domain_min = domain_minimums.get(domain.domain_id, 0.0)
            threshold_failed = raw_score < domain_min
            risk = _classify_domain_risk(raw_score, threshold_failed)

            domain_scores[domain.domain_id] = DomainScore(
                domain_id=domain.domain_id,
                domain_name=domain.domain_name,
                raw_score=round(raw_score, 4),
                normalized_score=normalized_score,
                weight=domain_weight,
                completion_percentage=round(completion_pct, 4),
                missing_control_count=len(missing),
                incomplete_control_count=len(incomplete),
                failed_control_count=len(failed),
                risk_classification=risk,
                threshold_failed=threshold_failed,
            )

        # --- Aggregate overall score ---
        overall_raw = _weighted_average(
            [(ds.raw_score, ds.weight) for ds in domain_scores.values()]
        )
        overall_score = round(overall_raw, 4)
        normalized_score = round(overall_raw / 100.0, 6)

        # --- Completion ---
        all_applicable = [cs for cs in control_scores.values() if cs.is_applicable]
        all_evaluated = [cs for cs in all_applicable if cs.is_evaluated]
        n_applicable = len(all_applicable)
        n_evaluated = len(all_evaluated)
        completion_pct = (n_evaluated / n_applicable * 100.0) if n_applicable else 0.0
        is_complete = n_applicable > 0 and n_evaluated == n_applicable

        if n_applicable == 0:
            completion_state = CompletionState.EMPTY
        elif n_evaluated == 0:
            completion_state = CompletionState.EMPTY
        elif is_complete:
            completion_state = CompletionState.COMPLETE
        elif completion_pct >= 50.0:
            completion_state = CompletionState.PARTIAL
        else:
            completion_state = CompletionState.INCOMPLETE

        # --- Control categorization ---
        missing_controls = tuple(
            cs.control_id for cs in all_applicable if not cs.is_evaluated
        )
        incomplete_controls = tuple(
            cs.control_id
            for cs in all_applicable
            if cs.outcome == AssessmentOutcome.PARTIALLY_COMPLIANT
        )
        failed_controls = tuple(
            cs.control_id
            for cs in control_scores.values()
            if cs.outcome == AssessmentOutcome.NON_COMPLIANT
        )
        not_applicable_controls = tuple(
            cs.control_id for cs in control_scores.values() if not cs.is_applicable
        )

        # --- Critical / required control analysis ---
        has_critical_failure = any(
            control_scores[cid].outcome == AssessmentOutcome.NON_COMPLIANT
            for cid in critical_control_ids
            if cid in control_scores
        )
        has_required_failure = any(
            cid in missing_controls
            or control_scores.get(cid, None) is not None
            and control_scores[cid].outcome
            in (AssessmentOutcome.NON_COMPLIANT, AssessmentOutcome.NOT_EVALUATED)
            for cid in required_control_ids
        )

        # --- Threshold failures ---
        threshold_failures: list[ThresholdFailure] = []
        if overall_score < overall_pass_threshold and overall_pass_threshold > 0.0:
            threshold_failures.append(
                ThresholdFailure(
                    threshold_type="overall_pass",
                    threshold_name="overall_pass",
                    required_value=overall_pass_threshold,
                    actual_value=overall_score,
                    message=(
                        f"Overall score {overall_score:.4f} is below required "
                        f"threshold {overall_pass_threshold:.4f}"
                    ),
                )
            )
        for ds in domain_scores.values():
            if ds.threshold_failed:
                threshold_failures.append(
                    ThresholdFailure(
                        threshold_type="domain_minimum",
                        threshold_name=ds.domain_name,
                        required_value=domain_minimums.get(ds.domain_id, 0.0),
                        actual_value=ds.raw_score,
                        message=(
                            f"Domain {ds.domain_name!r} score {ds.raw_score:.4f} is below "
                            f"minimum {domain_minimums.get(ds.domain_id, 0.0):.4f}"
                        ),
                    )
                )
        for cid in critical_control_ids:
            cs = control_scores.get(cid)
            if cs and cs.outcome == AssessmentOutcome.NON_COMPLIANT:
                threshold_failures.append(
                    ThresholdFailure(
                        threshold_type="required_control",
                        threshold_name=cid,
                        required_value=100.0,
                        actual_value=cs.raw_score,
                        message=f"Critical control {cs.control_identifier!r} is NON_COMPLIANT",
                    )
                )
        for cid in required_control_ids:
            cs = control_scores.get(cid)
            if cs is None:
                continue
            if (
                cs.outcome
                in (
                    AssessmentOutcome.NON_COMPLIANT,
                    AssessmentOutcome.NOT_EVALUATED,
                )
                or cid in missing_controls
            ):
                threshold_failures.append(
                    ThresholdFailure(
                        threshold_type="required_control",
                        threshold_name=cid,
                        required_value=100.0,
                        actual_value=cs.raw_score,
                        message=(
                            f"Required control {cs.control_identifier!r} is "
                            f"{cs.outcome.value.upper()}"
                        ),
                    )
                )

        # --- Risk and remediation classification ---
        no_controls = n_applicable == 0
        risk = _classify_risk(
            overall_score,
            is_complete=is_complete,
            has_critical_failure=has_critical_failure,
            has_required_failure=has_required_failure,
            no_controls=no_controls,
        )
        remediation_priority = _classify_remediation(
            risk,
            has_critical_failure=has_critical_failure,
            has_required_failure=has_required_failure,
        )
        remediation_factors = self._build_remediation_factors(
            control_scores=control_scores,
            domain_scores=domain_scores,
            critical_control_ids=critical_control_ids,
            required_control_ids=required_control_ids,
            missing_controls=missing_controls,
            is_complete=is_complete,
        )

        # --- Maturity tier ---
        maturity_tier, maturity_tier_id = self._evaluate_maturity(
            inp=inp,
            overall_score=overall_score,
            is_complete=is_complete,
            missing_controls=missing_controls,
            control_scores=control_scores,
        )

        # --- Maturity gate threshold failures ---
        if maturity_tier is None and inp.maturity_tiers and is_complete:
            threshold_failures.append(
                ThresholdFailure(
                    threshold_type="maturity_gate",
                    threshold_name="maturity_gate",
                    required_value=0.0,
                    actual_value=overall_score,
                    message="No maturity tier achieved; all gate criteria unmet",
                )
            )

        # --- Scoring warnings ---
        warnings: list[str] = []
        if n_applicable == 0:
            warnings.append("No applicable controls defined; score is meaningless.")
        if inp.scoring_contract is None:
            warnings.append(
                "No ScoringContract provided; default weights and thresholds used."
            )
        if not is_complete and n_evaluated > 0:
            warnings.append(
                f"Assessment is incomplete: {n_evaluated}/{n_applicable} controls evaluated."
            )

        return ScoreOutput(
            assessment_id=inp.assessment.assessment_id,
            tenant_id=inp.assessment.tenant_id,
            framework_id=inp.assessment.framework_id,
            framework_version_tag=inp.assessment.framework_version_tag,
            overall_score=overall_score,
            normalized_score=normalized_score,
            domain_scores=domain_scores,
            control_scores=control_scores,
            maturity_tier=maturity_tier,
            maturity_tier_id=maturity_tier_id,
            risk_classification=risk,
            remediation_priority=remediation_priority,
            remediation_factors=tuple(remediation_factors),
            missing_controls=missing_controls,
            incomplete_controls=incomplete_controls,
            failed_controls=failed_controls,
            not_applicable_controls=not_applicable_controls,
            threshold_failures=tuple(threshold_failures),
            scoring_warnings=tuple(warnings),
            completion_state=completion_state,
            completion_percentage=round(completion_pct, 4),
            is_complete=is_complete,
            computed_at=datetime.now(tz=timezone.utc),
            score_version=_SCORE_VERSION,
            scoring_contract_id=(
                inp.scoring_contract.contract_id if inp.scoring_contract else None
            ),
            scoring_contract_version=(
                inp.scoring_contract.scoring_schema_version
                if inp.scoring_contract
                else None
            ),
        )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self, inp: ScoringInput) -> None:
        assessment = inp.assessment
        # Tenant isolation: every result must belong to this tenant
        for r in inp.results:
            if r.tenant_id != assessment.tenant_id:
                raise TenantIsolationViolation(
                    f"Result {r.result_id!r} tenant {r.tenant_id!r} != "
                    f"assessment tenant {assessment.tenant_id!r}"
                )
        for ev in inp.evidence_refs:
            if ev.tenant_id != assessment.tenant_id:
                raise TenantIsolationViolation(
                    f"Evidence {ev.evidence_id!r} tenant {ev.tenant_id!r} != "
                    f"assessment tenant {assessment.tenant_id!r}"
                )
        # Framework consistency
        if inp.framework.framework_id != assessment.framework_id:
            raise FrameworkMismatchError(
                f"ScoringInput.framework.framework_id {inp.framework.framework_id!r} != "
                f"assessment.framework_id {assessment.framework_id!r}"
            )
        for ctrl in inp.controls:
            if ctrl.framework_id != assessment.framework_id:
                raise FrameworkMismatchError(
                    f"Control {ctrl.control_id!r} belongs to framework "
                    f"{ctrl.framework_id!r}, not {assessment.framework_id!r}"
                )
        # ScoringContract consistency
        if inp.scoring_contract is not None:
            if inp.scoring_contract.framework_id != assessment.framework_id:
                raise ScoringContractMismatchError(
                    f"ScoringContract framework_id {inp.scoring_contract.framework_id!r} != "
                    f"assessment.framework_id {assessment.framework_id!r}"
                )

    # ------------------------------------------------------------------
    # Contract parsing
    # ------------------------------------------------------------------

    def _parse_weights(self, inp: ScoringInput) -> dict:
        if inp.scoring_contract is None:
            return {}
        raw = inp.scoring_contract.weighting_metadata
        # Expected shape:
        #   {"controls": {control_id: float, ...}, "domains": {domain_id: float, ...}}
        return raw if isinstance(raw, dict) else {}

    def _parse_thresholds(self, inp: ScoringInput) -> dict:
        if inp.scoring_contract is None:
            return {}
        raw = inp.scoring_contract.scoring_metadata
        if not isinstance(raw, dict):
            return {}
        thresholds: dict = {}
        try:
            if "overall_pass" in raw:
                thresholds["overall_pass"] = float(raw["overall_pass"])
            if "domain_minimums" in raw and isinstance(raw["domain_minimums"], dict):
                thresholds["domain_minimums"] = {
                    k: float(v) for k, v in raw["domain_minimums"].items()
                }
            if "maturity_thresholds" in raw and isinstance(
                raw["maturity_thresholds"], dict
            ):
                thresholds["maturity_thresholds"] = {
                    k: float(v) for k, v in raw["maturity_thresholds"].items()
                }
        except (TypeError, ValueError) as exc:
            raise InvalidContractMetadataError(
                f"ScoringContract {inp.scoring_contract.contract_id!r} contains "
                f"a non-numeric threshold value: {exc}"
            ) from exc
        return thresholds

    def _parse_required(self, inp: ScoringInput) -> tuple[set[str], set[str]]:
        """Returns (critical_control_ids, required_control_ids)."""
        if inp.scoring_contract is None:
            return set(), set()
        raw = inp.scoring_contract.scoring_metadata
        if not isinstance(raw, dict):
            return set(), set()
        critical = set(raw.get("critical_controls", []))
        required = set(raw.get("required_controls", []))
        return critical, required

    # ------------------------------------------------------------------
    # Result and evidence maps
    # ------------------------------------------------------------------

    def _build_result_map(self, inp: ScoringInput) -> dict[str, AssessmentResult]:
        """Return most-recent result per control_id within this assessment."""
        by_control: dict[str, AssessmentResult] = {}
        for r in inp.results:
            if r.assessment_id != inp.assessment.assessment_id:
                continue
            existing = by_control.get(r.control_id)
            if existing is None or r.timestamp > existing.timestamp:
                by_control[r.control_id] = r
        return by_control

    def _build_evidence_count_map(self, inp: ScoringInput) -> dict[str, int]:
        """Return number of evidence references per control_id."""
        counts: dict[str, int] = {}
        for ev in inp.evidence_refs:
            for cid in ev.control_ids:
                counts[cid] = counts.get(cid, 0) + 1
        return counts

    # ------------------------------------------------------------------
    # Maturity evaluation
    # ------------------------------------------------------------------

    def _evaluate_maturity(
        self,
        *,
        inp: ScoringInput,
        overall_score: float,
        is_complete: bool,
        missing_controls: tuple[str, ...],
        control_scores: dict[str, ControlScore],
    ) -> tuple[Optional[str], Optional[str]]:
        """Return (tier_identifier, tier_id) of the highest achieved tier, or (None, None)."""
        if not inp.maturity_tiers:
            return None, None

        # Contract can supply per-tier score thresholds keyed by tier_identifier
        thresholds = self._parse_thresholds(inp).get("maturity_thresholds", {})

        # Sort tiers descending by tier_order so we award the highest achieved tier
        sorted_tiers = sorted(
            inp.maturity_tiers, key=lambda t: t.tier_order, reverse=True
        )
        n_tiers = len(sorted_tiers)

        for tier in sorted_tiers:
            # Score threshold: from contract or evenly distributed (e.g. 4 tiers: 75/50/25/0)
            if tier.tier_identifier in thresholds:
                required_score = float(thresholds[tier.tier_identifier])
            else:
                tier_index = sorted_tiers.index(tier)  # 0=highest tier
                # Even distribution: highest tier needs highest score
                # tier_index 0 → threshold = (n_tiers-1)/n_tiers * 100, descending
                required_score = ((n_tiers - 1 - tier_index) / n_tiers) * 100.0

            if overall_score < required_score:
                continue

            # Gate: required controls for this tier must all be evaluated + compliant
            tier_required = set(
                tier.tier_metadata.get("required_control_ids", [])
                if isinstance(tier.tier_metadata, dict)
                else []
            )
            if tier_required:
                if any(
                    cid in missing_controls
                    or (
                        cid in control_scores
                        and control_scores[cid].outcome
                        in (
                            AssessmentOutcome.NON_COMPLIANT,
                            AssessmentOutcome.NOT_EVALUATED,
                        )
                    )
                    for cid in tier_required
                ):
                    continue

            return tier.tier_identifier, tier.tier_id

        return None, None

    # ------------------------------------------------------------------
    # Remediation factors
    # ------------------------------------------------------------------

    def _build_remediation_factors(
        self,
        *,
        control_scores: dict[str, ControlScore],
        domain_scores: dict[str, DomainScore],
        critical_control_ids: set[str],
        required_control_ids: set[str],
        missing_controls: tuple[str, ...],
        is_complete: bool,
    ) -> list[RemediationFactor]:
        factors: list[RemediationFactor] = []

        for cid in critical_control_ids:
            cs = control_scores.get(cid)
            if cs and cs.outcome == AssessmentOutcome.NON_COMPLIANT:
                factors.append(
                    RemediationFactor(
                        factor_type="failed_critical_control",
                        description=(
                            f"Critical control {cs.control_identifier!r} is NON_COMPLIANT"
                        ),
                        severity="critical",
                    )
                )

        for cid in required_control_ids:
            if cid in missing_controls:
                cs = control_scores.get(cid)
                identifier = cs.control_identifier if cs else cid
                factors.append(
                    RemediationFactor(
                        factor_type="missing_required_control",
                        description=f"Required control {identifier!r} has no result",
                        severity="high",
                    )
                )

        for ds in domain_scores.values():
            if ds.threshold_failed:
                factors.append(
                    RemediationFactor(
                        factor_type="low_domain_score",
                        description=(
                            f"Domain {ds.domain_name!r} score {ds.raw_score:.1f} "
                            "is below minimum threshold"
                        ),
                        severity="high",
                    )
                )

        if not is_complete:
            factors.append(
                RemediationFactor(
                    factor_type="incomplete_assessment",
                    description="Assessment has unevaluated controls",
                    severity="medium",
                )
            )

        return factors
