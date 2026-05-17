"""Readiness Gap Analysis API — gap-analysis and remediation metadata endpoints.

All routes require control-plane:read scope.
Tenant isolation: tenant_id is always resolved from auth context, never from request.

Routes:
  GET /control-plane/readiness/assessments/{assessment_id}/gap-analysis
      Compute deterministic gap analysis for an assessment.
      Pure computation — no side effects, no mutations. Loads all required data
      from the store, runs ReadinessScoreEngine, then GapAnalysisEngine, and
      returns a frozen GapAnalysisResultResponse.

Security invariants:
  - No secrets, credentials, raw evidence bodies, provider payloads, or
    infrastructure topology in any response.
  - tenant_id resolved from auth context only — never from request body/query.
  - Gap analysis is fully read-only.
  - GovernanceOverride, PolicyException, CompensatingControl carry only
    governance-safe export metadata.
  - evidence_ownership_metadata, evidence_integrity_metadata, and raw evidence
    source payloads are NOT exposed.
  - inputs_canonical from integrity records is NOT exposed (replay-internal only).
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.deps import auth_ctx_db_session
from api.error_contracts import api_error
from services.readiness import ReadinessStore
from services.readiness.gap_analysis import (
    GapAnalysisEngine,
    GapAnalysisError,
    GapAnalysisFrameworkMismatchError,
    GapAnalysisInput,
    GapAnalysisInputError,
    GapAnalysisTenantIsolationError,
)
from services.readiness.gap_analysis.models import (
    CompensatingControl,
    DependencyChain,
    EvidenceFreshnessRecord,
    GapAnalysisResult,
    GapReplayContract,
    GovernanceOverride,
    MaturityBlocker,
    PolicyException,
    ReadinessBlocker,
    ReadinessGap,
    ReadinessImpactEstimate,
    RemediationRecommendation,
)
from services.readiness.scoring import (
    FrameworkMismatchError as ScoringFrameworkMismatchError,
    ReadinessScoreEngine,
    ScoringContractMismatchError,
    ScoringError,
    ScoringInput,
    TenantIsolationViolation as ScoringTenantIsolationViolation,
)
from services.readiness.store import (
    AssessmentNotFound,
    ReadinessStoreError,
    ScoringContractNotFound,
)

log = logging.getLogger("frostgate.readiness.gap_analysis_api")
router = APIRouter(tags=["readiness"])

_store = ReadinessStore()
_score_engine = ReadinessScoreEngine()
_gap_engine = GapAnalysisEngine()

_SCORE_PAGE = 200
_MAX_FETCH_PAGES = 100  # hard cap: prevents unbounded pagination on pathological stores

# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------

ERR_GAP_ANALYSIS_ERROR = "READY-GAP-001"
ERR_GAP_TENANT_ISOLATION = "READY-GAP-002"
ERR_GAP_FRAMEWORK_MISMATCH = "READY-GAP-003"
ERR_GAP_INPUT_ERROR = "READY-GAP-004"
ERR_ASSESSMENT_NOT_FOUND = "READY-API-005"
ERR_SCORING_ENGINE_ERROR = "READY-API-017"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tenant_from_auth(request: Request) -> Optional[str]:
    auth = getattr(getattr(request, "state", None), "auth", None)
    return getattr(getattr(request, "state", None), "tenant_id", None) or getattr(
        auth, "tenant_id", None
    )


def _fetch_all(fn, **kwargs) -> list:  # type: ignore[type-arg]
    items: list = []
    offset = 0
    for _ in range(_MAX_FETCH_PAGES):
        page = fn(**kwargs, limit=_SCORE_PAGE, offset=offset)
        items.extend(page)
        if len(page) < _SCORE_PAGE:
            break
        offset += _SCORE_PAGE
    return items


def _derive_result_id(
    assessment_id: str,
    framework_id: str,
    framework_version_tag: str,
    score_version: str,
    scoring_contract_version: Optional[str],
) -> str:
    """Deterministic artifact identity for gap analysis results.

    Derived from stable, immutable governance inputs only. Never uses
    random entropy, request-time UUIDs, timestamps, or correlation IDs.
    Same inputs always produce the same result_id for forensic replay.
    """
    parts = {
        "assessment_id": assessment_id,
        "framework_id": framework_id,
        "framework_version_tag": framework_version_tag,
        "score_version": score_version,
        "scoring_contract_version": scoring_contract_version,
    }
    canonical = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    h = hashlib.sha256(canonical.encode()).hexdigest()[:24]
    return f"gap::{assessment_id}::{h}"


# ---------------------------------------------------------------------------
# Response models — export-safe governance metadata only
# ---------------------------------------------------------------------------


class ReadinessGapResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    gap_id: str
    gap_classification: str
    gap_severity: str
    framework_id: str
    framework_version: str
    gap_rationale: str
    detected_at: str
    is_blocker: bool
    is_maturity_blocker: bool
    affected_control_ids: list[str]
    affected_framework_ids: list[str]
    evidence_ids: list[str]
    control_id: Optional[str]
    domain_id: Optional[str]

    @classmethod
    def from_domain(cls, g: ReadinessGap) -> "ReadinessGapResponse":
        return cls(
            gap_id=g.gap_id,
            gap_classification=g.gap_classification.value,
            gap_severity=g.gap_severity.value,
            framework_id=g.framework_id,
            framework_version=g.framework_version,
            gap_rationale=g.gap_rationale,
            detected_at=g.detected_at.isoformat(),
            is_blocker=g.is_blocker,
            is_maturity_blocker=g.is_maturity_blocker,
            affected_control_ids=list(g.affected_control_ids),
            affected_framework_ids=list(g.affected_framework_ids),
            evidence_ids=list(g.evidence_ids),
            control_id=g.control_id,
            domain_id=g.domain_id,
        )


class EvidenceFreshnessRecordResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    freshness_id: str
    evidence_id: str
    control_id: Optional[str]
    framework_id: str
    framework_version: str
    submitted_at: str
    freshness_window_days: int
    is_stale: bool
    staleness_days: Optional[int]
    evaluated_at: str

    @classmethod
    def from_domain(
        cls, r: EvidenceFreshnessRecord
    ) -> "EvidenceFreshnessRecordResponse":
        return cls(
            freshness_id=r.freshness_id,
            evidence_id=r.evidence_id,
            control_id=r.control_id,
            framework_id=r.framework_id,
            framework_version=r.framework_version,
            submitted_at=r.submitted_at.isoformat(),
            freshness_window_days=r.freshness_window_days,
            is_stale=r.is_stale,
            staleness_days=r.staleness_days,
            evaluated_at=r.evaluated_at.isoformat(),
        )


class ReadinessBlockerResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    blocker_id: str
    gap_id: str
    blocker_rationale: str
    severity: str
    affected_framework_ids: list[str]
    affected_control_ids: list[str]

    @classmethod
    def from_domain(cls, b: ReadinessBlocker) -> "ReadinessBlockerResponse":
        return cls(
            blocker_id=b.blocker_id,
            gap_id=b.gap_id,
            blocker_rationale=b.blocker_rationale,
            severity=b.severity.value,
            affected_framework_ids=list(b.affected_framework_ids),
            affected_control_ids=list(b.affected_control_ids),
        )


class MaturityBlockerResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    blocker_id: str
    gap_id: str
    maturity_tier_id: str
    blocker_rationale: str
    affected_control_ids: list[str]

    @classmethod
    def from_domain(cls, b: MaturityBlocker) -> "MaturityBlockerResponse":
        return cls(
            blocker_id=b.blocker_id,
            gap_id=b.gap_id,
            maturity_tier_id=b.maturity_tier_id,
            blocker_rationale=b.blocker_rationale,
            affected_control_ids=list(b.affected_control_ids),
        )


class DependencyChainResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    chain_id: str
    ordered_gap_ids: list[str]
    has_cycle: bool
    cycle_gap_ids: list[str]

    @classmethod
    def from_domain(cls, c: DependencyChain) -> "DependencyChainResponse":
        return cls(
            chain_id=c.chain_id,
            ordered_gap_ids=list(c.ordered_gap_ids),
            has_cycle=c.has_cycle,
            cycle_gap_ids=list(c.cycle_gap_ids),
        )


class ReadinessImpactEstimateResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    estimate_id: str
    gap_id: str
    maturity_impact: float
    framework_impact: float
    remediation_impact: float
    governance_coverage_impact: float
    domain_impact: dict[str, float]
    estimation_rationale: str

    @classmethod
    def from_domain(
        cls, e: ReadinessImpactEstimate
    ) -> "ReadinessImpactEstimateResponse":
        return cls(
            estimate_id=e.estimate_id,
            gap_id=e.gap_id,
            maturity_impact=e.maturity_impact,
            framework_impact=e.framework_impact,
            remediation_impact=e.remediation_impact,
            governance_coverage_impact=e.governance_coverage_impact,
            domain_impact=dict(e.domain_impact),
            estimation_rationale=e.estimation_rationale,
        )


class RemediationRecommendationResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    recommendation_id: str
    gap_id: str
    remediation_classification: str
    remediation_rationale: str
    affected_control_ids: list[str]
    affected_domain_ids: list[str]
    affected_framework_ids: list[str]
    estimated_readiness_impact: float
    maturity_implications: str
    governance_rationale: str
    dependency_ids: list[str]
    blocker_ids: list[str]
    compensating_control_ids: list[str]

    @classmethod
    def from_domain(
        cls, r: RemediationRecommendation
    ) -> "RemediationRecommendationResponse":
        return cls(
            recommendation_id=r.recommendation_id,
            gap_id=r.gap_id,
            remediation_classification=r.remediation_classification,
            remediation_rationale=r.remediation_rationale,
            affected_control_ids=list(r.affected_control_ids),
            affected_domain_ids=list(r.affected_domain_ids),
            affected_framework_ids=list(r.affected_framework_ids),
            estimated_readiness_impact=r.estimated_readiness_impact,
            maturity_implications=r.maturity_implications,
            governance_rationale=r.governance_rationale,
            dependency_ids=list(r.dependency_ids),
            blocker_ids=list(r.blocker_ids),
            compensating_control_ids=list(r.compensating_control_ids),
        )


class PolicyExceptionResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    exception_id: str
    exception_type: str
    exception_authority: str
    approval_rationale: str
    affected_control_ids: list[str]
    affected_framework_ids: list[str]
    approved_at: str
    expires_at: Optional[str]

    @classmethod
    def from_domain(cls, e: PolicyException) -> "PolicyExceptionResponse":
        return cls(
            exception_id=e.exception_id,
            exception_type=e.exception_type.value,
            exception_authority=e.exception_authority,
            approval_rationale=e.approval_rationale,
            affected_control_ids=list(e.affected_control_ids),
            affected_framework_ids=list(e.affected_framework_ids),
            approved_at=e.approved_at.isoformat(),
            expires_at=e.expires_at.isoformat() if e.expires_at else None,
        )


class CompensatingControlResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    compensating_id: str
    gap_id: str
    mitigation_rationale: str
    framework_applicability: list[str]
    approved_by: str
    approved_at: str

    @classmethod
    def from_domain(cls, c: CompensatingControl) -> "CompensatingControlResponse":
        return cls(
            compensating_id=c.compensating_id,
            gap_id=c.gap_id,
            mitigation_rationale=c.mitigation_rationale,
            framework_applicability=list(c.framework_applicability),
            approved_by=c.approved_by,
            approved_at=c.approved_at.isoformat(),
        )


class GovernanceOverrideResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    override_id: str
    gap_id: str
    override_type: str
    original_value: str
    overridden_value: str
    override_authority: str
    override_rationale: str
    approved_at: str

    @classmethod
    def from_domain(cls, o: GovernanceOverride) -> "GovernanceOverrideResponse":
        return cls(
            override_id=o.override_id,
            gap_id=o.gap_id,
            override_type=o.override_type.value,
            original_value=o.original_value,
            overridden_value=o.overridden_value,
            override_authority=o.override_authority,
            override_rationale=o.override_rationale,
            approved_at=o.approved_at.isoformat(),
        )


class GapReplayContractResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    contract_id: str
    result_id: str
    framework_version: str
    analysis_version: str
    scoring_contract_version: Optional[str]
    maturity_model_version: Optional[str]
    mapping_version: Optional[str]
    evidence_snapshot_version: Optional[str]

    @classmethod
    def from_domain(cls, c: GapReplayContract) -> "GapReplayContractResponse":
        return cls(
            contract_id=c.contract_id,
            result_id=c.result_id,
            framework_version=c.framework_version,
            analysis_version=c.analysis_version,
            scoring_contract_version=c.scoring_contract_version,
            maturity_model_version=c.maturity_model_version,
            mapping_version=c.mapping_version,
            evidence_snapshot_version=c.evidence_snapshot_version,
        )


class GapAnalysisResultResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    result_id: str
    assessment_id: Optional[str]
    framework_id: str
    framework_version: str
    analysis_version: str
    analyzed_at: str
    gaps: list[ReadinessGapResponse]
    readiness_blockers: list[ReadinessBlockerResponse]
    maturity_blockers: list[MaturityBlockerResponse]
    dependency_chains: list[DependencyChainResponse]
    remediation_recommendations: list[RemediationRecommendationResponse]
    impact_estimates: list[ReadinessImpactEstimateResponse]
    policy_exceptions: list[PolicyExceptionResponse]
    compensating_controls: list[CompensatingControlResponse]
    governance_overrides: list[GovernanceOverrideResponse]
    evidence_freshness_records: list[EvidenceFreshnessRecordResponse]
    replay_contract: GapReplayContractResponse
    scoring_contract_version: Optional[str]
    maturity_model_version: Optional[str]
    mapping_version: Optional[str]
    evidence_snapshot_version: Optional[str]

    @classmethod
    def from_domain(cls, result: GapAnalysisResult) -> "GapAnalysisResultResponse":
        return cls(
            result_id=result.result_id,
            assessment_id=result.assessment_id,
            framework_id=result.framework_id,
            framework_version=result.framework_version,
            analysis_version=result.analysis_version,
            analyzed_at=result.analyzed_at.isoformat(),
            gaps=[ReadinessGapResponse.from_domain(g) for g in result.gaps],
            readiness_blockers=[
                ReadinessBlockerResponse.from_domain(b)
                for b in result.readiness_blockers
            ],
            maturity_blockers=[
                MaturityBlockerResponse.from_domain(b) for b in result.maturity_blockers
            ],
            dependency_chains=[
                DependencyChainResponse.from_domain(c) for c in result.dependency_chains
            ],
            remediation_recommendations=[
                RemediationRecommendationResponse.from_domain(r)
                for r in result.remediation_recommendations
            ],
            impact_estimates=[
                ReadinessImpactEstimateResponse.from_domain(e)
                for e in result.impact_estimates
            ],
            policy_exceptions=[
                PolicyExceptionResponse.from_domain(e) for e in result.policy_exceptions
            ],
            compensating_controls=[
                CompensatingControlResponse.from_domain(c)
                for c in result.compensating_controls
            ],
            governance_overrides=[
                GovernanceOverrideResponse.from_domain(o)
                for o in result.governance_overrides
            ],
            evidence_freshness_records=[
                EvidenceFreshnessRecordResponse.from_domain(r)
                for r in result.evidence_freshness_records
            ],
            replay_contract=GapReplayContractResponse.from_domain(
                result.replay_contract
            ),
            scoring_contract_version=result.scoring_contract_version,
            maturity_model_version=result.maturity_model_version,
            mapping_version=result.mapping_version,
            evidence_snapshot_version=result.evidence_snapshot_version,
        )


# ---------------------------------------------------------------------------
# Gap analysis route
# ---------------------------------------------------------------------------


@router.get(
    "/control-plane/readiness/assessments/{assessment_id}/gap-analysis",
    tags=["readiness"],
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def get_gap_analysis(
    assessment_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> GapAnalysisResultResponse:
    """Compute deterministic readiness gap analysis for an assessment.

    Loads all framework, domain, control, maturity, result, and evidence data
    from the store, computes a Readiness score, then runs the GapAnalysisEngine
    and returns a frozen GapAnalysisResult. No data is mutated. Results are
    not persisted — call again for a fresh analysis reflecting current state.

    tenant_id is always resolved from auth context. The analysis is scoped to
    the authenticated tenant and will not expose cross-tenant information.
    """
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        # Platform-scoped keys (no tenant_id) are intentionally rejected here.
        # Cross-tenant / regulator-review / governance-admin gap analysis requires
        # an explicit future design and MUST NOT fall through into tenant-scoped paths.
        raise HTTPException(
            status_code=403,
            detail=api_error(
                "READY-API-403", "Gap analysis requires tenant auth context"
            ),
        )

    # Load assessment (enforces tenant isolation via store)
    try:
        assessment = _store.get_assessment(
            db, assessment_id=assessment_id, tenant_id=tenant_id
        )
    except AssessmentNotFound:
        raise HTTPException(
            status_code=404,
            detail=api_error(
                ERR_ASSESSMENT_NOT_FOUND, f"Assessment not found: {assessment_id!r}"
            ),
        )
    except ReadinessStoreError as exc:
        raise HTTPException(
            status_code=500, detail=api_error("READY-API-500", exc.message)
        )

    # Load all supporting data for scoring and gap analysis.
    # tenant_id is passed to ALL framework metadata reads so that tenant-specific
    # overlays (domains/controls/tiers) are correctly scoped. Without tenant_id,
    # list_* returns ALL tenant overlays for the framework, enabling cross-tenant leakage.
    # Store semantics: tenant_id filter returns (tenant_id=T OR tenant_id=NULL), so
    # platform records (tenant_id=NULL) remain visible to all tenants.
    try:
        framework = _store.get_framework(
            db, framework_id=assessment.framework_id, tenant_id=tenant_id
        )
        domains = _fetch_all(
            _store.list_domains,
            db=db,
            framework_id=assessment.framework_id,
            tenant_id=tenant_id,
        )
        controls = _fetch_all(
            _store.list_controls,
            db=db,
            framework_id=assessment.framework_id,
            tenant_id=tenant_id,
        )
        maturity_tiers = _fetch_all(
            _store.list_maturity_tiers,
            db=db,
            framework_id=assessment.framework_id,
            tenant_id=tenant_id,
        )
        results = _fetch_all(
            _store.list_assessment_results,
            db=db,
            assessment_id=assessment_id,
            tenant_id=tenant_id,
        )
        evidence_refs = _fetch_all(
            _store.list_evidence_references,
            db=db,
            assessment_id=assessment_id,
            tenant_id=tenant_id,
        )
        scoring_contract: Any = None
        if assessment.scoring_contract_id:
            try:
                scoring_contract = _store.get_scoring_contract(
                    db,
                    contract_id=assessment.scoring_contract_id,
                    tenant_id=tenant_id,
                )
            except ScoringContractNotFound:
                pass
    except ReadinessStoreError as exc:
        raise HTTPException(
            status_code=500, detail=api_error("READY-API-500", exc.message)
        )

    # Score the assessment
    try:
        score_inp = ScoringInput(
            assessment=assessment,
            framework=framework,
            controls=tuple(controls),
            domains=tuple(domains),
            maturity_tiers=tuple(maturity_tiers),
            results=tuple(results),
            evidence_refs=tuple(evidence_refs),
            scoring_contract=scoring_contract,
        )
        score_output = _score_engine.score(score_inp)
    except (
        ScoringTenantIsolationViolation,
        ScoringFrameworkMismatchError,
        ScoringContractMismatchError,
        ScoringError,
    ) as exc:
        raise HTTPException(
            status_code=422,
            detail=api_error(ERR_SCORING_ENGINE_ERROR, str(exc)),
        )

    # Extract critical/required control IDs from scoring contract if available
    critical_control_ids: frozenset[str] = frozenset()
    required_control_ids: frozenset[str] = frozenset()
    if scoring_contract is not None:
        sc_meta = scoring_contract.scoring_metadata
        critical_control_ids = frozenset(sc_meta.get("critical_controls", []))
        required_control_ids = frozenset(sc_meta.get("required_controls", []))

    # Run gap analysis.
    # result_id is deterministic: derived from stable governance inputs only.
    # Same assessment + framework + scoring contract → same result_id, enabling replay.
    result_id = _derive_result_id(
        assessment_id=assessment_id,
        framework_id=assessment.framework_id,
        framework_version_tag=score_output.framework_version_tag,
        score_version=score_output.score_version,
        scoring_contract_version=score_output.scoring_contract_version,
    )
    analyzed_at = datetime.now(tz=timezone.utc)
    try:
        gap_inp = GapAnalysisInput(
            assessment=assessment,
            framework=framework,
            controls=tuple(controls),
            domains=tuple(domains),
            maturity_tiers=tuple(maturity_tiers),
            results=tuple(results),
            evidence_refs=tuple(evidence_refs),
            score_output=score_output,
            critical_control_ids=critical_control_ids,
            required_control_ids=required_control_ids,
        )
        gap_result = _gap_engine.analyze(
            gap_inp, result_id=result_id, analyzed_at=analyzed_at
        )
    except GapAnalysisTenantIsolationError as exc:
        raise HTTPException(
            status_code=403,
            detail=api_error(ERR_GAP_TENANT_ISOLATION, str(exc)),
        )
    except GapAnalysisFrameworkMismatchError as exc:
        raise HTTPException(
            status_code=422,
            detail=api_error(ERR_GAP_FRAMEWORK_MISMATCH, str(exc)),
        )
    except GapAnalysisInputError as exc:
        raise HTTPException(
            status_code=422,
            detail=api_error(ERR_GAP_INPUT_ERROR, str(exc)),
        )
    except GapAnalysisError as exc:
        raise HTTPException(
            status_code=422,
            detail=api_error(ERR_GAP_ANALYSIS_ERROR, str(exc)),
        )

    return GapAnalysisResultResponse.from_domain(gap_result)
