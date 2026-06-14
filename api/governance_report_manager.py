"""Deterministic Governance Report API — tenant-scoped, fail-closed.

Routes:
  POST /ingest/assessment/{assessment_id}/governance-report
      Generate a deterministic governance report for an assessment.
      Requires: assessment must be scored.

  GET  /ingest/assessment/{assessment_id}/governance-report/{report_id}
      Retrieve a governance report with full deterministic payload.

  GET  /ingest/assessment/{assessment_id}/governance-report/{report_id}/replay
      Replay verification: re-generate and compare manifest hashes.
      Returns: {hash_matches: bool, report_id: str}

  GET  /ingest/assessment/{assessment_id}/governance-report/{report_id}/export/html
      Export as deterministic HTML artifact.

  GET  /ingest/assessment/{assessment_id}/governance-report/{report_id}/export/manifest
      Export manifest JSON (report_id, manifest_hash, schema_version, generated_at).

Security invariants:
  - tenant_id resolved from auth context only — never from request body.
  - All routes fail-closed on tenant mismatch or missing assessment.
  - is_finalized=True records are immutable — report_json and manifest_hash
    cannot be overwritten (enforced at manager layer, not DB trigger).
  - No secrets, raw evidence bodies, vectors, or PHI in responses.
  - Audit events emitted for all generate/replay/export actions.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from api.assessments import _resolve_caller_tenant, _get_assessment_or_404
from api.auth_scopes.resolution import require_scopes
from api.entitlements import require_capability
from api.db_models_governance_report import GovernanceReportRecord
from api.deps import auth_ctx_db_session
from services.governance.timeline import TimelineStore
from services.governance.timeline.adapters import governance_report_to_timeline_event
from api.error_contracts import api_error
from api.security_audit import AuditEvent, EventType, get_auditor
from services.governance.report import (
    EvidenceRef,
    GovernanceReportEngine,
    GovernanceReportError,
    ValidationState,
    deserialize_report,
    export_html,
    serialize_report,
)

logger = logging.getLogger("frostgate.api.governance_report")

router = APIRouter(
    prefix="/ingest/assessment",
    tags=["governance-reports"],
    dependencies=[Depends(require_scopes("ingest:assessment"))],
)

_engine = GovernanceReportEngine()
_timeline_store = TimelineStore()


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class EvidenceRefInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str | None = None
    source: str
    validation_state: Literal["VALIDATED", "PENDING", "MISSING"] = "PENDING"
    classification: str = "internal"
    provenance: str = ""
    freshness_days: int | None = None


class GenerateGovernanceReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_refs: list[EvidenceRefInput] = []
    reviewer_validated: bool = False


class FindingResponse(BaseModel):
    finding_id: str
    control_id: str
    domain: str
    severity: str
    confidence: float
    evidence_ids: list[str]
    framework_mappings: list[dict[str, Any]]
    remediation_id: str
    gap_classification: str
    description: str


class ConfidenceResponse(BaseModel):
    overall: float
    evidence_completeness: float
    evidence_freshness: float
    control_coverage: float
    reviewer_validated: bool
    degradation_reasons: list[str]


class GovernanceReportResponse(BaseModel):
    report_id: str
    assessment_id: str
    tenant_id: str
    version: int
    schema_version: str
    generated_at: str
    manifest_hash: str
    findings: list[dict[str, Any]]
    remediations: list[dict[str, Any]]
    evidence_appendix: list[dict[str, Any]]
    framework_summary: dict[str, list[str]]
    confidence: dict[str, Any]
    is_finalized: bool


class ReplayContractResponse(BaseModel):
    report_id: str
    canonical_inputs_hash: str
    findings_hash: str
    manifest_hash: str
    generated_at: str
    schema_version: str


class ReplayResponse(BaseModel):
    report_id: str
    hash_matches: bool
    original_manifest_hash: str
    replayed_manifest_hash: str
    replay_contract: ReplayContractResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_validation_state(s: str) -> ValidationState:
    return ValidationState(s.upper())


def _build_evidence_refs(inputs: list[EvidenceRefInput]) -> list[EvidenceRef]:
    from services.governance.report.identity import derive_evidence_id

    refs: list[EvidenceRef] = []
    for inp in inputs:
        ev_id = inp.evidence_id or derive_evidence_id(
            source=inp.source,
            classification=inp.classification,
            provenance_key=inp.provenance or inp.source,
        )
        refs.append(
            EvidenceRef(
                evidence_id=ev_id,
                source=inp.source,
                validation_state=_parse_validation_state(inp.validation_state),
                classification=inp.classification,
                provenance=inp.provenance,
                freshness_days=inp.freshness_days,
            )
        )
    return refs


def _emit_audit(
    event_type_str: str,
    tenant_id: str,
    report_id: str,
    assessment_id: str,
    *,
    extra: dict[str, Any] | None = None,
) -> None:
    details: dict[str, Any] = {
        "report_id": report_id,
        "assessment_id": assessment_id,
    }
    if extra:
        details.update(extra)
    try:
        get_auditor().log_event(
            AuditEvent(
                event_type=EventType.ADMIN_ACTION,
                tenant_id=tenant_id,
                reason=event_type_str,
                details=details,
            )
        )
    except Exception:
        logger.warning(
            "governance_report.audit_emit_failed event=%s report_id=%s",
            event_type_str,
            report_id,
        )


def _get_report_or_404(
    report_id: str,
    assessment_id: str,
    tenant_id: str,
    db: Session,
) -> GovernanceReportRecord:
    """Tenant-scoped report lookup. Fails closed on mismatch."""
    record = (
        db.query(GovernanceReportRecord)
        .filter(
            GovernanceReportRecord.id == report_id,
            GovernanceReportRecord.assessment_id == assessment_id,
            GovernanceReportRecord.tenant_id == tenant_id,
        )
        .first()
    )
    if record is None:
        raise HTTPException(status_code=404, detail="Governance report not found")
    return record


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/{assessment_id}/governance-report",
    status_code=201,
    response_model=GovernanceReportResponse,
)
def generate_governance_report(
    assessment_id: str,
    body: GenerateGovernanceReportRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> GovernanceReportResponse:
    """Generate a deterministic governance report for a scored assessment.

    Fails closed if the assessment is not yet scored or does not belong to
    the calling tenant.
    """
    caller_tenant = _resolve_caller_tenant(request)
    rec = _get_assessment_or_404(assessment_id, caller_tenant, db)

    if rec.status not in ("scored", "submitted"):
        raise HTTPException(
            status_code=409,
            detail=api_error(
                "GOVERNANCE_REPORT_ASSESSMENT_NOT_SCORED",
                f"Assessment must be scored before generating a governance report (status: {rec.status})",
            ),
        )

    if not rec.scores:
        raise HTTPException(
            status_code=422,
            detail=api_error(
                "GOVERNANCE_REPORT_MISSING_SCORES",
                "Assessment has no domain scores. Submit and score the assessment first.",
            ),
        )

    tenant_id = rec.tenant_id
    evidence_refs = _build_evidence_refs(body.evidence_refs)

    try:
        report = _engine.generate(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            scores=dict(rec.scores),
            responses=dict(rec.responses or {}),
            evidence_refs=evidence_refs,
            reviewer_validated=body.reviewer_validated,
        )
    except GovernanceReportError as exc:
        logger.error(
            "governance_report.generate_error assessment_id=%s tenant_id=%s error=%s",
            assessment_id,
            tenant_id,
            exc,
        )
        raise HTTPException(
            status_code=422,
            detail=api_error("GOVERNANCE_REPORT_GENERATION_FAILED", str(exc)),
        ) from exc

    # Idempotency: if a record with this ID already exists return it directly.
    # Same inputs → same report_id (derive_report_id covers scores + evidence),
    # so this is a genuine re-submission and not a collision.
    existing = (
        db.query(GovernanceReportRecord)
        .filter(
            GovernanceReportRecord.id == report.report_id,
            GovernanceReportRecord.tenant_id == tenant_id,
        )
        .first()
    )
    if existing:
        existing_dict = existing.report_json
        return GovernanceReportResponse(
            report_id=existing.id,
            assessment_id=existing.assessment_id,
            tenant_id=existing.tenant_id,
            version=existing.version,
            schema_version=existing.schema_version,
            generated_at=existing.generated_at,
            manifest_hash=existing.manifest_hash,
            findings=existing_dict.get("findings", []),
            remediations=existing_dict.get("remediations", []),
            evidence_appendix=existing_dict.get("evidence_appendix", []),
            framework_summary=existing_dict.get("framework_summary", {}),
            confidence=existing_dict.get("confidence", {}),
            is_finalized=existing.is_finalized,
        )

    # Persist to DB
    report_dict = serialize_report(report)
    record = GovernanceReportRecord(
        id=report.report_id,
        assessment_id=assessment_id,
        tenant_id=tenant_id,
        version=report.version,
        schema_version=report.schema_version,
        manifest_hash=report.manifest_hash,
        report_json=report_dict,
        generated_at=report.generated_at,
        is_finalized=False,
    )
    db.add(record)
    db.flush()  # send report INSERT before timeline savepoint; IntegrityError surfaces here
    try:
        _tl_event = governance_report_to_timeline_event(report)
        _timeline_store.record(db, _tl_event)
    except Exception:
        logger.warning(
            "governance_report.timeline_emit_failed report_id=%s", report.report_id
        )
    db.commit()

    _emit_audit(
        "governance_report_generated",
        tenant_id,
        report.report_id,
        assessment_id,
        extra={
            "manifest_hash": report.manifest_hash,
            "findings_count": len(report.findings),
            "schema_version": report.schema_version,
        },
    )

    logger.info(
        "governance_report.generated report_id=%s assessment_id=%s tenant_id=%s findings=%d",
        report.report_id,
        assessment_id,
        tenant_id,
        len(report.findings),
    )

    return GovernanceReportResponse(
        report_id=report.report_id,
        assessment_id=report.assessment_id,
        tenant_id=report.tenant_id,
        version=report.version,
        schema_version=report.schema_version,
        generated_at=report.generated_at,
        manifest_hash=report.manifest_hash,
        findings=report_dict["findings"],
        remediations=report_dict["remediations"],
        evidence_appendix=report_dict["evidence_appendix"],
        framework_summary=report_dict["framework_summary"],
        confidence=report_dict["confidence"],
        is_finalized=False,
    )


@router.get(
    "/{assessment_id}/governance-report/{report_id}",
    response_model=GovernanceReportResponse,
)
def get_governance_report(
    assessment_id: str,
    report_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> GovernanceReportResponse:
    """Retrieve a governance report with full deterministic payload."""
    caller_tenant = _resolve_caller_tenant(request)
    rec = _get_assessment_or_404(assessment_id, caller_tenant, db)
    tenant_id = rec.tenant_id

    record = _get_report_or_404(report_id, assessment_id, tenant_id, db)
    r = record.report_json

    return GovernanceReportResponse(
        report_id=record.id,
        assessment_id=record.assessment_id,
        tenant_id=record.tenant_id,
        version=record.version,
        schema_version=record.schema_version,
        generated_at=record.generated_at,
        manifest_hash=record.manifest_hash,
        findings=r.get("findings", []),
        remediations=r.get("remediations", []),
        evidence_appendix=r.get("evidence_appendix", []),
        framework_summary=r.get("framework_summary", {}),
        confidence=r.get("confidence", {}),
        is_finalized=record.is_finalized,
    )


@router.get(
    "/{assessment_id}/governance-report/{report_id}/replay",
    response_model=ReplayResponse,
    dependencies=[Depends(require_capability("trust.replay"))],
)
def replay_governance_report(
    assessment_id: str,
    report_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> ReplayResponse:
    """Replay verification: re-generate the report and compare manifest hashes.

    Returns hash_matches=True if the report is replay-equivalent (not tampered).
    """
    caller_tenant = _resolve_caller_tenant(request)
    rec = _get_assessment_or_404(assessment_id, caller_tenant, db)
    tenant_id = rec.tenant_id

    record = _get_report_or_404(report_id, assessment_id, tenant_id, db)

    # Deserialize stored report
    try:
        stored_report = deserialize_report(record.report_json)
    except (ValueError, KeyError, TypeError) as exc:
        logger.error(
            "governance_report.replay_deserialize_error report_id=%s error=%s",
            report_id,
            exc,
        )
        raise HTTPException(
            status_code=422,
            detail=api_error(
                "GOVERNANCE_REPORT_REPLAY_DESERIALIZE_FAILED",
                "Stored report could not be deserialized for replay.",
            ),
        ) from exc

    # Re-generate from stored evidence appendix + current scores
    evidence_refs = list(stored_report.evidence_appendix)

    try:
        replayed_report, hash_matches = _engine.replay(
            report=stored_report,
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            scores=dict(rec.scores or {}),
            responses=dict(rec.responses or {}),
            evidence_refs=evidence_refs,
            reviewer_validated=stored_report.confidence.reviewer_validated,
        )
    except GovernanceReportError as exc:
        raise HTTPException(
            status_code=422,
            detail=api_error("GOVERNANCE_REPORT_REPLAY_FAILED", str(exc)),
        ) from exc

    from services.governance.report.identity import (
        derive_findings_hash,
        derive_canonical_inputs_hash,
    )

    replayed_manifest = replayed_report.manifest_hash
    findings_hash = derive_findings_hash(
        [f.finding_id for f in replayed_report.findings]
    )
    canonical_inputs_hash = derive_canonical_inputs_hash(
        assessment_id=assessment_id,
        evidence_refs=evidence_refs,
        framework_ids=["NIST_AI_RMF", "SOC2", "HIPAA"],
    )

    _emit_audit(
        "governance_report_replayed",
        tenant_id,
        report_id,
        assessment_id,
        extra={
            "hash_matches": hash_matches,
            "original_manifest_hash": record.manifest_hash,
            "replayed_manifest_hash": replayed_manifest,
        },
    )

    return ReplayResponse(
        report_id=report_id,
        hash_matches=hash_matches,
        original_manifest_hash=record.manifest_hash,
        replayed_manifest_hash=replayed_manifest,
        replay_contract=ReplayContractResponse(
            report_id=replayed_report.report_id,
            canonical_inputs_hash=canonical_inputs_hash,
            findings_hash=findings_hash,
            manifest_hash=replayed_manifest,
            generated_at=replayed_report.generated_at,
            schema_version=replayed_report.schema_version,
        ),
    )


@router.get(
    "/{assessment_id}/governance-report/{report_id}/export/html",
)
def export_governance_report_html(
    assessment_id: str,
    report_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> Response:
    """Export governance report as deterministic HTML artifact."""
    caller_tenant = _resolve_caller_tenant(request)
    rec = _get_assessment_or_404(assessment_id, caller_tenant, db)
    tenant_id = rec.tenant_id

    record = _get_report_or_404(report_id, assessment_id, tenant_id, db)

    try:
        report = deserialize_report(record.report_json)
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(
            status_code=422,
            detail=api_error(
                "GOVERNANCE_REPORT_EXPORT_DESERIALIZE_FAILED",
                "Stored report could not be deserialized for export.",
            ),
        ) from exc

    html = export_html(report)

    _emit_audit(
        "governance_report_exported_html",
        tenant_id,
        report_id,
        assessment_id,
    )

    return Response(
        content=html,
        media_type="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="governance-report-{report_id}.html"',
            "X-Manifest-Hash": report.manifest_hash,
        },
    )


@router.get(
    "/{assessment_id}/governance-report/{report_id}/export/manifest",
)
def export_governance_report_manifest(
    assessment_id: str,
    report_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Export manifest JSON for the governance report.

    Returns report_id, manifest_hash, schema_version, generated_at, finding_ids.
    """
    caller_tenant = _resolve_caller_tenant(request)
    rec = _get_assessment_or_404(assessment_id, caller_tenant, db)
    tenant_id = rec.tenant_id

    record = _get_report_or_404(report_id, assessment_id, tenant_id, db)

    findings = record.report_json.get("findings", [])
    finding_ids = [f.get("finding_id", "") for f in findings if f.get("finding_id")]

    _emit_audit(
        "governance_report_exported_manifest",
        tenant_id,
        report_id,
        assessment_id,
    )

    return {
        "report_id": record.id,
        "assessment_id": record.assessment_id,
        "tenant_id": record.tenant_id,
        "manifest_hash": record.manifest_hash,
        "schema_version": record.schema_version,
        "version": record.version,
        "generated_at": record.generated_at,
        "finding_ids": finding_ids,
        "is_finalized": record.is_finalized,
    }
