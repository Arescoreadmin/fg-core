"""
api/reports_engine.py — AI-powered advisory report generation.

Uses fg-core's existing Anthropic provider (services/ai/dispatch.py → call_provider).
Generation runs as a FastAPI BackgroundTask so the endpoint returns immediately
with the report_id; the frontend polls GET /assessment/reports/{id} until complete.

Endpoints:
  POST /assessment/reports/generate   Kick off report generation
  GET  /assessment/reports/{id}       Poll status + retrieve content
  GET  /assessment/reports/{id}/download  Signed PDF URL (MinIO — stub for Stage 2)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
)
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from api.assessments import _resolve_caller_tenant, _question_score
from api.auth_scopes.resolution import require_bound_tenant, require_scopes
from api.db import get_sessionmaker, set_tenant_context
from api.db_models import AssessmentRecord, OrgProfile, PromptVersion, ReportRecord
from api.report_jobs import (
    REPORT_GENERATION_FAILED,
    REPORT_GENERATION_TIMEOUT,
    ReportJobState,
)
from api.report_exports import (
    EXPORT_AUDIT_DOWNLOADED,
    EXPORT_AUDIT_FINALIZED,
    EXPORT_AUDIT_GENERATED,
    EXPORT_AUDIT_HASH_FAILED,
    EXPORT_AUDIT_HASH_VERIFIED,
    EXPORT_AUDIT_REGENERATED,
    EXPORT_AUDIT_REPLAY_COMPLETED,
    EXPORT_AUDIT_REPLAY_MISMATCH,
    EXPORT_AUDIT_REPLAY_REQUESTED,
    EXPORT_AUDIT_REVIEWER_ASSIGNED,
    EXPORT_AUDIT_SUPERSEDED,
    ExportUnavailableError,
    ExportValidationError,
    build_hashed_manifest,
    emit_export_event,
    load_assessment,
    load_report_for_export,
    populate_deterministic_export_sections,
    render_html_export,
    render_pdf_export,
)
from api.config.env import is_production_env
from api.security_audit import AuditEvent, EventType, get_auditor
from services.governance.timeline import TimelineStore
from services.governance.timeline.adapters import (
    export_to_timeline_event,
    replay_verify_to_timeline_event,
)
from services.governance.timeline.records import (
    ExportTimelineEntry,
    ReplayTimelineEntry,
)

log = logging.getLogger("frostgate.reports")
_timeline_store = TimelineStore()

# Configurable generation timeout in seconds (default 300 s = 5 min).
_REPORT_GENERATION_TIMEOUT_S = int(os.getenv("FG_REPORT_GENERATION_TIMEOUT_S", "300"))

# ─── Bounded concurrency ──────────────────────────────────────────────────────


def _get_max_concurrent_jobs() -> int:
    """Return max concurrent report generation jobs from env (default: 4)."""
    val = os.environ.get("FG_REPORT_MAX_CONCURRENT_JOBS", "4")
    try:
        n = int(val)
        return max(1, n)
    except ValueError:
        return 4


_REPORT_SEMAPHORE: threading.BoundedSemaphore | None = None
_STATUS_LOCK = threading.Lock()
_queued_count: int = 0
_running_count: int = 0


def _get_semaphore() -> threading.BoundedSemaphore:
    """Return (lazily creating) the module-level concurrency semaphore."""
    global _REPORT_SEMAPHORE
    if _REPORT_SEMAPHORE is None:
        _REPORT_SEMAPHORE = threading.BoundedSemaphore(_get_max_concurrent_jobs())
    return _REPORT_SEMAPHORE


def _reset_semaphore() -> None:
    """Reset the module-level semaphore and counters (used in tests to re-initialise capacity)."""
    global _REPORT_SEMAPHORE, _queued_count, _running_count
    _REPORT_SEMAPHORE = None
    _queued_count = 0
    _running_count = 0


# ─── Queue depth visibility ───────────────────────────────────────────────────


def get_report_queue_status() -> dict[str, int]:
    """Return a snapshot of the current report queue depth.

    Keys:
      max_concurrent  — configured slot count
      running         — jobs currently in generation
      queued_waiting  — jobs waiting to acquire a slot
      available       — free slots right now (0 means fully saturated)
    """
    max_c = _get_max_concurrent_jobs()
    with _STATUS_LOCK:
        qc = _queued_count
        rc = _running_count
    return {
        "max_concurrent": max_c,
        "running": rc,
        "queued_waiting": qc,
        "available": max(0, max_c - rc),
    }


router = APIRouter(
    prefix="/ingest/assessment",
    tags=["reports"],
    dependencies=[Depends(require_scopes("ingest:assessment"))],
)

# ─── DB session ───────────────────────────────────────────────────────────────


def _get_db():
    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ─── Prompt rendering ─────────────────────────────────────────────────────────


def _render_prompt(template: str, context: dict[str, str]) -> str:
    for key, value in context.items():
        template = template.replace(f"{{{{{key}}}}}", value)
    return template


def _domain_scores_text(scores: dict[str, float]) -> str:
    labels = {
        "data_governance": "Data Governance",
        "security_posture": "Security Posture",
        "ai_maturity": "AI Maturity",
        "ai_trustworthiness": "AI Trustworthiness (Bias/Fairness/Explainability)",
        "infra_readiness": "Infrastructure Readiness",
        "compliance_awareness": "Compliance Awareness",
        "automation_potential": "Automation Potential",
    }
    lines = []
    for key, label in labels.items():
        score = scores.get(key)
        if score is None:
            continue
        if score < 25:
            band = "Critical"
        elif score < 50:
            band = "High Risk"
        elif score < 75:
            band = "Medium Risk"
        else:
            band = "Low Risk"
        lines.append(f"  {label}: {score:.1f}/100 ({band})")
    return "\n".join(lines)


# ─── JSON extraction from LLM response ───────────────────────────────────────


def _extract_json(text: str) -> dict[str, Any]:
    """
    Extract the first valid JSON object from the model response.
    Claude reliably returns clean JSON when instructed, but we handle
    markdown fences defensively.
    """
    # Strip markdown code fences
    cleaned = re.sub(r"```(?:json)?", "", text, flags=re.IGNORECASE).strip()
    cleaned = cleaned.rstrip("`").strip()

    # Try direct parse first
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Find the first {...} block
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError:
            pass

    raise ValueError("No valid JSON object found in model response")


# ─── Report generation (runs in background) ───────────────────────────────────


def _validate_report_content(content: dict[str, Any]) -> dict[str, Any]:
    """Ensure required fields are present and values are sane.

    Fills defaults rather than raising — we never want to lose a generated report
    over a minor schema mismatch.
    """
    content.setdefault("executive_summary", "")
    content.setdefault("key_strengths", [])
    content.setdefault("critical_gaps", [])
    content.setdefault("domain_findings", {})
    content["domain_findings"].setdefault("ai_trustworthiness", "")
    content.setdefault(
        "nist_function_findings",
        {
            "GOVERN": "",
            "MAP": "",
            "MEASURE": "",
            "MANAGE": "",
        },
    )
    content.setdefault(
        "risk_quantification",
        {
            "estimated_breach_cost": "",
            "regulatory_exposure": "",
            "insurance_impact": "",
        },
    )
    content.setdefault("roadmap", {"days_30": [], "days_60": [], "days_90": []})
    content.setdefault("framework_alignments", [])
    content.setdefault(
        "disclaimer",
        "This report reflects alignment with, not certification to, referenced frameworks. "
        "It is intended as an advisory tool to support internal risk management decisions. "
        "FrostGate AI Governance Assessment.",
    )
    # nist_control_matrix is injected deterministically by the caller — do not default it here.

    # Enforce language discipline: never say "certified"
    exec_summary = content["executive_summary"]
    if "certified" in exec_summary.lower():
        content["executive_summary"] = re.sub(
            r"\bcertified\b", "aligned with", exec_summary, flags=re.IGNORECASE
        )

    # Cap strengths and gaps
    content["key_strengths"] = content["key_strengths"][:3]
    content["critical_gaps"] = content["critical_gaps"][:5]

    # Normalize roadmap items — ensure estimated_cost and owner exist
    for phase in ("days_30", "days_60", "days_90"):
        for item in content["roadmap"].get(phase, []):
            item.setdefault("estimated_cost", "")
            item.setdefault("owner", "")

    return populate_deterministic_export_sections(content)


def _emit_report_event(
    event_type_str: str,
    tenant_id: str,
    report_id: str,
    assessment_id: str | None,
    *,
    state: ReportJobState,
    reason_code: str | None = None,
    duration_ms: int | None = None,
) -> None:
    """Emit a structured audit event for a report job lifecycle transition.

    Sensitive payload (report content, prompts, model outputs) is never included.
    """
    details: dict[str, Any] = {
        "report_id": report_id,
        "assessment_id": assessment_id,
        "job_state": state.value,
    }
    if reason_code is not None:
        details["reason_code"] = reason_code
    if duration_ms is not None:
        details["duration_ms"] = duration_ms
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
        # Audit failure must never abort the background job itself.
        log.warning(
            "reports.audit_emit_failed event=%s report_id=%s",
            event_type_str,
            report_id,
        )


async def _generate_report_core_async(report_id: str) -> None:
    """Pure async wrapper — no semaphore; timeout-guarded executor call only."""
    loop = asyncio.get_event_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(None, _do_generate_report, report_id),
            timeout=_REPORT_GENERATION_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        _handle_timeout(report_id)


def _handle_timeout(report_id: str) -> None:
    """Mark the report as failed due to timeout and emit the failure audit event.

    Guards against overwriting a terminal state that may have been written
    concurrently (e.g. by the executor thread's exception handler).
    """
    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        report = db.query(ReportRecord).filter(ReportRecord.id == report_id).first()
        if report:
            # Terminal-state guard: never overwrite a final outcome.
            if report.status in ("complete", "failed"):
                log.warning(
                    "reports.timeout_skipped_terminal report_id=%s status=%s",
                    report_id,
                    report.status,
                )
            else:
                report.status = "failed"
                report.error_message = REPORT_GENERATION_TIMEOUT
                report.completed_at = datetime.now(timezone.utc)
                db.commit()
                _emit_report_event(
                    "report_job_failed",
                    report.tenant_id,
                    report_id,
                    report.assessment_id,
                    state=ReportJobState.FAILED,
                    reason_code=REPORT_GENERATION_TIMEOUT,
                )
        log.error(
            "reports.timeout report_id=%s timeout_s=%d",
            report_id,
            _REPORT_GENERATION_TIMEOUT_S,
        )
    except Exception:
        log.exception("reports.timeout_handler_error report_id=%s", report_id)
    finally:
        db.close()


def _do_generate_report(report_id: str) -> None:
    """
    Blocking report generation — called via BackgroundTasks executor.
    Opens its own DB session (the request session is closed by the time this runs).
    """
    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    start_ms = int(time.monotonic() * 1000)
    tenant_id: str = "unknown"
    assessment_id: str | None = None
    try:
        report = db.query(ReportRecord).filter(ReportRecord.id == report_id).first()
        if report is None:
            log.error("reports.generate report_not_found id=%s", report_id)
            return

        # Terminal-state guard: if timeout already marked this failed, do not
        # overwrite it — the slot was acquired after the timeout fired.
        if report.status in ("complete", "failed"):
            log.warning(
                "reports.generate_skipped_terminal report_id=%s status=%s",
                report_id,
                report.status,
            )
            return

        tenant_id = report.tenant_id or "unknown"
        assessment_id = report.assessment_id

        report.status = "generating"
        db.commit()

        _emit_report_event(
            "report_job_started",
            tenant_id,
            report_id,
            assessment_id,
            state=ReportJobState.RUNNING,
        )

        # Load assessment
        assessment = (
            db.query(AssessmentRecord)
            .filter(AssessmentRecord.id == report.assessment_id)
            .first()
        )
        if assessment is None:
            raise ValueError(f"Assessment {report.assessment_id} not found")

        # Load org profile
        org = (
            db.query(OrgProfile)
            .filter(OrgProfile.id == assessment.org_profile_id)
            .first()
        )
        org_name = org.org_name if org else "Your Organization"
        industry = (org.industry if org else "other").replace("_", " ").title()

        # Load prompt template
        prompt_key = f"{report.prompt_type}_report"
        prompt_rec = (
            db.query(PromptVersion)
            .filter(
                PromptVersion.prompt_key == prompt_key,
                PromptVersion.is_active.is_(True),
            )
            .first()
        )
        if prompt_rec is None:
            # Fallback to executive
            prompt_rec = (
                db.query(PromptVersion)
                .filter(
                    PromptVersion.prompt_key == "executive_report",
                    PromptVersion.is_active.is_(True),
                )
                .first()
            )
        if prompt_rec is None:
            raise ValueError("No active prompt template found — run database seeds")

        domain_scores = assessment.scores or {}

        # Build deterministic NIST AI RMF control matrix from assessment data.
        # Import here to avoid a circular import at module load time.
        from services.governance.report.framework_mappings import (
            build_nist_control_matrix,
            nist_coverage_text,
        )

        # We need the question bank to score per control. Load it from the schema.
        try:
            from api.assessments import _load_questions

            questions_list = _load_questions(db)
        except Exception:
            questions_list = []

        responses_raw = dict(assessment.responses or {})
        nist_matrix = build_nist_control_matrix(
            questions_list, responses_raw, _question_score
        )

        context = {
            "org_name": org_name,
            "industry": industry,
            "profile_type": assessment.profile_type.replace("_", " ").title(),
            "overall_score": f"{assessment.overall_score:.1f}"
            if assessment.overall_score
            else "0",
            "risk_band": (assessment.risk_band or "unknown").title(),
            "domain_scores": _domain_scores_text(domain_scores),
            "nist_coverage": nist_coverage_text(nist_matrix),
        }

        user_prompt = _render_prompt(prompt_rec.user_prompt_template, context)
        system_prompt = prompt_rec.system_prompt

        # Call fg-core's Anthropic provider
        from services.ai.dispatch import call_provider, ProviderCallError

        try:
            resp = call_provider(
                provider_id="anthropic",
                prompt=user_prompt,
                max_tokens=4096,
                request_id=report_id,
                tenant_id=report.tenant_id,
                system_prompt=system_prompt,
            )
            raw_text = resp.text
        except ProviderCallError as exc:
            raise ValueError(f"Anthropic call failed: {exc}") from exc

        content = _extract_json(raw_text)
        content = _validate_report_content(content)

        # Inject deterministic NIST control matrix — authoritative, not AI-generated.
        content["nist_control_matrix"] = nist_matrix

        report.content = content
        report.status = "complete"
        report.completed_at = datetime.now(timezone.utc)
        db.commit()

        duration_ms = int(time.monotonic() * 1000) - start_ms
        _emit_report_event(
            "report_job_succeeded",
            tenant_id,
            report_id,
            assessment_id,
            state=ReportJobState.SUCCEEDED,
            duration_ms=duration_ms,
        )

        log.info(
            "reports.generated report_id=%s assessment_id=%s duration_ms=%d",
            report_id,
            report.assessment_id,
            duration_ms,
        )

    except Exception as exc:
        log.exception("reports.generate_failed report_id=%s error=%s", report_id, exc)
        duration_ms = int(time.monotonic() * 1000) - start_ms
        try:
            # Use the in-scope report object when available. Re-querying here can
            # exhaust mocked query side effects in tests and is unnecessary for
            # normal failure handling.
            if "report" in locals() and report:
                # Terminal-state guard: do not overwrite a state already set by
                # the timeout handler or a concurrent path.
                if report.status not in ("complete", "failed"):
                    report.status = "failed"
                    report.error_message = str(exc)[:500]
                    report.completed_at = datetime.now(timezone.utc)
                    db.commit()
            _emit_report_event(
                "report_job_failed",
                tenant_id,
                report_id,
                assessment_id,
                state=ReportJobState.FAILED,
                reason_code=REPORT_GENERATION_FAILED,
                duration_ms=duration_ms,
            )
        except Exception:
            log.exception(
                "reports.failure_audit_emit_failed report_id=%s",
                report_id,
            )
    finally:
        db.close()


def _generate_report_sync(report_id: str) -> None:
    """
    BackgroundTask entry point: acquires the concurrency semaphore in thread
    context (loop-safe), manages counters, then drives async generation.

    threading.BoundedSemaphore is used instead of asyncio.Semaphore because
    _generate_report_sync runs in a BackgroundTask thread while
    asyncio.run() creates a fresh event loop per call — asyncio.Semaphore
    waiters registered in one loop cannot be woken by a release from another.
    """
    global _queued_count, _running_count
    sem = _get_semaphore()
    with _STATUS_LOCK:
        _queued_count += 1
    try:
        sem.acquire()
    except Exception:
        with _STATUS_LOCK:
            _queued_count -= 1
        raise
    with _STATUS_LOCK:
        _queued_count -= 1
        _running_count += 1
    try:
        asyncio.run(_generate_report_core_async(report_id))
    finally:
        with _STATUS_LOCK:
            _running_count -= 1
        sem.release()


# ─── Pydantic schemas ─────────────────────────────────────────────────────────


class GenerateReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    prompt_type: str = "executive"


class GenerateReportResponse(BaseModel):
    report_id: str
    status: str


class FinalizeReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reviewer_ref: str


class RegenerateReportResponse(BaseModel):
    report_id: str
    previous_report_id: str
    status: str


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post(
    "/reports/generate", response_model=GenerateReportResponse, status_code=202
)
def generate_report(
    body: GenerateReportRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(_get_db),
):
    """
    Start async report generation for a scored assessment.
    Returns immediately with report_id; client polls GET /reports/{id}.
    """
    if body.prompt_type not in ("executive", "technical", "compliance"):
        raise HTTPException(
            status_code=400,
            detail="prompt_type must be one of: executive, technical, compliance",
        )

    caller_tenant = _resolve_caller_tenant(request)
    assessment_q = db.query(AssessmentRecord).filter(
        AssessmentRecord.id == body.assessment_id
    )
    if caller_tenant:
        assessment_q = assessment_q.filter(AssessmentRecord.tenant_id == caller_tenant)
    else:
        assessment_q = assessment_q.filter(
            AssessmentRecord.tenant_id == f"lead:{body.assessment_id}"
        )
    assessment = assessment_q.first()
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    if assessment.status not in ("scored", "submitted"):
        raise HTTPException(
            status_code=409,
            detail=f"Assessment must be scored before generating a report (status: {assessment.status})",
        )

    report_id = str(uuid.uuid4())
    tenant_id = assessment.tenant_id
    report = ReportRecord(
        id=report_id,
        tenant_id=tenant_id,
        assessment_id=assessment.id,
        org_id=assessment.org_id,
        org_profile_id=assessment.org_profile_id,
        status="pending",
        prompt_type=body.prompt_type,
    )
    db.add(report)
    db.commit()

    _emit_report_event(
        "report_job_queued",
        tenant_id,
        report_id,
        assessment.id,
        state=ReportJobState.QUEUED,
    )

    background_tasks.add_task(_generate_report_sync, report_id)

    log.info(
        "reports.enqueued report_id=%s assessment_id=%s type=%s tenant_id=%s",
        report_id,
        body.assessment_id,
        body.prompt_type,
        tenant_id,
    )

    return GenerateReportResponse(report_id=report_id, status="pending")


@router.get("/reports/{report_id}")
def get_report(
    report_id: str,
    request: Request,
    db: Session = Depends(_get_db),
    x_assessment_id: str | None = Header(
        default=None,
        alias="X-Assessment-Id",
        description=(
            "Required for pre-tenant (unbound) callers. "
            "Must match the assessment_id that owns this report. "
            "Not required for tenant-bound API keys."
        ),
    ),
):
    """Poll report status and retrieve content when complete."""
    caller_tenant = _resolve_caller_tenant(request)
    # Tenant isolation: fail-closed. Wrong-tenant and missing-tenant both 404
    # to avoid enumeration. Pre-tenant callers must supply X-Assessment-Id to
    # prove lead-namespace ownership; tenant-bound callers use strict predicate.
    q = db.query(ReportRecord).filter(ReportRecord.id == report_id)
    if caller_tenant:
        q = q.filter(ReportRecord.tenant_id == caller_tenant)
    else:
        assessment_token = (x_assessment_id or "").strip()
        if not assessment_token:
            raise HTTPException(status_code=404, detail="Report not found")
        q = q.filter(ReportRecord.tenant_id == f"lead:{assessment_token}")
    report = q.first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    overall_score: float | None = None
    if report.assessment_id:
        assessment = (
            db.query(AssessmentRecord)
            .filter(AssessmentRecord.id == report.assessment_id)
            .first()
        )
        if assessment:
            overall_score = assessment.overall_score

    return {
        "id": report.id,
        "assessment_id": report.assessment_id,
        "org_id": report.org_id,
        "status": report.status,
        "prompt_type": report.prompt_type,
        "content": report.content,
        "error_message": report.error_message,
        "overall_score": overall_score,
        "created_at": report.created_at.isoformat() if report.created_at else None,
        "completed_at": report.completed_at.isoformat()
        if report.completed_at
        else None,
    }


@router.get("/reports/{report_id}/manifest")
def get_report_manifest(
    report_id: str,
    request: Request,
    db: Session = Depends(_get_db),
    x_assessment_id: str | None = Header(default=None, alias="X-Assessment-Id"),
):
    """Return the canonical governance export manifest and SHA-256 hash."""
    require_bound_tenant(request)
    report = load_report_for_export(
        db, request, report_id, x_assessment_id=x_assessment_id
    )
    try:
        hashed = build_hashed_manifest(report, load_assessment(db, report))
    except ExportValidationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    report.manifest_hash = hashed["manifest_hash"]
    db.commit()
    emit_export_event(
        EXPORT_AUDIT_GENERATED,
        report.tenant_id,
        report.id,
        report.assessment_id,
        manifest_hash_value=hashed["manifest_hash"],
    )
    return hashed


_SIGNATURE_VERSION = "report-signature-v1"
_SIGNATURE_ALGORITHM = "ed25519"


def _build_signing_payload(report: ReportRecord) -> str:
    """Return the canonical JSON string that is signed and stored on the report.

    The payload is deterministic over stable report fields only. Transport
    metadata, response headers, and timestamps are excluded. The manifest_hash
    used here is the finalized value — either finalized_manifest_hash (after
    finalize_report) or manifest_hash (during generation if not yet finalized).
    """
    return json.dumps(
        {
            "report_id": report.id,
            "manifest_hash": report.finalized_manifest_hash or report.manifest_hash,
            "report_version": report.report_version,
            "signature_version": _SIGNATURE_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _persist_report_signature(report: ReportRecord) -> None:
    """Sign the canonical report payload and write metadata onto the report object.

    In prod/staging: raises RuntimeError if the signing key is absent or signing fails.
    In dev/test: logs a warning and leaves signature fields None.
    Callers must db.commit() after this returns.
    """
    import hashlib as _hl

    from services.governance.report.signing import (
        ReportSigningKeyError,
        get_public_key_hex,
        sign_report,
    )

    payload = _build_signing_payload(report)
    try:
        sig = sign_report(payload)
        pub_hex = get_public_key_hex()
        report.signature = sig
        report.signature_algorithm = _SIGNATURE_ALGORITHM
        report.signature_key_id = _hl.sha256(bytes.fromhex(pub_hex)).hexdigest()[:16]
        report.signed_at = datetime.now(timezone.utc)
        report.signature_payload_hash = _hl.sha256(payload.encode("utf-8")).hexdigest()
        report.signature_version = _SIGNATURE_VERSION
    except ReportSigningKeyError:
        if is_production_env():
            raise RuntimeError(
                f"report.signing_key_missing report_id={report.id} — "
                "FG_REPORT_SIGNING_KEY must be set in prod/staging; "
                "refusing to finalize unsigned report"
            ) from None
        log.warning(
            "report.signing_key_missing report_id=%s — signature not persisted",
            report.id,
        )


@router.get("/reports/{report_id}/exports/{export_format}")
def export_report_artifact(
    report_id: str,
    export_format: str,
    request: Request,
    db: Session = Depends(_get_db),
    x_assessment_id: str | None = Header(default=None, alias="X-Assessment-Id"),
):
    """Return deterministic PDF or HTML governance artifact bytes."""
    require_bound_tenant(request)
    if export_format not in {"pdf", "html"}:
        raise HTTPException(status_code=400, detail="export_format must be pdf or html")
    report = load_report_for_export(
        db, request, report_id, x_assessment_id=x_assessment_id
    )
    try:
        hashed = build_hashed_manifest(report, load_assessment(db, report))
    except ExportValidationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    manifest = hashed["manifest"]
    digest = hashed["manifest_hash"]
    report.manifest_hash = digest
    try:
        set_tenant_context(db, report.tenant_id)
        _tl_entry = ExportTimelineEntry(
            tenant_id=report.tenant_id,
            export_id=f"export-{digest[:16]}",
            report_id=report.id,
            assessment_id=report.assessment_id,
            export_format=export_format,
            manifest_hash=digest,
            export_version=getattr(report, "export_version", None)
            or "governance-export-v1",
            exported_at_iso=datetime.now(timezone.utc).isoformat(),
        )
        _timeline_store.record(db, export_to_timeline_event(_tl_entry))
    except Exception:
        log.warning("export.timeline_emit_failed report_id=%s", report.id)
    db.commit()
    emit_export_event(
        EXPORT_AUDIT_DOWNLOADED,
        report.tenant_id,
        report.id,
        report.assessment_id,
        manifest_hash_value=digest,
    )
    if export_format == "html":
        return Response(
            content=render_html_export(manifest, digest),
            media_type="text/html; charset=utf-8",
            headers={"X-FrostGate-Manifest-Hash": digest},
        )
    try:
        pdf_bytes = render_pdf_export(manifest, digest)
    except ExportUnavailableError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc

    pdf_headers: dict[str, str] = {"X-FrostGate-Manifest-Hash": digest}

    if report.signature:
        # Prefer the persisted signing event recorded at finalization time.
        pdf_headers["X-Report-Signature"] = report.signature
        if report.signature_key_id:
            pdf_headers["X-Report-Public-Key-Id"] = report.signature_key_id
    elif not is_production_env():
        # Dev/test only: sign on the fly so unsigned legacy reports can be
        # tested without a full finalize cycle. Never allowed in production.
        import hashlib as _hl

        from services.governance.report.signing import (
            ReportSigningKeyError as _RskErr,
            get_public_key_hex as _gpkh,
            sign_report as _sign,
        )

        try:
            _sig = _sign(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
            pdf_headers["X-Report-Signature"] = _sig
            _pub = _gpkh()
            pdf_headers["X-Report-Public-Key-Id"] = _hl.sha256(
                bytes.fromhex(_pub)
            ).hexdigest()[:16]
        except _RskErr:
            pass
    else:
        # Production: report was never finalized or was created before 0104.
        # Omit signing headers rather than producing an unanchored signature.
        log.warning(
            "report.export_unsigned report_id=%s — no persisted signature; "
            "omitting X-Report-Signature (legacy or unfinalized report)",
            report.id,
        )

    return Response(
        content=pdf_bytes, media_type="application/pdf", headers=pdf_headers
    )


@router.post("/reports/{report_id}/finalize")
def finalize_report(
    report_id: str,
    body: FinalizeReportRequest,
    request: Request,
    db: Session = Depends(_get_db),
    x_assessment_id: str | None = Header(default=None, alias="X-Assessment-Id"),
):
    """Preserve reviewer approval and freeze the current canonical manifest hash."""
    require_bound_tenant(request)
    reviewer_ref = body.reviewer_ref.strip()
    if not reviewer_ref:
        raise HTTPException(status_code=400, detail="reviewer_ref is required")
    report = load_report_for_export(
        db, request, report_id, x_assessment_id=x_assessment_id
    )
    if report.finalized_at is not None:
        raise HTTPException(status_code=409, detail="Report already finalized")
    from services.field_assessment.trust_enforcement_adapter import (  # noqa: PLC0415
        enforce_report_finalization,
    )
    from services.field_assessment.trust_enforcement import (  # noqa: PLC0415
        TrustEnforcementError,
    )

    _sig_valid = True if getattr(report, "signature", None) else None
    try:
        enforce_report_finalization(
            db,
            tenant_id=report.tenant_id,
            engagement_id=report.assessment_id,
            signature_valid=_sig_valid,
            is_legacy=(_sig_valid is None),
        )
    except TrustEnforcementError as _te:
        raise HTTPException(
            status_code=422,
            detail={"code": "TRUST_ENFORCEMENT_BLOCKED", "message": str(_te)},
        ) from _te
    report.reviewer_ref = reviewer_ref
    report.approval_status = "finalized"
    report.finalized_at = datetime.now(timezone.utc)
    try:
        hashed = build_hashed_manifest(report, load_assessment(db, report))
    except ExportValidationError as exc:
        report.reviewer_ref = None
        report.approval_status = "unapproved"
        report.finalized_at = None
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    report.manifest_hash = hashed["manifest_hash"]
    report.finalized_manifest_hash = hashed["manifest_hash"]
    _persist_report_signature(report)
    db.commit()
    emit_export_event(
        EXPORT_AUDIT_REVIEWER_ASSIGNED,
        report.tenant_id,
        report.id,
        report.assessment_id,
        manifest_hash_value=hashed["manifest_hash"],
    )
    emit_export_event(
        EXPORT_AUDIT_FINALIZED,
        report.tenant_id,
        report.id,
        report.assessment_id,
        manifest_hash_value=hashed["manifest_hash"],
    )
    return {
        "report_id": report.id,
        "approval_status": report.approval_status,
        "reviewer_ref": report.reviewer_ref,
        "finalized_at": report.finalized_at.isoformat(),
        "manifest_hash": hashed["manifest_hash"],
    }


@router.post("/reports/{report_id}/replay-verify")
def replay_verify_report(
    report_id: str,
    request: Request,
    db: Session = Depends(_get_db),
    expected_manifest_hash: str | None = Query(default=None),
    x_assessment_id: str | None = Header(default=None, alias="X-Assessment-Id"),
):
    """Rebuild the canonical manifest and verify the report hash deterministically."""
    require_bound_tenant(request)
    report = load_report_for_export(
        db, request, report_id, x_assessment_id=x_assessment_id
    )
    emit_export_event(
        EXPORT_AUDIT_REPLAY_REQUESTED,
        report.tenant_id,
        report.id,
        report.assessment_id,
    )
    try:
        hashed = build_hashed_manifest(report, load_assessment(db, report))
    except ExportValidationError as exc:
        emit_export_event(
            EXPORT_AUDIT_HASH_FAILED,
            report.tenant_id,
            report.id,
            report.assessment_id,
            state=ReportJobState.FAILED,
            reason_code=str(exc),
        )
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    actual = hashed["manifest_hash"]
    expected = (
        expected_manifest_hash or report.finalized_manifest_hash or report.manifest_hash
    )
    if expected and actual != expected:
        emit_export_event(
            EXPORT_AUDIT_REPLAY_MISMATCH,
            report.tenant_id,
            report.id,
            report.assessment_id,
            state=ReportJobState.FAILED,
            manifest_hash_value=actual,
        )
        raise HTTPException(status_code=409, detail="Manifest hash mismatch")
    report.manifest_hash = actual
    try:
        set_tenant_context(db, report.tenant_id)
        _tl_replay = ReplayTimelineEntry(
            tenant_id=report.tenant_id,
            replay_id=f"replay-{actual[:16]}",
            report_id=report.id,
            assessment_id=report.assessment_id,
            actual_manifest_hash=actual,
            expected_manifest_hash=expected,
            verified=True,
            replayed_at_iso=datetime.now(timezone.utc).isoformat(),
            replay_contract_version="governance-export-v1",
        )
        _timeline_store.record(db, replay_verify_to_timeline_event(_tl_replay))
    except Exception:
        log.warning("replay.timeline_emit_failed report_id=%s", report.id)
    db.commit()
    emit_export_event(
        EXPORT_AUDIT_HASH_VERIFIED,
        report.tenant_id,
        report.id,
        report.assessment_id,
        manifest_hash_value=actual,
    )
    emit_export_event(
        EXPORT_AUDIT_REPLAY_COMPLETED,
        report.tenant_id,
        report.id,
        report.assessment_id,
        manifest_hash_value=actual,
    )
    return {"report_id": report.id, "manifest_hash": actual, "verified": True}


@router.post(
    "/reports/{report_id}/regenerate",
    response_model=RegenerateReportResponse,
    status_code=202,
)
def regenerate_report(
    report_id: str,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(_get_db),
    x_assessment_id: str | None = Header(default=None, alias="X-Assessment-Id"),
):
    """Create a new report version instead of mutating a finalized artifact."""
    require_bound_tenant(request)
    report = load_report_for_export(
        db, request, report_id, x_assessment_id=x_assessment_id
    )
    if report.finalized_at is None:
        raise HTTPException(status_code=409, detail="Report is not finalized")
    new_report_id = str(uuid.uuid4())
    new_report = ReportRecord(
        id=new_report_id,
        tenant_id=report.tenant_id,
        assessment_id=report.assessment_id,
        org_id=report.org_id,
        org_profile_id=report.org_profile_id,
        status="pending",
        prompt_type=report.prompt_type,
        previous_report_id=report.id,
        report_version=(report.report_version or 1) + 1,
    )
    report.superseded_by_report_id = new_report_id
    db.add(new_report)
    db.commit()
    emit_export_event(
        EXPORT_AUDIT_SUPERSEDED,
        report.tenant_id,
        report.id,
        report.assessment_id,
        manifest_hash_value=report.finalized_manifest_hash,
    )
    emit_export_event(
        EXPORT_AUDIT_REGENERATED,
        new_report.tenant_id,
        new_report.id,
        new_report.assessment_id,
    )
    background_tasks.add_task(_generate_report_sync, new_report_id)
    return RegenerateReportResponse(
        report_id=new_report_id,
        previous_report_id=report.id,
        status="pending",
    )


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    request: Request,
    db: Session = Depends(_get_db),
    x_assessment_id: str | None = Header(
        default=None,
        alias="X-Assessment-Id",
        description=(
            "Required for pre-tenant (unbound) callers. "
            "Must match the assessment_id that owns this report. "
            "Not required for tenant-bound API keys."
        ),
    ),
):
    """
    Return a download URL for the PDF version of the report.
    PDF generation via MinIO/S3 is a Stage 2 feature.
    For now, return a data URL hint so the frontend can render a fallback.
    """
    caller_tenant = _resolve_caller_tenant(request)
    q = db.query(ReportRecord).filter(ReportRecord.id == report_id)
    if caller_tenant:
        q = q.filter(ReportRecord.tenant_id == caller_tenant)
    else:
        assessment_token = (x_assessment_id or "").strip()
        if not assessment_token:
            raise HTTPException(status_code=404, detail="Report not found")
        q = q.filter(ReportRecord.tenant_id == f"lead:{assessment_token}")
    report = q.first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != "complete":
        raise HTTPException(status_code=409, detail="Report not yet complete")

    # Stage 2: generate PDF via WeasyPrint + upload to MinIO, return signed URL
    # For now: return a marker so the frontend shows a "PDF coming soon" message
    return {
        "url": None,
        "expires_in": 0,
        "message": "PDF export is a Stage 2 feature. Use the on-screen report view.",
    }
