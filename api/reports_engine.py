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
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.auth_scopes.resolution import require_scopes
from api.db import get_sessionmaker
from api.db_models import AssessmentRecord, OrgProfile, PromptVersion, ReportRecord
from api.report_jobs import (
    REPORT_GENERATION_FAILED,
    REPORT_GENERATION_TIMEOUT,
    ReportJobState,
)
from api.security_audit import AuditEvent, EventType, get_auditor

log = logging.getLogger("frostgate.reports")

# Configurable generation timeout in seconds (default 300 s = 5 min).
_REPORT_GENERATION_TIMEOUT_S = int(os.getenv("FG_REPORT_GENERATION_TIMEOUT_S", "300"))

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
        "infra_readiness": "Infrastructure Readiness",
        "compliance_awareness": "Compliance Awareness",
        "automation_potential": "Automation Potential",
    }
    lines = []
    for key, label in labels.items():
        score = scores.get(key, 0.0)
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
    """
    Ensure required fields are present and values are sane.
    Fills defaults rather than raising — we never want to lose a generated report
    over a minor schema mismatch.
    """
    content.setdefault("executive_summary", "")
    content.setdefault("key_strengths", [])
    content.setdefault("critical_gaps", [])
    content.setdefault("domain_findings", {})
    content.setdefault("roadmap", {"days_30": [], "days_60": [], "days_90": []})
    content.setdefault("framework_alignments", [])
    content.setdefault(
        "disclaimer",
        "This report reflects alignment with, not certification to, referenced frameworks. "
        "It is intended as an advisory tool to support internal risk management decisions.",
    )

    # Enforce AIEG language discipline: never say "certified"
    exec_summary = content["executive_summary"]
    if "certified" in exec_summary.lower():
        content["executive_summary"] = re.sub(
            r"\bcertified\b", "aligned with", exec_summary, flags=re.IGNORECASE
        )

    # Cap strengths and gaps per AIEG spec
    content["key_strengths"] = content["key_strengths"][:3]
    content["critical_gaps"] = content["critical_gaps"][:5]

    return content


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


async def _generate_report_async(report_id: str) -> None:
    """
    Async wrapper that runs blocking report generation in an executor with a
    configurable timeout.  Called via BackgroundTasks (which runs in an event loop).
    """
    loop = asyncio.get_event_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(None, _do_generate_report, report_id),
            timeout=_REPORT_GENERATION_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        _handle_timeout(report_id)


def _handle_timeout(report_id: str) -> None:
    """Mark the report as failed due to timeout and emit the failure audit event."""
    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        report = db.query(ReportRecord).filter(ReportRecord.id == report_id).first()
        if report:
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
        context = {
            "org_name": org_name,
            "industry": industry,
            "profile_type": assessment.profile_type.replace("_", " ").title(),
            "overall_score": f"{assessment.overall_score:.1f}"
            if assessment.overall_score
            else "0",
            "risk_band": (assessment.risk_band or "unknown").title(),
            "domain_scores": _domain_scores_text(domain_scores),
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
            report = db.query(ReportRecord).filter(ReportRecord.id == report_id).first()
            if report:
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
            pass
    finally:
        db.close()


def _generate_report_sync(report_id: str) -> None:
    """
    BackgroundTask entry point: runs the async wrapper in an event loop.
    FastAPI BackgroundTasks do not automatically provide a running loop for
    synchronous callables, so we bridge via asyncio.run().
    """
    asyncio.run(_generate_report_async(report_id))


# ─── Pydantic schemas ─────────────────────────────────────────────────────────


class GenerateReportRequest(BaseModel):
    assessment_id: str
    prompt_type: str = "executive"


class GenerateReportResponse(BaseModel):
    report_id: str
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

    assessment = (
        db.query(AssessmentRecord)
        .filter(AssessmentRecord.id == body.assessment_id)
        .first()
    )
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
def get_report(report_id: str, request: Request, db: Session = Depends(_get_db)):
    """Poll report status and retrieve content when complete."""
    report = db.query(ReportRecord).filter(ReportRecord.id == report_id).first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    # Tenant isolation: wrong tenant gets 404 (not 403) to avoid enumeration.
    caller_tenant: str | None = getattr(
        getattr(request, "state", None), "tenant_id", None
    )
    if caller_tenant and report.tenant_id and caller_tenant != report.tenant_id:
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


@router.get("/reports/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(_get_db)):
    """
    Return a download URL for the PDF version of the report.
    PDF generation via MinIO/S3 is a Stage 2 feature.
    For now, return a data URL hint so the frontend can render a fallback.
    """
    report = db.query(ReportRecord).filter(ReportRecord.id == report_id).first()
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
