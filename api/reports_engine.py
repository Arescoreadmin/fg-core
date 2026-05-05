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

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db import get_sessionmaker
from api.db_models import AssessmentRecord, OrgProfile, PromptVersion, ReportRecord

log = logging.getLogger("frostgate.reports")

router = APIRouter(prefix="/assessment", tags=["reports"])

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
        "data_governance":      "Data Governance",
        "security_posture":     "Security Posture",
        "ai_maturity":          "AI Maturity",
        "infra_readiness":      "Infrastructure Readiness",
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


def _generate_report_sync(report_id: str) -> None:
    """
    Blocking report generation — called via BackgroundTasks.
    Opens its own DB session (the request session is closed by the time this runs).
    """
    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        report = db.query(ReportRecord).filter(ReportRecord.id == report_id).first()
        if report is None:
            log.error("reports.generate report_not_found id=%s", report_id)
            return

        report.status = "generating"
        db.commit()

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
            "overall_score": f"{assessment.overall_score:.1f}" if assessment.overall_score else "0",
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

        log.info(
            "reports.generated report_id=%s assessment_id=%s",
            report_id, report.assessment_id,
        )

    except Exception as exc:
        log.exception("reports.generate_failed report_id=%s error=%s", report_id, exc)
        try:
            report = db.query(ReportRecord).filter(ReportRecord.id == report_id).first()
            if report:
                report.status = "failed"
                report.error_message = str(exc)[:500]
                report.completed_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


# ─── Pydantic schemas ─────────────────────────────────────────────────────────

class GenerateReportRequest(BaseModel):
    assessment_id: str
    prompt_type: str = "executive"


class GenerateReportResponse(BaseModel):
    report_id: str
    status: str


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/reports/generate", response_model=GenerateReportResponse, status_code=202)
def generate_report(
    body: GenerateReportRequest,
    background_tasks: BackgroundTasks,
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
    report = ReportRecord(
        id=report_id,
        tenant_id=assessment.tenant_id,
        assessment_id=assessment.id,
        org_id=assessment.org_id,
        org_profile_id=assessment.org_profile_id,
        status="pending",
        prompt_type=body.prompt_type,
    )
    db.add(report)
    db.commit()

    background_tasks.add_task(_generate_report_sync, report_id)

    log.info(
        "reports.enqueued report_id=%s assessment_id=%s type=%s",
        report_id, body.assessment_id, body.prompt_type,
    )

    return GenerateReportResponse(report_id=report_id, status="pending")


@router.get("/reports/{report_id}")
def get_report(report_id: str, db: Session = Depends(_get_db)):
    """Poll report status and retrieve content when complete."""
    report = db.query(ReportRecord).filter(ReportRecord.id == report_id).first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    overall_score: float | None = None
    if report.assessment_id:
        assessment = db.query(AssessmentRecord).filter(AssessmentRecord.id == report.assessment_id).first()
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
        "completed_at": report.completed_at.isoformat() if report.completed_at else None,
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
