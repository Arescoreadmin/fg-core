"""
api/assessment_scan.py — Microsoft Graph scan endpoints for field assessments.

Trust-but-verify flow:
  1. POST /assessment/{id}/scan/manifest
     Returns the pre-execution manifest listing every Graph API call, scope
     required, and business reason. Client reviews before authorising.

  2. POST /assessment/{id}/scan/acknowledge
     Client submits the acknowledgment token to authorise execution.
     Returns the session ID for the next step.

  3. POST /assessment/{id}/scan/execute
     Runs the scan against the client's tenant using the provided Graph token.
     Requires a previously acknowledged session.

  4. GET /assessment/{id}/scan/{session_id}
     Returns the session status, structured findings, and methodology statement.

Auth model: same UUID-as-token model as the rest of the assessment flow.
The Graph access token is provided by the consultant at execution time — it is
never stored by FrostGate (only the HMAC-chained audit log is persisted).
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.auth_scopes.resolution import require_scopes
from api.db import get_sessionmaker
from api.db_models import AssessmentRecord
from api.db_models_assessment_scan import AssessmentScanSession
from api.assessments import _resolve_caller_tenant
from services.connectors.drivers.msgraph import (
    GraphClient,
    ScanSession,
    acknowledgment_token,
    build_scan_manifest,
    execute_action,
    generate_methodology_statement,
    verify_acknowledgment,
)

log = logging.getLogger("frostgate.assessment_scan")

router = APIRouter(
    prefix="/ingest/assessment",
    tags=["assessment-scan"],
    dependencies=[Depends(require_scopes("ingest:assessment"))],
)


def _get_db():
    SessionLocal = get_sessionmaker()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _get_assessment_or_404(
    assessment_id: str, tenant_id: str, db: Session
) -> AssessmentRecord:
    record = (
        db.query(AssessmentRecord)
        .filter(
            AssessmentRecord.id == assessment_id,
            AssessmentRecord.tenant_id == tenant_id,
        )
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="assessment_not_found")
    return record


def _get_session_or_404(
    session_id: str, assessment_id: str, tenant_id: str, db: Session
) -> AssessmentScanSession:
    row = (
        db.query(AssessmentScanSession)
        .filter(
            AssessmentScanSession.id == session_id,
            AssessmentScanSession.assessment_id == assessment_id,
            AssessmentScanSession.tenant_id == tenant_id,
        )
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="scan_session_not_found")
    return row


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ScanManifestRequest(BaseModel):
    action_ids: list[str] | None = Field(
        None,
        description="Specific action IDs to include. Omit for all available actions.",
    )


class ScanManifestResponse(BaseModel):
    session_id: str
    manifest_id: str
    acknowledgment_token: str
    generated_at: str
    actions: list[dict[str, Any]]
    total_scopes_required: list[str]
    instructions: str


class AcknowledgeRequest(BaseModel):
    session_id: str
    acknowledgment_token: str


class AcknowledgeResponse(BaseModel):
    session_id: str
    status: str
    acknowledged_at: str
    message: str


class ExecuteRequest(BaseModel):
    session_id: str
    graph_access_token: str = Field(
        ...,
        description=(
            "Short-lived Microsoft Graph access token with the scopes listed in the manifest. "
            "This token is used to call Graph APIs and is NEVER stored — only the HMAC-chained "
            "audit log of actions is persisted."
        ),
    )


class ExecuteResponse(BaseModel):
    session_id: str
    status: str
    actions_executed: int
    actions_ok: int
    actions_error: int
    total_findings: int
    completed_at: str
    message: str


class ScanResultResponse(BaseModel):
    session_id: str
    assessment_id: str
    status: str
    manifest_id: str
    findings: list[dict[str, Any]]
    action_log: list[dict[str, Any]]
    methodology_statement: str | None
    completed_at: str | None
    error_detail: str | None


# ---------------------------------------------------------------------------
# Live Graph client (used in production)
# ---------------------------------------------------------------------------


class _LiveGraphClient:
    """Thin wrapper around Microsoft Graph REST API.

    Handles paging ($skipToken) automatically and caps records at max_records.
    The token is held in memory only for the duration of the scan — never logged
    or persisted.
    """

    def __init__(self, access_token: str) -> None:
        self._token = access_token
        self._base = "https://graph.microsoft.com/v1.0"

    def get(
        self,
        path: str,
        *,
        select: list[str] | None = None,
        top: int | None = None,
        filter_expr: str | None = None,
    ) -> list[dict[str, Any]]:
        import urllib.parse

        import urllib.request

        # graph_endpoint strings carry the HTTP verb (e.g. "GET /applications").
        # Strip it so we concatenate only the path onto self._base.
        if " " in path:
            path = path.split(" ", 1)[1]

        # Build the URL — path may already contain query params
        separator = "&" if "?" in path else "?"
        params: list[str] = []
        if select:
            params.append("$select=" + ",".join(select))
        if top:
            params.append(f"$top={min(top, 999)}")
        if filter_expr and "?" not in path:
            params.append(f"$filter={urllib.parse.quote(filter_expr)}")

        url = self._base + path
        if params:
            url += separator + "&".join(params)

        results: list[dict[str, Any]] = []
        pages = 0
        while url and pages < 10:
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Accept": "application/json",
                    "ConsistencyLevel": "eventual",
                },
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read().decode())

            if isinstance(body, dict):
                batch = body.get("value", [])
                results.extend(batch)
                url = body.get("@odata.nextLink")
            else:
                break

            pages += 1
            if top and len(results) >= top:
                results = results[:top]
                break

        return results


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/{assessment_id}/scan/manifest", response_model=ScanManifestResponse)
def create_scan_manifest(
    assessment_id: str,
    body: ScanManifestRequest,
    request: Request,
    db: Session = Depends(_get_db),
) -> ScanManifestResponse:
    """Generate a pre-execution manifest of all Graph API calls that will be made.

    The manifest lists every endpoint, OAuth scope, and business reason.
    Review it, then POST to /acknowledge with the returned acknowledgment_token.
    """
    tenant_id = _resolve_caller_tenant(request)
    _get_assessment_or_404(assessment_id, tenant_id, db)

    manifest = build_scan_manifest(action_ids=body.action_ids)
    ack_token = acknowledgment_token(manifest, tenant_id)

    session_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()

    row = AssessmentScanSession(
        id=session_id,
        assessment_id=assessment_id,
        tenant_id=tenant_id,
        status="pending_acknowledgment",
        manifest_id=manifest.manifest_id,
        manifest_json=json.dumps(
            [
                {
                    "action_id": a.action_id,
                    "name": a.name,
                    "graph_endpoint": a.graph_endpoint,
                    "select_fields": a.select_fields,
                    "oauth_scope_required": a.oauth_scope_required,
                    "business_reason": a.business_reason,
                    "data_touched": a.data_touched,
                    "nist_control_id": a.nist_control_id,
                    "domain": a.domain,
                    "max_records": a.max_records,
                }
                for a in manifest.actions
            ]
        ),
        ack_token=ack_token,
        created_at=now,
    )
    db.add(row)
    db.commit()

    log.info(
        "scan_manifest.created assessment=%s session=%s manifest=%s tenant=%s",
        assessment_id,
        session_id,
        manifest.manifest_id,
        tenant_id,
    )

    return ScanManifestResponse(
        session_id=session_id,
        manifest_id=manifest.manifest_id,
        acknowledgment_token=ack_token,
        generated_at=manifest.generated_at,
        actions=[
            {
                "action_id": a.action_id,
                "name": a.name,
                "graph_endpoint": a.graph_endpoint,
                "oauth_scope_required": a.oauth_scope_required,
                "business_reason": a.business_reason,
                "data_touched": a.data_touched,
                "nist_control_id": a.nist_control_id,
                "domain": a.domain,
            }
            for a in manifest.actions
        ],
        total_scopes_required=manifest.total_scopes_required,
        instructions=(
            "Review the actions above. Each entry shows exactly what Graph API will be "
            "called, why, and what data will be touched. When ready, POST to "
            f"/assessment/{assessment_id}/scan/acknowledge with the session_id and "
            "acknowledgment_token to authorise execution."
        ),
    )


@router.post("/{assessment_id}/scan/acknowledge", response_model=AcknowledgeResponse)
def acknowledge_scan(
    assessment_id: str,
    body: AcknowledgeRequest,
    request: Request,
    db: Session = Depends(_get_db),
) -> AcknowledgeResponse:
    """Authorise scan execution by submitting the acknowledgment token.

    This records that the client has reviewed the manifest and consents to
    the listed Graph API calls being executed against their tenant.
    """
    tenant_id = _resolve_caller_tenant(request)
    _get_assessment_or_404(assessment_id, tenant_id, db)
    row = _get_session_or_404(body.session_id, assessment_id, tenant_id, db)

    if row.status != "pending_acknowledgment":
        raise HTTPException(
            status_code=409,
            detail=f"scan_session_already_{row.status}",
        )

    if row.ack_token != body.acknowledgment_token:
        raise HTTPException(status_code=403, detail="invalid_acknowledgment_token")

    now = datetime.now(UTC).isoformat()
    row.status = "acknowledged"
    row.acknowledged_at = now
    db.commit()

    log.info(
        "scan_manifest.acknowledged assessment=%s session=%s tenant=%s",
        assessment_id,
        body.session_id,
        tenant_id,
    )

    return AcknowledgeResponse(
        session_id=body.session_id,
        status="acknowledged",
        acknowledged_at=now,
        message=(
            "Scan authorised. POST to "
            f"/assessment/{assessment_id}/scan/execute with the session_id "
            "and a short-lived Graph access token to begin data collection."
        ),
    )


@router.post("/{assessment_id}/scan/execute", response_model=ExecuteResponse)
def execute_scan(
    assessment_id: str,
    body: ExecuteRequest,
    request: Request,
    db: Session = Depends(_get_db),
) -> ExecuteResponse:
    """Execute the acknowledged scan against the client's M365 tenant.

    Provide a short-lived Microsoft Graph access token with the scopes listed
    in the manifest. The token is used to call Graph APIs and is NEVER stored.
    Only the HMAC-chained action log and structured findings are persisted.
    """
    tenant_id = _resolve_caller_tenant(request)
    _get_assessment_or_404(assessment_id, tenant_id, db)
    row = _get_session_or_404(body.session_id, assessment_id, tenant_id, db)

    if row.status not in ("acknowledged",):
        raise HTTPException(
            status_code=409,
            detail=f"scan_session_not_executable_status_{row.status}",
        )

    # Rebuild manifest from stored JSON
    actions_raw = json.loads(row.manifest_json)
    manifest = build_scan_manifest(action_ids=[a["action_id"] for a in actions_raw])

    now = datetime.now(UTC).isoformat()
    row.status = "running"
    row.started_at = now
    db.commit()

    graph: GraphClient = _LiveGraphClient(body.graph_access_token)
    session = ScanSession(session_id=body.session_id, manifest=manifest)

    all_findings: list[dict[str, Any]] = []
    error_detail: str | None = None

    try:
        for action in manifest.actions:
            result = execute_action(session, action, graph)
            all_findings.extend(result.findings)
            log.info(
                "scan_action.completed session=%s action=%s status=%s records=%d",
                body.session_id,
                action.action_id,
                result.status,
                result.record_count,
            )

        methodology = generate_methodology_statement(session, tenant_id)
        final_status = "completed"

    except Exception as exc:
        log.exception("scan_session.failed session=%s: %s", body.session_id, exc)
        methodology = None
        final_status = "failed"
        error_detail = str(exc)

    completed_at = datetime.now(UTC).isoformat()
    actions_ok = sum(1 for r in session.results if r.status == "ok")
    actions_error = sum(1 for r in session.results if r.status == "error")

    row.status = final_status
    row.completed_at = completed_at
    row.action_log_json = json.dumps(session.hmac_chain)
    row.findings_json = json.dumps(all_findings)
    row.methodology_md = methodology
    row.error_detail = error_detail
    db.commit()

    log.info(
        "scan_session.%s assessment=%s session=%s actions=%d findings=%d tenant=%s",
        final_status,
        assessment_id,
        body.session_id,
        len(session.results),
        len(all_findings),
        tenant_id,
    )

    return ExecuteResponse(
        session_id=body.session_id,
        status=final_status,
        actions_executed=len(session.results),
        actions_ok=actions_ok,
        actions_error=actions_error,
        total_findings=len(all_findings),
        completed_at=completed_at,
        message=(
            "Scan complete. Retrieve full results at "
            f"/assessment/{assessment_id}/scan/{body.session_id}"
        ),
    )


@router.get("/{assessment_id}/scan/{session_id}", response_model=ScanResultResponse)
def get_scan_results(
    assessment_id: str,
    session_id: str,
    request: Request,
    db: Session = Depends(_get_db),
) -> ScanResultResponse:
    """Retrieve scan session results, findings, and methodology statement."""
    tenant_id = _resolve_caller_tenant(request)
    _get_assessment_or_404(assessment_id, tenant_id, db)
    row = _get_session_or_404(session_id, assessment_id, tenant_id, db)

    findings = json.loads(row.findings_json) if row.findings_json else []
    action_log = json.loads(row.action_log_json) if row.action_log_json else []

    return ScanResultResponse(
        session_id=session_id,
        assessment_id=assessment_id,
        status=row.status,
        manifest_id=row.manifest_id,
        findings=findings,
        action_log=action_log,
        methodology_statement=row.methodology_md,
        completed_at=row.completed_at,
        error_detail=row.error_detail,
    )
