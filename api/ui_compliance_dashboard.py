from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from api.db_models import ComplianceFindingRecord, ComplianceRequirementRecord
from services.compliance_registry import ComplianceRegistry

router = APIRouter(tags=["ui-compliance"], dependencies=[Depends(require_scopes("ui:read"))])


@router.get("/ui/compliance/overview")
def overview(request: Request) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    snap = ComplianceRegistry().snapshot(tenant_id)
    return {
        "requirement_coverage": snap["coverage"],
        "open_findings": snap["findings"].get("open", 0),
        "expired_waivers": snap["expired_waivers"],
        "timestamp_utc": snap["timestamp_utc"],
    }


@router.get("/ui/compliance/requirements/status")
def requirement_status(request: Request) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as session:
        rows = (
            session.query(ComplianceRequirementRecord)
            .filter(ComplianceRequirementRecord.tenant_id == tenant_id)
            .order_by(ComplianceRequirementRecord.req_id.asc(), ComplianceRequirementRecord.id.desc())
            .all()
        )
    latest: dict[str, ComplianceRequirementRecord] = {}
    for row in rows:
        latest.setdefault(row.req_id, row)
    return {
        "requirements": [
            {"req_id": r.req_id, "severity": r.severity, "status": r.status, "version": r.version}
            for r in sorted(latest.values(), key=lambda x: x.req_id)
        ]
    }


@router.get("/ui/compliance/findings")
def findings(request: Request) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    now = datetime.now(UTC)
    with Session(get_engine()) as session:
        rows = (
            session.query(ComplianceFindingRecord)
            .filter(ComplianceFindingRecord.tenant_id == tenant_id)
            .order_by(ComplianceFindingRecord.id.desc())
            .all()
        )
    items = []
    for row in rows:
        expiry_warning = False
        waiver = row.waiver_json if isinstance(row.waiver_json, dict) else None
        if waiver and waiver.get("expires_utc"):
            try:
                if datetime.fromisoformat(waiver["expires_utc"].replace("Z", "+00:00")) <= now:
                    expiry_warning = True
            except Exception:
                expiry_warning = True
        items.append(
            {
                "finding_id": row.finding_id,
                "severity": row.severity,
                "status": row.status,
                "waiver": waiver,
                "waiver_expiry_warning": expiry_warning,
            }
        )
    return {"findings": items}


@router.get("/ui/compliance/exam-readiness")
def exam_readiness(request: Request) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    snap = ComplianceRegistry().snapshot(tenant_id)
    ready = (
        not snap["expired_waivers"] and snap["coverage"].get("unknown", 0) == 0
    )
    return {
        "ready": ready,
        "coverage_unknown": snap["coverage"].get("unknown", 0),
        "expired_waivers": snap["expired_waivers"],
        "download_evidence_bundle": "/ui/audit/export-link",
    }
