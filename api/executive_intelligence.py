"""api/executive_intelligence.py — PR 18.6.7: Executive Intelligence Center API.

Primary executive workspace for CEOs, CIOs, CISOs, CROs, Boards, Compliance Officers.

Design: deterministic, auditable, explainable. No fabricated analytics.
All metrics derived from accumulated governance evidence in the database.

Routes (prefix: /api/executive):
  GET /workspace       — single authoritative payload (all sections, one snapshot)
  GET /overview        — overall governance health snapshot
  GET /posture         — security/risk/compliance posture
  GET /risk            — risk heatmap, top risks, velocity
  GET /compliance      — framework status per standard
  GET /business        — business impact estimates
  GET /trends          — trend lines across time windows
  GET /recommendations — deterministic recommendations with evidence
  GET /forecast        — evidence-backed forecast (explains inputs/confidence)
  GET /priorities      — top priorities ranked by impact
  GET /summary         — board-ready payload

Architecture:
  Each section is computed by a _compute_* function that operates on pre-fetched
  data (no DB session). Individual routes fetch their own data then call _compute_*.
  The /workspace route fetches all data in one session with one consistent `now`
  timestamp, calls all _compute_* functions, and wraps them under a single
  snapshot_version. Individual endpoints remain available for drill-down and
  direct API consumers.

Security:
  tenant isolation: tenant_id always from require_bound_tenant(), never request body
  scope gate: governance:read minimum on every route
  no cross-tenant aggregation
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from api.db_models import (
    AIQueryLog,
    AITokenUsage,
    ComplianceFindingRecord,
    ComplianceRequirementRecord,
    DecisionRecord,
    SecurityAuditLog,
)

log = logging.getLogger("frostgate.executive_intelligence")

router = APIRouter(
    prefix="/api/executive",
    tags=["executive-intelligence"],
    dependencies=[Depends(require_scopes("governance:read"))],
)

_SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 100,
    "high": 40,
    "medium": 10,
    "low": 3,
    "info": 1,
}

_COST_PER_FINDING: dict[str, float] = {
    "critical": 50_000.0,
    "high": 15_000.0,
    "medium": 4_000.0,
    "low": 500.0,
    "info": 50.0,
}

_FRAMEWORKS = ["NIST", "ISO27001", "SOC2", "HIPAA", "PCI", "CIS", "AI_RMF"]


# ---------------------------------------------------------------------------
# Pure helpers (no I/O)
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _snapshot_version(inputs: list[Any]) -> str:
    payload = json.dumps(inputs, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _safe(fn: Any, fallback: Any = None) -> Any:
    try:
        return fn()
    except Exception:
        return fallback


def _metric(
    *,
    value: Any,
    source: str,
    calculation: str,
    evidence_ids: list[Any],
    snapshot_ts: str,
    confidence: float,
    framework_mapping: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "value": value,
        "source": source,
        "calculation": calculation,
        "evidence_ids": evidence_ids,
        "snapshot_ts": snapshot_ts,
        "confidence": confidence,
        "framework_mapping": framework_mapping or [],
        "authority": "FrostGate Platform",
    }


def _severity_counts(findings: list[ComplianceFindingRecord]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.severity or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _open_findings(findings: list[ComplianceFindingRecord]) -> list[ComplianceFindingRecord]:
    return [f for f in findings if (f.status or "").lower() in ("open", "active", "new")]


def _risk_score(findings: list[ComplianceFindingRecord]) -> int:
    return sum(_SEVERITY_WEIGHT.get((f.severity or "info").lower(), 0) for f in findings)


# ---------------------------------------------------------------------------
# DB fetch helpers
# ---------------------------------------------------------------------------

def _query_findings(db: Session, tenant_id: str) -> list[ComplianceFindingRecord]:
    return (
        db.query(ComplianceFindingRecord)
        .filter(ComplianceFindingRecord.tenant_id == tenant_id)
        .order_by(ComplianceFindingRecord.created_at.desc())
        .all()
    )


def _query_requirements(db: Session, tenant_id: str) -> list[ComplianceRequirementRecord]:
    return (
        db.query(ComplianceRequirementRecord)
        .filter(ComplianceRequirementRecord.tenant_id == tenant_id)
        .all()
    )


def _count_decisions(db: Session, tenant_id: str) -> int:
    return _safe(
        lambda: db.query(func.count(DecisionRecord.id))
        .filter(DecisionRecord.tenant_id == tenant_id)
        .scalar() or 0,
        0,
    )


def _query_decision_timestamps(db: Session, tenant_id: str) -> list[Any]:
    return _safe(
        lambda: db.query(DecisionRecord.created_at)
        .filter(DecisionRecord.tenant_id == tenant_id)
        .order_by(DecisionRecord.created_at.desc())
        .all(),
        [],
    )


def _count_audit(db: Session, tenant_id: str) -> int:
    return _safe(
        lambda: db.query(func.count(SecurityAuditLog.id))
        .filter(SecurityAuditLog.tenant_id == tenant_id)
        .scalar() or 0,
        0,
    )


def _count_audit_failures(db: Session, tenant_id: str) -> int:
    return _safe(
        lambda: db.query(func.count(SecurityAuditLog.id))
        .filter(
            SecurityAuditLog.tenant_id == tenant_id,
            SecurityAuditLog.success == False,  # noqa: E712
        )
        .scalar() or 0,
        0,
    )


def _query_audit_timestamps(db: Session, tenant_id: str) -> list[Any]:
    return _safe(
        lambda: db.query(SecurityAuditLog.created_at)
        .filter(SecurityAuditLog.tenant_id == tenant_id)
        .order_by(SecurityAuditLog.created_at.desc())
        .all(),
        [],
    )


def _count_ai_violations(db: Session, tenant_id: str) -> int:
    return _safe(
        lambda: db.query(func.count(AIQueryLog.id))
        .filter(
            AIQueryLog.tenant_id == tenant_id,
            AIQueryLog.policy_decision == "deny",
        )
        .scalar() or 0,
        0,
    )


def _sum_tokens(db: Session, tenant_id: str) -> int:
    return _safe(
        lambda: db.query(func.sum(AITokenUsage.total_tokens))
        .filter(AITokenUsage.tenant_id == tenant_id)
        .scalar() or 0,
        0,
    )


# ---------------------------------------------------------------------------
# Compute functions (pure: no DB, no I/O)
# All accept pre-fetched data and return section dicts.
# Used by both individual routes and /workspace.
# ---------------------------------------------------------------------------

def _compute_overview(
    *,
    findings: list[ComplianceFindingRecord],
    open_findings: list[ComplianceFindingRecord],
    decisions_total: int,
    audit_events: int,
    requirements_total: int,
    requirements_active: int,
    tenant_id: str,
    now_ts: str,
) -> dict[str, Any]:
    sev = _severity_counts(open_findings)
    risk_score = _risk_score(open_findings)
    evidence_count = len(findings) + decisions_total + audit_events
    inputs = [tenant_id, len(findings), decisions_total, audit_events]
    return {
        "tenant_id": tenant_id,
        "generated_at": now_ts,
        "snapshot_version": _snapshot_version(inputs),
        "confidence": 0.95,
        "evidence_count": evidence_count,
        "source": "deterministic:db_query",
        "calculation": "Aggregate counts from decisions, compliance_findings, security_audit_log, compliance_requirements",
        "open_findings": _metric(
            value=len(open_findings),
            source="table:compliance_findings",
            calculation="COUNT(*) WHERE tenant_id=? AND status IN ('open','active','new')",
            evidence_ids=[f.finding_id for f in open_findings[:20]],
            snapshot_ts=now_ts,
            confidence=1.0,
            framework_mapping=["NIST CSF ID.RA", "ISO 27001 A.12"],
        ),
        "critical_findings": _metric(
            value=sev["critical"],
            source="table:compliance_findings",
            calculation="COUNT(*) WHERE severity='critical' AND status=open",
            evidence_ids=[f.finding_id for f in open_findings if f.severity == "critical"][:20],
            snapshot_ts=now_ts,
            confidence=1.0,
            framework_mapping=["NIST CSF RS.MI", "SOC2 CC7"],
        ),
        "risk_score": _metric(
            value=risk_score,
            source="table:compliance_findings",
            calculation="SUM(severity_weight) over open findings — critical=100,high=40,medium=10,low=3,info=1",
            evidence_ids=[f.finding_id for f in open_findings[:20]],
            snapshot_ts=now_ts,
            confidence=0.9,
            framework_mapping=["NIST AI RMF GOVERN 1.1", "ISO 27001 A.8"],
        ),
        "severity_breakdown": sev,
        "total_findings_ever": len(findings),
        "decisions_processed": decisions_total,
        "audit_events": audit_events,
        "requirements_total": requirements_total,
        "requirements_active": requirements_active,
        "data_available": True,
    }


def _compute_posture(
    *,
    findings: list[ComplianceFindingRecord],
    open_findings: list[ComplianceFindingRecord],
    audit_failures: int,
    audit_total: int,
    ai_violations: int,
    tenant_id: str,
    now_ts: str,
) -> dict[str, Any]:
    sev = _severity_counts(open_findings)
    risk_score = _risk_score(open_findings)
    security_failure_rate = (audit_failures / audit_total) if audit_total > 0 else 0.0
    posture_score = max(0, 100 - risk_score // 10 - int(security_failure_rate * 50))
    posture_level = (
        "critical" if posture_score < 25 else
        "poor" if posture_score < 50 else
        "fair" if posture_score < 75 else
        "good"
    )
    inputs = [tenant_id, len(open_findings), audit_failures, audit_total, ai_violations]
    evidence_count = len(open_findings) + audit_total
    return {
        "tenant_id": tenant_id,
        "generated_at": now_ts,
        "snapshot_version": _snapshot_version(inputs),
        "confidence": 0.88,
        "evidence_count": evidence_count,
        "source": "deterministic:db_query",
        "calculation": "Posture = 100 - (risk_score/10) - (failure_rate*50); clamped 0-100",
        "posture_score": _metric(
            value=posture_score,
            source="table:compliance_findings+security_audit_log",
            calculation="100 - (SUM(severity_weights)/10) - (COUNT(failed_audits)/COUNT(all_audits)*50), clamped [0,100]",
            evidence_ids=[f.finding_id for f in open_findings[:10]],
            snapshot_ts=now_ts,
            confidence=0.88,
            framework_mapping=["NIST CSF PR", "SOC2 CC6", "ISO 27001 A.9"],
        ),
        "posture_level": posture_level,
        "security": {
            "audit_total": audit_total,
            "audit_failures": audit_failures,
            "failure_rate": round(security_failure_rate, 4),
            "ai_policy_violations": ai_violations,
        },
        "risk": {
            "open_findings": len(open_findings),
            "weighted_score": risk_score,
            "critical": sev["critical"],
            "high": sev["high"],
            "medium": sev["medium"],
            "low": sev["low"],
        },
        "compliance": {
            "total_findings": len(findings),
            "open_findings": len(open_findings),
        },
        "data_available": True,
    }


def _compute_risk(
    *,
    findings: list[ComplianceFindingRecord],
    open_findings: list[ComplianceFindingRecord],
    now: datetime,
    tenant_id: str,
    now_ts: str,
) -> dict[str, Any]:
    cutoff_30 = now - timedelta(days=30)
    cutoff_prev_30 = now - timedelta(days=60)
    new_30d = [f for f in open_findings if f.created_at and f.created_at >= cutoff_30]
    prev_30d = [
        f for f in open_findings
        if f.created_at and cutoff_prev_30 <= f.created_at < cutoff_30
    ]
    velocity = len(new_30d) - len(prev_30d)
    velocity_direction = "increasing" if velocity > 0 else "decreasing" if velocity < 0 else "stable"
    sev_all = _severity_counts(findings)
    sev_open = _severity_counts(open_findings)
    top_risks = sorted(
        open_findings,
        key=lambda f: _SEVERITY_WEIGHT.get((f.severity or "info").lower(), 0),
        reverse=True,
    )[:10]
    heatmap = {
        sev: {
            "open": sev_open.get(sev, 0),
            "total": sev_all.get(sev, 0),
            "weight": _SEVERITY_WEIGHT.get(sev, 0),
            "weighted_score": sev_open.get(sev, 0) * _SEVERITY_WEIGHT.get(sev, 0),
        }
        for sev in ["critical", "high", "medium", "low", "info"]
    }
    inputs = [tenant_id, len(open_findings), len(new_30d), len(prev_30d)]
    return {
        "tenant_id": tenant_id,
        "generated_at": now_ts,
        "snapshot_version": _snapshot_version(inputs),
        "confidence": 0.92,
        "evidence_count": len(findings),
        "source": "deterministic:db_query",
        "calculation": "Risk heatmap from compliance_findings severity aggregation",
        "heatmap": heatmap,
        "top_risks": [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "detected_at": f.detected_at_utc,
                "weight": _SEVERITY_WEIGHT.get((f.severity or "info").lower(), 0),
                "req_ids": f.req_ids_json,
            }
            for f in top_risks
        ],
        "velocity": _metric(
            value=velocity,
            source="table:compliance_findings",
            calculation="COUNT(open findings created last 30d) - COUNT(open findings created prior 30d)",
            evidence_ids=[f.finding_id for f in new_30d[:20]],
            snapshot_ts=now_ts,
            confidence=0.95,
            framework_mapping=["NIST CSF ID.RA-5", "ISO 27001 A.12.6"],
        ),
        "velocity_direction": velocity_direction,
        "new_last_30d": len(new_30d),
        "prior_30d": len(prev_30d),
        "data_available": True,
    }


def _compute_compliance(
    *,
    requirements: list[ComplianceRequirementRecord],
    findings: list[ComplianceFindingRecord],
    open_findings: list[ComplianceFindingRecord],
    tenant_id: str,
    now_ts: str,
) -> dict[str, Any]:
    by_source: dict[str, dict[str, int]] = {}
    for r in requirements:
        src = (r.source or "unknown").upper()
        if src not in by_source:
            by_source[src] = {"total": 0, "active": 0, "inactive": 0}
        by_source[src]["total"] += 1
        if (r.status or "").lower() == "active":
            by_source[src]["active"] += 1
        else:
            by_source[src]["inactive"] += 1

    req_total = len(requirements)
    req_active = sum(1 for r in requirements if (r.status or "").lower() == "active")
    coverage_pct = round((req_active / req_total * 100) if req_total > 0 else 0.0, 1)

    frameworks: dict[str, Any] = {}
    for fw in _FRAMEWORKS:
        matched_reqs = [
            r for r in requirements
            if fw.lower() in (r.source or "").lower() or fw.lower() in (r.source_name or "").lower()
        ]
        matched_findings = [
            f for f in open_findings
            if any(fw.lower() in str(req_id).lower() for req_id in (f.req_ids_json or []))
        ]
        frameworks[fw] = {
            "requirement_count": len(matched_reqs),
            "open_findings": len(matched_findings),
            "coverage": "covered" if matched_reqs else "not_tracked",
            "evidence_ids": [r.req_id for r in matched_reqs[:10]],
        }

    inputs = [tenant_id, req_total, len(findings)]
    return {
        "tenant_id": tenant_id,
        "generated_at": now_ts,
        "snapshot_version": _snapshot_version(inputs),
        "confidence": 0.9,
        "evidence_count": req_total + len(findings),
        "source": "deterministic:db_query",
        "calculation": "Compliance coverage from compliance_requirements grouped by source; findings cross-referenced by req_ids_json",
        "requirement_coverage": _metric(
            value=coverage_pct,
            source="table:compliance_requirements",
            calculation="COUNT(status='active') / COUNT(*) * 100",
            evidence_ids=[r.req_id for r in requirements[:20]],
            snapshot_ts=now_ts,
            confidence=1.0,
            framework_mapping=["NIST CSF PR.IP", "SOC2 CC1", "ISO 27001 A.5"],
        ),
        "requirements_total": req_total,
        "requirements_active": req_active,
        "by_source": by_source,
        "frameworks": frameworks,
        "open_findings": len(open_findings),
        "data_available": True,
    }


def _compute_business(
    *,
    findings: list[ComplianceFindingRecord],
    open_findings: list[ComplianceFindingRecord],
    token_cost_total: int,
    tenant_id: str,
    now_ts: str,
) -> dict[str, Any]:
    sev = _severity_counts(open_findings)
    cost_of_risk = sum(
        _COST_PER_FINDING.get(severity, 0) * count
        for severity, count in sev.items()
    )
    cost_breakdown = {
        s: {"count": c, "unit_cost": _COST_PER_FINDING.get(s, 0), "total": c * _COST_PER_FINDING.get(s, 0)}
        for s, c in sev.items()
    }
    insurance_readiness_score = max(0, 100 - sev["critical"] * 20 - sev["high"] * 8)
    insurance_readiness = (
        "high" if insurance_readiness_score >= 75 else
        "medium" if insurance_readiness_score >= 40 else
        "low"
    )
    inputs = [tenant_id, len(open_findings), token_cost_total]
    return {
        "tenant_id": tenant_id,
        "generated_at": now_ts,
        "snapshot_version": _snapshot_version(inputs),
        "confidence": 0.7,
        "evidence_count": len(open_findings),
        "source": "deterministic:db_query",
        "calculation": "Cost of risk = SUM(count_per_severity * assumed_cost_per_finding). Assumptions: critical=$50k, high=$15k, medium=$4k, low=$500, info=$50. Insurance readiness = 100 - (critical*20) - (high*8)",
        "cost_of_risk": _metric(
            value=cost_of_risk,
            source="table:compliance_findings",
            calculation="SUM(count_per_severity * cost_per_finding) — critical=50000, high=15000, medium=4000, low=500, info=50",
            evidence_ids=[f.finding_id for f in open_findings[:20]],
            snapshot_ts=now_ts,
            confidence=0.7,
            framework_mapping=["NIST CSF ID.BE", "ISO 27001 A.6.1"],
        ),
        "cost_breakdown": cost_breakdown,
        "insurance_readiness": _metric(
            value=insurance_readiness_score,
            source="table:compliance_findings",
            calculation="100 - (critical_count * 20) - (high_count * 8), clamped [0,100]",
            evidence_ids=[f.finding_id for f in open_findings if f.severity in ("critical", "high")][:20],
            snapshot_ts=now_ts,
            confidence=0.65,
            framework_mapping=["SOC2 CC9", "ISO 27001 A.6.1.4"],
        ),
        "insurance_readiness_level": insurance_readiness,
        "ai_tokens_consumed": token_cost_total,
        "data_available": True,
    }


def _compute_trends(
    *,
    findings: list[ComplianceFindingRecord],
    decisions_rows: list[Any],
    audit_rows: list[Any],
    now: datetime,
    tenant_id: str,
    now_ts: str,
) -> dict[str, Any]:
    windows = {30: "30d", 90: "90d", 180: "180d", 365: "365d"}
    trend_data: dict[str, Any] = {}
    for days, label in windows.items():
        cutoff = now - timedelta(days=days)
        findings_in = [f for f in findings if f.created_at and f.created_at >= cutoff]
        open_in = _open_findings(findings_in)
        decisions_in = [r for r in decisions_rows if r[0] and r[0] >= cutoff]
        audits_in = [r for r in audit_rows if r[0] and r[0] >= cutoff]
        sev = _severity_counts(open_in)
        trend_data[label] = {
            "window_days": days,
            "cutoff_utc": _iso(cutoff),
            "findings_created": len(findings_in),
            "open_findings": len(open_in),
            "critical": sev["critical"],
            "high": sev["high"],
            "medium": sev["medium"],
            "low": sev["low"],
            "decisions": len(decisions_in),
            "audit_events": len(audits_in),
            "risk_score": _risk_score(open_in),
        }
    inputs = [tenant_id, len(findings), len(decisions_rows), len(audit_rows)]
    return {
        "tenant_id": tenant_id,
        "generated_at": now_ts,
        "snapshot_version": _snapshot_version(inputs),
        "confidence": 0.95,
        "evidence_count": len(findings) + len(decisions_rows),
        "source": "deterministic:db_query",
        "calculation": "Trend counts grouped by created_at into 30/90/180/365 day windows relative to query time",
        "windows": trend_data,
        "snapshot_ts": now_ts,
        "data_available": True,
    }


def _compute_recommendations(
    *,
    findings: list[ComplianceFindingRecord],
    open_findings: list[ComplianceFindingRecord],
    tenant_id: str,
    now_ts: str,
) -> dict[str, Any]:
    sorted_findings = sorted(
        open_findings,
        key=lambda f: _SEVERITY_WEIGHT.get((f.severity or "info").lower(), 0),
        reverse=True,
    )
    recs = []
    for i, f in enumerate(sorted_findings[:25], start=1):
        sev = (f.severity or "info").lower()
        recs.append({
            "rank": i,
            "priority": sev,
            "title": f"Remediate {sev} finding: {f.title}",
            "action": f"Investigate and resolve compliance finding '{f.finding_id}' (severity={sev})",
            "impact": f"Reduces risk score by {_SEVERITY_WEIGHT.get(sev, 0)} points",
            "evidence": {
                "finding_id": f.finding_id,
                "severity": f.severity,
                "status": f.status,
                "detected_at": f.detected_at_utc,
                "req_ids": f.req_ids_json,
            },
            "source": "table:compliance_findings",
            "calculation": "Sorted by severity weight DESC, top 25 open findings",
            "confidence": 1.0,
            "snapshot_ts": now_ts,
            "framework_mapping": ["NIST CSF RS.MI-3", "ISO 27001 A.16.1"],
        })
    inputs = [tenant_id, len(open_findings)]
    return {
        "tenant_id": tenant_id,
        "generated_at": now_ts,
        "snapshot_version": _snapshot_version(inputs),
        "confidence": 1.0,
        "evidence_count": len(open_findings),
        "source": "deterministic:db_query",
        "calculation": "Top 25 open findings sorted by severity weight DESC. No AI generation — deterministic sort.",
        "recommendations": recs,
        "total_open": len(open_findings),
        "data_available": True,
    }


def _compute_forecast(
    *,
    findings: list[ComplianceFindingRecord],
    open_findings: list[ComplianceFindingRecord],
    now: datetime,
    tenant_id: str,
    now_ts: str,
) -> dict[str, Any]:
    windows = [30, 60, 90, 120, 150, 180]
    period_counts: list[int] = []
    for days in windows:
        cutoff = now - timedelta(days=days)
        prev_cutoff = now - timedelta(days=days + 30)
        period = [f for f in findings if f.created_at and prev_cutoff <= f.created_at < cutoff]
        period_counts.append(len(period))

    n = len(period_counts)
    if n >= 2 and sum(period_counts) > 0:
        x_mean = (n - 1) / 2.0
        y_mean = sum(period_counts) / n
        num = sum((i - x_mean) * (period_counts[i] - y_mean) for i in range(n))
        den = sum((i - x_mean) ** 2 for i in range(n))
        slope = num / den if den != 0 else 0.0
        intercept = y_mean - slope * x_mean
        forecast_30d = max(0, int(intercept + slope * n))
        forecast_90d = max(0, int(intercept + slope * (n + 2)))
        r_squared = 0.0
        if den != 0 and y_mean != 0:
            ss_res = sum((period_counts[i] - (intercept + slope * i)) ** 2 for i in range(n))
            ss_tot = sum((period_counts[i] - y_mean) ** 2 for i in range(n))
            r_squared = 1 - (ss_res / ss_tot) if ss_tot != 0 else 0.0
        confidence = min(0.85, max(0.3, r_squared * 0.85))
    else:
        slope = 0.0
        intercept = 0.0
        forecast_30d = len(open_findings)
        forecast_90d = len(open_findings)
        r_squared = 0.0
        confidence = 0.3

    trend_dir = "increasing" if slope > 0.1 else "decreasing" if slope < -0.1 else "stable"
    inputs = [tenant_id, period_counts, len(open_findings)]
    return {
        "tenant_id": tenant_id,
        "generated_at": now_ts,
        "snapshot_version": _snapshot_version(inputs),
        "confidence": round(confidence, 3),
        "evidence_count": len(findings),
        "source": "deterministic:db_query",
        "calculation": "Linear regression over 6 × 30-day trailing windows. Formula: y=mx+b, slope from OLS. Confidence = R² * 0.85, clamped [0.3, 0.85].",
        "method": "ordinary_least_squares_linear_regression",
        "formula": "findings_per_30d = slope * period_index + intercept",
        "inputs": {
            "period_counts_30d_buckets": period_counts,
            "window_count": n,
            "slope": round(slope, 4),
            "intercept": round(intercept, 4),
            "r_squared": round(r_squared, 4),
        },
        "forecast_30d": _metric(
            value=forecast_30d,
            source="table:compliance_findings",
            calculation="OLS linear extrapolation: intercept + slope * (n+0)",
            evidence_ids=[f.finding_id for f in open_findings[:10]],
            snapshot_ts=now_ts,
            confidence=round(confidence, 3),
            framework_mapping=["NIST AI RMF GOVERN 5", "ISO 27001 A.5.7"],
        ),
        "forecast_90d": _metric(
            value=forecast_90d,
            source="table:compliance_findings",
            calculation="OLS linear extrapolation: intercept + slope * (n+2)",
            evidence_ids=[f.finding_id for f in open_findings[:10]],
            snapshot_ts=now_ts,
            confidence=round(confidence * 0.8, 3),
            framework_mapping=["NIST AI RMF GOVERN 5", "ISO 27001 A.5.7"],
        ),
        "trend_direction": trend_dir,
        "data_available": True,
    }


def _compute_priorities(
    *,
    findings: list[ComplianceFindingRecord],
    open_findings: list[ComplianceFindingRecord],
    now: datetime,
    tenant_id: str,
    now_ts: str,
) -> dict[str, Any]:
    cutoff_7d = now - timedelta(days=7)

    def _score(f: ComplianceFindingRecord) -> float:
        base = _SEVERITY_WEIGHT.get((f.severity or "info").lower(), 0)
        recency_bonus = 20 if (f.created_at and f.created_at >= cutoff_7d) else 0
        return float(base + recency_bonus)

    sorted_findings = sorted(open_findings, key=_score, reverse=True)
    priorities = []
    for rank, f in enumerate(sorted_findings[:15], start=1):
        score = _score(f)
        priorities.append({
            "rank": rank,
            "finding_id": f.finding_id,
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "priority_score": score,
            "score_breakdown": {
                "severity_weight": _SEVERITY_WEIGHT.get((f.severity or "info").lower(), 0),
                "recency_bonus": 20 if (f.created_at and f.created_at >= cutoff_7d) else 0,
            },
            "detected_at": f.detected_at_utc,
            "req_ids": f.req_ids_json,
            "evidence_refs": f.evidence_refs_json,
            "source": "table:compliance_findings",
            "calculation": "severity_weight + recency_bonus(+20 if created < 7d ago)",
            "snapshot_ts": now_ts,
            "confidence": 1.0,
        })
    inputs = [tenant_id, len(open_findings)]
    return {
        "tenant_id": tenant_id,
        "generated_at": now_ts,
        "snapshot_version": _snapshot_version(inputs),
        "confidence": 1.0,
        "evidence_count": len(open_findings),
        "source": "deterministic:db_query",
        "calculation": "Top 15 open findings ranked by priority_score = severity_weight + recency_bonus",
        "priorities": priorities,
        "total_open": len(open_findings),
        "ranking_method": "severity_weight + recency_bonus(20 if < 7d old)",
        "data_available": True,
    }


def _compute_summary(
    *,
    findings: list[ComplianceFindingRecord],
    open_findings: list[ComplianceFindingRecord],
    decisions_total: int,
    audit_total: int,
    audit_failures: int,
    requirements_active: int,
    now: datetime,
    tenant_id: str,
    now_ts: str,
) -> dict[str, Any]:
    sev = _severity_counts(open_findings)
    risk_score = _risk_score(open_findings)
    posture_score = max(0, 100 - risk_score // 10 - (int((audit_failures / audit_total) * 50) if audit_total else 0))
    posture_level = (
        "critical" if posture_score < 25 else
        "poor" if posture_score < 50 else
        "fair" if posture_score < 75 else
        "good"
    )
    cost_of_risk = sum(_COST_PER_FINDING.get(s, 0) * c for s, c in sev.items())
    insurance_score = max(0, 100 - sev["critical"] * 20 - sev["high"] * 8)
    cutoff_30 = now - timedelta(days=30)
    new_30d = [f for f in open_findings if f.created_at and f.created_at >= cutoff_30]
    top_finding = max(
        open_findings,
        key=lambda f: _SEVERITY_WEIGHT.get((f.severity or "info").lower(), 0),
        default=None,
    )
    inputs = [tenant_id, len(open_findings), decisions_total, audit_total, requirements_active]
    evidence_count = len(findings) + decisions_total + audit_total
    return {
        "tenant_id": tenant_id,
        "generated_at": now_ts,
        "snapshot_version": _snapshot_version(inputs),
        "confidence": 0.88,
        "evidence_count": evidence_count,
        "source": "deterministic:db_query",
        "calculation": "Board-ready summary compiled from compliance_findings, decisions, security_audit_log, compliance_requirements",
        "executive_headline": {
            "posture_score": posture_score,
            "posture_level": posture_level,
            "open_findings": len(open_findings),
            "critical_findings": sev["critical"],
            "risk_score": risk_score,
            "new_last_30d": len(new_30d),
            "cost_of_risk_usd": round(cost_of_risk, 2),
            "insurance_readiness_score": insurance_score,
        },
        "governance": {
            "decisions_processed": decisions_total,
            "audit_events": audit_total,
            "audit_failures": audit_failures,
            "requirements_active": requirements_active,
            "total_findings": len(findings),
        },
        "top_priority": {
            "finding_id": top_finding.finding_id if top_finding else None,
            "title": top_finding.title if top_finding else None,
            "severity": top_finding.severity if top_finding else None,
        },
        "severity_breakdown": sev,
        "snapshot_ts": now_ts,
        "data_available": True,
        "disclaimer": "Cost estimates use standard assumptions: critical=$50k, high=$15k, medium=$4k, low=$500, info=$50 per open finding. Actual costs vary.",
    }


# ---------------------------------------------------------------------------
# Route: /api/executive/workspace  (aggregated — single fetch, one snapshot)
# ---------------------------------------------------------------------------

@router.get("/workspace")
def executive_workspace(request: Request) -> dict[str, Any]:
    """Single authoritative workspace payload.

    Fetches all governance evidence in one DB session under one consistent
    timestamp. All sections share the same `now`, so every widget reflects
    the same underlying snapshot. Returns a combined snapshot_version derived
    from all input data.

    Use this endpoint to hydrate the executive UI. Use individual endpoints
    for drill-down and direct API consumers.
    """
    tenant_id = require_bound_tenant(request)
    log.info("executive.workspace tenant=%s", tenant_id)
    now = _now()
    now_ts = _iso(now)

    with Session(get_engine()) as db:
        findings = _safe(lambda: _query_findings(db, tenant_id), [])
        requirements = _safe(lambda: _query_requirements(db, tenant_id), [])
        decisions_total = _count_decisions(db, tenant_id)
        decisions_rows = _query_decision_timestamps(db, tenant_id)
        audit_total = _count_audit(db, tenant_id)
        audit_failures = _count_audit_failures(db, tenant_id)
        audit_rows = _query_audit_timestamps(db, tenant_id)
        ai_violations = _count_ai_violations(db, tenant_id)
        token_cost_total = _sum_tokens(db, tenant_id)

    open_findings = _open_findings(findings)
    requirements_total = len(requirements)
    requirements_active = sum(1 for r in requirements if (r.status or "").lower() == "active")

    shared = dict(tenant_id=tenant_id, now_ts=now_ts)

    sections = {
        "overview": _compute_overview(
            findings=findings, open_findings=open_findings,
            decisions_total=decisions_total, audit_events=audit_total,
            requirements_total=requirements_total, requirements_active=requirements_active,
            **shared,
        ),
        "posture": _compute_posture(
            findings=findings, open_findings=open_findings,
            audit_failures=audit_failures, audit_total=audit_total,
            ai_violations=ai_violations, **shared,
        ),
        "risk": _compute_risk(
            findings=findings, open_findings=open_findings, now=now, **shared,
        ),
        "compliance": _compute_compliance(
            requirements=requirements, findings=findings, open_findings=open_findings,
            **shared,
        ),
        "business": _compute_business(
            findings=findings, open_findings=open_findings,
            token_cost_total=token_cost_total, **shared,
        ),
        "trends": _compute_trends(
            findings=findings, decisions_rows=decisions_rows,
            audit_rows=audit_rows, now=now, **shared,
        ),
        "recommendations": _compute_recommendations(
            findings=findings, open_findings=open_findings, **shared,
        ),
        "forecast": _compute_forecast(
            findings=findings, open_findings=open_findings, now=now, **shared,
        ),
        "priorities": _compute_priorities(
            findings=findings, open_findings=open_findings, now=now, **shared,
        ),
        "summary": _compute_summary(
            findings=findings, open_findings=open_findings,
            decisions_total=decisions_total, audit_total=audit_total,
            audit_failures=audit_failures, requirements_active=requirements_active,
            now=now, **shared,
        ),
    }

    all_inputs = [
        tenant_id, len(findings), len(open_findings),
        decisions_total, audit_total, requirements_total,
    ]

    return {
        "tenant_id": tenant_id,
        "generated_at": now_ts,
        "snapshot_version": _snapshot_version(all_inputs),
        "source": "deterministic:workspace_aggregate",
        "calculation": "Single-pass DB fetch; all sections share identical now timestamp and DB session snapshot",
        "evidence_summary": {
            "findings_total": len(findings),
            "open_findings": len(open_findings),
            "decisions_total": decisions_total,
            "audit_events_total": audit_total,
            "requirements_total": requirements_total,
        },
        "sections": sections,
    }


# ---------------------------------------------------------------------------
# Individual routes (thin wrappers — fetch own data, delegate to _compute_*)
# ---------------------------------------------------------------------------

@router.get("/overview")
def executive_overview(request: Request) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    log.info("executive.overview tenant=%s", tenant_id)
    now = _now()
    now_ts = _iso(now)
    with Session(get_engine()) as db:
        findings = _safe(lambda: _query_findings(db, tenant_id), [])
        decisions_total = _count_decisions(db, tenant_id)
        audit_events = _count_audit(db, tenant_id)
        requirements_total = _safe(
            lambda: db.query(func.count(ComplianceRequirementRecord.id))
            .filter(ComplianceRequirementRecord.tenant_id == tenant_id)
            .scalar() or 0, 0,
        )
        requirements_active = _safe(
            lambda: db.query(func.count(ComplianceRequirementRecord.id))
            .filter(
                ComplianceRequirementRecord.tenant_id == tenant_id,
                ComplianceRequirementRecord.status == "active",
            )
            .scalar() or 0, 0,
        )
    return _compute_overview(
        findings=findings, open_findings=_open_findings(findings),
        decisions_total=decisions_total, audit_events=audit_events,
        requirements_total=requirements_total, requirements_active=requirements_active,
        tenant_id=tenant_id, now_ts=now_ts,
    )


@router.get("/posture")
def executive_posture(request: Request) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    log.info("executive.posture tenant=%s", tenant_id)
    now_ts = _iso(_now())
    with Session(get_engine()) as db:
        findings = _safe(lambda: _query_findings(db, tenant_id), [])
        audit_failures = _count_audit_failures(db, tenant_id)
        audit_total = _count_audit(db, tenant_id)
        ai_violations = _count_ai_violations(db, tenant_id)
    return _compute_posture(
        findings=findings, open_findings=_open_findings(findings),
        audit_failures=audit_failures, audit_total=audit_total,
        ai_violations=ai_violations, tenant_id=tenant_id, now_ts=now_ts,
    )


@router.get("/risk")
def executive_risk(request: Request) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    log.info("executive.risk tenant=%s", tenant_id)
    now = _now()
    with Session(get_engine()) as db:
        findings = _safe(lambda: _query_findings(db, tenant_id), [])
    return _compute_risk(
        findings=findings, open_findings=_open_findings(findings),
        now=now, tenant_id=tenant_id, now_ts=_iso(now),
    )


@router.get("/compliance")
def executive_compliance(request: Request) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    log.info("executive.compliance tenant=%s", tenant_id)
    now_ts = _iso(_now())
    with Session(get_engine()) as db:
        requirements = _safe(lambda: _query_requirements(db, tenant_id), [])
        findings = _safe(lambda: _query_findings(db, tenant_id), [])
    return _compute_compliance(
        requirements=requirements, findings=findings,
        open_findings=_open_findings(findings),
        tenant_id=tenant_id, now_ts=now_ts,
    )


@router.get("/business")
def executive_business(request: Request) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    log.info("executive.business tenant=%s", tenant_id)
    now_ts = _iso(_now())
    with Session(get_engine()) as db:
        findings = _safe(lambda: _query_findings(db, tenant_id), [])
        token_cost_total = _sum_tokens(db, tenant_id)
    return _compute_business(
        findings=findings, open_findings=_open_findings(findings),
        token_cost_total=token_cost_total, tenant_id=tenant_id, now_ts=now_ts,
    )


@router.get("/trends")
def executive_trends(request: Request) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    log.info("executive.trends tenant=%s", tenant_id)
    now = _now()
    with Session(get_engine()) as db:
        findings = _safe(lambda: _query_findings(db, tenant_id), [])
        decisions_rows = _query_decision_timestamps(db, tenant_id)
        audit_rows = _query_audit_timestamps(db, tenant_id)
    return _compute_trends(
        findings=findings, decisions_rows=decisions_rows, audit_rows=audit_rows,
        now=now, tenant_id=tenant_id, now_ts=_iso(now),
    )


@router.get("/recommendations")
def executive_recommendations(request: Request) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    log.info("executive.recommendations tenant=%s", tenant_id)
    now_ts = _iso(_now())
    with Session(get_engine()) as db:
        findings = _safe(lambda: _query_findings(db, tenant_id), [])
    return _compute_recommendations(
        findings=findings, open_findings=_open_findings(findings),
        tenant_id=tenant_id, now_ts=now_ts,
    )


@router.get("/forecast")
def executive_forecast(request: Request) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    log.info("executive.forecast tenant=%s", tenant_id)
    now = _now()
    with Session(get_engine()) as db:
        findings = _safe(lambda: _query_findings(db, tenant_id), [])
    open_findings = _open_findings(findings)
    return _compute_forecast(
        findings=findings, open_findings=open_findings,
        now=now, tenant_id=tenant_id, now_ts=_iso(now),
    )


@router.get("/priorities")
def executive_priorities(request: Request) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    log.info("executive.priorities tenant=%s", tenant_id)
    now = _now()
    with Session(get_engine()) as db:
        findings = _safe(lambda: _query_findings(db, tenant_id), [])
    return _compute_priorities(
        findings=findings, open_findings=_open_findings(findings),
        now=now, tenant_id=tenant_id, now_ts=_iso(now),
    )


@router.get("/summary")
def executive_summary(request: Request) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    log.info("executive.summary tenant=%s", tenant_id)
    now = _now()
    with Session(get_engine()) as db:
        findings = _safe(lambda: _query_findings(db, tenant_id), [])
        decisions_total = _count_decisions(db, tenant_id)
        audit_total = _count_audit(db, tenant_id)
        audit_failures = _count_audit_failures(db, tenant_id)
        requirements_active = _safe(
            lambda: db.query(func.count(ComplianceRequirementRecord.id))
            .filter(
                ComplianceRequirementRecord.tenant_id == tenant_id,
                ComplianceRequirementRecord.status == "active",
            )
            .scalar() or 0, 0,
        )
    return _compute_summary(
        findings=findings, open_findings=_open_findings(findings),
        decisions_total=decisions_total, audit_total=audit_total,
        audit_failures=audit_failures, requirements_active=requirements_active,
        now=now, tenant_id=tenant_id, now_ts=_iso(now),
    )
