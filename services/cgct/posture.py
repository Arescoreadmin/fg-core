"""P0-11: CGCT Posture Computation Service.

Computes governance posture by aggregating from authoritative source tables only.
No new trust/cert/risk/evidence engines are built here.

Authority sources:
  - TIM: FaTimTrustSnapshot   — trust_score, risk_level, open_drift_count
  - CLM: FaClmCert            — cert_score (certified_count / total)
  - Verification: FaVerificationBundle — evidence_score (coverage_status)

Entry points:
  compute_posture(db, *, tenant_id, engagement_id, actor="system") -> dict
  get_latest_posture(db, *, tenant_id, engagement_id) -> dict | None
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("frostgate.cgct.posture")

_SCHEMA_VERSION = "1.0"

# Coverage status → evidence_score mapping
_EVIDENCE_SCORE_MAP: dict[str, int] = {
    "complete": 100,
    "partial": 70,
    "missing_evidence": 40,
    "missing_report": 20,
    "tampered": 0,
}

# risk_level → risk_score mapping
_RISK_SCORE_MAP: dict[str, int] = {
    "low": 90,
    "medium": 70,
    "high": 40,
    "critical": 10,
    "unknown": 50,
}

# Governance health thresholds
_HEALTH_LEVELS = [
    (80, "healthy"),
    (60, "attention_required"),
    (40, "degraded"),
    (20, "at_risk"),
    (0, "critical"),
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id() -> str:
    return uuid.uuid4().hex


def _governance_health(overall_score: int) -> str:
    for threshold, label in _HEALTH_LEVELS:
        if overall_score >= threshold:
            return label
    return "critical"


def _fetch_tim_snapshot(db: Any, *, tenant_id: str, engagement_id: str) -> dict:
    """Fetch latest TIM trust snapshot for the tenant+engagement."""
    defaults = {
        "snapshot_id": None,
        "trust_score": 0,
        "risk_level": "unknown",
        "open_drift_count": 0,
        "drift_direction": "stable",
    }
    try:
        from api.db_models_tim import FaTimTrustSnapshot  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        q = (
            select(FaTimTrustSnapshot)
            .where(
                FaTimTrustSnapshot.tenant_id == tenant_id,
                FaTimTrustSnapshot.engagement_id == engagement_id,
            )
            .order_by(FaTimTrustSnapshot.evaluated_at.desc())
            .limit(1)
        )
        row = db.execute(q).scalar_one_or_none()
        if row is None:
            return defaults
        return {
            "snapshot_id": row.id,
            "trust_score": int(row.posture_score or 0),
            "risk_level": str(row.risk_level or "unknown"),
            "open_drift_count": int(row.open_drift_count or 0),
            "drift_direction": str(row.drift_direction or "stable"),
        }
    except Exception:
        log.debug("cgct.posture: TIM snapshot unavailable", exc_info=True)
        return defaults


def _fetch_clm_certs(db: Any, *, tenant_id: str, engagement_id: str) -> dict:
    """Fetch CLM cert stats for the tenant+engagement."""
    defaults = {
        "cert_score": 0,
        "total_cert_count": 0,
        "active_cert_count": 0,
        "latest_cert_id": None,
    }
    try:
        from api.db_models_clm import FaClmCert  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        q = select(FaClmCert).where(
            FaClmCert.tenant_id == tenant_id,
            FaClmCert.engagement_id == engagement_id,
        )
        rows = db.execute(q).scalars().all()
        if not rows:
            return defaults

        total = len(rows)
        certified = sum(
            1 for r in rows if r.lifecycle_status in ("certified", "approved")
        )
        active = sum(
            1
            for r in rows
            if r.lifecycle_status not in ("archived", "revoked", "superseded")
        )
        cert_score = round((certified / max(total, 1)) * 100)
        # most recently created cert
        latest_id = rows[0].id if rows else None

        return {
            "cert_score": cert_score,
            "total_cert_count": total,
            "active_cert_count": active,
            "latest_cert_id": latest_id,
        }
    except Exception:
        log.debug("cgct.posture: CLM certs unavailable", exc_info=True)
        return defaults


def _fetch_verification_bundle(db: Any, *, tenant_id: str, engagement_id: str) -> dict:
    """Fetch latest verification bundle for the tenant+engagement."""
    defaults = {
        "bundle_id": None,
        "evidence_score": 60,
        "coverage_status": "unknown",
    }
    try:
        from api.db_models_verification_bundle import FaVerificationBundle  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        q = (
            select(FaVerificationBundle)
            .where(
                FaVerificationBundle.tenant_id == tenant_id,
                FaVerificationBundle.engagement_id == engagement_id,
            )
            .order_by(FaVerificationBundle.generated_at.desc())
            .limit(1)
        )
        row = db.execute(q).scalar_one_or_none()
        if row is None:
            return defaults
        coverage = str(row.coverage_status or "unknown")
        score = _EVIDENCE_SCORE_MAP.get(coverage, 60)
        return {
            "bundle_id": row.id,
            "evidence_score": score,
            "coverage_status": coverage,
        }
    except Exception:
        log.debug("cgct.posture: verification bundle unavailable", exc_info=True)
        return defaults


def compute_posture(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    actor: str = "system",
) -> dict:
    """Compute and persist governance posture for (tenant_id, engagement_id).

    Aggregates from TIM, CLM, and Verification Bundle.
    Appends a new row to fg_cgct_posture_snapshots (caller must commit).
    Returns the full posture dict with score_inputs_json.
    """
    tim = _fetch_tim_snapshot(db, tenant_id=tenant_id, engagement_id=engagement_id)
    clm = _fetch_clm_certs(db, tenant_id=tenant_id, engagement_id=engagement_id)
    bundle = _fetch_verification_bundle(
        db, tenant_id=tenant_id, engagement_id=engagement_id
    )

    trust_score = tim["trust_score"]
    cert_score = clm["cert_score"]
    evidence_score = bundle["evidence_score"]
    risk_level = tim["risk_level"]
    risk_score = _RISK_SCORE_MAP.get(risk_level, 50)

    # Weighted composite: trust 35%, cert 25%, evidence 25%, risk 15%
    overall_score = int(
        trust_score * 0.35
        + cert_score * 0.25
        + evidence_score * 0.25
        + risk_score * 0.15
    )

    governance_health = _governance_health(overall_score)

    score_inputs = {
        "trust": {
            "score": trust_score,
            "source_id": tim["snapshot_id"],
            "weight": 0.35,
        },
        "cert": {
            "score": cert_score,
            "source_id": clm["latest_cert_id"],
            "weight": 0.25,
            "total_certs": clm["total_cert_count"],
            "active_certs": clm["active_cert_count"],
        },
        "evidence": {
            "score": evidence_score,
            "source_id": bundle["bundle_id"],
            "coverage_status": bundle["coverage_status"],
            "weight": 0.25,
        },
        "risk": {
            "score": risk_score,
            "risk_level": risk_level,
            "source_id": tim["snapshot_id"],
            "weight": 0.15,
        },
    }

    snapshot_id = _new_id()
    computed_at = _now_iso()

    try:
        from api.db_models_cgct import FaCgctPostureSnapshot  # noqa: PLC0415

        row = FaCgctPostureSnapshot(
            id=snapshot_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            overall_score=overall_score,
            governance_health=governance_health,
            trust_score=trust_score,
            cert_score=cert_score,
            risk_score=risk_score,
            evidence_score=evidence_score,
            open_drift_count=tim["open_drift_count"],
            active_cert_count=clm["active_cert_count"],
            total_cert_count=clm["total_cert_count"],
            trust_source_id=tim["snapshot_id"],
            cert_source_id=clm["latest_cert_id"],
            risk_source_id=tim["snapshot_id"],
            evidence_source_id=bundle["bundle_id"],
            score_inputs_json=json.dumps(score_inputs, default=str),
            actor_type=actor,
            computed_at=computed_at,
            schema_version=_SCHEMA_VERSION,
        )
        db.add(row)
    except Exception:
        log.warning("cgct.posture: failed to persist snapshot", exc_info=True)

    return {
        "snapshot_id": snapshot_id,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "overall_score": overall_score,
        "governance_health": governance_health,
        "trust_score": trust_score,
        "cert_score": cert_score,
        "risk_score": risk_score,
        "evidence_score": evidence_score,
        "risk_level": risk_level,
        "open_drift_count": tim["open_drift_count"],
        "active_cert_count": clm["active_cert_count"],
        "total_cert_count": clm["total_cert_count"],
        "trust_source_id": tim["snapshot_id"],
        "cert_source_id": clm["latest_cert_id"],
        "risk_source_id": tim["snapshot_id"],
        "evidence_source_id": bundle["bundle_id"],
        "score_inputs_json": score_inputs,
        "actor_type": actor,
        "computed_at": computed_at,
        "schema_version": _SCHEMA_VERSION,
        "version": "CGCTv1",
    }


def get_latest_posture(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
) -> dict | None:
    """Return the most recently computed posture snapshot, or None."""
    try:
        from api.db_models_cgct import FaCgctPostureSnapshot  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        q = (
            select(FaCgctPostureSnapshot)
            .where(
                FaCgctPostureSnapshot.tenant_id == tenant_id,
                FaCgctPostureSnapshot.engagement_id == engagement_id,
            )
            .order_by(FaCgctPostureSnapshot.computed_at.desc())
            .limit(1)
        )
        row = db.execute(q).scalar_one_or_none()
        if row is None:
            return None

        try:
            score_inputs = json.loads(row.score_inputs_json or "{}")
        except (ValueError, TypeError):
            score_inputs = {}

        return {
            "snapshot_id": row.id,
            "tenant_id": row.tenant_id,
            "engagement_id": row.engagement_id,
            "overall_score": row.overall_score,
            "governance_health": row.governance_health,
            "trust_score": row.trust_score,
            "cert_score": row.cert_score,
            "risk_score": row.risk_score,
            "evidence_score": row.evidence_score,
            "open_action_count": row.open_action_count,
            "open_drift_count": row.open_drift_count,
            "active_cert_count": row.active_cert_count,
            "total_cert_count": row.total_cert_count,
            "trust_source_id": row.trust_source_id,
            "cert_source_id": row.cert_source_id,
            "risk_source_id": row.risk_source_id,
            "evidence_source_id": row.evidence_source_id,
            "score_inputs_json": score_inputs,
            "actor_type": row.actor_type,
            "computed_at": row.computed_at,
            "schema_version": row.schema_version,
            "version": "CGCTv1",
        }
    except Exception:
        log.warning("cgct.posture: get_latest_posture failed", exc_info=True)
        return None
