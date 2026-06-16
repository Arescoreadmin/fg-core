"""P0-11: CGCT Aggregation Functions.

Read-only aggregations against existing authority tables.
No writes, no new engines, no AI recommendations.

All functions use graceful degradation — try/except throughout.

Functions:
  aggregate_decisions(db, *, tenant_id, engagement_id, limit=50) -> dict
  aggregate_drift(db, *, tenant_id, engagement_id) -> dict
  aggregate_risk(db, *, tenant_id, engagement_id) -> dict
  aggregate_evidence(db, *, tenant_id, engagement_id) -> dict
  aggregate_timeline(db, *, tenant_id, engagement_id, limit=100) -> dict
  aggregate_certifications(db, *, tenant_id, engagement_id) -> dict
  get_executive_view(db, *, tenant_id, engagement_id) -> dict
  get_authority_matrix(tenant_id) -> dict
  get_governance_graph(db, *, tenant_id) -> dict
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

log = logging.getLogger("frostgate.cgct.aggregators")


# ---------------------------------------------------------------------------
# aggregate_decisions
# ---------------------------------------------------------------------------


def aggregate_decisions(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    limit: int = 50,
) -> dict:
    """Aggregate governance decisions from FaGovernanceDecision."""
    try:
        from api.db_models_governance_decision import FaGovernanceDecision  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        q = (
            select(FaGovernanceDecision)
            .where(
                FaGovernanceDecision.tenant_id == tenant_id,
                FaGovernanceDecision.engagement_id == engagement_id,
            )
            .order_by(FaGovernanceDecision.id.desc())
            .limit(limit)
        )
        rows = db.execute(q).scalars().all()
        decisions = [
            {
                "decision_id": r.id,
                "decision_type": r.decision_type,
                "actor_id": r.actor_id,
                "decision_reason": r.decision_reason,
                "evidence_snapshot_hash": r.evidence_snapshot_hash,
                "status": r.status,
                "created_at": r.decision_at,
            }
            for r in rows
        ]
        return {
            "decisions": decisions,
            "total": len(decisions),
            "engagement_id": engagement_id,
            "version": "CGCTv1",
        }
    except Exception:
        log.debug("cgct.aggregators: aggregate_decisions failed", exc_info=True)
        return {
            "decisions": [],
            "total": 0,
            "engagement_id": engagement_id,
            "version": "CGCTv1",
        }


# ---------------------------------------------------------------------------
# aggregate_drift
# ---------------------------------------------------------------------------


def aggregate_drift(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
) -> dict:
    """Aggregate drift state from TIM drift events and trust snapshots."""
    defaults = {
        "open_count": 0,
        "resolved_count": 0,
        "latest_drift_direction": "stable",
        "drift_score": 0,
        "open_events": [],
        "engagement_id": engagement_id,
        "version": "CGCTv1",
    }
    try:
        from api.db_models_tim import FaTimDriftEvent, FaTimTrustSnapshot  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        drift_q = select(FaTimDriftEvent).where(
            FaTimDriftEvent.tenant_id == tenant_id,
            FaTimDriftEvent.engagement_id == engagement_id,
        )
        drift_rows = db.execute(drift_q).scalars().all()

        open_events = [r for r in drift_rows if r.resolved_at is None]
        resolved_events = [r for r in drift_rows if r.resolved_at is not None]

        snap_q = (
            select(FaTimTrustSnapshot)
            .where(
                FaTimTrustSnapshot.tenant_id == tenant_id,
                FaTimTrustSnapshot.engagement_id == engagement_id,
            )
            .order_by(FaTimTrustSnapshot.evaluated_at.desc())
            .limit(1)
        )
        snap = db.execute(snap_q).scalar_one_or_none()
        drift_direction = snap.drift_direction if snap else "stable"
        drift_score = snap.drift_score if snap else 0

        return {
            "open_count": len(open_events),
            "resolved_count": len(resolved_events),
            "latest_drift_direction": drift_direction,
            "drift_score": drift_score,
            "open_events": [
                {
                    "event_id": e.id,
                    "drift_rule": e.drift_rule,
                    "severity": e.severity,
                    "detected_at": e.detected_at,
                }
                for e in open_events[:20]
            ],
            "engagement_id": engagement_id,
            "version": "CGCTv1",
        }
    except Exception:
        log.debug("cgct.aggregators: aggregate_drift failed", exc_info=True)
        return defaults


# ---------------------------------------------------------------------------
# aggregate_risk
# ---------------------------------------------------------------------------


def aggregate_risk(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
) -> dict:
    """Aggregate risk state from latest TIM trust snapshot."""
    defaults = {
        "risk_level": "unknown",
        "risk_score": 0,
        "posture_score": 0,
        "posture_level": "unknown",
        "risk_rollup": {},
        "engagement_id": engagement_id,
        "version": "CGCTv1",
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

        risk_rollup = {
            "risk_level": row.risk_level,
            "posture_score": row.posture_score,
            "posture_level": row.posture_level,
            "drift_score": row.drift_score,
            "drift_direction": row.drift_direction,
            "open_drift_count": row.open_drift_count,
            "certification_level": row.certification_level,
            "replay_status": row.replay_status,
            "evaluated_at": row.evaluated_at,
        }
        return {
            "risk_level": row.risk_level,
            "risk_score": int(row.posture_score or 0),
            "posture_score": int(row.posture_score or 0),
            "posture_level": row.posture_level,
            "risk_rollup": risk_rollup,
            "engagement_id": engagement_id,
            "version": "CGCTv1",
        }
    except Exception:
        log.debug("cgct.aggregators: aggregate_risk failed", exc_info=True)
        return defaults


# ---------------------------------------------------------------------------
# aggregate_evidence
# ---------------------------------------------------------------------------


def aggregate_evidence(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
) -> dict:
    """Aggregate evidence state from verification bundles."""
    defaults = {
        "coverage_distribution": {},
        "tamper_count": 0,
        "total_bundles": 0,
        "latest_bundle_id": None,
        "latest_generated_at": None,
        "engagement_id": engagement_id,
        "version": "CGCTv1",
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
            .limit(20)
        )
        rows = db.execute(q).scalars().all()
        if not rows:
            return defaults

        coverage_dist: dict[str, int] = {}
        tamper_count = 0
        for r in rows:
            cs = r.coverage_status or "unknown"
            coverage_dist[cs] = coverage_dist.get(cs, 0) + 1
            if cs == "tampered":
                tamper_count += 1

        latest = rows[0]
        return {
            "coverage_distribution": coverage_dist,
            "tamper_count": tamper_count,
            "total_bundles": len(rows),
            "latest_bundle_id": latest.id,
            "latest_generated_at": latest.generated_at,
            "engagement_id": engagement_id,
            "version": "CGCTv1",
        }
    except Exception:
        log.debug("cgct.aggregators: aggregate_evidence failed", exc_info=True)
        return defaults


# ---------------------------------------------------------------------------
# aggregate_timeline
# ---------------------------------------------------------------------------


def aggregate_timeline(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    limit: int = 100,
) -> dict:
    """Aggregate governance timeline events from TimelineEventRecord."""
    defaults = {
        "events": [],
        "total": 0,
        "engagement_id": engagement_id,
        "version": "CGCTv1",
    }
    try:
        from api.db_models_timeline import TimelineEventRecord  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        # Do not filter by source_id == engagement_id — many emitters (TIM, CLM,
        # verification bundles) store the authority record id as source_id and
        # place engagement_id in the payload. A tenant-scoped query returns the
        # complete unified timeline across all governance sources.
        q = (
            select(TimelineEventRecord)
            .where(TimelineEventRecord.tenant_id == tenant_id)
            .order_by(TimelineEventRecord.occurred_at.desc())
            .limit(limit)
        )
        rows = db.execute(q).scalars().all()
        events = [
            {
                "event_id": r.id,
                "source_type": r.source_type,
                "source_id": r.source_id,
                "event_type": r.event_type,
                "occurred_at": r.occurred_at,
                "classification": r.classification,
                "replay_eligible": r.replay_eligible,
            }
            for r in rows
        ]
        return {
            "events": events,
            "total": len(events),
            "engagement_id": engagement_id,
            "version": "CGCTv1",
        }
    except Exception:
        log.debug("cgct.aggregators: aggregate_timeline failed", exc_info=True)
        return defaults


# ---------------------------------------------------------------------------
# aggregate_certifications
# ---------------------------------------------------------------------------


def aggregate_certifications(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
) -> dict:
    """Aggregate certification state from CLM certs and TIM snapshots."""
    defaults = {
        "status_distribution": {},
        "expiry_warnings": [],
        "total": 0,
        "health": "unknown",
        "engagement_id": engagement_id,
        "version": "CGCTv1",
    }
    try:
        from api.db_models_clm import FaClmCert  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        q = select(FaClmCert).where(
            FaClmCert.tenant_id == tenant_id,
            FaClmCert.engagement_id == engagement_id,
        )
        certs = db.execute(q).scalars().all()

        status_dist: dict[str, int] = {}
        for cert in certs:
            s = cert.lifecycle_status or "unknown"
            status_dist[s] = status_dist.get(s, 0) + 1

        # Expiry warnings: valid_until within 90 days
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ninety_days = (datetime.now(timezone.utc) + timedelta(days=90)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        expiry_warnings = [
            {
                "cert_id": c.id,
                "cert_name": c.cert_name,
                "lifecycle_status": c.lifecycle_status,
                "valid_until": c.valid_until,
            }
            for c in certs
            if c.valid_until and now_str <= c.valid_until <= ninety_days
        ]

        # Simple health heuristic
        total = len(certs)
        certified = status_dist.get("certified", 0) + status_dist.get("approved", 0)
        health = "unknown"
        if total > 0:
            ratio = certified / total
            if ratio >= 0.8:
                health = "healthy"
            elif ratio >= 0.5:
                health = "attention_required"
            else:
                health = "degraded"

        return {
            "status_distribution": status_dist,
            "expiry_warnings": expiry_warnings,
            "total": total,
            "health": health,
            "engagement_id": engagement_id,
            "version": "CGCTv1",
        }
    except Exception:
        log.debug("cgct.aggregators: aggregate_certifications failed", exc_info=True)
        return defaults


# ---------------------------------------------------------------------------
# get_executive_view
# ---------------------------------------------------------------------------


def get_executive_view(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
) -> dict:
    """30-second executive summary combining posture, actions, drift, risk, and certs."""
    try:
        from services.cgct.posture import get_latest_posture  # noqa: PLC0415

        posture = get_latest_posture(db, tenant_id=tenant_id, engagement_id=engagement_id)
    except Exception:
        posture = None

    try:
        from api.db_models_cgct import FaCgctActionItem  # noqa: PLC0415
        from sqlalchemy import func, select  # noqa: PLC0415

        action_q = select(func.count()).select_from(FaCgctActionItem).where(
            FaCgctActionItem.tenant_id == tenant_id,
            FaCgctActionItem.engagement_id == engagement_id,
            FaCgctActionItem.status == "open",
        )
        open_action_count = db.execute(action_q).scalar() or 0
    except Exception:
        open_action_count = 0

    drift = aggregate_drift(db, tenant_id=tenant_id, engagement_id=engagement_id)
    risk = aggregate_risk(db, tenant_id=tenant_id, engagement_id=engagement_id)
    certs = aggregate_certifications(
        db, tenant_id=tenant_id, engagement_id=engagement_id
    )

    return {
        "overall_score": posture["overall_score"] if posture else 0,
        "governance_health": posture["governance_health"] if posture else "unknown",
        "risk_level": risk.get("risk_level", "unknown"),
        "open_action_count": open_action_count,
        "open_drift_count": drift.get("open_count", 0),
        "total_certifications": certs.get("total", 0),
        "cert_health": certs.get("health", "unknown"),
        "last_computed_at": posture["computed_at"] if posture else None,
        "engagement_id": engagement_id,
        "version": "CGCTv1",
    }


# ---------------------------------------------------------------------------
# get_authority_matrix
# ---------------------------------------------------------------------------


def get_authority_matrix(tenant_id: str) -> dict:
    """Return static authority matrix documenting all governance sources.

    No DB access — this is a static descriptor of the system's authority model.
    """
    return {
        "tenant_id": tenant_id,
        "authority_sources": {
            "trust_arc": {
                "producer": "FaTrustCertification",
                "authority_level": "primary",
                "consumer_systems": ["tim", "cgct", "etcc", "qtb"],
                "replay_support": True,
                "tenant_scoped": True,
                "evidence_support": True,
                "audit_support": True,
                "refresh_trigger": "trust_arc_activation",
            },
            "tim": {
                "producer": "FaTimTrustSnapshot + FaTimDriftEvent",
                "authority_level": "primary",
                "consumer_systems": ["cgct", "etcc", "qtb", "clm"],
                "replay_support": True,
                "tenant_scoped": True,
                "evidence_support": True,
                "audit_support": True,
                "refresh_trigger": "periodic_evaluation + drift_rule_trigger",
            },
            "etcc": {
                "producer": "FaTrustCertification (composite)",
                "authority_level": "primary",
                "consumer_systems": ["cgct", "qtb"],
                "replay_support": True,
                "tenant_scoped": True,
                "evidence_support": True,
                "audit_support": True,
                "refresh_trigger": "trust_arc_activation",
            },
            "qtb": {
                "producer": "FaQtbBrief + FaQtbBriefManifest",
                "authority_level": "secondary",
                "consumer_systems": ["cgct"],
                "replay_support": True,
                "tenant_scoped": True,
                "evidence_support": True,
                "audit_support": True,
                "refresh_trigger": "quarterly_schedule + on_demand",
            },
            "clm": {
                "producer": "FaClmCert + FaClmLifecycleEvent",
                "authority_level": "primary",
                "consumer_systems": ["cgct", "etcc"],
                "replay_support": True,
                "tenant_scoped": True,
                "evidence_support": True,
                "audit_support": True,
                "refresh_trigger": "lifecycle_transition",
            },
            "verification_bundles": {
                "producer": "FaVerificationBundle",
                "authority_level": "primary",
                "consumer_systems": ["cgct", "qtb", "clm"],
                "replay_support": True,
                "tenant_scoped": True,
                "evidence_support": True,
                "audit_support": True,
                "refresh_trigger": "bundle_generation",
            },
            "decision_memory": {
                "producer": "FaGovernanceDecision",
                "authority_level": "primary",
                "consumer_systems": ["cgct", "qtb"],
                "replay_support": True,
                "tenant_scoped": True,
                "evidence_support": True,
                "audit_support": True,
                "refresh_trigger": "governance_action",
            },
            "timeline": {
                "producer": "TimelineEventRecord",
                "authority_level": "secondary",
                "consumer_systems": ["cgct", "qtb"],
                "replay_support": True,
                "tenant_scoped": True,
                "evidence_support": False,
                "audit_support": True,
                "refresh_trigger": "any_governance_event",
            },
            "risk_rollups": {
                "producer": "FaTimTrustSnapshot (risk_level + posture_score)",
                "authority_level": "secondary",
                "consumer_systems": ["cgct", "etcc"],
                "replay_support": True,
                "tenant_scoped": True,
                "evidence_support": False,
                "audit_support": True,
                "refresh_trigger": "tim_evaluation",
            },
            "capability_authority": {
                "producer": "TenantEntitlement + CAPABILITY_REGISTRY",
                "authority_level": "primary",
                "consumer_systems": ["all"],
                "replay_support": False,
                "tenant_scoped": True,
                "evidence_support": False,
                "audit_support": True,
                "refresh_trigger": "entitlement_grant_revoke",
            },
        },
        "version": "CGCTv1",
    }


# ---------------------------------------------------------------------------
# get_governance_graph
# ---------------------------------------------------------------------------


def get_governance_graph(
    db: Any,
    *,
    tenant_id: str,
) -> dict:
    """Return governance graph derived from stored edges in fg_cgct_graph_edges."""
    try:
        from api.db_models_cgct import FaCgctGraphEdge  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        q = select(FaCgctGraphEdge).where(FaCgctGraphEdge.tenant_id == tenant_id)
        edges = db.execute(q).scalars().all()

        # Derive node list from edges
        nodes: dict[str, dict] = {}
        edge_list = []
        for edge in edges:
            from_key = f"{edge.from_node_type}:{edge.from_node_id}"
            to_key = f"{edge.to_node_type}:{edge.to_node_id}"
            if from_key not in nodes:
                nodes[from_key] = {
                    "node_id": edge.from_node_id,
                    "node_type": edge.from_node_type,
                }
            if to_key not in nodes:
                nodes[to_key] = {
                    "node_id": edge.to_node_id,
                    "node_type": edge.to_node_type,
                }
            edge_list.append(
                {
                    "edge_id": edge.id,
                    "from_node_type": edge.from_node_type,
                    "from_node_id": edge.from_node_id,
                    "to_node_type": edge.to_node_type,
                    "to_node_id": edge.to_node_id,
                    "relationship": edge.relationship,
                    "weight": edge.weight,
                    "direction": edge.direction,
                }
            )

        return {
            "nodes": list(nodes.values()),
            "edges": edge_list,
            "node_count": len(nodes),
            "edge_count": len(edge_list),
            "tenant_id": tenant_id,
            "version": "CGCTv1",
        }
    except Exception:
        log.debug("cgct.aggregators: get_governance_graph failed", exc_info=True)
        return {
            "nodes": [],
            "edges": [],
            "node_count": 0,
            "edge_count": 0,
            "tenant_id": tenant_id,
            "version": "CGCTv1",
        }
