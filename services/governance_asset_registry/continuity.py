"""Governance Asset Continuity Service.

NOT standalone. Component of the Field Assessment Engagement Substrate,
Governance Platform, Asset Governance Layer (AGL), and future Autonomous
Systems Governance architecture.

Authoritative source for governance health, attestation health, coverage gaps,
asset freshness, and operational debt.

Future consumers: Governance Workflow Engine, Governance Promotion Engine,
Governance Readiness Drift Detector, Executive Readiness Dashboard,
Autonomous Governance Agents, Regulatory Evidence Generation,
Governance Reporting Engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db_models_governance_assets import GaAsset, GaAssetOwner
from services.governance_asset_registry.attestation import (
    compute_next_due_at,
    days_overdue as _days_overdue,
)
from services.governance_asset_registry.risk_engine import compute_attestation_staleness

_DUE_SOON_DEFAULT_DAYS = 30

_TIER_PRIORITY: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "minimal": 1,
    "unclassified": 0,
}


@dataclass
class AttestationHealthReport:
    compliant: int
    due_soon: int
    overdue: int
    never_attested: int
    total: int
    health_pct: float


@dataclass
class ContinuityGap:
    asset_id: str
    asset_type: str
    asset_name: str
    risk_tier: str
    days_overdue: int
    staleness_index: int
    last_attested_at: str | None


def _latest_attestation_subquery(db: Session, *, tenant_id: str):
    """Subquery returning the most recent last_attested_at per asset_id."""
    return (
        select(
            GaAssetOwner.asset_id,
            func.max(GaAssetOwner.last_attested_at).label("last_attested_at"),
        )
        .where(GaAssetOwner.tenant_id == tenant_id)
        .group_by(GaAssetOwner.asset_id)
        .subquery()
    )


def attestation_health(
    db: Session,
    *,
    tenant_id: str,
) -> AttestationHealthReport:
    """Compute tenant-scoped governance attestation health.

    Every active asset belongs to exactly one category:
      COMPLIANT — attested and not due within the default window
      DUE_SOON  — attested, not overdue, but due within 30 days
      OVERDUE   — attestation interval has elapsed
      NEVER_ATTESTED — no owner or no attestation on record

    health_pct = (compliant / total) * 100; 100.0 when total == 0.
    """
    latest = _latest_attestation_subquery(db, tenant_id=tenant_id)

    stmt = (
        select(
            GaAsset.asset_id,
            GaAsset.risk_tier,
            latest.c.last_attested_at,
        )
        .outerjoin(latest, latest.c.asset_id == GaAsset.asset_id)
        .where(
            GaAsset.tenant_id == tenant_id,
            GaAsset.status == "active",
        )
    )

    rows = db.execute(stmt).all()
    total = len(rows)

    if total == 0:
        return AttestationHealthReport(
            compliant=0,
            due_soon=0,
            overdue=0,
            never_attested=0,
            total=0,
            health_pct=100.0,
        )

    compliant = due_soon = overdue = never_attested = 0
    now = datetime.now(UTC)
    due_soon_cutoff = now + timedelta(days=_DUE_SOON_DEFAULT_DAYS)

    for row in rows:
        last_at = row.last_attested_at
        if last_at is None:
            never_attested += 1
            continue

        next_due_str = compute_next_due_at(row.risk_tier, last_at)
        od = _days_overdue(next_due_str)

        if od > 0:
            overdue += 1
        else:
            next_due = datetime.fromisoformat(next_due_str.replace("Z", "+00:00"))
            if next_due <= due_soon_cutoff:
                due_soon += 1
            else:
                compliant += 1

    health_pct = round((compliant / total) * 100, 2)

    return AttestationHealthReport(
        compliant=compliant,
        due_soon=due_soon,
        overdue=overdue,
        never_attested=never_attested,
        total=total,
        health_pct=health_pct,
    )


def continuity_gaps(
    db: Session,
    *,
    tenant_id: str,
    risk_tier: str | None = None,
    days_overdue_min: int = 0,
) -> list[ContinuityGap]:
    """Return overdue active assets sorted by automation priority order.

    Sort order (canonical for future automation): risk_tier (highest first),
    staleness_index (highest first), days_overdue (highest first).

    Excludes compliant and due-soon assets.
    """
    latest = _latest_attestation_subquery(db, tenant_id=tenant_id)

    stmt = (
        select(
            GaAsset.asset_id,
            GaAsset.asset_type,
            GaAsset.name,
            GaAsset.risk_tier,
            latest.c.last_attested_at,
        )
        .outerjoin(latest, latest.c.asset_id == GaAsset.asset_id)
        .where(
            GaAsset.tenant_id == tenant_id,
            GaAsset.status == "active",
        )
    )

    if risk_tier is not None:
        stmt = stmt.where(GaAsset.risk_tier == risk_tier)

    rows = db.execute(stmt).all()

    gaps: list[ContinuityGap] = []
    for row in rows:
        next_due_str = compute_next_due_at(row.risk_tier, row.last_attested_at)
        od = _days_overdue(next_due_str)

        if od <= 0:
            continue
        if od < days_overdue_min:
            continue

        staleness = compute_attestation_staleness(od)
        gaps.append(
            ContinuityGap(
                asset_id=row.asset_id,
                asset_type=row.asset_type,
                asset_name=row.name,
                risk_tier=row.risk_tier,
                days_overdue=od,
                staleness_index=staleness,
                last_attested_at=row.last_attested_at,
            )
        )

    gaps.sort(
        key=lambda g: (
            -_TIER_PRIORITY.get(g.risk_tier, 0),
            -g.staleness_index,
            -g.days_overdue,
        )
    )

    return gaps


def due_soon(
    db: Session,
    *,
    tenant_id: str,
    days: int = _DUE_SOON_DEFAULT_DAYS,
) -> list[dict]:
    """Return active assets whose next attestation is due within `days` days.

    Excludes overdue assets and never-attested assets.
    """
    latest = _latest_attestation_subquery(db, tenant_id=tenant_id)

    stmt = (
        select(
            GaAsset.asset_id,
            GaAsset.asset_type,
            GaAsset.name,
            GaAsset.risk_tier,
            latest.c.last_attested_at,
        )
        .outerjoin(latest, latest.c.asset_id == GaAsset.asset_id)
        .where(
            GaAsset.tenant_id == tenant_id,
            GaAsset.status == "active",
        )
    )

    rows = db.execute(stmt).all()

    now = datetime.now(UTC)
    cutoff = now + timedelta(days=days)
    result: list[dict] = []

    for row in rows:
        last_at = row.last_attested_at
        if last_at is None:
            continue

        next_due_str = compute_next_due_at(row.risk_tier, last_at)
        od = _days_overdue(next_due_str)

        if od > 0:
            continue

        next_due = datetime.fromisoformat(next_due_str.replace("Z", "+00:00"))
        if next_due <= cutoff:
            result.append(
                {
                    "asset_id": row.asset_id,
                    "asset_type": row.asset_type,
                    "name": row.name,
                    "risk_tier": row.risk_tier,
                    "last_attested_at": last_at,
                    "next_due_at": next_due_str,
                }
            )

    return result
