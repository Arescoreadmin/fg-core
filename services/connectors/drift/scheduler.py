"""Connector run scheduling registry.

Stores cron expressions per (tenant_id, engagement_id, source_type).
This is a registry — it records *when* runs should happen, not the runner itself.
One active schedule per engagement/source_type pair.

cron_expression format: standard 5-field cron (min hour dom mon dow).
  "0 6 * * 1"  — every Monday at 06:00 UTC
  "0 */6 * * *" — every 6 hours

trigger_type values (PR 6 add-in):
  "cron"               — time-based; cron_expression is required and validated
  "on_anomaly_detected" — fire when governance graph anomaly is detected
  "on_graph_rebuild"   — fire after each governance graph rebuild completes
  "on_finding_import"  — fire after findings are imported for the engagement

Validation rejects expressions with wrong field count or non-printable characters.
Full cron semantics (range, step, list) are not validated here — the scheduler
runtime is responsible for interpreting the expression.
"""

from __future__ import annotations

import hashlib
import logging
import re

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from api.db_models_drift import FaConnectorSchedule
from services.canonical import utc_iso8601_z_now

log = logging.getLogger("frostgate.connectors.drift.scheduler")

_CRON_FIELD_RE = re.compile(r"^[\d*/,\-]+$")
_VALID_SOURCE_TYPES = frozenset(
    {"microsoft_graph", "okta", "aws", "intune", "google_workspace"}
)

VALID_TRIGGER_TYPES = frozenset(
    {
        "cron",
        "on_anomaly_detected",
        "on_graph_rebuild",
        "on_finding_import",
    }
)


class InvalidCronExpression(ValueError):
    pass


class UnsupportedSourceType(ValueError):
    pass


class InvalidTriggerType(ValueError):
    pass


def validate_cron_expression(expr: str) -> None:
    """Raise InvalidCronExpression if expr is not a valid 5-field cron string."""
    parts = expr.strip().split()
    if len(parts) != 5:
        raise InvalidCronExpression(
            f"cron expression must have exactly 5 fields, got {len(parts)}: {expr!r}"
        )
    for part in parts:
        if not _CRON_FIELD_RE.match(part):
            raise InvalidCronExpression(
                f"cron field {part!r} contains invalid characters in {expr!r}"
            )


def _schedule_id(tenant_id: str, engagement_id: str, source_type: str) -> str:
    raw = f"{tenant_id}:{engagement_id}:{source_type}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def upsert_schedule(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    source_type: str,
    cron_expression: str,
    created_by: str,
    trigger_type: str = "cron",
) -> tuple[FaConnectorSchedule, bool]:
    """Create or update a connector schedule for (engagement_id, source_type).

    Returns (schedule, is_new).
    Raises InvalidCronExpression on bad cron syntax (only for trigger_type="cron").
    Raises InvalidTriggerType for unknown trigger types.
    """
    if trigger_type not in VALID_TRIGGER_TYPES:
        raise InvalidTriggerType(
            f"trigger_type must be one of {sorted(VALID_TRIGGER_TYPES)}, "
            f"got {trigger_type!r}"
        )
    if trigger_type == "cron":
        validate_cron_expression(cron_expression)

    now = utc_iso8601_z_now()
    existing = db.execute(
        select(FaConnectorSchedule).where(
            FaConnectorSchedule.tenant_id == tenant_id,
            FaConnectorSchedule.engagement_id == engagement_id,
            FaConnectorSchedule.source_type == source_type,
        )
    ).scalar_one_or_none()

    if existing is not None:
        existing.cron_expression = cron_expression
        existing.trigger_type = trigger_type
        existing.created_by = created_by
        existing.is_active = True
        existing.updated_at = now
        db.flush()
        return existing, False

    schedule = FaConnectorSchedule(
        id=_schedule_id(tenant_id, engagement_id, source_type),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type=source_type,
        cron_expression=cron_expression,
        trigger_type=trigger_type,
        created_by=created_by,
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    db.add(schedule)
    db.flush()
    return schedule, True


def list_schedules(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
) -> list[FaConnectorSchedule]:
    rows = (
        db.execute(
            select(FaConnectorSchedule).where(
                FaConnectorSchedule.tenant_id == tenant_id,
                FaConnectorSchedule.engagement_id == engagement_id,
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


def list_schedules_by_trigger(
    db: Session,
    *,
    tenant_id: str,
    trigger_type: str,
    active_only: bool = True,
) -> list[FaConnectorSchedule]:
    """Return all schedules for a tenant with a specific trigger_type.

    Used by the msgraph bridge and graph rebuilder to fire event-driven schedules.
    """
    stmt = select(FaConnectorSchedule).where(
        FaConnectorSchedule.tenant_id == tenant_id,
        FaConnectorSchedule.trigger_type == trigger_type,
    )
    if active_only:
        stmt = stmt.where(FaConnectorSchedule.is_active.is_(True))
    return list(db.execute(stmt).scalars().all())


def deactivate_schedule(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    source_type: str,
) -> bool:
    """Deactivate a schedule. Returns True if a row was updated."""
    now = utc_iso8601_z_now()
    result = db.execute(
        update(FaConnectorSchedule)
        .where(
            FaConnectorSchedule.tenant_id == tenant_id,
            FaConnectorSchedule.engagement_id == engagement_id,
            FaConnectorSchedule.source_type == source_type,
            FaConnectorSchedule.is_active.is_(True),
        )
        .values(is_active=False, updated_at=now)
    )
    db.flush()
    return (result.rowcount or 0) > 0
