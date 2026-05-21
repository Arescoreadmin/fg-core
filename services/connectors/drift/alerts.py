"""Deterministic drift alert record generation with fingerprint deduplication.

Alert fingerprint: SHA-256(tenant_id:engagement_id:pattern:finding_id:severity)
  Guarantees one active alert row per condition — no duplicate records for
  ongoing posture issues regardless of how many drift reports are computed.

Alert family grouping:
  Alerts are grouped into families by NIST-AI-RMF function domain when the
  finding has nist_ai_rmf_mappings. Three or more alerts in the same domain
  produce one family alert in addition to the individual records. This reduces
  notification noise for clients with many findings in the same control area.

Lifecycle:
  create_or_refresh_alert  — upserts by fingerprint; refreshes last_seen_at if active
  resolve_alert            — stamps resolved_at; sets is_active=False
  list_active_alerts       — returns active alerts for an engagement
"""

from __future__ import annotations

import hashlib
import logging

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from api.db_models_drift import FaDriftAlert
from services.canonical import utc_iso8601_z_now

log = logging.getLogger("frostgate.connectors.drift.alerts")

_FAMILY_THRESHOLD = 3  # alerts per NIST domain before a family alert is created


def _fingerprint(
    tenant_id: str,
    engagement_id: str,
    pattern: str,
    finding_id: str,
    severity: str,
) -> str:
    raw = f"{tenant_id}:{engagement_id}:{pattern}:{finding_id}:{severity}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _alert_id(fingerprint: str, now: str) -> str:
    return hashlib.sha256(f"{fingerprint}:{now}".encode()).hexdigest()[:32]


def create_or_refresh_alert(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    pattern: str,
    finding_id: str | None,
    severity: str,
    title: str,
    description: str,
    alert_family: str | None = None,
) -> FaDriftAlert:
    """Upsert an alert by fingerprint.

    If an active alert with this fingerprint exists: refresh last_seen_at and return it.
    If no active alert exists: create a new row.
    """
    fp = _fingerprint(
        tenant_id,
        engagement_id,
        pattern,
        finding_id or "",
        severity,
    )
    now = utc_iso8601_z_now()

    # Search for ANY row with this fingerprint (active or previously resolved).
    # The uniqueness constraint on alert_fingerprint means only one row can exist;
    # inserting a second would violate the constraint when the condition reoccurs
    # after resolve_alert() marked the prior row inactive.
    existing = db.execute(
        select(FaDriftAlert).where(
            FaDriftAlert.tenant_id == tenant_id,
            FaDriftAlert.engagement_id == engagement_id,
            FaDriftAlert.alert_fingerprint == fp,
        )
    ).scalar_one_or_none()

    if existing is not None:
        existing.last_seen_at = now
        if not existing.is_active:
            # Reopen a previously resolved alert rather than inserting a duplicate
            existing.is_active = True
            existing.resolved_at = None
        db.flush()
        return existing

    alert = FaDriftAlert(
        id=_alert_id(fp, now),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        alert_fingerprint=fp,
        pattern=pattern,
        finding_id=finding_id,
        severity=severity,
        title=title,
        description=description,
        alert_family=alert_family,
        is_active=True,
        first_seen_at=now,
        last_seen_at=now,
        resolved_at=None,
    )
    db.add(alert)
    db.flush()
    return alert


def resolve_alert(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    pattern: str,
    finding_id: str | None,
    severity: str,
) -> bool:
    """Mark an active alert as resolved. Returns True if an alert was found and resolved."""
    fp = _fingerprint(
        tenant_id,
        engagement_id,
        pattern,
        finding_id or "",
        severity,
    )
    now = utc_iso8601_z_now()
    result = db.execute(
        update(FaDriftAlert)
        .where(
            FaDriftAlert.tenant_id == tenant_id,
            FaDriftAlert.engagement_id == engagement_id,
            FaDriftAlert.alert_fingerprint == fp,
            FaDriftAlert.is_active.is_(True),
        )
        .values(is_active=False, resolved_at=now)
    )
    db.flush()
    return (result.rowcount or 0) > 0


def emit_drift_alerts(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    drift_findings: list[dict],
) -> list[FaDriftAlert]:
    """Generate alerts from a drift report's classified findings.

    drift_findings: list of dicts with keys:
      finding_id, severity, title, delta_class, nist_ai_rmf_mappings (optional)

    Emits alerts for regressed, escalated, and net-new critical/high findings.
    Groups alerts by NIST domain into family alerts when threshold is reached.
    Returns all created/refreshed alert rows.
    """
    emitted: list[FaDriftAlert] = []
    domain_counts: dict[str, int] = {}

    for f in drift_findings:
        delta = f.get("delta_class", "")
        severity = f.get("severity", "informational")
        fid = f.get("finding_id", "")
        title = f.get("title", "Unknown finding")

        # Determine if this finding warrants an alert
        if delta == "regressed":
            pattern = "drift.regressed"
            alert_severity = severity
            desc = (
                f"Finding '{title}' was previously resolved but has returned "
                f"with severity={severity}."
            )
        elif delta == "escalated":
            pattern = "drift.escalated"
            alert_severity = severity
            base_sev = f.get("baseline_severity", "unknown")
            desc = (
                f"Finding '{title}' severity escalated from {base_sev} to {severity}."
            )
        elif delta == "new" and severity in ("critical", "high"):
            pattern = "drift.new_high_critical"
            alert_severity = severity
            desc = f"New {severity} finding: '{title}'."
        else:
            continue

        # Domain family tracking
        nist_mappings = f.get("nist_ai_rmf_mappings") or []
        nist_function: str | None = None
        for m in nist_mappings:
            if isinstance(m, dict) and m.get("function"):
                nist_function = str(m["function"]).upper()
                break
        if nist_function:
            domain_counts[nist_function] = domain_counts.get(nist_function, 0) + 1

        alert = create_or_refresh_alert(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            pattern=pattern,
            finding_id=fid,
            severity=alert_severity,
            title=f"[{pattern}] {title}",
            description=desc,
            alert_family=nist_function,
        )
        emitted.append(alert)

    # Family alerts for domains over threshold
    for nist_function, count in domain_counts.items():
        if count >= _FAMILY_THRESHOLD:
            # Use nist_function as finding_id so each domain gets a distinct fingerprint
            alert = create_or_refresh_alert(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                pattern="drift.domain_cluster",
                finding_id=nist_function,
                severity="high",
                title=f"[drift.domain_cluster] {count} drift events in NIST {nist_function}",
                description=(
                    f"{count} findings in NIST-AI-RMF domain {nist_function} "
                    "are regressed, escalated, or new high/critical."
                ),
                alert_family=nist_function,
            )
            emitted.append(alert)

    return emitted


def list_active_alerts(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    limit: int = 100,
) -> list[FaDriftAlert]:
    return (
        db.execute(
            select(FaDriftAlert)
            .where(
                FaDriftAlert.tenant_id == tenant_id,
                FaDriftAlert.engagement_id == engagement_id,
                FaDriftAlert.is_active.is_(True),
            )
            .order_by(FaDriftAlert.last_seen_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
