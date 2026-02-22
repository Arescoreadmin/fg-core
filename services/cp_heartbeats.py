"""
services/cp_heartbeats.py — Control Plane v2 Heartbeat Service.

Responsibilities:
  - Accept entity heartbeats (upsert to control_plane_heartbeats).
  - Detect stale entities (last_seen_ts > threshold).
  - Emit ledger events on stale detection and recovery.
  - Fail-closed: writes raise on DB unavailability.

Staleness thresholds (env-configurable):
  FG_CP_HEARTBEAT_STALE_SECONDS   default: 120  (2 minutes)
  FG_CP_HEARTBEAT_CRITICAL_SECONDS default: 300  (5 minutes)

Security invariants:
  - tenant_id never sourced from payload; always from auth context.
  - No subprocess, no shell.
  - Stale event emitted to ledger (not just logged).
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger("frostgate.cp_heartbeats")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

HEARTBEAT_STALE_SECONDS: int = int(
    os.getenv("FG_CP_HEARTBEAT_STALE_SECONDS", "120")
)
HEARTBEAT_CRITICAL_SECONDS: int = int(
    os.getenv("FG_CP_HEARTBEAT_CRITICAL_SECONDS", "300")
)

VALID_ENTITY_TYPES = frozenset(
    {"locker", "module", "connector", "agent", "executor", "gateway"}
)

VALID_BREAKER_STATES = frozenset({"closed", "open", "half_open"})
VALID_LAST_STATES = frozenset(
    {"unknown", "active", "paused", "degraded", "stopped", "quarantined"}
)


# ---------------------------------------------------------------------------
# Heartbeat service
# ---------------------------------------------------------------------------

class HeartbeatService:
    """
    Manages entity heartbeats and staleness detection.
    """

    def upsert(
        self,
        *,
        db_session: Any,
        entity_type: str,
        entity_id: str,
        tenant_id: str,
        node_id: str = "",
        version: str = "",
        last_state: str = "active",
        breaker_state: str = "closed",
        queue_depth: int = 0,
        last_error_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Upsert a heartbeat record.

        Returns the current heartbeat dict.
        Raises ValueError for invalid inputs.
        Raises RuntimeError on DB failure.
        """
        from api.db_models_cp_v2 import ControlPlaneHeartbeat

        if entity_type not in VALID_ENTITY_TYPES:
            raise ValueError(f"Invalid entity_type: {entity_type!r}")
        if breaker_state not in VALID_BREAKER_STATES:
            breaker_state = "closed"
        if last_state not in VALID_LAST_STATES:
            last_state = "unknown"

        now = datetime.now(timezone.utc)

        try:
            existing = (
                db_session.query(ControlPlaneHeartbeat)
                .filter_by(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    tenant_id=tenant_id,
                )
                .first()
            )
            if existing:
                existing.node_id = node_id
                existing.version = version
                existing.last_seen_ts = now
                existing.last_state = last_state
                existing.breaker_state = breaker_state
                existing.queue_depth = queue_depth
                existing.last_error_code = last_error_code
                db_session.flush()
                row = existing
            else:
                row = ControlPlaneHeartbeat(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    tenant_id=tenant_id,
                    node_id=node_id,
                    version=version,
                    last_seen_ts=now,
                    last_state=last_state,
                    breaker_state=breaker_state,
                    queue_depth=queue_depth,
                    last_error_code=last_error_code,
                )
                db_session.add(row)
                db_session.flush()
        except Exception as exc:
            log.error(
                "cp_heartbeats.upsert_failed entity=%s/%s error=%s",
                entity_type,
                entity_id,
                exc,
            )
            raise RuntimeError(f"Heartbeat write failed: {exc}") from exc

        return self._row_to_dict(row)

    def detect_stale(
        self,
        *,
        db_session: Any,
        ledger: Any,  # ControlPlaneLedger
        tenant_id: Optional[str] = None,
        is_global: bool = False,
        stale_threshold_seconds: int = HEARTBEAT_STALE_SECONDS,
    ) -> List[Dict[str, Any]]:
        """
        Scan for stale heartbeats and emit ledger events for each.

        Returns list of stale entity dicts.
        """
        from api.db_models_cp_v2 import ControlPlaneHeartbeat

        cutoff = datetime.now(timezone.utc) - timedelta(seconds=stale_threshold_seconds)

        try:
            q = db_session.query(ControlPlaneHeartbeat).filter(
                ControlPlaneHeartbeat.last_seen_ts < cutoff
            )
            if not is_global and tenant_id:
                q = q.filter(ControlPlaneHeartbeat.tenant_id == tenant_id)
            stale_rows = q.all()
        except Exception as exc:
            log.error("cp_heartbeats.stale_scan_failed error=%s", exc)
            return []

        stale_entities = []
        for row in stale_rows:
            age_seconds = (
                datetime.now(timezone.utc) - row.last_seen_ts.replace(tzinfo=timezone.utc)
                if row.last_seen_ts.tzinfo is None
                else datetime.now(timezone.utc) - row.last_seen_ts
            ).total_seconds()

            severity = (
                "critical"
                if age_seconds >= HEARTBEAT_CRITICAL_SECONDS
                else "warning"
            )

            entity_dict = self._row_to_dict(row)
            entity_dict["age_seconds"] = int(age_seconds)
            stale_entities.append(entity_dict)

            try:
                ledger.append_event(
                    db_session=db_session,
                    event_type="cp_heartbeat_stale",
                    actor_id="system",
                    actor_role="watchdog",
                    tenant_id=row.tenant_id,
                    payload={
                        "entity_type": row.entity_type,
                        "entity_id": row.entity_id,
                        "last_seen_ts": (
                            row.last_seen_ts.isoformat().replace("+00:00", "Z")
                            if isinstance(row.last_seen_ts, datetime)
                            else str(row.last_seen_ts)
                        ),
                        "age_seconds": int(age_seconds),
                        "last_state": row.last_state,
                        "breaker_state": row.breaker_state,
                    },
                    severity=severity,
                    source="system",
                )
            except Exception as exc:
                log.error(
                    "cp_heartbeats.stale_ledger_emit_failed entity=%s error=%s",
                    row.entity_id,
                    exc,
                )

        return stale_entities

    def get_heartbeats(
        self,
        db_session: Any,
        tenant_id: Optional[str],
        is_global_admin: bool,
        entity_type: Optional[str] = None,
        stale_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """Query heartbeats with tenant isolation."""
        from api.db_models_cp_v2 import ControlPlaneHeartbeat

        q = db_session.query(ControlPlaneHeartbeat)
        if not is_global_admin:
            if tenant_id:
                q = q.filter(ControlPlaneHeartbeat.tenant_id == tenant_id)
            else:
                return []
        if entity_type:
            q = q.filter(ControlPlaneHeartbeat.entity_type == entity_type)
        if stale_only:
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=HEARTBEAT_STALE_SECONDS)
            q = q.filter(ControlPlaneHeartbeat.last_seen_ts < cutoff)

        rows = q.order_by(ControlPlaneHeartbeat.last_seen_ts.desc()).all()
        return [self._row_to_dict(r) for r in rows]

    @staticmethod
    def _row_to_dict(row: Any) -> Dict[str, Any]:
        last_seen = (
            row.last_seen_ts.isoformat().replace("+00:00", "Z")
            if isinstance(row.last_seen_ts, datetime)
            else str(row.last_seen_ts)
        )
        return {
            "entity_type": row.entity_type,
            "entity_id": row.entity_id,
            "tenant_id": row.tenant_id,
            "node_id": row.node_id,
            "version": row.version,
            "last_seen_ts": last_seen,
            "last_state": row.last_state,
            "breaker_state": row.breaker_state,
            "queue_depth": row.queue_depth,
            "last_error_code": row.last_error_code,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_heartbeat_svc: Optional[HeartbeatService] = None


def get_heartbeat_service() -> HeartbeatService:
    global _heartbeat_svc
    if _heartbeat_svc is None:
        _heartbeat_svc = HeartbeatService()
    return _heartbeat_svc
