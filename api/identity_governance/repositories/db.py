"""api/identity_governance/repositories/db.py — SQLAlchemy repositories.

Opt-in DB persistence for identity governance records. Backed by the tables
created in ``migrations/postgres/0148_identity_governance.sql``. Enabled by
:env:`FG_IDENTITY_PERSISTENCE_ENABLED=1`; otherwise the in-memory
repositories are used.

All queries are tenant-scoped by an explicit ``tenant_id`` filter. Postgres
Row Level Security (defined by migration 0148) is a secondary check when
``app.tenant_id`` is set upstream by the request context.

Timestamps and details are stored as ISO strings / JSON strings (matching
the 0148 schema which uses VARCHAR for portability). Reads convert back to
native dataclasses so callers see the same shape regardless of backend.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from api.identity_governance.models import (
    BreakGlassRequest,
    BreakGlassStatus,
    DeviceRecord,
    DeviceTrustState,
    IdentityLifecycleRecord,
    IdentityLifecycleState,
    IdentityTimelineEvent,
    IdentityTimelineEventType,
)

log = logging.getLogger("frostgate.identity_governance.repositories.db")


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _now_iso() -> str:
    return _iso(datetime.now(tz=timezone.utc))


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class DbLifecycleRepository:
    """SQLAlchemy repository for identity_lifecycle_events."""

    def __init__(self, session_factory) -> None:
        # session_factory is a callable returning a Session (e.g. sessionmaker
        # or a factory bound to the request DB).
        self._session_factory = session_factory

    def _session(self) -> Session:
        return self._session_factory()

    def create(self, record: IdentityLifecycleRecord) -> IdentityLifecycleRecord:
        if not record.tenant_id:
            raise ValueError("tenant_id is required")
        stmt = text(
            """
            INSERT INTO identity_lifecycle_events
                (record_id, tenant_id, subject, from_state, to_state, reason,
                 actor, occurred_at, created_at)
            VALUES
                (:record_id, :tenant_id, :subject, :from_state, :to_state,
                 :reason, :actor, :occurred_at, :created_at)
            """
        )
        with self._session() as session:
            session.execute(
                stmt,
                {
                    "record_id": record.record_id,
                    "tenant_id": record.tenant_id,
                    "subject": record.subject,
                    "from_state": record.from_state.value,
                    "to_state": record.to_state.value,
                    "reason": record.reason,
                    "actor": record.actor,
                    "occurred_at": _iso(record.occurred_at),
                    "created_at": _now_iso(),
                },
            )
            session.commit()
        return record

    def get(self, tenant_id: str, record_id: str) -> Optional[IdentityLifecycleRecord]:
        stmt = text(
            """
            SELECT record_id, tenant_id, subject, from_state, to_state,
                   reason, actor, occurred_at
            FROM identity_lifecycle_events
            WHERE tenant_id = :tenant_id AND record_id = :record_id
            """
        )
        with self._session() as session:
            row = (
                session.execute(stmt, {"tenant_id": tenant_id, "record_id": record_id})
                .mappings()
                .first()
            )
        if row is None:
            return None
        return _row_to_lifecycle_record(row)

    def list_for_subject(
        self, tenant_id: str, subject: str, limit: int = 100
    ) -> list[IdentityLifecycleRecord]:
        limit = max(0, int(limit))
        if limit == 0:
            return []
        stmt = text(
            """
            SELECT record_id, tenant_id, subject, from_state, to_state,
                   reason, actor, occurred_at
            FROM identity_lifecycle_events
            WHERE tenant_id = :tenant_id AND subject = :subject
            ORDER BY occurred_at ASC
            """
        )
        with self._session() as session:
            rows = (
                session.execute(stmt, {"tenant_id": tenant_id, "subject": subject})
                .mappings()
                .all()
            )
        records = [_row_to_lifecycle_record(r) for r in rows]
        return records[-limit:]


def _row_to_lifecycle_record(row) -> IdentityLifecycleRecord:
    return IdentityLifecycleRecord(
        record_id=row["record_id"],
        tenant_id=row["tenant_id"],
        subject=row["subject"],
        from_state=IdentityLifecycleState(row["from_state"]),
        to_state=IdentityLifecycleState(row["to_state"]),
        reason=row["reason"],
        actor=row["actor"],
        occurred_at=_parse_iso(row["occurred_at"]),
    )


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


class DbDeviceRepository:
    """SQLAlchemy repository for identity_devices."""

    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    def _session(self) -> Session:
        return self._session_factory()

    def upsert(self, record: DeviceRecord) -> DeviceRecord:
        if not record.tenant_id:
            raise ValueError("tenant_id is required")
        # Delete-then-insert idempotent upsert, portable to both Postgres
        # and SQLite (the test backend has neither MERGE nor ON CONFLICT
        # standardized across versions used in CI).
        with self._session() as session:
            session.execute(
                text(
                    "DELETE FROM identity_devices "
                    "WHERE tenant_id = :tenant_id AND device_id = :device_id"
                ),
                {"tenant_id": record.tenant_id, "device_id": record.device_id},
            )
            session.execute(
                text(
                    """
                    INSERT INTO identity_devices
                        (device_id, tenant_id, subject, fingerprint_hash,
                         user_agent_hash, ip_metadata, trust_state,
                         risk_score, last_reason, registered_at, updated_at)
                    VALUES
                        (:device_id, :tenant_id, :subject, :fingerprint_hash,
                         :user_agent_hash, :ip_metadata, :trust_state,
                         :risk_score, :last_reason, :registered_at, :updated_at)
                    """
                ),
                {
                    "device_id": record.device_id,
                    "tenant_id": record.tenant_id,
                    "subject": record.subject,
                    "fingerprint_hash": record.fingerprint_hash,
                    "user_agent_hash": record.user_agent_hash,
                    "ip_metadata": record.ip_metadata,
                    "trust_state": record.trust_state.value,
                    "risk_score": record.risk_score,
                    "last_reason": record.last_reason,
                    "registered_at": _iso(record.registered_at),
                    "updated_at": _iso(record.updated_at),
                },
            )
            session.commit()
        return record

    def get(self, tenant_id: str, device_id: str) -> Optional[DeviceRecord]:
        stmt = text(
            """
            SELECT device_id, tenant_id, subject, fingerprint_hash,
                   user_agent_hash, ip_metadata, trust_state, risk_score,
                   last_reason, registered_at, updated_at
            FROM identity_devices
            WHERE tenant_id = :tenant_id AND device_id = :device_id
            """
        )
        with self._session() as session:
            row = (
                session.execute(stmt, {"tenant_id": tenant_id, "device_id": device_id})
                .mappings()
                .first()
            )
        if row is None:
            return None
        return _row_to_device_record(row)

    def list_for_subject(self, tenant_id: str, subject: str) -> list[DeviceRecord]:
        stmt = text(
            """
            SELECT device_id, tenant_id, subject, fingerprint_hash,
                   user_agent_hash, ip_metadata, trust_state, risk_score,
                   last_reason, registered_at, updated_at
            FROM identity_devices
            WHERE tenant_id = :tenant_id AND subject = :subject
            ORDER BY device_id ASC
            """
        )
        with self._session() as session:
            rows = (
                session.execute(stmt, {"tenant_id": tenant_id, "subject": subject})
                .mappings()
                .all()
            )
        return [_row_to_device_record(r) for r in rows]


def _row_to_device_record(row) -> DeviceRecord:
    return DeviceRecord(
        device_id=row["device_id"],
        tenant_id=row["tenant_id"],
        subject=row["subject"],
        fingerprint_hash=row["fingerprint_hash"],
        user_agent_hash=row["user_agent_hash"],
        ip_metadata=row["ip_metadata"] or "",
        trust_state=DeviceTrustState(row["trust_state"]),
        risk_score=float(row["risk_score"]),
        registered_at=_parse_iso(row["registered_at"]),
        updated_at=_parse_iso(row["updated_at"]),
        last_reason=row["last_reason"] or "",
    )


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


class DbTimelineRepository:
    """SQLAlchemy repository for identity_timeline_events."""

    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    def _session(self) -> Session:
        return self._session_factory()

    def append(self, event: IdentityTimelineEvent) -> IdentityTimelineEvent:
        if not event.tenant_id:
            raise ValueError("tenant_id is required")
        details_json = json.dumps({k: v for k, v in event.details}, sort_keys=True)
        stmt = text(
            """
            INSERT INTO identity_timeline_events
                (event_id, tenant_id, subject, actor, event_type,
                 occurred_at, correlation_id, details_json, previous_hash,
                 event_hash, created_at)
            VALUES
                (:event_id, :tenant_id, :subject, :actor, :event_type,
                 :occurred_at, :correlation_id, :details_json, :previous_hash,
                 :event_hash, :created_at)
            """
        )
        with self._session() as session:
            session.execute(
                stmt,
                {
                    "event_id": event.event_id,
                    "tenant_id": event.tenant_id,
                    "subject": event.subject,
                    "actor": event.actor,
                    "event_type": event.event_type.value,
                    "occurred_at": _iso(event.occurred_at),
                    "correlation_id": event.correlation_id,
                    "details_json": details_json,
                    "previous_hash": event.previous_hash,
                    "event_hash": event.event_hash,
                    "created_at": _now_iso(),
                },
            )
            session.commit()
        return event

    def list_events(
        self,
        tenant_id: str,
        subject: Optional[str] = None,
        limit: int = 100,
    ) -> list[IdentityTimelineEvent]:
        limit = max(0, int(limit))
        if limit == 0:
            return []
        if subject is None:
            stmt = text(
                """
                SELECT event_id, tenant_id, subject, actor, event_type,
                       occurred_at, correlation_id, details_json,
                       previous_hash, event_hash
                FROM identity_timeline_events
                WHERE tenant_id = :tenant_id
                ORDER BY occurred_at ASC
                """
            )
            params = {"tenant_id": tenant_id}
        else:
            stmt = text(
                """
                SELECT event_id, tenant_id, subject, actor, event_type,
                       occurred_at, correlation_id, details_json,
                       previous_hash, event_hash
                FROM identity_timeline_events
                WHERE tenant_id = :tenant_id AND subject = :subject
                ORDER BY occurred_at ASC
                """
            )
            params = {"tenant_id": tenant_id, "subject": subject}
        with self._session() as session:
            rows = session.execute(stmt, params).mappings().all()
        events = [_row_to_timeline_event(r) for r in rows]
        return events[-limit:]


def _row_to_timeline_event(row) -> IdentityTimelineEvent:
    details_json = row["details_json"] or "{}"
    try:
        parsed = json.loads(details_json)
    except (ValueError, TypeError):
        parsed = {}
    details = tuple(sorted((str(k), str(v)) for k, v in parsed.items()))
    return IdentityTimelineEvent(
        event_id=row["event_id"],
        event_type=IdentityTimelineEventType(row["event_type"]),
        subject=row["subject"],
        tenant_id=row["tenant_id"],
        actor=row["actor"],
        occurred_at=_parse_iso(row["occurred_at"]),
        details=details,
        correlation_id=row["correlation_id"],
        previous_hash=row["previous_hash"],
        event_hash=row["event_hash"],
    )


# ---------------------------------------------------------------------------
# Break-glass
# ---------------------------------------------------------------------------


class DbBreakGlassRepository:
    """SQLAlchemy repository for identity_break_glass_requests."""

    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    def _session(self) -> Session:
        return self._session_factory()

    def create(self, request: BreakGlassRequest) -> BreakGlassRequest:
        if not request.tenant_id:
            raise ValueError("tenant_id is required")
        stmt = text(
            """
            INSERT INTO identity_break_glass_requests
                (request_id, tenant_id, subject, requested_capability, reason,
                 requested_by, requested_at, duration_seconds, status,
                 approver, approved_at, expires_at, revoked_by, revoked_at,
                 created_at)
            VALUES
                (:request_id, :tenant_id, :subject, :requested_capability,
                 :reason, :requested_by, :requested_at, :duration_seconds,
                 :status, :approver, :approved_at, :expires_at, :revoked_by,
                 :revoked_at, :created_at)
            """
        )
        with self._session() as session:
            session.execute(stmt, _break_glass_params(request))
            session.commit()
        return request

    def update(self, request: BreakGlassRequest) -> BreakGlassRequest:
        if not request.tenant_id:
            raise ValueError("tenant_id is required")
        stmt = text(
            """
            UPDATE identity_break_glass_requests
            SET status = :status,
                approver = :approver,
                approved_at = :approved_at,
                expires_at = :expires_at,
                revoked_by = :revoked_by,
                revoked_at = :revoked_at
            WHERE tenant_id = :tenant_id AND request_id = :request_id
            """
        )
        params = _break_glass_params(request)
        with self._session() as session:
            result = session.execute(
                stmt,
                {
                    "status": params["status"],
                    "approver": params["approver"],
                    "approved_at": params["approved_at"],
                    "expires_at": params["expires_at"],
                    "revoked_by": params["revoked_by"],
                    "revoked_at": params["revoked_at"],
                    "tenant_id": request.tenant_id,
                    "request_id": request.request_id,
                },
            )
            # rowcount is available on the underlying cursor result but the
            # mypy stub for Result[Any] does not expose it uniformly; access
            # via getattr with a sensible default keeps the fallback safe.
            rowcount = getattr(result, "rowcount", None)
            if rowcount is not None and rowcount == 0:
                raise ValueError(
                    f"break-glass request {request.request_id!r} not found for tenant"
                )
            session.commit()
        return request

    def get(self, tenant_id: str, request_id: str) -> Optional[BreakGlassRequest]:
        stmt = text(
            """
            SELECT request_id, tenant_id, subject, requested_capability,
                   reason, requested_by, requested_at, duration_seconds,
                   status, approver, approved_at, expires_at,
                   revoked_by, revoked_at
            FROM identity_break_glass_requests
            WHERE tenant_id = :tenant_id AND request_id = :request_id
            """
        )
        with self._session() as session:
            row = (
                session.execute(
                    stmt, {"tenant_id": tenant_id, "request_id": request_id}
                )
                .mappings()
                .first()
            )
        if row is None:
            return None
        return _row_to_break_glass_request(row)

    def list_active_for_subject(
        self, tenant_id: str, subject: str
    ) -> list[BreakGlassRequest]:
        stmt = text(
            """
            SELECT request_id, tenant_id, subject, requested_capability,
                   reason, requested_by, requested_at, duration_seconds,
                   status, approver, approved_at, expires_at,
                   revoked_by, revoked_at
            FROM identity_break_glass_requests
            WHERE tenant_id = :tenant_id AND subject = :subject
              AND status = :status
            ORDER BY request_id ASC
            """
        )
        with self._session() as session:
            rows = (
                session.execute(
                    stmt,
                    {
                        "tenant_id": tenant_id,
                        "subject": subject,
                        "status": BreakGlassStatus.ACTIVE.value,
                    },
                )
                .mappings()
                .all()
            )
        return [_row_to_break_glass_request(r) for r in rows]


def _break_glass_params(request: BreakGlassRequest) -> dict[str, object]:
    return {
        "request_id": request.request_id,
        "tenant_id": request.tenant_id,
        "subject": request.subject,
        "requested_capability": request.requested_capability,
        "reason": request.reason,
        "requested_by": request.requested_by,
        "requested_at": _iso(request.requested_at),
        "duration_seconds": request.duration_seconds,
        "status": request.status.value,
        "approver": request.approver,
        "approved_at": _iso(request.approved_at) if request.approved_at else None,
        "expires_at": _iso(request.expires_at) if request.expires_at else None,
        "revoked_by": request.revoked_by,
        "revoked_at": _iso(request.revoked_at) if request.revoked_at else None,
        "created_at": _now_iso(),
    }


def _row_to_break_glass_request(row) -> BreakGlassRequest:
    return BreakGlassRequest(
        request_id=row["request_id"],
        tenant_id=row["tenant_id"],
        subject=row["subject"],
        requested_capability=row["requested_capability"],
        reason=row["reason"],
        requested_by=row["requested_by"],
        requested_at=_parse_iso(row["requested_at"]),
        duration_seconds=int(row["duration_seconds"]),
        status=BreakGlassStatus(row["status"]),
        approver=row["approver"],
        approved_at=_parse_iso(row["approved_at"]) if row["approved_at"] else None,
        expires_at=_parse_iso(row["expires_at"]) if row["expires_at"] else None,
        revoked_by=row["revoked_by"],
        revoked_at=_parse_iso(row["revoked_at"]) if row["revoked_at"] else None,
    )


__all__ = [
    "DbBreakGlassRepository",
    "DbDeviceRepository",
    "DbLifecycleRepository",
    "DbTimelineRepository",
]
