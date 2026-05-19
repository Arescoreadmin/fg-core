"""services/governance/timeline/store.py — Timeline storage operations.

TimelineStore is a stateless service object (no mutable class-level state).
All methods accept a SQLAlchemy Session explicitly; callers manage transactions.

Write contract:
  record() is idempotent — duplicate event_id for the same tenant is a no-op.
  Primary-key conflict is caught and swallowed; no error is raised.

Read contract:
  list() returns at most `limit` events (clamped to 1–100) newest-first.
  Pagination uses a cursor over (occurred_at DESC, id ASC) — stable under
  concurrent inserts unlike OFFSET pagination.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sqlalchemy.exc import IntegrityError

from .identity import decode_cursor, encode_cursor
from .models import SourceType, TimelineEvent

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger("frostgate.governance.timeline")

_LIMIT_MAX = 100
_LIMIT_DEFAULT = 50


class TimelineStore:
    """Append-only timeline event store.  Thread-safe: no instance state."""

    def record(self, db: "Session", event: TimelineEvent) -> None:
        """Persist a timeline event.  Idempotent: duplicate IDs are silently ignored."""
        from api.db_models_timeline import TimelineEventRecord

        source_type_val = (
            event.source_type.value
            if isinstance(event.source_type, SourceType)
            else str(event.source_type)
        )
        record = TimelineEventRecord(
            id=event.event_id,
            tenant_id=event.tenant_id,
            source_type=source_type_val,
            source_id=event.source_id,
            event_type=event.event_type,
            occurred_at=event.occurred_at,
            recorded_at=event.recorded_at,
            payload=dict(event.payload),
            classification=event.classification,
            manifest_hash=event.manifest_hash,
            replay_eligible=event.replay_eligible,
            schema_version=event.schema_version,
            event_version=event.event_version,
        )
        sp = db.begin_nested()
        try:
            db.add(record)
            db.flush()
            sp.commit()
        except IntegrityError:
            sp.rollback()
            logger.debug(
                "timeline.record_duplicate event_id=%s — already exists, skipped",
                event.event_id,
            )
        except Exception:
            sp.rollback()
            raise

    def get(
        self,
        db: "Session",
        event_id: str,
        tenant_id: str,
    ):
        """Return a single TimelineEventRecord or None.  Always tenant-scoped."""
        from api.db_models_timeline import TimelineEventRecord

        return (
            db.query(TimelineEventRecord)
            .filter(
                TimelineEventRecord.id == event_id,
                TimelineEventRecord.tenant_id == tenant_id,
            )
            .first()
        )

    def list(
        self,
        db: "Session",
        tenant_id: str,
        *,
        source_type: str | None = None,
        event_type: str | None = None,
        from_dt: str | None = None,
        to_dt: str | None = None,
        cursor: str | None = None,
        limit: int = _LIMIT_DEFAULT,
    ) -> tuple[list, str | None]:
        """Return (rows, next_cursor).

        next_cursor is None when there are no more results.
        Rows are ordered: occurred_at DESC, id ASC (deterministic tie-break).
        """
        from api.db_models_timeline import TimelineEventRecord

        limit = min(max(1, limit), _LIMIT_MAX)

        q = db.query(TimelineEventRecord).filter(
            TimelineEventRecord.tenant_id == tenant_id
        )

        if source_type:
            q = q.filter(TimelineEventRecord.source_type == source_type)
        if event_type:
            q = q.filter(TimelineEventRecord.event_type == event_type)
        if from_dt:
            q = q.filter(TimelineEventRecord.occurred_at >= from_dt)
        if to_dt:
            q = q.filter(TimelineEventRecord.occurred_at < to_dt)

        if cursor:
            cursor_time, cursor_id = decode_cursor(cursor)
            q = q.filter(
                (TimelineEventRecord.occurred_at < cursor_time)
                | (
                    (TimelineEventRecord.occurred_at == cursor_time)
                    & (TimelineEventRecord.id > cursor_id)
                )
            )

        q = q.order_by(
            TimelineEventRecord.occurred_at.desc(),
            TimelineEventRecord.id.asc(),
        )

        rows = q.limit(limit + 1).all()
        has_more = len(rows) > limit
        rows = rows[:limit]

        next_cursor: str | None = None
        if has_more and rows:
            last = rows[-1]
            next_cursor = encode_cursor(last.occurred_at, last.id)

        return rows, next_cursor
