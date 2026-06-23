"""Timeline Authority repository — append-only ledger storage."""

from __future__ import annotations

import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from services.timeline_authority.schemas import (
    TimelineConflict,
    TimelineEventNotFound,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger("frostgate.timeline_authority")

_GENESIS_HASH = "0" * 64


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _dt_to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def derive_event_id(
    tenant_id: str,
    entity_type: str,
    entity_id: str,
    event_type: str,
    occurred_at: str,
    source_system: str,
) -> str:
    canonical = json.dumps(
        {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "event_type": event_type,
            "occurred_at": occurred_at,
            "source_system": source_system,
            "tenant_id": tenant_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_event_hash(
    event_id: str,
    tenant_id: str,
    entity_type: str,
    entity_id: str,
    event_type: str,
    occurred_at: str,
    source_system: str,
    prev_event_hash: str,
    metadata_json: dict,
) -> str:
    canonical = json.dumps(
        {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "event_id": event_id,
            "event_type": event_type,
            "metadata_json": metadata_json,
            "occurred_at": occurred_at,
            "prev_event_hash": prev_event_hash,
            "source_system": source_system,
            "tenant_id": tenant_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class TimelineAuthorityRepository:
    """Stateless append-only timeline ledger operations."""

    def get_latest_event_hash(
        self,
        db: "Session",
        *,
        tenant_id: str,
        entity_type: str,
        entity_id: str,
    ) -> str:
        from api.db_models_timeline_authority import TimelineAuthorityEventRecord

        row = (
            db.query(TimelineAuthorityEventRecord)
            .filter(
                TimelineAuthorityEventRecord.tenant_id == tenant_id,
                TimelineAuthorityEventRecord.entity_type == entity_type,
                TimelineAuthorityEventRecord.entity_id == entity_id,
            )
            .order_by(
                TimelineAuthorityEventRecord.occurred_at.desc(),
                TimelineAuthorityEventRecord.id.asc(),
            )
            .first()
        )
        if row is None:
            return _GENESIS_HASH
        return row.event_hash or _GENESIS_HASH

    def insert(
        self,
        db: "Session",
        *,
        tenant_id: str,
        event_id: str,
        event_hash: str,
        prev_event_hash: str,
        source_system: str,
        source_type: str,
        entity_type: str,
        entity_id: str,
        event_type: str,
        actor_type: str,
        actor_id: str,
        occurred_at: datetime,
        severity: str,
        metadata_json: dict,
        correlation_id: str,
        causation_id: str,
        authority_level: str = "SYSTEM",
        signature_algorithm: str = "",
        signature_value: str = "",
        signed_at: datetime | None = None,
        external_reference: str = "",
        external_reference_type: str = "",
        origin_system: str = "",
        origin_tenant: str = "",
        origin_event_id: str = "",
    ):
        from api.db_models_timeline_authority import TimelineAuthorityEventRecord

        record = TimelineAuthorityEventRecord(
            id=event_id,
            tenant_id=tenant_id,
            event_id=event_id,
            event_hash=event_hash,
            prev_event_hash=prev_event_hash,
            source_system=source_system,
            source_type=source_type,
            entity_type=entity_type,
            entity_id=entity_id,
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            occurred_at=occurred_at,
            recorded_at=datetime.now(timezone.utc),
            severity=severity,
            metadata_json=metadata_json,
            correlation_id=correlation_id,
            causation_id=causation_id,
            authority_level=authority_level,
            signature_algorithm=signature_algorithm,
            signature_value=signature_value,
            signed_at=signed_at,
            external_reference=external_reference,
            external_reference_type=external_reference_type,
            origin_system=origin_system,
            origin_tenant=origin_tenant,
            origin_event_id=origin_event_id,
        )
        try:
            db.add(record)
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise TimelineConflict(f"Duplicate event_id: {event_id}") from exc
        return record

    def get_by_event_id(
        self,
        db: "Session",
        *,
        tenant_id: str,
        event_id: str,
    ):
        from api.db_models_timeline_authority import TimelineAuthorityEventRecord

        row = (
            db.query(TimelineAuthorityEventRecord)
            .filter(
                TimelineAuthorityEventRecord.tenant_id == tenant_id,
                TimelineAuthorityEventRecord.event_id == event_id,
            )
            .first()
        )
        if row is None:
            raise TimelineEventNotFound(f"Event {event_id} not found")
        return row

    def list_events(
        self,
        db: "Session",
        *,
        tenant_id: str,
        entity_type: str | None = None,
        source_system: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list:
        from api.db_models_timeline_authority import TimelineAuthorityEventRecord

        q = db.query(TimelineAuthorityEventRecord).filter(
            TimelineAuthorityEventRecord.tenant_id == tenant_id
        )
        if entity_type:
            q = q.filter(TimelineAuthorityEventRecord.entity_type == entity_type)
        if source_system:
            q = q.filter(TimelineAuthorityEventRecord.source_system == source_system)
        q = q.order_by(
            TimelineAuthorityEventRecord.occurred_at.asc(),
            TimelineAuthorityEventRecord.id.asc(),
        )
        return q.offset(offset).limit(min(limit, 200)).all()

    def get_entity_events(
        self,
        db: "Session",
        *,
        tenant_id: str,
        entity_type: str,
        entity_id: str,
    ) -> list:
        from api.db_models_timeline_authority import TimelineAuthorityEventRecord

        return (
            db.query(TimelineAuthorityEventRecord)
            .filter(
                TimelineAuthorityEventRecord.tenant_id == tenant_id,
                TimelineAuthorityEventRecord.entity_type == entity_type,
                TimelineAuthorityEventRecord.entity_id == entity_id,
            )
            .order_by(
                TimelineAuthorityEventRecord.occurred_at.asc(),
                TimelineAuthorityEventRecord.id.asc(),
            )
            .all()
        )

    def count_total(self, db: "Session", *, tenant_id: str) -> int:
        from api.db_models_timeline_authority import TimelineAuthorityEventRecord

        return (
            db.query(func.count(TimelineAuthorityEventRecord.id))
            .filter(TimelineAuthorityEventRecord.tenant_id == tenant_id)
            .scalar()
            or 0
        )

    def count_by_field(
        self, db: "Session", *, tenant_id: str, field_name: str
    ) -> dict[str, int]:
        from api.db_models_timeline_authority import TimelineAuthorityEventRecord

        col = getattr(TimelineAuthorityEventRecord, field_name)
        rows = (
            db.query(col, func.count(TimelineAuthorityEventRecord.id))
            .filter(TimelineAuthorityEventRecord.tenant_id == tenant_id)
            .group_by(col)
            .all()
        )
        return {str(k): v for k, v in rows}

    def distinct_entities(self, db: "Session", *, tenant_id: str) -> int:
        from api.db_models_timeline_authority import TimelineAuthorityEventRecord

        return (
            db.query(
                TimelineAuthorityEventRecord.entity_type,
                TimelineAuthorityEventRecord.entity_id,
            )
            .filter(TimelineAuthorityEventRecord.tenant_id == tenant_id)
            .distinct()
            .count()
        )

    def get_all_entity_pairs(
        self, db: "Session", *, tenant_id: str
    ) -> list[tuple[str, str]]:
        from api.db_models_timeline_authority import TimelineAuthorityEventRecord

        rows = (
            db.query(
                TimelineAuthorityEventRecord.entity_type,
                TimelineAuthorityEventRecord.entity_id,
            )
            .filter(TimelineAuthorityEventRecord.tenant_id == tenant_id)
            .distinct()
            .all()
        )
        return [(r[0], r[1]) for r in rows]
