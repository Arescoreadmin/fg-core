"""Timeline Authority engine — PR 14.6.2."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from services.timeline_authority.repository import (
    TimelineAuthorityRepository,
    compute_event_hash,
    derive_event_id,
    _GENESIS_HASH,
    _dt_to_iso,
)
from services.timeline_authority.schemas import (
    TimelineChainStatus,
    TimelineEventRecordRequest,
    TimelineEventResponse,
    TimelineExportChainSummary,
    TimelineExportResponse,
    TimelineIntegrityResponse,
    TimelineReplayResponse,
    TimelineSourceSystem,
    TimelineStatisticsResponse,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Prometheus counters (noop-safe)
# ---------------------------------------------------------------------------

try:
    from prometheus_client import Counter as _PrometheusCounter
except Exception:  # pragma: no cover
    _COUNTER_CLS = None
else:
    _COUNTER_CLS = _PrometheusCounter


class _NoopCounter:
    def inc(self, amount: float = 1.0) -> None:
        pass

    def labels(self, *args, **kwargs) -> "_NoopCounter":
        return self


def _counter(name: str, doc: str):
    if _COUNTER_CLS is None:
        return _NoopCounter()
    try:
        return _COUNTER_CLS(name, doc)
    except Exception:
        return _NoopCounter()


TIMELINE_EVENTS_RECORDED_TOTAL = _counter(
    "frostgate_timeline_authority_events_recorded_total",
    "Total events recorded by Timeline Authority",
)
TIMELINE_REPLAY_RUNS_TOTAL = _counter(
    "frostgate_timeline_authority_replay_runs_total",
    "Total Timeline Authority replay runs",
)
TIMELINE_EXPORTS_TOTAL = _counter(
    "frostgate_timeline_authority_exports_total",
    "Total Timeline Authority export operations",
)
TIMELINE_INTEGRITY_FAILURES_TOTAL = _counter(
    "frostgate_timeline_authority_integrity_failures_total",
    "Total Timeline Authority hash chain integrity failures detected",
)
TIMELINE_HASH_CHAIN_VALIDATIONS_TOTAL = _counter(
    "frostgate_timeline_authority_hash_chain_validations_total",
    "Total Timeline Authority hash chain validation runs",
)
TIMELINE_SOURCES_REGISTERED_TOTAL = _counter(
    "frostgate_timeline_authority_sources_registered_total",
    "Total registered source systems in Timeline Authority",
)

# ---------------------------------------------------------------------------
# Source registry
# ---------------------------------------------------------------------------

SOURCE_REGISTRY: dict[str, dict[str, str]] = {
    s.value: {
        "display_name": s.value.replace("_", " ").title(),
        "description": f"Events from the {s.value.replace('_', ' ').title()} subsystem",
    }
    for s in TimelineSourceSystem
}


def _record_to_response(row) -> TimelineEventResponse:
    def _iso(v) -> str:
        if isinstance(v, datetime):
            return _dt_to_iso(v)
        return str(v) if v is not None else ""

    return TimelineEventResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        event_id=row.event_id,
        event_hash=row.event_hash or "",
        prev_event_hash=row.prev_event_hash or "",
        source_system=row.source_system,
        source_type=row.source_type or "",
        entity_type=row.entity_type,
        entity_id=row.entity_id,
        event_type=row.event_type,
        actor_type=row.actor_type or "",
        actor_id=row.actor_id or "",
        occurred_at=_iso(row.occurred_at),
        recorded_at=_iso(row.recorded_at),
        severity=row.severity,
        metadata_json=row.metadata_json or {},
        correlation_id=row.correlation_id or "",
        causation_id=row.causation_id or "",
        replay_version=row.replay_version,
        schema_version=row.schema_version,
    )


class TimelineAuthorityEngine:
    def __init__(self, repository: TimelineAuthorityRepository | None = None) -> None:
        self._repo = repository or TimelineAuthorityRepository()

    def record_event(
        self,
        db: "Session",
        *,
        tenant_id: str,
        actor: str,
        payload: TimelineEventRecordRequest,
    ) -> TimelineEventResponse:
        occurred_dt = datetime.fromisoformat(payload.occurred_at.replace("Z", "+00:00"))
        occurred_iso = _dt_to_iso(occurred_dt)

        event_id = derive_event_id(
            tenant_id=tenant_id,
            entity_type=payload.entity_type.value,
            entity_id=payload.entity_id,
            event_type=payload.event_type,
            occurred_at=occurred_iso,
            source_system=payload.source_system.value,
        )

        prev_hash = self._repo.get_latest_event_hash(
            db,
            tenant_id=tenant_id,
            entity_type=payload.entity_type.value,
            entity_id=payload.entity_id,
        )

        event_hash = compute_event_hash(
            event_id=event_id,
            tenant_id=tenant_id,
            entity_type=payload.entity_type.value,
            entity_id=payload.entity_id,
            event_type=payload.event_type,
            occurred_at=occurred_iso,
            source_system=payload.source_system.value,
            prev_event_hash=prev_hash,
            metadata_json=payload.metadata_json,
        )

        actor_id = payload.actor_id or actor

        row = self._repo.insert(
            db,
            tenant_id=tenant_id,
            event_id=event_id,
            event_hash=event_hash,
            prev_event_hash=prev_hash,
            source_system=payload.source_system.value,
            source_type=payload.source_type,
            entity_type=payload.entity_type.value,
            entity_id=payload.entity_id,
            event_type=payload.event_type,
            actor_type=payload.actor_type.value,
            actor_id=actor_id,
            occurred_at=occurred_dt,
            severity=payload.severity.value,
            metadata_json=payload.metadata_json,
            correlation_id=payload.correlation_id,
            causation_id=payload.causation_id,
        )
        TIMELINE_EVENTS_RECORDED_TOTAL.inc()
        return _record_to_response(row)

    def get_event(
        self, db: "Session", *, tenant_id: str, event_id: str
    ) -> TimelineEventResponse:
        row = self._repo.get_by_event_id(db, tenant_id=tenant_id, event_id=event_id)
        return _record_to_response(row)

    def list_events(
        self,
        db: "Session",
        *,
        tenant_id: str,
        entity_type: str | None = None,
        source_system: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[TimelineEventResponse]:
        rows = self._repo.list_events(
            db,
            tenant_id=tenant_id,
            entity_type=entity_type,
            source_system=source_system,
            limit=limit,
            offset=offset,
        )
        return [_record_to_response(r) for r in rows]

    def get_entity_timeline(
        self,
        db: "Session",
        *,
        tenant_id: str,
        entity_type: str,
        entity_id: str,
    ) -> list[TimelineEventResponse]:
        rows = self._repo.get_entity_events(
            db,
            tenant_id=tenant_id,
            entity_type=entity_type,
            entity_id=entity_id,
        )
        return [_record_to_response(r) for r in rows]

    def replay(
        self,
        db: "Session",
        *,
        tenant_id: str,
        entity_type: str | None = None,
        entity_id: str | None = None,
        source_system: str | None = None,
    ) -> TimelineReplayResponse:
        TIMELINE_REPLAY_RUNS_TOTAL.inc()
        if entity_type and entity_id:
            rows = self._repo.get_entity_events(
                db,
                tenant_id=tenant_id,
                entity_type=entity_type,
                entity_id=entity_id,
            )
        else:
            rows = self._repo.list_events(
                db,
                tenant_id=tenant_id,
                entity_type=entity_type,
                source_system=source_system,
                limit=200,
                offset=0,
            )
        events = [_record_to_response(r) for r in rows]
        return TimelineReplayResponse(
            tenant_id=tenant_id,
            events=events,
            event_count=len(events),
            replay_deterministic=True,
            entity_type=entity_type,
            entity_id=entity_id,
            source_system=source_system,
        )

    def export(
        self,
        db: "Session",
        *,
        tenant_id: str,
        entity_type: str | None = None,
        entity_id: str | None = None,
    ) -> TimelineExportResponse:
        TIMELINE_EXPORTS_TOTAL.inc()
        if entity_type and entity_id:
            rows = self._repo.get_entity_events(
                db,
                tenant_id=tenant_id,
                entity_type=entity_type,
                entity_id=entity_id,
            )
        else:
            rows = self._repo.list_events(
                db,
                tenant_id=tenant_id,
                limit=200,
                offset=0,
            )
        events = [_record_to_response(r) for r in rows]

        # Build chain verification summary per entity
        entity_map: dict[tuple[str, str], list] = {}
        for r, ev in zip(rows, events):
            key = (r.entity_type, r.entity_id)
            entity_map.setdefault(key, []).append((r, ev))

        chain_summaries = []
        all_valid = True
        for (etype, eid), pairs in entity_map.items():
            valid = _verify_chain([p[0] for p in pairs])
            if not valid:
                all_valid = False
            chain_summaries.append(
                TimelineExportChainSummary(
                    entity_type=etype,
                    entity_id=eid,
                    event_count=len(pairs),
                    chain_valid=valid,
                    first_event_id=pairs[0][1].event_id,
                    last_event_id=pairs[-1][1].event_id,
                    last_event_hash=pairs[-1][1].event_hash,
                )
            )

        return TimelineExportResponse(
            tenant_id=tenant_id,
            format="json",
            events=events,
            event_count=len(events),
            integrity_status="valid" if all_valid else "invalid",
            chain_verification_summary=chain_summaries,
            deterministic_ordering=True,
        )

    def verify_integrity(
        self, db: "Session", *, tenant_id: str
    ) -> TimelineIntegrityResponse:
        TIMELINE_HASH_CHAIN_VALIDATIONS_TOTAL.inc()
        pairs = self._repo.get_all_entity_pairs(db, tenant_id=tenant_id)
        total_events = self._repo.count_total(db, tenant_id=tenant_id)

        chain_details = []
        valid_count = 0
        invalid_count = 0

        for entity_type, entity_id in pairs:
            rows = self._repo.get_entity_events(
                db,
                tenant_id=tenant_id,
                entity_type=entity_type,
                entity_id=entity_id,
            )
            chain_valid = _verify_chain(rows)
            broken_at = None
            if not chain_valid:
                TIMELINE_INTEGRITY_FAILURES_TOTAL.inc()
                invalid_count += 1
                # Find the first broken link
                for i, row in enumerate(rows[1:], 1):
                    if row.prev_event_hash != rows[i - 1].event_hash:
                        broken_at = row.event_id
                        break
            else:
                valid_count += 1
            chain_details.append(
                TimelineChainStatus(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    event_count=len(rows),
                    chain_valid=chain_valid,
                    broken_at_event_id=broken_at,
                )
            )

        return TimelineIntegrityResponse(
            tenant_id=tenant_id,
            total_events=total_events,
            chains_checked=len(pairs),
            chains_valid=valid_count,
            chains_invalid=invalid_count,
            integrity_valid=(invalid_count == 0),
            chain_details=chain_details,
            hash_chain_validations=len(pairs),
        )

    def get_statistics(
        self, db: "Session", *, tenant_id: str
    ) -> TimelineStatisticsResponse:
        total = self._repo.count_total(db, tenant_id=tenant_id)
        by_source = self._repo.count_by_field(
            db, tenant_id=tenant_id, field_name="source_system"
        )
        by_entity = self._repo.count_by_field(
            db, tenant_id=tenant_id, field_name="entity_type"
        )
        by_severity = self._repo.count_by_field(
            db, tenant_id=tenant_id, field_name="severity"
        )
        unique_entities = self._repo.distinct_entities(db, tenant_id=tenant_id)
        return TimelineStatisticsResponse(
            tenant_id=tenant_id,
            total_events=total,
            events_by_source_system=by_source,
            events_by_entity_type=by_entity,
            events_by_severity=by_severity,
            unique_entities=unique_entities,
            unique_source_systems=len(by_source),
        )


def _verify_chain(rows: list) -> bool:
    if not rows:
        return True
    if rows[0].prev_event_hash != _GENESIS_HASH:
        return False
    for i, row in enumerate(rows[1:], 1):
        if row.prev_event_hash != rows[i - 1].event_hash:
            return False
    return True
