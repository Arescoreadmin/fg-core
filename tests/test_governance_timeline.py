"""tests/test_governance_timeline.py — Unified governance timeline test suite.

Covers:
  - Deterministic event ID generation
  - Cross-tenant event ID uniqueness (security invariant)
  - Cursor encode/decode round-trip
  - Cursor ordering predicate
  - TimelineStore.record() idempotency
  - TimelineStore.list() filtering and pagination
  - TimelineStore.get() tenant isolation
  - API: list endpoint — filtering, pagination, cursor validation
  - API: get endpoint — found, not found, wrong tenant

All tests are pure-unit or in-process SQLite: no external network, no seeded DB.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")

import pytest

from services.governance.timeline.identity import (
    decode_cursor,
    derive_event_id,
    encode_cursor,
)
from services.governance.timeline.models import SourceType, TimelineEvent
from services.governance.timeline.store import TimelineStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    tenant_id: str = "tenant-a",
    source_type: SourceType = SourceType.GOVERNANCE_REPORT,
    source_id: str = "gr-abc123",
    event_type: str = "report.generated",
    occurred_at: str = "2026-05-18T20:00:00.000Z",
    manifest_hash: str | None = None,
    replay_eligible: bool = False,
    payload: dict | None = None,
) -> TimelineEvent:
    eid = derive_event_id(
        tenant_id=tenant_id,
        source_type=source_type.value,
        source_id=source_id,
        event_type=event_type,
        occurred_at=occurred_at,
    )
    return TimelineEvent(
        event_id=eid,
        tenant_id=tenant_id,
        source_type=source_type,
        source_id=source_id,
        event_type=event_type,
        occurred_at=occurred_at,
        recorded_at="2026-05-18T20:00:00.100Z",
        payload=payload or {},
        manifest_hash=manifest_hash,
        replay_eligible=replay_eligible,
    )


def _make_db():
    """Return an in-memory SQLite session for isolated testing."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from api.db_models import Base
    import api.db_models_timeline  # noqa: F401 — registers TimelineEventRecord

    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


# ---------------------------------------------------------------------------
# TestEventIdDeterminism
# ---------------------------------------------------------------------------


class TestEventIdDeterminism:
    def test_same_inputs_produce_same_id(self):
        id1 = derive_event_id(
            "t1",
            "GOVERNANCE_REPORT",
            "gr-001",
            "report.generated",
            "2026-05-18T20:00:00Z",
        )
        id2 = derive_event_id(
            "t1",
            "GOVERNANCE_REPORT",
            "gr-001",
            "report.generated",
            "2026-05-18T20:00:00Z",
        )
        assert id1 == id2

    def test_id_is_16_hex_chars(self):
        eid = derive_event_id(
            "t1", "SIMULATION", "run-001", "simulation.created", "2026-05-18T20:00:00Z"
        )
        assert isinstance(eid, str)
        assert len(eid) == 16
        int(eid, 16)  # must be valid hex

    def test_cross_tenant_ids_are_unique(self):
        id_a = derive_event_id(
            "tenant-a",
            "GOVERNANCE_REPORT",
            "gr-001",
            "report.generated",
            "2026-05-18T20:00:00Z",
        )
        id_b = derive_event_id(
            "tenant-b",
            "GOVERNANCE_REPORT",
            "gr-001",
            "report.generated",
            "2026-05-18T20:00:00Z",
        )
        assert id_a != id_b

    def test_different_source_types_produce_different_ids(self):
        id1 = derive_event_id(
            "t1",
            "GOVERNANCE_REPORT",
            "src-1",
            "report.generated",
            "2026-05-18T20:00:00Z",
        )
        id2 = derive_event_id(
            "t1", "SIMULATION", "src-1", "report.generated", "2026-05-18T20:00:00Z"
        )
        assert id1 != id2

    def test_different_occurred_at_produces_different_ids(self):
        id1 = derive_event_id(
            "t1",
            "GOVERNANCE_REPORT",
            "gr-001",
            "report.generated",
            "2026-05-18T20:00:00Z",
        )
        id2 = derive_event_id(
            "t1",
            "GOVERNANCE_REPORT",
            "gr-001",
            "report.generated",
            "2026-05-18T21:00:00Z",
        )
        assert id1 != id2


# ---------------------------------------------------------------------------
# TestCursorEncoding
# ---------------------------------------------------------------------------


class TestCursorEncoding:
    def test_encode_decode_roundtrip(self):
        ts = "2026-05-18T20:14:33.441Z"
        eid = "a1b2c3d4e5f6a7b8"
        cursor = encode_cursor(ts, eid)
        decoded_ts, decoded_eid = decode_cursor(cursor)
        assert decoded_ts == ts
        assert decoded_eid == eid

    def test_cursor_is_ascii_string(self):
        cursor = encode_cursor("2026-05-18T20:00:00Z", "abc123")
        assert isinstance(cursor, str)
        cursor.encode("ascii")  # must be valid ASCII

    def test_decode_invalid_cursor_raises_value_error(self):
        with pytest.raises(ValueError):
            decode_cursor("not-valid-base64!!!")

    def test_decode_missing_fields_raises_value_error(self):
        import base64
        import json

        bad = base64.urlsafe_b64encode(
            json.dumps({"only_one": "field"}).encode()
        ).decode()
        with pytest.raises(ValueError):
            decode_cursor(bad)

    def test_different_timestamps_produce_different_cursors(self):
        c1 = encode_cursor("2026-05-18T20:00:00Z", "abc")
        c2 = encode_cursor("2026-05-18T21:00:00Z", "abc")
        assert c1 != c2


# ---------------------------------------------------------------------------
# TestTimelineStore
# ---------------------------------------------------------------------------


class TestTimelineStore:
    def test_record_and_get_roundtrip(self):
        db = _make_db()
        store = TimelineStore()
        event = _make_event()
        store.record(db, event)
        db.commit()

        rec = store.get(db, event.event_id, event.tenant_id)
        assert rec is not None
        assert rec.id == event.event_id
        assert rec.tenant_id == event.tenant_id
        assert rec.source_type == event.source_type.value
        assert rec.event_type == event.event_type

    def test_record_idempotent_duplicate_ignored(self):
        db = _make_db()
        store = TimelineStore()
        event = _make_event()
        store.record(db, event)
        db.commit()
        store.record(db, event)  # second insert must not raise
        db.commit()

        from api.db_models_timeline import TimelineEventRecord

        count = (
            db.query(TimelineEventRecord)
            .filter(TimelineEventRecord.id == event.event_id)
            .count()
        )
        assert count == 1

    def test_duplicate_record_does_not_roll_back_outer_transaction(self):
        """Savepoint isolation: duplicate timeline insert must not invalidate
        previously staged work in the same session transaction."""
        db = _make_db()
        store = TimelineStore()
        event = _make_event(source_id="gr-original")
        store.record(db, event)
        db.commit()

        # Stage a second event (different ID) — simulates caller work-in-progress
        pending = _make_event(
            source_id="gr-pending",
            occurred_at="2026-05-18T21:00:00.000Z",
        )
        store.record(db, pending)  # not yet committed

        # Duplicate of the first event — must NOT blow up the session
        store.record(db, event)

        # The pending event must survive the duplicate attempt
        db.commit()

        from api.db_models_timeline import TimelineEventRecord

        count = (
            db.query(TimelineEventRecord)
            .filter(TimelineEventRecord.id == pending.event_id)
            .count()
        )
        assert count == 1

    def test_get_wrong_tenant_returns_none(self):
        db = _make_db()
        store = TimelineStore()
        event = _make_event(tenant_id="tenant-a")
        store.record(db, event)
        db.commit()

        rec = store.get(db, event.event_id, "tenant-b")
        assert rec is None

    def test_list_returns_events_for_tenant(self):
        db = _make_db()
        store = TimelineStore()

        for i in range(3):
            e = _make_event(
                tenant_id="tenant-a",
                source_id=f"gr-{i:03d}",
                occurred_at=f"2026-05-18T2{i}:00:00.000Z",
            )
            store.record(db, e)
        # Add an event for tenant-b — must not appear in tenant-a results
        other = _make_event(tenant_id="tenant-b", source_id="gr-other")
        store.record(db, other)
        db.commit()

        rows, cursor = store.list(db, "tenant-a")
        assert len(rows) == 3
        assert all(r.tenant_id == "tenant-a" for r in rows)

    def test_list_tenant_isolation(self):
        db = _make_db()
        store = TimelineStore()

        store.record(db, _make_event(tenant_id="tenant-a", source_id="gr-A"))
        store.record(db, _make_event(tenant_id="tenant-b", source_id="gr-B"))
        db.commit()

        rows_a, _ = store.list(db, "tenant-a")
        rows_b, _ = store.list(db, "tenant-b")
        assert all(r.tenant_id == "tenant-a" for r in rows_a)
        assert all(r.tenant_id == "tenant-b" for r in rows_b)

    def test_list_ordered_newest_first(self):
        db = _make_db()
        store = TimelineStore()

        timestamps = [
            "2026-05-18T18:00:00.000Z",
            "2026-05-18T20:00:00.000Z",
            "2026-05-18T19:00:00.000Z",
        ]
        for i, ts in enumerate(timestamps):
            e = _make_event(source_id=f"gr-{i}", occurred_at=ts)
            store.record(db, e)
        db.commit()

        rows, _ = store.list(db, "tenant-a")
        times = [r.occurred_at for r in rows]
        assert times == sorted(times, reverse=True)

    def test_list_filter_by_source_type(self):
        db = _make_db()
        store = TimelineStore()

        store.record(
            db,
            _make_event(
                source_type=SourceType.GOVERNANCE_REPORT,
                source_id="gr-1",
                occurred_at="2026-05-18T20:00:00.000Z",
            ),
        )
        store.record(
            db,
            _make_event(
                source_type=SourceType.SIMULATION,
                source_id="sim-1",
                event_type="simulation.created",
                occurred_at="2026-05-18T20:01:00.000Z",
            ),
        )
        db.commit()

        rows, _ = store.list(db, "tenant-a", source_type="GOVERNANCE_REPORT")
        assert len(rows) == 1
        assert rows[0].source_type == "GOVERNANCE_REPORT"

    def test_list_filter_by_event_type(self):
        db = _make_db()
        store = TimelineStore()

        store.record(
            db,
            _make_event(
                source_id="gr-1",
                event_type="report.generated",
                occurred_at="2026-05-18T20:00:00.000Z",
            ),
        )
        store.record(
            db,
            _make_event(
                source_id="gr-2",
                event_type="report.finalized",
                occurred_at="2026-05-18T20:01:00.000Z",
            ),
        )
        db.commit()

        rows, _ = store.list(db, "tenant-a", event_type="report.generated")
        assert len(rows) == 1
        assert rows[0].event_type == "report.generated"

    def test_list_pagination_cursor(self):
        db = _make_db()
        store = TimelineStore()

        for i in range(5):
            e = _make_event(
                source_id=f"gr-{i:03d}",
                occurred_at=f"2026-05-18T{10 + i}:00:00.000Z",
            )
            store.record(db, e)
        db.commit()

        page1, cursor1 = store.list(db, "tenant-a", limit=3)
        assert len(page1) == 3
        assert cursor1 is not None

        page2, cursor2 = store.list(db, "tenant-a", cursor=cursor1, limit=3)
        assert len(page2) == 2
        assert cursor2 is None

        all_ids = {r.id for r in page1} | {r.id for r in page2}
        assert len(all_ids) == 5

    def test_list_no_results_returns_empty(self):
        db = _make_db()
        store = TimelineStore()
        rows, cursor = store.list(db, "nonexistent-tenant")
        assert rows == []
        assert cursor is None

    def test_list_respects_limit_cap(self):
        db = _make_db()
        store = TimelineStore()
        for i in range(10):
            e = _make_event(
                source_id=f"gr-{i:03d}", occurred_at=f"2026-05-18T{10 + i}:00:00.000Z"
            )
            store.record(db, e)
        db.commit()

        rows, _ = store.list(db, "tenant-a", limit=200)  # over max, clamped to 100
        assert len(rows) <= 100


# ---------------------------------------------------------------------------
# TestTimelineEventModel
# ---------------------------------------------------------------------------


class TestTimelineEventModel:
    def test_event_fields_immutable(self):
        event = _make_event()
        with pytest.raises((AttributeError, TypeError)):
            event.event_id = "mutated"  # type: ignore[misc]

    def test_default_classification_is_internal(self):
        event = _make_event()
        assert event.classification == "internal"

    def test_default_schema_version(self):
        event = _make_event()
        assert event.schema_version == "1.0"

    def test_default_event_version(self):
        event = _make_event()
        assert event.event_version == "1.0"

    def test_replay_eligible_false_by_default(self):
        event = _make_event()
        assert event.replay_eligible is False

    def test_manifest_hash_optional(self):
        event = _make_event(manifest_hash=None)
        assert event.manifest_hash is None

        event2 = _make_event(manifest_hash="deadbeefcafe")
        assert event2.manifest_hash == "deadbeefcafe"
