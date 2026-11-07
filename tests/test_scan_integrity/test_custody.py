"""
Tests for the chain-of-custody service.

L14-SCAN-INTEGRITY-001 — test_custody.py

Uses an in-memory SQLite database (via SQLAlchemy) to test real custody
event insertion and retrieval without requiring a running Postgres instance.

Verifies:
- record() stores event with correct fields
- get_history() returns events in creation order
- Cross-tenant lookup raises PermissionError (fail-closed)
- Duplicate event types allowed (idempotent logging)
- Out-of-order event types allowed (append-only, no enforcement)
- Nonexistent evidence raises LookupError
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from services.field_assessment.custody import (
    CustodyEventType,
    EvidenceCustodyService,
)


# ---------------------------------------------------------------------------
# In-memory SQLite setup
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS fa_scan_evidence_envelopes (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    scan_result_id TEXT,
    scan_job_id TEXT,
    schema_version TEXT NOT NULL DEFAULT '1.0',
    scanner_id TEXT NOT NULL,
    scanner_version TEXT,
    authorization_ref TEXT,
    authorization_version INTEGER,
    collected_at TEXT NOT NULL,
    collection_status TEXT NOT NULL DEFAULT 'complete',
    source_type TEXT NOT NULL,
    source_id TEXT,
    payload_digest TEXT NOT NULL,
    canonicalization_ver TEXT NOT NULL DEFAULT '1.0',
    provenance_status TEXT NOT NULL DEFAULT 'UNVERIFIED',
    signature_ref TEXT,
    data_sensitivity TEXT NOT NULL DEFAULT 'internal',
    correlation_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fa_evidence_custody_events (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    actor_type TEXT NOT NULL DEFAULT 'system',
    from_state TEXT,
    to_state TEXT,
    reason TEXT,
    correlation_id TEXT,
    digest_ref TEXT,
    created_at TEXT NOT NULL
);
"""


def _make_session() -> Session:
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    with engine.connect() as conn:
        for stmt in _DDL.strip().split(";"):
            s = stmt.strip()
            if s:
                conn.execute(text(s))
        conn.commit()
    Session_ = sessionmaker(bind=engine)
    return Session_()


def _insert_envelope(
    db: Session,
    tenant_id: str = "tenant-abc",
    engagement_id: str = "eng-001",
    envelope_id: str | None = None,
) -> str:
    eid = envelope_id or str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        text(
            """
            INSERT INTO fa_scan_evidence_envelopes
                (id, tenant_id, engagement_id, scanner_id, collected_at,
                 source_type, payload_digest, created_at, updated_at)
            VALUES
                (:id, :tid, :eid, :scanner, :cat, :src, :digest, :cat, :cat)
            """
        ),
        {
            "id": eid,
            "tid": tenant_id,
            "eid": engagement_id,
            "scanner": "network_scan",
            "cat": now,
            "src": "scan_result",
            "digest": "sha256:aabbcc",
        },
    )
    db.commit()
    return eid


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCustodyRecord:
    def test_record_stores_event(self):
        """record() must insert a custody event with the correct fields."""
        svc = EvidenceCustodyService()
        db = _make_session()
        eid = _insert_envelope(db)

        event_id = svc.record(
            db,
            evidence_id=eid,
            tenant_id="tenant-abc",
            engagement_id="eng-001",
            event_type=CustodyEventType.COLLECTED,
            actor="scanner:network_scan",
        )
        assert event_id is not None

        row = db.execute(
            text("SELECT * FROM fa_evidence_custody_events WHERE id = :id"),
            {"id": event_id},
        ).fetchone()
        assert row is not None
        assert row.evidence_id == eid
        assert row.tenant_id == "tenant-abc"
        assert row.event_type == "COLLECTED"
        assert row.actor == "scanner:network_scan"
        assert row.actor_type == "system"

    def test_record_stores_optional_fields(self):
        """Optional fields (from_state, to_state, reason, correlation_id, digest_ref)
        must be stored when provided."""
        svc = EvidenceCustodyService()
        db = _make_session()
        eid = _insert_envelope(db)

        event_id = svc.record(
            db,
            evidence_id=eid,
            tenant_id="tenant-abc",
            engagement_id="eng-001",
            event_type=CustodyEventType.VERIFIED,
            actor="integrity-service",
            from_state="UNVERIFIED",
            to_state="VERIFIED_INTEGRITY_ONLY",
            reason="digest check passed",
            correlation_id="corr-xyz",
            digest_ref="sha256:aabbcc",
        )
        row = db.execute(
            text("SELECT * FROM fa_evidence_custody_events WHERE id = :id"),
            {"id": event_id},
        ).fetchone()
        assert row.from_state == "UNVERIFIED"
        assert row.to_state == "VERIFIED_INTEGRITY_ONLY"
        assert row.reason == "digest check passed"
        assert row.correlation_id == "corr-xyz"
        assert row.digest_ref == "sha256:aabbcc"

    def test_record_returns_event_id_string(self):
        """record() must return a non-empty string event ID."""
        svc = EvidenceCustodyService()
        db = _make_session()
        eid = _insert_envelope(db)
        event_id = svc.record(
            db,
            evidence_id=eid,
            tenant_id="tenant-abc",
            engagement_id="eng-001",
            event_type=CustodyEventType.INGESTED,
            actor="system",
        )
        assert isinstance(event_id, str)
        assert len(event_id) > 0
        # Should be a valid UUID
        uuid.UUID(event_id)

    def test_cross_tenant_raises_permission_error(self):
        """record() with wrong tenant_id must raise PermissionError (fail-closed)."""
        svc = EvidenceCustodyService()
        db = _make_session()
        eid = _insert_envelope(db, tenant_id="tenant-owner")

        with pytest.raises(PermissionError):
            svc.record(
                db,
                evidence_id=eid,
                tenant_id="tenant-attacker",
                engagement_id="eng-001",
                event_type=CustodyEventType.COLLECTED,
                actor="attacker",
            )

    def test_nonexistent_evidence_raises_lookup_error(self):
        """record() for nonexistent evidence_id must raise LookupError."""
        svc = EvidenceCustodyService()
        db = _make_session()

        with pytest.raises(LookupError):
            svc.record(
                db,
                evidence_id="nonexistent-id",
                tenant_id="tenant-abc",
                engagement_id="eng-001",
                event_type=CustodyEventType.COLLECTED,
                actor="system",
            )

    def test_duplicate_event_type_allowed(self):
        """Duplicate event types must be allowed (idempotent logging)."""
        svc = EvidenceCustodyService()
        db = _make_session()
        eid = _insert_envelope(db)

        event_id_1 = svc.record(
            db,
            evidence_id=eid,
            tenant_id="tenant-abc",
            engagement_id="eng-001",
            event_type=CustodyEventType.COLLECTED,
            actor="system",
        )
        # Second COLLECTED event (retry after transient failure)
        event_id_2 = svc.record(
            db,
            evidence_id=eid,
            tenant_id="tenant-abc",
            engagement_id="eng-001",
            event_type=CustodyEventType.COLLECTED,
            actor="system",
        )
        assert event_id_1 != event_id_2  # Both stored, distinct IDs

        rows = db.execute(
            text(
                "SELECT id FROM fa_evidence_custody_events "
                "WHERE evidence_id = :eid AND event_type = 'COLLECTED'"
            ),
            {"eid": eid},
        ).fetchall()
        assert len(rows) == 2


class TestCustodyGetHistory:
    def test_get_history_returns_events_in_order(self):
        """get_history() must return events in ascending created_at order."""
        svc = EvidenceCustodyService()
        db = _make_session()
        eid = _insert_envelope(db)

        for event_type in [
            CustodyEventType.COLLECTED,
            CustodyEventType.INGESTED,
            CustodyEventType.VERIFIED,
            CustodyEventType.LOCKED,
        ]:
            svc.record(
                db,
                evidence_id=eid,
                tenant_id="tenant-abc",
                engagement_id="eng-001",
                event_type=event_type,
                actor="system",
            )

        history = svc.get_history(db, evidence_id=eid, tenant_id="tenant-abc")
        assert len(history) == 4
        event_types = [h["event_type"] for h in history]
        assert event_types == ["COLLECTED", "INGESTED", "VERIFIED", "LOCKED"]

    def test_get_history_returns_list_of_dicts(self):
        """get_history() must return a list of dicts."""
        svc = EvidenceCustodyService()
        db = _make_session()
        eid = _insert_envelope(db)
        svc.record(
            db,
            evidence_id=eid,
            tenant_id="tenant-abc",
            engagement_id="eng-001",
            event_type=CustodyEventType.COLLECTED,
            actor="system",
        )
        history = svc.get_history(db, evidence_id=eid, tenant_id="tenant-abc")
        assert isinstance(history, list)
        assert all(isinstance(h, dict) for h in history)

    def test_get_history_cross_tenant_raises(self):
        """get_history() with wrong tenant must raise PermissionError."""
        svc = EvidenceCustodyService()
        db = _make_session()
        eid = _insert_envelope(db, tenant_id="tenant-owner")

        with pytest.raises(PermissionError):
            svc.get_history(db, evidence_id=eid, tenant_id="tenant-attacker")

    def test_get_history_nonexistent_raises_lookup_error(self):
        """get_history() for nonexistent evidence must raise LookupError."""
        svc = EvidenceCustodyService()
        db = _make_session()
        with pytest.raises(LookupError):
            svc.get_history(db, evidence_id="does-not-exist", tenant_id="tenant-abc")

    def test_out_of_order_event_allowed(self):
        """Events may be recorded out of logical order (append-only, no enforcement)."""
        svc = EvidenceCustodyService()
        db = _make_session()
        eid = _insert_envelope(db)

        # Record LOCKED before INGESTED — out-of-order is allowed
        svc.record(
            db,
            evidence_id=eid,
            tenant_id="tenant-abc",
            engagement_id="eng-001",
            event_type=CustodyEventType.LOCKED,
            actor="system",
        )
        svc.record(
            db,
            evidence_id=eid,
            tenant_id="tenant-abc",
            engagement_id="eng-001",
            event_type=CustodyEventType.INGESTED,
            actor="system",
        )

        history = svc.get_history(db, evidence_id=eid, tenant_id="tenant-abc")
        assert len(history) == 2
        # Order is by created_at, not by logical workflow order
        assert history[0]["event_type"] == "LOCKED"
        assert history[1]["event_type"] == "INGESTED"

    def test_empty_history_returned_for_new_envelope(self):
        """A freshly inserted envelope with no events has empty history."""
        svc = EvidenceCustodyService()
        db = _make_session()
        eid = _insert_envelope(db)
        history = svc.get_history(db, evidence_id=eid, tenant_id="tenant-abc")
        assert history == []
