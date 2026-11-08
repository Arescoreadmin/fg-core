"""Real-persistence fixtures for L14-SCAN-RUNNER-INTEGRITY-001.

A file-backed SQLite database built from the real ORM metadata (every FA table,
including fa_scan_evidence_envelopes / fa_evidence_custody_events), so the
evidence, custody and confidence authorities run unmocked.  Only external
network I/O is mocked by individual tests.  Synthetic data only.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

import api.db_models_field_assessment  # noqa: F401 — registers FA tables
from api.db_models import Base
from api.db_models_field_assessment import (
    FaEngagement,
    FaEvidenceCustodyEvent,
    FaNormalizedFinding,
    FaScanEvidenceEnvelope,
    FaScanJob,
)

T1 = "tenant-alpha"
T2 = "tenant-bravo"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/runner_integrity.db")

    # pysqlite: let SQLAlchemy own BEGIN so SAVEPOINT (begin_nested) works.
    @event.listens_for(engine, "connect")
    def _connect(dbapi_conn, _rec):
        dbapi_conn.isolation_level = None

    @event.listens_for(engine, "begin")
    def _begin(conn):
        conn.exec_driver_sql("BEGIN")

    tables = [t for name, t in Base.metadata.tables.items() if name.startswith("fa_")]
    Base.metadata.create_all(engine, tables=tables)
    with engine.begin() as conn:
        # Postgres-only table (migration 0200); same DDL api/db.py init_db() uses.
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS fa_scan_emergency_stops ("
            " id TEXT PRIMARY KEY, scope TEXT NOT NULL, activated_by TEXT NOT NULL,"
            " reason TEXT NOT NULL, activated_at TEXT, cleared_at TEXT,"
            " cleared_by TEXT, is_active BOOLEAN NOT NULL DEFAULT 1)"
        )
        # fa_scan_jobs cancellation columns (migration 0200; not in ORM).
        for col in (
            "cancel_requested_at",
            "cancelled_at",
            "cancellation_reason",
            "cancelled_by",
        ):
            conn.exec_driver_sql(f"ALTER TABLE fa_scan_jobs ADD COLUMN {col} TEXT")
    return engine, sessionmaker(bind=engine, expire_on_commit=False)


def seed_engagement(
    Session, *, tenant_id: str = T1, engagement_id: str | None = None
) -> str:
    eid = engagement_id or f"eng-{uuid.uuid4().hex[:8]}"
    with Session() as db:
        db.add(
            FaEngagement(
                id=eid,
                tenant_id=tenant_id,
                client_name="Synthetic Corp",
                assessor_id="assessor-1",
                assessment_type="ai_governance",
                created_at=now_iso(),
                updated_at=now_iso(),
            )
        )
        db.commit()
    return eid


def seed_job(
    Session,
    *,
    tenant_id: str,
    engagement_id: str,
    scanner_type: str,
    status: str = "queued",
) -> str:
    jid = str(uuid.uuid4())
    with Session() as db:
        db.add(
            FaScanJob(
                id=jid,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                verified_target_ids="[]",
                scanner_type=scanner_type,
                status=status,
                attempt_count=0,
                max_retries=3,
                actor="assessor-1",
                created_at=now_iso(),
            )
        )
        db.commit()
    return jid


def auth_context(
    *,
    tenant_id: str,
    engagement_id: str,
    job_id: str,
    scanner: str,
    receipt: str | None = None,
) -> dict[str, Any]:
    """The worker-start authorization record the guarded worker embeds (PR #812)."""
    return {
        "schema": "fg.scan_authorization_context.v1",
        "scan_job_id": job_id,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "scanner_type": scanner,
        "operation": scanner,
        "authorization_id": str(uuid.uuid4()),
        "authorization_version": 2,
        "customer_receipt_id": receipt or str(uuid.uuid4()),
        "consent_status": "CUSTOMER_APPROVED",
        "proof_level": "SERVER_ATTESTED_AUTHENTICATED_APPROVAL",
        "worker_start_authorized_at": now_iso(),
        "execution_checkpoints_passed": 3,
        "execution_denied_targets": [],
        "interrupted": None,
    }


def envelopes(db, **filters) -> list[FaScanEvidenceEnvelope]:
    q = db.query(FaScanEvidenceEnvelope)
    for k, v in filters.items():
        q = q.filter(getattr(FaScanEvidenceEnvelope, k) == v)
    return q.all()


def custody(db, evidence_id: str) -> list[FaEvidenceCustodyEvent]:
    return (
        db.query(FaEvidenceCustodyEvent)
        .filter(FaEvidenceCustodyEvent.evidence_id == evidence_id)
        .order_by(FaEvidenceCustodyEvent.created_at)
        .all()
    )


def findings(db, engagement_id: str) -> list[FaNormalizedFinding]:
    return (
        db.query(FaNormalizedFinding)
        .filter(FaNormalizedFinding.engagement_id == engagement_id)
        .all()
    )


def tamper_raw_payload(engine, scan_result_id: str, mutate) -> None:
    """Direct out-of-band edit of stored evidence (the attack being detected)."""
    import json

    with engine.begin() as conn:
        raw = conn.execute(
            text("SELECT raw_payload FROM fa_scan_results WHERE id = :i"),
            {"i": scan_result_id},
        ).scalar_one()
        payload = json.loads(raw) if isinstance(raw, str) else raw
        mutate(payload)
        conn.execute(
            text("UPDATE fa_scan_results SET raw_payload = :p WHERE id = :i"),
            {"p": json.dumps(payload), "i": scan_result_id},
        )
