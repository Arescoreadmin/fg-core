from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text


@pytest.mark.skipif(not os.getenv("FG_DB_URL"), reason="FG_DB_URL not configured")
def test_postgres_migrations_apply_smoke() -> None:
    engine = create_engine(os.environ["FG_DB_URL"], future=True)
    with engine.connect() as conn:
        tables = {
            row[0]
            for row in conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname='public'")
            )
        }
        assert "schema_migrations" in tables
        assert "decisions" in tables

        versions = {
            row[0]
            for row in conn.execute(text("SELECT version FROM schema_migrations"))
        }
        assert "0007" in versions

        row = conn.execute(
            text(
                """
                SELECT relrowsecurity, relforcerowsecurity
                FROM pg_class
                WHERE relname = 'decisions'
                """
            )
        ).one()
        assert row[0] is True
        assert row[1] is True


@pytest.mark.skipif(not os.getenv("FG_DB_URL"), reason="FG_DB_URL not configured")
def test_postgres_runtime_evidence_round_trip() -> None:
    """L14-SCAN-RUNNER-INTEGRITY-001: capture against the MIGRATED Postgres schema.

    Exercises the ORM/psycopg binding of UUID, TIMESTAMPTZ and
    fa_collection_status_enum columns (finding/job inserts, envelope insert,
    finding updates), raw custody inserts, the 0204 immutability trigger, and
    the evidence manifest.  Runs inside a transaction that is always rolled back.
    """
    import uuid

    from sqlalchemy.orm import Session

    from api.db_models_field_assessment import (
        FaEngagement,
        FaNormalizedFinding,
        FaScanEvidenceEnvelope,
        FaScanJob,
    )
    from services.field_assessment import runtime_evidence as rte
    from services.field_assessment.connectors.web_headers_bridge import (
        import_web_headers_scan,
    )
    from services.field_assessment.evidence_integrity import ProvenanceStatus

    engine = create_engine(os.environ["FG_DB_URL"], future=True)
    conn = engine.connect()
    trans = conn.begin()
    db = Session(bind=conn, join_transaction_mode="create_savepoint")
    try:
        tenant = f"pg-rte-{uuid.uuid4().hex[:8]}"
        eid = uuid.uuid4().hex
        now = "2026-11-08T00:00:00+00:00"
        db.add(
            FaEngagement(
                id=eid,
                tenant_id=tenant,
                client_name="Synthetic PG",
                assessor_id="a",
                assessment_type="ai_governance",
                created_at=now,
                updated_at=now,
            )
        )
        db.flush()
        auth_id = conn.execute(
            text(
                "INSERT INTO fa_scan_authorizations (tenant_id, engagement_id, "
                "authorization_ref, approved_targets, status, expires_at) VALUES "
                "(:t, :e, 'ROE-SYNTH', '[]'::jsonb, 'active', NOW() + interval '1 day') "
                "RETURNING id"
            ),
            {"t": tenant, "e": eid},
        ).scalar_one()
        job_id = str(uuid.uuid4())
        db.add(  # collection_status unset → must not bind NULL::VARCHAR into the enum
            FaScanJob(
                id=job_id,
                tenant_id=tenant,
                engagement_id=eid,
                verified_target_ids="[]",
                scanner_type="web_headers",
                status="running",
                attempt_count=1,
                max_retries=3,
                actor="a",
                created_at=now,
            )
        )
        db.flush()
        payload = {
            "targets": [
                {
                    "url": "https://app.example.com",
                    "collection_status": "COMPLETE",
                    "error": None,
                }
            ],
            "findings": [
                {
                    "type": "missing_hsts",
                    "severity": "high",
                    "title": "t",
                    "description": "d",
                    "target": "app.example.com",
                }
            ],
            "collection_status": "COMPLETE",
            "authorization_context": {
                "tenant_id": tenant,
                "engagement_id": eid,
                "scan_job_id": job_id,
                "scanner_type": "web_headers",
                "authorization_id": str(auth_id),
                "authorization_version": 1,
                "customer_receipt_id": None,
                "proof_level": "LEGACY_OPERATOR_ASSERTED",
            },
        }
        sr = import_web_headers_scan(
            db=db, tenant_id=tenant, engagement_id=eid, scan_result=payload, actor="a"
        ).scan_result_id
        res = rte.capture_with_retry(
            db,
            tenant_id=tenant,
            engagement_id=eid,
            scan_result_id=sr,
            scanner_id="web_headers",
            scan_job_id=job_id,
        )
        assert res.created == 2 and res.findings_linked == 1
        db.flush()
        envs = db.query(FaScanEvidenceEnvelope).filter_by(tenant_id=tenant).all()
        assert {e.scan_job_id for e in envs} == {job_id}
        assert {e.authorization_ref for e in envs} == {str(auth_id)}
        (finding,) = db.query(FaNormalizedFinding).filter_by(tenant_id=tenant).all()
        assert finding.collection_status == "COMPLETE"
        assert finding.confidence_level == "CONFIRMED"
        status = rte.verify_stored_evidence(
            db, tenant_id=tenant, evidence_id=res.scan_envelope_id, record_custody=True
        )
        assert status == ProvenanceStatus.VERIFIED_INTEGRITY_ONLY
        manifest = rte.build_evidence_manifest(db, tenant_id=tenant, engagement_id=eid)
        assert (
            manifest["findings"][0]["evidence_integrity_status"] == "INTEGRITY_VERIFIED"
        )
        # 0204 trigger: captured digest is immutable at the database level.
        db.flush()
        with pytest.raises(Exception, match="immutable"):
            with conn.begin_nested():
                conn.execute(
                    text(
                        "UPDATE fa_scan_evidence_envelopes SET payload_digest = 'sha256:x' WHERE id = :i"
                    ),
                    {"i": res.scan_envelope_id},
                )
    finally:
        db.close()
        trans.rollback()
        conn.close()
