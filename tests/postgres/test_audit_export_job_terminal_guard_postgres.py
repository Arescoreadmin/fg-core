from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError


@pytest.mark.postgres
def test_audit_export_job_terminal_state_is_immutable(pg_engine: Engine):
    job_id = f"job-t-{uuid.uuid4().hex[:12]}"
    with pg_engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO audit_export_jobs(
                    tenant_id, job_id, idempotency_key, status, start_utc, end_utc,
                    purpose, retention_class, triggered_by, force
                ) VALUES (
                    'tenant-a', :job_id, :idem, 'queued',
                    '2026-01-01T00:00:00Z', '2026-01-01T01:00:00Z',
                    'audit', 'regulated', 'actor-1', false
                )
                """
            ),
            {"job_id": job_id, "idem": f"idem-{job_id}"},
        )
        conn.execute(
            text("UPDATE audit_export_jobs SET status='cancelled', last_error_code='AUDIT_EXPORT_JOB_CANCELLED' WHERE job_id=:job_id"),
            {"job_id": job_id},
        )

    with pytest.raises(DBAPIError):
        with pg_engine.begin() as conn:
            conn.execute(text("UPDATE audit_export_jobs SET status='running' WHERE job_id=:job_id"), {"job_id": job_id})
