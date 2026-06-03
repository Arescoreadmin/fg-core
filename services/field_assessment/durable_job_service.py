"""H12: DurableJobService — scan job lifecycle management.

All nine scan routes MUST call DurableJobService.create_job() before launching a
background task so that job state survives process restarts, deployment swaps, and
worker crashes.

Lease model
-----------
Every background worker identifies itself as  ``hostname:pid``.  After calling
mark_running() the worker owns a lease that expires in LEASE_TTL_SECONDS (300 s).
Workers that support long-running scans should call renew_lease() periodically.
DurableJobService.recover_orphans() detects jobs in 'running' state whose leases
have lapsed and either requeues them (retryable scanner types with remaining
attempts) or dead-letters them (MSAL interactive scans, or attempts exhausted).

Retry policy
------------
mark_failed() consults the job's attempt_count vs max_retries and the scanner's
membership in _RETRYABLE_SCANNER_TYPES:
  - retryable + attempts remaining → status='failed', next_retry_at set with
    exponential backoff (2^attempt_count * BASE_RETRY_SECONDS)
  - otherwise → status='dead_letter', completed_at set, lease cleared

MSAL device-code scans are non-retryable because they require interactive user
authentication that cannot be replayed automatically.

Idempotency
-----------
An optional idempotency_key (unique partial index) prevents duplicate job creation
for the same logical operation.  find_duplicate() returns an existing job if found.

Status values
-------------
  queued      — created, awaiting worker pickup
  running     — worker holds an active lease
  complete    — terminal: scan and import succeeded
  failed      — retryable: attempt failed, next_retry_at is set
  dead_letter — terminal: max retries exceeded or non-retryable failure
  cancelled   — terminal: operator-cancelled (set externally)
"""

from __future__ import annotations

import json
import os
import socket
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaScanJob
from services.canonical import utc_iso8601_z_now

LEASE_TTL_SECONDS = 300
BASE_RETRY_SECONDS = 30

# MSAL device-code scanner types require interactive user auth and cannot be
# automatically retried after a process restart.
_RETRYABLE_SCANNER_TYPES = frozenset(
    {
        "network_scan",
        "web_headers",
        "dns_email",
    }
)


def _worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


def _future_iso(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


class DurableJobService:
    """Lifecycle manager for fa_scan_jobs."""

    # ------------------------------------------------------------------
    # Creation / dedup
    # ------------------------------------------------------------------

    def create_job(
        self,
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
        actor: str,
        scanner_type: str,
        target_ids: list[str] | None = None,
        idempotency_key: str | None = None,
        metadata: dict | None = None,
        max_retries: int = 3,
    ) -> FaScanJob:
        """Create and persist a queued FaScanJob.  Returns existing job on dedup hit."""
        if idempotency_key:
            existing = self.find_duplicate(db, idempotency_key=idempotency_key)
            if existing is not None:
                return existing
        job = FaScanJob(
            id=uuid.uuid4().hex[:32],
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            verified_target_ids=json.dumps(target_ids or []),
            scanner_type=scanner_type,
            status="queued",
            attempt_count=0,
            max_retries=max_retries,
            idempotency_key=idempotency_key,
            scan_metadata=json.dumps(metadata) if metadata else None,
            actor=actor,
            created_at=utc_iso8601_z_now(),
        )
        db.add(job)
        db.flush()
        return job

    def find_duplicate(self, db: Session, *, idempotency_key: str) -> FaScanJob | None:
        return db.execute(
            select(FaScanJob).where(FaScanJob.idempotency_key == idempotency_key)
        ).scalar_one_or_none()

    # ------------------------------------------------------------------
    # Lease operations
    # ------------------------------------------------------------------

    def acquire_lease(
        self,
        db: Session,
        *,
        job_id: str,
        worker_id: str | None = None,
        ttl_seconds: int = LEASE_TTL_SECONDS,
    ) -> bool:
        """Atomically claim a queued job.  Returns True if lease was acquired."""
        worker = worker_id or _worker_id()
        now = utc_iso8601_z_now()
        result = db.execute(
            update(FaScanJob)
            .where(FaScanJob.id == job_id, FaScanJob.status == "queued")
            .values(
                lease_owner=worker,
                lease_acquired_at=now,
                lease_expires_at=_future_iso(ttl_seconds),
            )
        )
        return result.rowcount > 0

    def renew_lease(
        self,
        db: Session,
        *,
        job_id: str,
        worker_id: str | None = None,
        ttl_seconds: int = LEASE_TTL_SECONDS,
    ) -> bool:
        """Extend the lease expiry for a running job.  Returns True if extended."""
        worker = worker_id or _worker_id()
        result = db.execute(
            update(FaScanJob)
            .where(
                FaScanJob.id == job_id,
                FaScanJob.lease_owner == worker,
                FaScanJob.status == "running",
            )
            .values(lease_expires_at=_future_iso(ttl_seconds))
        )
        return result.rowcount > 0

    # ------------------------------------------------------------------
    # State transitions (called by background workers)
    # ------------------------------------------------------------------

    def mark_running(self, db: Session, *, job_id: str) -> None:
        db.execute(
            update(FaScanJob)
            .where(FaScanJob.id == job_id)
            .values(
                status="running",
                started_at=utc_iso8601_z_now(),
                attempt_count=FaScanJob.attempt_count + 1,
                lease_owner=_worker_id(),
                lease_acquired_at=utc_iso8601_z_now(),
                lease_expires_at=_future_iso(LEASE_TTL_SECONDS),
            )
        )

    def mark_complete(
        self,
        db: Session,
        *,
        job_id: str,
        scan_result_id: str | None = None,
    ) -> None:
        db.execute(
            update(FaScanJob)
            .where(FaScanJob.id == job_id)
            .values(
                status="complete",
                completed_at=utc_iso8601_z_now(),
                scan_result_id=scan_result_id,
                lease_owner=None,
                lease_acquired_at=None,
                lease_expires_at=None,
            )
        )

    def mark_failed(
        self,
        db: Session,
        *,
        job_id: str,
        failure_reason: str,
    ) -> None:
        """Mark failed; schedule retry if retryable with remaining attempts."""
        job = db.execute(
            select(FaScanJob).where(FaScanJob.id == job_id)
        ).scalar_one_or_none()
        if job is None:
            return

        can_retry = (
            job.scanner_type in _RETRYABLE_SCANNER_TYPES
            and job.attempt_count < job.max_retries
        )
        if can_retry:
            delay = BASE_RETRY_SECONDS * (2**job.attempt_count)
            db.execute(
                update(FaScanJob)
                .where(FaScanJob.id == job_id)
                .values(
                    status="failed",
                    failure_reason=failure_reason[:2000],
                    next_retry_at=_future_iso(delay),
                    lease_owner=None,
                    lease_acquired_at=None,
                    lease_expires_at=None,
                )
            )
        else:
            db.execute(
                update(FaScanJob)
                .where(FaScanJob.id == job_id)
                .values(
                    status="dead_letter",
                    failure_reason=failure_reason[:2000],
                    completed_at=utc_iso8601_z_now(),
                    lease_owner=None,
                    lease_acquired_at=None,
                    lease_expires_at=None,
                )
            )

    # ------------------------------------------------------------------
    # Query helpers (used by status route + new list/detail routes)
    # ------------------------------------------------------------------

    def get_job(
        self,
        db: Session,
        *,
        job_id: str,
        tenant_id: str,
    ) -> FaScanJob | None:
        return db.execute(
            select(FaScanJob).where(
                FaScanJob.id == job_id,
                FaScanJob.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()

    def list_jobs(
        self,
        db: Session,
        *,
        tenant_id: str,
        engagement_id: str,
        status: str | None = None,
        limit: int = 50,
    ) -> list[FaScanJob]:
        q = select(FaScanJob).where(
            FaScanJob.tenant_id == tenant_id,
            FaScanJob.engagement_id == engagement_id,
        )
        if status:
            q = q.where(FaScanJob.status == status)
        q = q.order_by(FaScanJob.created_at.desc()).limit(limit)
        return list(db.execute(q).scalars())

    # ------------------------------------------------------------------
    # Orphan recovery (call on worker startup or via a periodic task)
    # ------------------------------------------------------------------

    def recover_orphans(self, db: Session) -> int:
        """Requeue or dead-letter running jobs whose leases have expired.

        Returns the number of jobs recovered.
        """
        now = utc_iso8601_z_now()
        orphans = list(
            db.execute(
                select(FaScanJob).where(
                    FaScanJob.status == "running",
                    FaScanJob.lease_expires_at < now,
                )
            ).scalars()
        )
        for job in orphans:
            can_retry = (
                job.scanner_type in _RETRYABLE_SCANNER_TYPES
                and job.attempt_count < job.max_retries
            )
            if can_retry:
                job.status = "queued"
                job.lease_owner = None
                job.lease_acquired_at = None
                job.lease_expires_at = None
            else:
                job.status = "dead_letter"
                job.completed_at = now
                job.failure_reason = "orphan recovery: lease expired without completion"
                job.lease_owner = None
                job.lease_acquired_at = None
                job.lease_expires_at = None
        return len(orphans)

    # ------------------------------------------------------------------
    # Serialization helper
    # ------------------------------------------------------------------

    @staticmethod
    def job_to_dict(job: FaScanJob) -> dict:
        return {
            "job_id": job.id,
            "tenant_id": job.tenant_id,
            "engagement_id": job.engagement_id,
            "scanner_type": job.scanner_type,
            "status": job.status,
            "attempt_count": job.attempt_count,
            "max_retries": job.max_retries,
            "actor": job.actor,
            "scan_result_id": job.scan_result_id,
            "failure_reason": job.failure_reason,
            "next_retry_at": job.next_retry_at,
            "lease_owner": job.lease_owner,
            "lease_expires_at": job.lease_expires_at,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
        }


durable_job_svc = DurableJobService()
