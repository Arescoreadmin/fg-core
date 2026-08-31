"""AUTH-ROLE-001B: Projection worker — consumes identity_projection_outbox rows.

Responsibilities:
- Poll ``identity_projection_outbox`` for ``pending`` rows.
- Lock each row with ``SELECT ... FOR UPDATE SKIP LOCKED`` so multiple worker
  instances do not process the same row concurrently.
- Compare ``projection_revision`` against the existing value in Auth0
  app_metadata before writing (stale-write safety).
- Call ``Auth0ManagementClient.update_user_app_metadata`` when the incoming
  revision is strictly greater than the stored one (or the field is absent).
- On success: mark ``done``, set ``processed_at``.
- On failure: mark ``pending`` again with exponential backoff on
  ``next_attempt_at``, set ``last_error_code``.
- On duplicate/stale revision: treat as success (converge safely).
- Never roll back FrostGate state; all failures are retryable.

Auth0 tokens/credentials are never stored in or read from the outbox.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from admin_gateway.identity.auth0_management import (
    Auth0ManagementClient,
    Auth0ManagementError,
    Auth0RateLimitError,
)

log = logging.getLogger("admin-gateway.identity.projection_worker")

# ------------------------------------------------------------------
# Backoff schedule (seconds): attempt 1→30s, 2→120s, 3→600s, max 3600s
# ------------------------------------------------------------------
_BACKOFF_SECONDS = [30, 120, 600, 3600]

# NOTE: FOR UPDATE SKIP LOCKED is PostgreSQL-only.  Tests that run against
# SQLite must patch ``_fetch_pending_rows`` or use the ``_sqlite_mode`` path.
_SELECT_PENDING_SQL = text(
    """
    SELECT id, principal_id, membership_id, tenant_id,
           provider, provider_subject, roles, projection_revision,
           attempt_count
    FROM identity_projection_outbox
    WHERE status IN ('pending', 'processing')
      AND next_attempt_at <= now()
    ORDER BY next_attempt_at
    LIMIT :limit
    FOR UPDATE SKIP LOCKED
    """
)

_SELECT_PENDING_SQLITE_SQL = text(
    """
    SELECT id, principal_id, membership_id, tenant_id,
           provider, provider_subject, roles, projection_revision,
           attempt_count
    FROM identity_projection_outbox
    WHERE status IN ('pending', 'processing')
      AND julianday(next_attempt_at) <= julianday('now')
    ORDER BY next_attempt_at
    LIMIT :limit
    """
)

_MARK_PROCESSING_SQL = text(
    """
    UPDATE identity_projection_outbox
    SET status        = 'processing',
        attempt_count = attempt_count + 1
    WHERE id = :id
    """
)

_MARK_DONE_SQL = text(
    """
    UPDATE identity_projection_outbox
    SET status       = 'done',
        processed_at = :processed_at
    WHERE id = :id
    """
)

_MARK_FAILED_SQL = text(
    """
    UPDATE identity_projection_outbox
    SET status          = 'pending',
        next_attempt_at = :next_attempt_at,
        last_error_code = :last_error_code
    WHERE id = :id
    """
)

# Reset a row to pending without changing attempt_count or next_attempt_at.
# Used when subject-level advisory lock is not acquired — the row is released
# back to pending so another pass can pick it up after the contending worker
# has finished and released the subject lock.
_MARK_PENDING_RESET_SQL = text(
    """
    UPDATE identity_projection_outbox
    SET status = 'pending'
    WHERE id = :id
    """
)


def _backoff_dt(attempt_count: int) -> datetime:
    idx = min(attempt_count, len(_BACKOFF_SECONDS) - 1)
    return datetime.now(timezone.utc) + timedelta(seconds=_BACKOFF_SECONDS[idx])


def _process_one(
    db: Session,
    row: object,
    auth0_client: Auth0ManagementClient,
    *,
    _sqlite_mode: bool = False,
) -> None:
    """Process a single outbox row.  Caller owns the open transaction."""
    row_id = row.id  # type: ignore[attr-defined]
    subject = row.provider_subject  # type: ignore[attr-defined]
    incoming_revision = int(row.projection_revision)  # type: ignore[attr-defined]
    attempt_count = int(row.attempt_count)  # type: ignore[attr-defined]

    db.execute(_MARK_PROCESSING_SQL, {"id": row_id})

    # Acquire a per-subject advisory lock so two concurrent workers processing
    # different revision rows for the same Auth0 subject cannot interleave their
    # GET/PATCH sequences and regress the revision.  SKIP LOCKED prevents two
    # workers from locking the *same* row; it does not prevent them from locking
    # *different* rows for the *same* subject.  The advisory lock closes that gap.
    # Lock is transaction-scoped and released automatically on commit/rollback.
    if not _sqlite_mode:
        lock_acquired = db.execute(
            text("SELECT pg_try_advisory_xact_lock(hashtext(:key))"),
            {"key": f"iproj:{subject}"},
        ).scalar()
        if not lock_acquired:
            # Another worker holds the subject lock; reset this row to pending
            # so it is retried after the contending worker releases the lock.
            db.execute(_MARK_PENDING_RESET_SQL, {"id": row_id})
            log.debug(
                "projection_worker.subject_locked outbox_id=%s subject_hash=%s",
                row_id,
                Auth0ManagementClient.hash_subject(subject),
            )
            return

    try:
        # ------------------------------------------------------------------
        # Stale-write safety: read current app_metadata.projection_revision
        # before writing.  Skip if incoming revision ≤ existing.
        # ------------------------------------------------------------------
        try:
            existing_meta = auth0_client.get_user_app_metadata(subject)
        except Auth0ManagementError as exc:
            log.warning(
                "projection_worker.get_app_metadata_failed "
                "outbox_id=%s subject_hash=%s code=%s",
                row_id,
                Auth0ManagementClient.hash_subject(subject),
                exc.code,
            )
            raise

        existing_revision: Optional[int] = None
        if existing_meta:
            raw = existing_meta.get("projection_revision")
            if raw is not None:
                try:
                    existing_revision = int(raw)
                except (TypeError, ValueError):
                    existing_revision = None

        if existing_revision is not None and incoming_revision <= existing_revision:
            # Stale or duplicate — converge safely, mark done.
            log.info(
                "projection_worker.stale_revision_skipped "
                "outbox_id=%s incoming=%d existing=%d",
                row_id,
                incoming_revision,
                existing_revision,
            )
            db.execute(
                _MARK_DONE_SQL,
                {"id": row_id, "processed_at": datetime.now(timezone.utc).isoformat()},
            )
            return

        # ------------------------------------------------------------------
        # Apply the projection.
        # ------------------------------------------------------------------
        import json

        roles_raw = row.roles  # type: ignore[attr-defined]
        roles: list[str] = (
            roles_raw if isinstance(roles_raw, list) else json.loads(roles_raw)
        )

        auth0_client.update_user_app_metadata(
            subject,
            principal_id=str(row.principal_id),  # type: ignore[attr-defined]
            roles=roles,
            projection_revision=incoming_revision,
        )
        db.execute(
            _MARK_DONE_SQL,
            {"id": row_id, "processed_at": datetime.now(timezone.utc).isoformat()},
        )
        log.info(
            "projection_worker.projected outbox_id=%s membership_id=%s revision=%d",
            row_id,
            row.membership_id,  # type: ignore[attr-defined]
            incoming_revision,
        )

    except Exception as exc:
        error_code = (
            exc.code  # type: ignore[attr-defined]
            if isinstance(exc, Auth0ManagementError)
            else type(exc).__name__
        )

        # Determine backoff: 429 → honor Retry-After; permanent 4xx → max backoff.
        # Permanent failures (404 user-not-found, 400 bad-request) are
        # distinguished here so the worker can log them differently.  The schema
        # does NOT have a terminal status (would require a migration), so we
        # leave the row as 'pending' with max backoff and let worker_main.py
        # detect rows that have exceeded _MAX_PERMANENT_ATTEMPTS and log CRITICAL.
        is_rate_limit = isinstance(exc, Auth0RateLimitError)
        is_permanent = isinstance(exc, Auth0ManagementError) and exc.status in (
            400,
            404,
        )

        if is_rate_limit:
            retry_after_secs = exc.retry_after  # type: ignore[attr-defined]
            next_attempt = datetime.now(timezone.utc) + timedelta(
                seconds=retry_after_secs
            )
            log.warning(
                "projection_worker.rate_limited outbox_id=%s retry_after=%ds",
                row_id,
                retry_after_secs,
            )
        elif is_permanent:
            # Max backoff — will be flagged by _check_and_log_permanent_rows
            next_attempt = _backoff_dt(len(_BACKOFF_SECONDS) - 1)
            log.error(
                "projection_worker.permanent_failure "
                "outbox_id=%s error=%s status=%d "
                "note=row_left_pending_for_ops_visibility",
                row_id,
                error_code,
                exc.status,  # type: ignore[attr-defined]
            )
        else:
            next_attempt = _backoff_dt(attempt_count)
            log.warning(
                "projection_worker.failed outbox_id=%s error=%s next_attempt=%s",
                row_id,
                error_code,
                next_attempt.isoformat(),
            )

        db.execute(
            _MARK_FAILED_SQL,
            {
                "id": row_id,
                "next_attempt_at": next_attempt.isoformat(),
                "last_error_code": str(error_code)[:128],
            },
        )


def run_projection_pass(
    db: Session,
    auth0_client: Auth0ManagementClient,
    *,
    batch_size: int = 50,
    _sqlite_mode: bool = False,
) -> int:
    """Process up to ``batch_size`` pending outbox rows.

    Each row is processed in its own inner savepoint so a failure on one row
    does not prevent subsequent rows from being processed.  The caller is
    responsible for committing (or rolling back) the outer transaction.

    Args:
        db: Active SQLAlchemy session.
        auth0_client: Auth0ManagementClient instance.
        batch_size: Maximum rows to process per call.
        _sqlite_mode: Use SQLite-compatible query (no FOR UPDATE SKIP LOCKED).
            For testing only — do not set in production.

    Returns:
        Number of rows processed (attempted).
    """
    query = _SELECT_PENDING_SQLITE_SQL if _sqlite_mode else _SELECT_PENDING_SQL
    rows = db.execute(query, {"limit": batch_size}).fetchall()
    if not rows:
        return 0

    processed = 0
    for row in rows:
        sp = db.begin_nested()  # savepoint
        try:
            _process_one(db, row, auth0_client, _sqlite_mode=_sqlite_mode)
            sp.commit()
        except Exception:
            sp.rollback()
            log.exception(
                "projection_worker.row_exception_rolled_back outbox_id=%s", row.id
            )
        processed += 1

    return processed
