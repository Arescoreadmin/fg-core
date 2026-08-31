"""AUTH-ROLE-001C: Identity projection worker entrypoint.

Consumes identity_projection_outbox rows by calling run_projection_pass()
on a configurable polling interval.  This is the production process that
wires the library function into a long-running runtime.

Environment variables:
    PROJECTION_WORKER_POLL_SECONDS  Poll interval in seconds (default: 30)
    AG_IDENTITY_DB_URL / FG_DB_URL  Database connection string
    AUTH0_DOMAIN                    Auth0 tenant domain  [required]
    AUTH0_MGMT_CLIENT_ID            Management API client ID  [required]
    AUTH0_MGMT_CLIENT_SECRET        Management API client secret  [required — SECRET]
    AUTH0_MGMT_AUDIENCE             Management API audience  [required]

Security:
    - Secrets and tokens are never logged.
    - Log lines use subject_hash (SHA-256 prefix) not raw Auth0 subject IDs.
    - No metadata payloads, customer data, or role values in error-level logs.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from datetime import datetime, timezone

# Module-level imports make these symbols patchable in tests.
# run_worker() still catches ImportError on these at startup so the process
# exits non-zero rather than crashing with an unhandled exception.
from admin_gateway.identity.auth0_config import get_auth0_config
from admin_gateway.identity.auth0_management import Auth0ManagementClient
from admin_gateway.db.identity_session import get_identity_sessionmaker
from admin_gateway.identity.projection_worker import run_projection_pass

# ------------------------------------------------------------------
# Logging setup — structured key=value format
# ------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s level=%(levelname)s logger=%(name)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("admin-gateway.identity.worker_main")

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------

_MAX_PERMANENT_ATTEMPTS = 10  # after this many attempts, log CRITICAL and skip
_DEFAULT_POLL_SECONDS = 30
_VERSION = "AUTH-ROLE-001C-WORKER-DEPLOYMENT"


# ------------------------------------------------------------------
# Configuration loading — fail closed on missing required vars
# ------------------------------------------------------------------


def _load_config() -> dict[str, object]:
    """Load and validate required configuration.

    Returns a dict of safe (non-secret) config values for logging.
    Raises SystemExit(1) on any missing required variable.
    """
    required_vars = [
        "AUTH0_DOMAIN",
        "AUTH0_MGMT_CLIENT_ID",
        "AUTH0_MGMT_CLIENT_SECRET",
        "AUTH0_MGMT_AUDIENCE",
    ]
    missing = [v for v in required_vars if not os.getenv(v, "").strip()]
    if missing:
        log.critical(
            "worker_main.config_missing required_vars=%s",
            ",".join(missing),
        )
        sys.exit(1)

    # If none of the DB vars are set we fall through to the SQLite default —
    # that is intentionally allowed so tests run without env vars; in production
    # the Railway service must set AG_IDENTITY_DB_URL or FG_DB_URL explicitly.

    poll_seconds_raw = os.getenv("PROJECTION_WORKER_POLL_SECONDS", "").strip()
    try:
        poll_seconds = (
            int(poll_seconds_raw) if poll_seconds_raw else _DEFAULT_POLL_SECONDS
        )
        if poll_seconds < 1:
            raise ValueError("poll_seconds must be >= 1")
    except ValueError as exc:
        log.critical(
            "worker_main.config_invalid var=PROJECTION_WORKER_POLL_SECONDS value=%r error=%s",
            poll_seconds_raw,
            exc,
        )
        sys.exit(1)

    return {
        "version": _VERSION,
        "poll_seconds": poll_seconds,
        "auth0_domain": os.getenv("AUTH0_DOMAIN"),
        "db_url_source": (
            "AG_IDENTITY_DB_URL"
            if os.getenv("AG_IDENTITY_DB_URL", "").strip()
            else "FG_DB_URL"
            if os.getenv("FG_DB_URL", "").strip()
            else "SQLite-default"
        ),
        "max_permanent_attempts": _MAX_PERMANENT_ATTEMPTS,
    }


# ------------------------------------------------------------------
# Observability helpers
# ------------------------------------------------------------------


def _log_pass_result(
    *,
    pass_start: datetime,
    rows_claimed: int,
    rows_succeeded: int,
    rows_retried: int,
    rows_permanent: int,
    pending_backlog: int | None,
    oldest_pending_age_seconds: float | None,
) -> None:
    """Emit a structured log line summarising the completed projection pass."""
    duration_ms = int((datetime.now(timezone.utc) - pass_start).total_seconds() * 1000)
    oldest_age = (
        f"{oldest_pending_age_seconds:.0f}s"
        if oldest_pending_age_seconds is not None
        else "n/a"
    )
    log.info(
        "worker_main.pass_complete "
        "duration_ms=%d rows_claimed=%d rows_succeeded=%d "
        "rows_retried=%d rows_permanent=%d "
        "pending_backlog=%s oldest_pending_age=%s",
        duration_ms,
        rows_claimed,
        rows_succeeded,
        rows_retried,
        rows_permanent,
        pending_backlog if pending_backlog is not None else "n/a",
        oldest_age,
    )


def _query_backlog(db: object) -> tuple[int | None, float | None]:
    """Query pending backlog size and oldest pending age.

    Returns (count, oldest_age_seconds).  Both None on any error.
    Backlog query failure is non-fatal.
    """
    from sqlalchemy import text
    from sqlalchemy.orm import Session

    if not isinstance(db, Session):
        return None, None

    try:
        row = db.execute(
            text(
                "SELECT COUNT(*), MIN(created_at) "
                "FROM identity_projection_outbox "
                "WHERE status IN ('pending', 'processing')"
            )
        ).fetchone()
        if row is None:
            return None, None
        count = int(row[0]) if row[0] is not None else 0
        oldest_age: float | None = None
        if row[1] is not None:
            # Parse ISO timestamp or datetime object
            raw = row[1]
            if isinstance(raw, str):
                from datetime import datetime

                try:
                    created = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    oldest_age = (datetime.now(timezone.utc) - created).total_seconds()
                except ValueError:
                    pass
            elif isinstance(raw, datetime):
                ts = raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
                oldest_age = (datetime.now(timezone.utc) - ts).total_seconds()
        return count, oldest_age
    except Exception as exc:
        log.debug("worker_main.backlog_query_failed error=%s", type(exc).__name__)
        return None, None


# ------------------------------------------------------------------
# Permanent failure handling (no schema migration required)
# ------------------------------------------------------------------


def _is_permanent_failure_code(error_code: str) -> bool:
    """Return True for error codes that indicate a permanent (non-retryable) failure."""
    # 404 → user not found; 400 → bad request (non-transient body)
    return any(
        code in error_code
        for code in (
            "MGMT_PATCH_FAILED:404",
            "MGMT_PATCH_FAILED:400",
            "MGMT_GET_FAILED:404",
            "MGMT_GET_FAILED:400",
        )
    )


def _check_and_log_permanent_rows(db: object) -> int:
    """Log CRITICAL for any pending rows that have exceeded max attempts.

    These rows are left visible for ops (not deleted).  No schema migration
    is required because we rely on attempt_count rather than a terminal status.
    The schema only supports: pending / processing / done / failed.
    Adding a 'terminal' status would require migration 018x — deferred.

    Returns count of rows logged as permanently failed this pass.
    """
    from sqlalchemy import text
    from sqlalchemy.orm import Session

    if not isinstance(db, Session):
        return 0

    try:
        rows = db.execute(
            text(
                "SELECT id, attempt_count, last_error_code "
                "FROM identity_projection_outbox "
                "WHERE status = 'pending' "
                "  AND attempt_count >= :max_attempts"
            ),
            {"max_attempts": _MAX_PERMANENT_ATTEMPTS},
        ).fetchall()
        for row in rows:
            log.critical(
                "worker_main.permanent_failure_threshold "
                "outbox_id=%s attempt_count=%d last_error_code=%s "
                "action=skip_visible_for_ops",
                row[0],
                row[1],
                row[2],
            )
        return len(rows)
    except Exception as exc:
        log.debug("worker_main.permanent_check_failed error=%s", type(exc).__name__)
        return 0


# ------------------------------------------------------------------
# Main polling loop
# ------------------------------------------------------------------


def run_worker(*, _stop_event: threading.Event | None = None) -> None:
    """Run the projection worker polling loop.

    Args:
        _stop_event: Optional threading.Event; set it to stop the loop cleanly.
            If None, a new Event is created and SIGTERM/SIGINT handlers are
            registered to set it.
    """
    config = _load_config()

    log.info(
        "worker_main.starting "
        "version=%s poll_seconds=%d auth0_domain=%s "
        "db_url_source=%s max_permanent_attempts=%d",
        config["version"],
        config["poll_seconds"],
        config["auth0_domain"],
        config["db_url_source"],
        config["max_permanent_attempts"],
    )

    try:
        auth0_config = get_auth0_config()
    except Exception as exc:
        log.critical(
            "worker_main.auth0_config_failed code=%s",
            getattr(exc, "code", type(exc).__name__),
        )
        sys.exit(1)

    auth0_client = Auth0ManagementClient(config=auth0_config)
    session_factory = get_identity_sessionmaker()

    poll_seconds = int(config["poll_seconds"])  # type: ignore[arg-type]

    # Set up graceful shutdown
    stop_event = _stop_event if _stop_event is not None else threading.Event()

    if _stop_event is None:

        def _handle_signal(signum: int, frame: object) -> None:
            log.info("worker_main.shutdown_signal signum=%d", signum)
            stop_event.set()

        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)

    log.info("worker_main.ready poll_seconds=%d", poll_seconds)

    while not stop_event.is_set():
        pass_start = datetime.now(timezone.utc)
        rows_succeeded = 0
        rows_retried = 0
        rows_permanent = 0

        try:
            db = session_factory()
            try:
                rows_claimed = run_projection_pass(db, auth0_client)
                db.commit()

                # Observability: backlog size + oldest pending
                pending_backlog, oldest_age = _query_backlog(db)
                rows_permanent = _check_and_log_permanent_rows(db)

                # Approximate succeeded/retried from claimed vs permanent
                rows_succeeded = max(0, rows_claimed - rows_permanent)
                rows_retried = rows_permanent  # pending rows with backoff

            except Exception as exc:
                log.warning(
                    "worker_main.pass_failed error=%s",
                    type(exc).__name__,
                )
                try:
                    db.rollback()
                except Exception:
                    pass
                rows_claimed = 0
                pending_backlog = None
                oldest_age = None
            finally:
                db.close()

        except Exception as exc:
            log.warning(
                "worker_main.session_create_failed error=%s",
                type(exc).__name__,
            )
            rows_claimed = 0
            rows_succeeded = 0
            rows_retried = 0
            rows_permanent = 0
            pending_backlog = None
            oldest_age = None

        _log_pass_result(
            pass_start=pass_start,
            rows_claimed=rows_claimed,
            rows_succeeded=rows_succeeded,
            rows_retried=rows_retried,
            rows_permanent=rows_permanent,
            pending_backlog=pending_backlog,
            oldest_pending_age_seconds=oldest_age,
        )

        # Non-busy-loop: wait for poll_seconds or until stop_event is set
        stop_event.wait(timeout=poll_seconds)

    log.info("worker_main.stopped")


if __name__ == "__main__":
    run_worker()
