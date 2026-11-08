"""Execution-time scan authorization guard — L14-SCAN-AUTH-HARDENING-001 (AUTH-GAP-002).

Dispatch-time authorization (the API route) proves nothing about the moment a
background worker actually opens a socket.  This guard re-reads AUTHORITATIVE
database state — never a cached decision — at:

* worker startup (all targets, before the job transitions to running);
* every outbound work boundary inside a runner (next target, next redirect hop),
  via the ``checkpoint`` callable defined in
  ``services/connectors/execution_checkpoint.py``;
* immediately before result persistence (job state only).

Each check opens a short-lived session from the sessionmaker, binds the tenant
context, reads current rows, and closes the session.  No ORM identity map or
module-level cache survives between checks, so stale state cannot establish
permission.  Any failure to read state fails closed (``AUTHORIZATION_STORE_UNAVAILABLE``).

Revocation observation boundary
-------------------------------
A revocation, expiry, cancellation or emergency stop committed at time T is
observed at the next checkpoint after T.  Requests already in flight are NOT
aborted; the maximum un-observed window is one target's collection time
(network: one host's port probes; web headers: one HTTP hop; DNS: one domain's
lookups) plus one guard round trip.

Not standalone: decisions are delegated to ``check_scan_authorized()`` (scope +
customer receipt + emergency stop) and to the canonical ``fa_scan_jobs`` state.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from services.connectors.execution_checkpoint import (
    ScanCheckpointHalt,
    ScanTargetDenied,
)
from services.field_assessment.scan_authorization import (
    ScanAuthorizationError,
    check_scan_authorized,
    classify_target_for_auth,
)

log = logging.getLogger("frostgate.scan_execution_guard")

# Scope-mismatch codes affect ONE target only; everything else is state-level
# loss of authority and halts the whole job.
TARGET_LEVEL_CODES: frozenset[str] = frozenset(
    {
        "TARGET_NOT_IN_SCOPE",
        "OPERATION_NOT_PERMITTED",
        "TARGET_NORMALIZATION_FAILED",
        "RECEIPT_TARGET_NOT_APPROVED",
    }
)

EXECUTABLE_JOB_STATUSES = ("queued", "running")
CANCELLED_JOB_STATUSES = ("cancel_requested", "cancelled")


class ScanExecutionHalted(ScanCheckpointHalt):
    """Authority to perform outbound work is gone (or cannot be proven)."""


@dataclass
class ExecutionContext:
    tenant_id: str
    engagement_id: str
    job_id: str
    operation: str
    scanner_type: str
    actor: str
    targets: list[str] = field(default_factory=list)


class ScanExecutionGuard:
    """Fresh-read authorization guard for one scan job execution."""

    def __init__(
        self,
        session_factory: Callable[[], Any],
        ctx: ExecutionContext,
        *,
        set_tenant_context: Callable[[Any, str], None] | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self.ctx = ctx
        self._set_tenant = set_tenant_context
        self._now = now_fn or (lambda: datetime.now(timezone.utc))
        self.checks_performed = 0
        self.last_decision: dict[str, Any] | None = None
        self.denied_targets: list[dict[str, str]] = []

    # -- session --------------------------------------------------------------

    def _open(self) -> Any:
        try:
            db = self._session_factory()
        except Exception as exc:  # noqa: BLE001
            raise ScanExecutionHalted(
                "AUTHORIZATION_STORE_UNAVAILABLE", type(exc).__name__
            ) from exc
        try:
            if self._set_tenant is not None:
                self._set_tenant(db, self.ctx.tenant_id)
        except Exception as exc:  # noqa: BLE001
            _close(db)
            raise ScanExecutionHalted(
                "AUTHORIZATION_STORE_UNAVAILABLE", type(exc).__name__
            ) from exc
        return db

    # -- job state ------------------------------------------------------------

    def _check_job(self, db: Any, *, allow_queued: bool) -> str:
        from sqlalchemy import text

        try:
            row = db.execute(
                text(
                    "SELECT status, tenant_id, engagement_id FROM fa_scan_jobs "
                    "WHERE id = :id"
                ),
                {"id": self.ctx.job_id},
            ).fetchone()
        except Exception as exc:  # noqa: BLE001
            raise ScanExecutionHalted(
                "AUTHORIZATION_STORE_UNAVAILABLE", type(exc).__name__
            ) from exc
        if row is None:
            raise ScanExecutionHalted("JOB_NOT_FOUND")
        status, tenant_id, engagement_id = str(row[0]), str(row[1]), str(row[2])
        if tenant_id != self.ctx.tenant_id:
            raise ScanExecutionHalted("WORKER_TENANT_MISMATCH")
        if engagement_id != self.ctx.engagement_id:
            raise ScanExecutionHalted("WORKER_ENGAGEMENT_MISMATCH")
        if status in CANCELLED_JOB_STATUSES:
            raise ScanExecutionHalted("JOB_CANCELLED", status)
        allowed = EXECUTABLE_JOB_STATUSES if allow_queued else ("running",)
        if status not in allowed:
            # Duplicate delivery / retry of a job that already finished.
            raise ScanExecutionHalted("JOB_NOT_EXECUTABLE", status)
        return status

    # -- authorization --------------------------------------------------------

    def _authorize(self, db: Any, raw_target: str) -> dict[str, Any]:
        target, target_type = classify_target_for_auth(raw_target)
        try:
            decision = check_scan_authorized(
                db,
                tenant_id=self.ctx.tenant_id,
                engagement_id=self.ctx.engagement_id,
                target=target,
                target_type=target_type,
                operation=self.ctx.operation,
                now=self._now(),
            )
        except ScanAuthorizationError as exc:
            if exc.audit_code in TARGET_LEVEL_CODES:
                raise ScanTargetDenied(exc.audit_code, raw_target) from exc
            raise ScanExecutionHalted(exc.audit_code) from exc
        self.last_decision = decision
        return decision

    # -- public API -----------------------------------------------------------

    def worker_start(self) -> dict[str, Any]:
        """Before any outbound I/O: job executable + EVERY target authorized now.

        A single unauthorized target at startup halts the job: the dispatch-time
        contract was "all targets authorized", and that contract no longer holds.
        """
        db = self._open()
        try:
            self._check_job(db, allow_queued=True)
            if not self.ctx.targets:
                raise ScanExecutionHalted("NO_TARGETS")
            decision: dict[str, Any] = {}
            for raw in self.ctx.targets:
                try:
                    decision = self._authorize(db, raw)
                except ScanTargetDenied as exc:
                    raise ScanExecutionHalted(exc.reason_code, raw) from exc
            self.checks_performed += 1
            return decision
        finally:
            _close(db)

    def checkpoint(self, phase: str, target: str | None = None) -> None:
        """Runner callback before each outbound work boundary."""
        db = self._open()
        try:
            self._check_job(db, allow_queued=False)
            if target is not None:
                try:
                    self._authorize(db, target)
                except ScanTargetDenied as exc:
                    self.denied_targets.append(
                        {"target": target, "phase": phase, "code": exc.reason_code}
                    )
                    raise
            self.checks_performed += 1
        finally:
            _close(db)

    def job_state_before_persist(self) -> str:
        """Return the current job status without raising (used to pick a terminal path)."""
        db = self._open()
        try:
            from sqlalchemy import text

            row = db.execute(
                text("SELECT status FROM fa_scan_jobs WHERE id = :id"),
                {"id": self.ctx.job_id},
            ).fetchone()
            return str(row[0]) if row is not None else "missing"
        except Exception:  # noqa: BLE001
            return "unknown"
        finally:
            _close(db)


def _close(db: Any) -> None:
    try:
        db.close()
    except Exception:  # noqa: BLE001
        log.debug("scan_execution_guard: session close failed")
