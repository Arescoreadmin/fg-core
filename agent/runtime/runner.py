from __future__ import annotations

import logging
from collections.abc import Callable

from agent.core.audit import AuditContext, build_audit_event
from agent.core.config import ConfigManager
from agent.core.queue import QueueJob, QueueCorruptionError, SQLiteTaskQueue


TASK_TYPES = {"ping", "inventory_snapshot", "self_test", "config_refresh"}


class Runner:
    def __init__(
        self,
        *,
        queue: SQLiteTaskQueue,
        config: ConfigManager,
        handlers: dict[str, Callable[[dict], None]],
        audit_sink: Callable[[dict], None],
        agent_id: str,
        agent_persistent_id: str,
        tenant_id: str | None,
        now: Callable[[], float],
        refresh_transport_pinned: bool = False,
    ) -> None:
        self.queue = queue
        self.config = config
        self.handlers = handlers
        self.audit_sink = audit_sink
        self.agent_id = agent_id
        self.agent_persistent_id = agent_persistent_id
        self.tenant_id = tenant_id
        self.now = now
        self.refresh_transport_pinned = refresh_transport_pinned
        self.last_success_at: float | None = None
        self.last_error: str | None = None

    def run_once(self) -> bool:
        try:
            job = self.queue.lease_next()
        except QueueCorruptionError:
            self.last_error = "queue_quarantined"
            return False
        if job is None:
            return False
        self._emit(job, stage="start", outcome="start")

        if job.task_type not in TASK_TYPES:
            self._fail(job, "handler_not_found", retry_delay=0)
            return True

        if not self.config.can_execute(
            job.task_type,
            refresh_transport_pinned=self.refresh_transport_pinned,
        ):
            self._fail(job, "policy_denied", retry_delay=0)
            return True

        handler = self.handlers.get(job.task_type)
        if handler is None:
            self._fail(job, "handler_not_found", retry_delay=0)
            return True

        try:
            handler(job.payload)
        except Exception as exc:  # noqa: BLE001
            retry_delay = 2 ** (job.attempts + 1)
            self._fail(job, "task_failed", retry_delay=retry_delay)
            logging.warning(
                "task failure job_id=%s error=%s", job.job_id, type(exc).__name__
            )
            return True

        self.queue.ack(job.job_id, job.lease_id)
        self.last_success_at = self.now()
        self.last_error = None
        self._emit(job, stage="success", outcome="success")
        return True

    def _fail(self, job: QueueJob, code: str, *, retry_delay: float) -> None:
        self.queue.fail(job, code, retry_delay_seconds=retry_delay)
        self.last_error = code
        self._emit(job, stage="failure", outcome="failure", error_code=code)

    def _emit(
        self,
        job: QueueJob,
        *,
        stage: str,
        outcome: str,
        error_code: str | None = None,
    ) -> None:
        config_hash = self.config.config_hash or "degraded"
        event = build_audit_event(
            context=AuditContext(
                agent_id=self.agent_id,
                agent_persistent_id=self.agent_persistent_id,
                tenant_id=self.tenant_id,
                config_hash=config_hash,
            ),
            job_id=job.job_id,
            task_type=job.task_type,
            stage=stage,
            attempt=job.attempts + 1,
            outcome=outcome,
            timestamp=self.now(),
            error_code=error_code,
        )
        self.audit_sink(event)
