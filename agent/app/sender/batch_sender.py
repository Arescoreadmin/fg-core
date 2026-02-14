from __future__ import annotations

import hashlib
import logging
import time
import uuid

from agent.app.sender.http_sender import HTTPSender
from agent.core_client import CoreClientError


_TERMINAL_CODE_MAP = {
    "AUTH_REQUIRED": "auth_invalid",
    "SCOPE_DENIED": "auth_invalid",
    "INVALID_SCHEMA": "schema_invalid",
    "SCHEMA_INVALID": "schema_invalid",
    "PAYLOAD_TOO_LARGE": "payload_too_large",
}


class BatchSender:
    def __init__(self, queue, batch_size: int = 100, sender: HTTPSender | None = None):
        self.queue = queue
        self.batch_size = batch_size
        self.sender = sender or HTTPSender()
        self.last_success_at: float | None = None
        self.rate_limited_count = 0

    @staticmethod
    def _request_id_for_batch(event_ids: list[str]) -> str:
        stable = "|".join(sorted(event_ids))
        digest = hashlib.sha256(stable.encode("utf-8")).hexdigest()
        return str(uuid.uuid5(uuid.NAMESPACE_URL, digest))

    @staticmethod
    def _terminal_reason(err: CoreClientError) -> str | None:
        if err.status_code == 413:
            return "payload_too_large"
        return _TERMINAL_CODE_MAP.get(err.code)

    @staticmethod
    def _retry_delay(event_ids: list[str], attempt: int, retry_after: float | None = None) -> float:
        if retry_after is not None:
            return max(1.0, min(60.0, float(retry_after)))
        base = min(60.0, max(1.0, float(2**min(6, attempt))))
        jitter_seed = hashlib.sha256("|".join(sorted(event_ids)).encode("utf-8")).hexdigest()
        jitter_unit = int(jitter_seed[:8], 16) / 0xFFFFFFFF
        jitter = 0.25 * jitter_unit
        return min(60.0, base + jitter)

    def flush_once(self) -> dict:
        batch = self.queue.due_batch(self.batch_size)
        if not batch:
            return {"status": "empty"}

        event_ids = [item["event_id"] for item in batch]
        payload = [item["payload"] for item in batch]
        max_attempt = max(item["attempts"] for item in batch)
        request_id = self._request_id_for_batch(event_ids)

        try:
            self.sender.send_events(payload, request_id=request_id)
            self.queue.ack(event_ids)
            self.last_success_at = time.time()
            return {"status": "sent", "sent": len(event_ids), "request_id": request_id}
        except CoreClientError as err:
            terminal_reason = self._terminal_reason(err)
            if terminal_reason is not None:
                for event_id in event_ids:
                    self.queue.dead_letter(event_id, terminal_reason, last_failed_at=time.time())
                if terminal_reason == "auth_invalid":
                    logging.error("fatal auth/scope failure")
                    return {"status": "fatal", "code": err.code}
                return {"status": "dead_letter", "reason": terminal_reason, "request_id": request_id}

            if err.code in {"ABUSE_CAP_EXCEEDED", "PLAN_LIMIT_EXCEEDED"}:
                delay = max(60.0, float(err.retry_after_seconds or 60.0))
            else:
                delay = self._retry_delay(event_ids, attempt=max_attempt + 1, retry_after=err.retry_after_seconds)
            self.queue.retry_later(event_ids, time.time() + delay)
            return {
                "status": "retry",
                "code": err.code,
                "delay": delay,
                "request_id": request_id,
            }
