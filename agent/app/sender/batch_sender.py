from __future__ import annotations

import hashlib
import time
import uuid

from agent.app.sender.http_sender import HTTPSender
from agent.core_client import CoreClientError


TERMINAL_CODES = {
    "AUTH_REQUIRED": "auth_invalid",
    "SCOPE_DENIED": "auth_invalid",
    "SCHEMA_INVALID": "schema_invalid",
    "PAYLOAD_TOO_LARGE": "payload_too_large",
}


def _deterministic_backoff(attempt: int) -> float:
    return float(min(60, 2 ** max(0, attempt)))


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
            if err.code in TERMINAL_CODES:
                self.queue.dead_letter(event_ids, TERMINAL_CODES[err.code])
                return {"status": "dead_letter", "code": err.code}

            self.rate_limited_count += 1
            if err.code in {"ABUSE_CAP_EXCEEDED", "PLAN_LIMIT_EXCEEDED"}:
                delay = max(60.0, err.retry_after_seconds or 60.0)
            else:
                delay = (
                    err.retry_after_seconds
                    if err.retry_after_seconds is not None
                    else _deterministic_backoff(max_attempt)
                )
            self.queue.retry_later(event_ids, time.time() + delay)
            return {
                "status": "retry",
                "code": err.code,
                "delay": delay,
                "request_id": request_id,
            }
