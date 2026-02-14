from __future__ import annotations

import hashlib
import logging
import time
import uuid

from agent.app.queue.backoff import backoff_delay
from agent.app.sender.http_sender import HTTPSender
from agent.core_client import CoreClientError


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
            if err.code in {"AUTH_REQUIRED", "SCOPE_DENIED"}:
                logging.error("fatal auth/scope failure")
                return {"status": "fatal", "code": err.code}
            if err.code in {"ABUSE_CAP_EXCEEDED", "PLAN_LIMIT_EXCEEDED"}:
                delay = (
                    err.retry_after_seconds
                    if err.retry_after_seconds is not None
                    else 60.0
                )
                delay = max(60.0, delay)
            elif err.code == "RATE_LIMITED" or err.transient:
                self.rate_limited_count += 1
                delay = (
                    err.retry_after_seconds
                    if err.retry_after_seconds is not None
                    else backoff_delay(max_attempt)
                )
            else:
                return {"status": "drop", "code": err.code}
            self.queue.retry_later(event_ids, time.time() + delay)
            return {
                "status": "retry",
                "code": err.code,
                "delay": delay,
                "request_id": request_id,
            }
