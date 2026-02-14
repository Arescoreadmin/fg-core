from agent.app.queue.sqlite_queue import SQLiteQueue
from agent.app.sender.batch_sender import BatchSender
from agent.core_client import CoreClientError


class TooLargeSender:
    def send_events(self, events, request_id=None):
        raise CoreClientError(413, "PAYLOAD_TOO_LARGE", "too large", {}, "r")


class RateLimitedSender:
    def send_events(self, events, request_id=None):
        raise CoreClientError(429, "RATE_LIMITED", "later", {}, "r")


def test_terminal_reasons_dead_letter_immediately(tmp_path):
    queue = SQLiteQueue(str(tmp_path / "q.db"))
    queue.enqueue({"event_id": "e1"})
    result = BatchSender(queue=queue, sender=TooLargeSender()).flush_once()
    assert result["status"] == "dead_letter"
    assert queue.size() == 0
    assert queue.dead_count() == 1
    reason = queue._conn.execute(
        "SELECT reason FROM dead_events WHERE event_id='e1'"
    ).fetchone()[0]
    assert reason == "payload_too_large"


def test_max_attempts_moves_to_dead_letter(tmp_path):
    queue = SQLiteQueue(str(tmp_path / "q.db"), max_attempts=2)
    queue.enqueue({"event_id": "e1"})
    sender = BatchSender(queue=queue, sender=RateLimitedSender())
    sender.flush_once()
    queue.retry_later(["e1"], next_attempt_at=0)
    assert queue.size() == 0
    assert queue.dead_count() == 1
    reason = queue._conn.execute(
        "SELECT reason FROM dead_events WHERE event_id='e1'"
    ).fetchone()[0]
    assert reason == "max_attempts_exceeded"


def test_dead_letter_timestamps_recorded(tmp_path):
    queue = SQLiteQueue(str(tmp_path / "q.db"))
    queue.enqueue({"event_id": "e1"})
    queue.dead_letter("e1", "schema_invalid", last_failed_at=123.0)
    row = queue._conn.execute(
        "SELECT reason, first_seen_at, last_failed_at FROM dead_events WHERE event_id='e1'"
    ).fetchone()
    assert row[0] == "schema_invalid"
    assert row[2] == 123.0


def test_dead_letter_retention_cap(tmp_path):
    queue = SQLiteQueue(str(tmp_path / "q.db"), dead_letter_max=2)
    for idx in range(3):
        event_id = f"e{idx}"
        queue.enqueue({"event_id": event_id})
        queue.dead_letter(event_id, "schema_invalid", last_failed_at=float(idx))

    kept = queue._conn.execute(
        "SELECT event_id FROM dead_events ORDER BY last_failed_at ASC, event_id ASC"
    ).fetchall()
    assert [row[0] for row in kept] == ["e1", "e2"]
