from agent.app.sender.batch_sender import BatchSender
from agent.core_client import CoreClientError


class FakeQueue:
    def __init__(self):
        self.events = [{"event_id": "a", "payload": {"event_id": "a"}, "attempts": 0}]
        self.acked = []
        self.retried = []
        self.dead = []

    def due_batch(self, limit):
        return self.events[:limit]

    def ack(self, ids):
        self.acked.extend(ids)

    def retry_later(self, ids, next_attempt_at):
        self.retried.append((ids, next_attempt_at))

    def dead_letter(self, event_id, reason, **kwargs):
        self.dead.append((event_id, reason))

    def dead_letter_count(self):
        return len(self.dead)

    def size(self):
        return len(self.events)


class GoodSender:
    def __init__(self):
        self.request_ids = []

    def send_events(self, events, request_id=None):
        self.request_ids.append(request_id)
        return {"ok": True}


class BadSender:
    def send_events(self, events, request_id=None):
        raise CoreClientError(429, "RATE_LIMITED", "rate", {}, "r1")


class AbuseSender:
    def send_events(self, events, request_id=None):
        raise CoreClientError(
            429, "ABUSE_CAP_EXCEEDED", "abuse", {}, "r2", retry_after_seconds=1
        )


class FatalSender:
    def send_events(self, events, request_id=None):
        raise CoreClientError(401, "AUTH_REQUIRED", "bad", {}, "r3")


def test_batch_sender_ack_on_success():
    q = FakeQueue()
    sink = GoodSender()
    sender = BatchSender(queue=q, sender=sink)
    sender.flush_once()
    assert q.acked == ["a"]
    assert sink.request_ids[0]


def test_batch_sender_retry_on_rate_limit():
    q = FakeQueue()
    sender = BatchSender(queue=q, sender=BadSender())
    sender.flush_once()
    assert q.retried


def test_batch_sender_abuse_cap_uses_minimum_pause():
    q = FakeQueue()
    sender = BatchSender(queue=q, sender=AbuseSender())
    result = sender.flush_once()
    assert result["status"] == "retry"
    assert result["delay"] >= 60


def test_batch_sender_terminal_dead_letters():
    q = FakeQueue()
    sender = BatchSender(queue=q, sender=FatalSender())
    result = sender.flush_once()
    assert result["status"] == "dead_letter"
    assert q.dead


def test_batch_sender_reuses_request_id_for_same_batch():
    q = FakeQueue()
    sink = GoodSender()
    sender = BatchSender(queue=q, sender=sink)
    rid1 = sender._request_id_for_batch(["a", "b"])
    rid2 = sender._request_id_for_batch(["b", "a"])
    assert rid1 == rid2
