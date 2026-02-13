import time

from agent.app.queue.sqlite_queue import SQLiteQueue


def test_queue_dedupe_and_persistence(tmp_path):
    path = tmp_path / "queue.db"
    q1 = SQLiteQueue(str(path), max_size=10)
    event = {"event_id": "e1", "x": 1}
    assert q1.enqueue(event) is True
    assert q1.enqueue(event) is False
    assert q1.size() == 1
    q2 = SQLiteQueue(str(path), max_size=10)
    assert q2.size() == 1


def test_queue_retry_timing(tmp_path):
    q = SQLiteQueue(str(tmp_path / "q.db"))
    q.enqueue({"event_id": "e2"})
    q.retry_later(["e2"], time.time() + 60)
    assert q.due_batch(10) == []
