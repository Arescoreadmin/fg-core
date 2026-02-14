import threading
import time

from agent.app.queue.sqlite_queue import SQLiteQueue


def test_terminal_errors_dead_letter_immediately(tmp_path):
    q = SQLiteQueue(str(tmp_path / "q.db"), max_attempts=20)
    q.enqueue({"event_id": "e1"})
    q.retry_later(["e1"], time.time() + 1, reason="schema_invalid")
    assert q.dead_count() == 1
    assert q.size() == 0


def test_max_attempts_dead_letters(tmp_path):
    q = SQLiteQueue(str(tmp_path / "q.db"), max_attempts=2)
    q.enqueue({"event_id": "e1"})
    q.retry_later(["e1"], 0)
    q.retry_later(["e1"], 0)
    assert q.dead_count() == 1


def test_timestamps_recorded(tmp_path):
    q = SQLiteQueue(str(tmp_path / "q.db"), max_attempts=2)
    q.enqueue({"event_id": "e1"})
    q.retry_later(["e1"], 0)
    q.retry_later(["e1"], 0)
    rows = q._conn.execute(
        "SELECT first_seen_at,last_failed_at FROM dead_events WHERE event_id='e1'"
    ).fetchone()
    assert rows[0] is not None
    assert rows[1] is not None


def test_retention_cap_enforced(tmp_path, monkeypatch):
    monkeypatch.setenv("FG_DEAD_LETTER_MAX", "2")
    q = SQLiteQueue(str(tmp_path / "q.db"), max_attempts=1)
    for i in range(4):
        q.enqueue({"event_id": f"e{i}"})
        q.retry_later([f"e{i}"], 0)
    assert q.dead_count() == 2


def test_atomic_capacity_under_concurrency(tmp_path):
    q = SQLiteQueue(str(tmp_path / "q.db"), max_size=5)

    def worker(i):
        q.enqueue({"event_id": f"e{i}"})

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert q.size() == 5
