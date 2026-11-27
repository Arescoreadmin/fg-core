from concurrent.futures import ThreadPoolExecutor

from agent.app.queue.sqlite_queue import SQLiteQueue


def test_queue_capacity_not_exceeded_under_concurrency(tmp_path):
    path = tmp_path / "race.db"
    max_size = 5

    def worker(i: int) -> bool:
        queue = SQLiteQueue(str(path), max_size=max_size)
        try:
            return queue.enqueue({"event_id": f"e{i}"})
        finally:
            queue.close()

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(worker, range(20)))

    final_queue = SQLiteQueue(str(path), max_size=max_size)
    try:
        assert sum(1 for r in results if r) <= max_size
        assert final_queue.size() <= max_size
    finally:
        final_queue.close()


def test_enqueue_cap_changes_query_enforced(tmp_path):
    queue = SQLiteQueue(str(tmp_path / "cap.db"), max_size=1)
    try:
        assert queue.enqueue({"event_id": "e1"}) is True
        assert queue.enqueue({"event_id": "e2"}) is False
        assert queue.size() == 1
    finally:
        queue.close()


def test_close_idempotent(tmp_path):
    queue = SQLiteQueue(str(tmp_path / "close.db"))
    queue.close()
    queue.close()


def _hold_write_lock(path, seconds: float):
    """Another connection holds a write lock on a database not yet in WAL mode."""
    import sqlite3
    import threading

    holder = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
    holder.execute("CREATE TABLE IF NOT EXISTS other(a)")
    holder.execute("BEGIN IMMEDIATE")
    timer = threading.Timer(seconds, lambda: (holder.execute("COMMIT"), holder.close()))
    timer.start()
    return timer


def test_first_open_waits_for_a_concurrent_writer(tmp_path):
    """#930: the WAL switch failed at once with "database is locked" while another
    connection held a write lock on a fresh database (busy_timeout is not
    consulted for it). The first open now waits, bounded, and confirms WAL."""
    path = tmp_path / "first-open.db"
    timer = _hold_write_lock(path, 0.3)
    try:
        queue = SQLiteQueue(str(path), max_size=5)
    finally:
        timer.join()
    try:
        assert queue._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert queue.enqueue({"event_id": "e1"}) is True
        assert queue.size() == 1
    finally:
        queue.close()


def test_first_open_lock_wait_is_bounded(tmp_path, monkeypatch):
    """A lock that never clears fails loudly after the deadline; no hang."""
    import sqlite3
    import time

    import pytest

    import agent.app.queue.sqlite_queue as sq

    monkeypatch.setattr(sq, "WAL_INIT_TIMEOUT_SECONDS", 0.2)
    path = tmp_path / "held.db"
    timer = _hold_write_lock(path, 2.0)
    started = time.monotonic()
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            SQLiteQueue(str(path))
        assert time.monotonic() - started < 1.5
    finally:
        timer.join()
