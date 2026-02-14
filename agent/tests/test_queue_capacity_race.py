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
