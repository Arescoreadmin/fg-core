"""AGENT-QUEUE-DEADLOCK-001 — regression tests for issue #853.

``SQLiteQueue.retry_later`` used to call ``dead_letter`` while holding the
queue's non-reentrant ``threading.Lock`` when an event reached
``max_attempts``. ``dead_letter`` reacquired the lock and the sender thread
blocked forever, halting the deployed agent's telemetry without crashing it.

Every scenario that could hang runs under a hard bound: the direct reproducer
in a subprocess with a timeout, and the in-process scenarios in a daemon
worker (a deadlocked daemon thread cannot keep the test process alive). On the
pre-fix code each of these tests fails at its bound instead of hanging CI.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import textwrap
import threading
import types
from pathlib import Path

import pytest

import agent.app.sender.batch_sender as batch_sender_mod
from agent.app.queue.sqlite_queue import SQLiteQueue
from agent.app.sender.batch_sender import BatchSender
from agent.core_client import CoreClientError

REPO = Path(__file__).resolve().parents[2]
BOUND_S = 10.0


def _bounded(fn, *args, timeout: float = BOUND_S):
    """Run ``fn`` in a daemon thread; fail (not hang) if it does not return."""
    result: dict = {}

    def target():
        try:
            result["value"] = fn(*args)
        except BaseException as exc:  # re-raised in the test thread
            result["error"] = exc

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        pytest.fail(f"{getattr(fn, '__name__', fn)} did not return within {timeout}s")
    if "error" in result:
        raise result["error"]
    return result.get("value")


def _dead_row(q: SQLiteQueue, event_id: str):
    return q._conn.execute(
        "SELECT reason, attempts, payload FROM dead_events WHERE event_id=?",
        (event_id,),
    ).fetchone()


def _attempts(q: SQLiteQueue, event_id: str):
    row = q._conn.execute(
        "SELECT attempts FROM events WHERE event_id=?", (event_id,)
    ).fetchone()
    return None if row is None else row[0]


def _close(q: SQLiteQueue) -> None:
    # A regressed queue leaves its lock held by an abandoned worker; closing
    # must not then block teardown (that would hang CI after the test failed).
    if q._lock.acquire(timeout=1):
        q._lock.release()
        q.close()


@pytest.fixture()
def queue(tmp_path):
    q = SQLiteQueue(str(tmp_path / "q.db"), max_attempts=2)
    yield q
    _close(q)


# --- Direct reproducer from issue #853, hard process timeout -----------------


def test_issue_853_reproducer_terminates_in_subprocess(tmp_path):
    script = textwrap.dedent(
        f"""
        import faulthandler
        faulthandler.dump_traceback_later(5, exit=True)
        from agent.app.queue.sqlite_queue import SQLiteQueue
        q = SQLiteQueue({str(tmp_path / "q.db")!r}, max_attempts=2)
        q.enqueue({{"event_id": "e1"}})
        q.retry_later(["e1"], 0)
        q.retry_later(["e1"], 0)
        print("RETURNED", q.size(), q.dead_count())
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=30,
    )
    # Pre-fix: faulthandler fires after 5s inside dead_letter and exits 1.
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "RETURNED 0 1"


# --- A: retry exhaustion terminates and dead-letters correctly ---------------


def test_retry_exhaustion_returns_and_dead_letters(queue):
    payload = {"event_id": "e1", "tenant_id": "t-1", "kind": "heartbeat"}
    assert queue.enqueue(payload)

    _bounded(queue.retry_later, ["e1"], 0)
    assert _attempts(queue, "e1") == 1 and queue.dead_count() == 0

    _bounded(queue.retry_later, ["e1"], 0)
    assert queue.size() == 0 and queue.dead_count() == 1
    reason, attempts, stored = _dead_row(queue, "e1")
    assert reason == "max_attempts_exceeded"
    assert attempts == 2  # the exhausting attempt is recorded, not lost
    # Payload is moved byte-for-byte (tenant/event identifiers preserved).
    assert stored == '{"event_id":"e1","kind":"heartbeat","tenant_id":"t-1"}'


def test_retry_later_noops_do_not_mutate_or_block(queue):
    queue.enqueue({"event_id": "e1"})
    _bounded(queue.retry_later, [], 0)  # empty batch
    _bounded(queue.retry_later, ["unknown"], 0)  # unknown id
    queue.ack(["e1"])
    _bounded(queue.retry_later, ["e1"], 0)  # already acknowledged
    _bounded(queue.dead_letter, "e1", "schema_invalid")  # already acknowledged
    assert queue.size() == 0 and queue.dead_count() == 0
    # Duplicate ids are rejected rather than overwriting the queued event.
    assert queue.enqueue({"event_id": "e2"}) is True
    assert queue.enqueue({"event_id": "e2", "other": 1}) is False


def test_repeated_retries_after_exhaustion_do_not_duplicate(queue):
    queue.enqueue({"event_id": "e1"})
    for _ in range(5):
        _bounded(queue.retry_later, ["e1"], 0)
    assert queue.size() == 0
    assert queue._conn.execute("SELECT COUNT(*) FROM dead_events").fetchone()[0] == 1
    assert _dead_row(queue, "e1")[1] == 2


def test_terminal_reason_path_still_dead_letters_immediately(queue):
    queue.enqueue({"event_id": "e1"})
    _bounded(queue.retry_later, ["e1"], 0)
    queue.enqueue({"event_id": "e2"})
    _bounded(lambda: queue.retry_later(["e2"], 0, reason="schema_invalid"))
    assert _dead_row(queue, "e2")[0] == "schema_invalid"
    assert _attempts(queue, "e1") == 1  # untouched by e2's terminal failure


# --- B: queue remains operational after exhaustion ---------------------------


def test_queue_keeps_working_after_exhaustion(queue):
    queue.enqueue({"event_id": "e1"})
    _bounded(queue.retry_later, ["e1"], 0)
    _bounded(queue.retry_later, ["e1"], 0)

    assert _bounded(queue.enqueue, {"event_id": "e2"}) is True
    batch = _bounded(queue.due_batch, 10)
    assert [b["event_id"] for b in batch] == ["e2"]
    _bounded(queue.ack, ["e2"])
    assert _bounded(queue.size) == 0
    assert _bounded(queue.dead_count) == 1


# --- C: BatchSender under a sustained Core outage ----------------------------


class _FailingSender:
    """Stands in for HTTPSender: records calls, never touches the network."""

    def __init__(self, status: int, code: str):
        self.status, self.code = status, code
        self.calls = 0
        self.fail = True

    def send_events(self, events, request_id=None):
        self.calls += 1
        if self.fail:
            raise CoreClientError(self.status, self.code, "outage", {}, "r")
        return {"ok": True}


@pytest.mark.parametrize(
    ("status", "code"),
    [(429, "RATE_LIMITED"), (500, "INTERNAL"), (503, "UNAVAILABLE")],
)
def test_batch_sender_sustained_outage_dead_letters_at_limit(
    tmp_path, monkeypatch, status, code
):
    # Schedule retries relative to t=0 so each one is immediately due again,
    # instead of sleeping through real backoff.
    monkeypatch.setattr(
        batch_sender_mod, "time", types.SimpleNamespace(time=lambda: 0.0)
    )
    q = SQLiteQueue(str(tmp_path / "q.db"))  # production default max_attempts
    assert q.max_attempts == 20
    q.enqueue({"event_id": "e1"})
    sink = _FailingSender(status, code)
    sender = BatchSender(queue=q, sender=sink)

    statuses = [_bounded(sender.flush_once)["status"] for _ in range(20)]
    assert statuses == ["retry"] * 20
    assert sink.calls == 20
    assert q.size() == 0
    assert _dead_row(q, "e1")[:2] == ("max_attempts_exceeded", 20)

    # Terminal: the exhausted event is not retried again.
    assert _bounded(sender.flush_once) == {"status": "empty"}
    assert sink.calls == 20

    # New telemetry still flows once Core recovers.
    q.enqueue({"event_id": "e2"})
    sink.fail = False
    assert _bounded(sender.flush_once)["status"] == "sent"
    assert q.size() == 0 and q.dead_count() == 1
    q.close()


@pytest.mark.parametrize(
    "exc",
    [ConnectionRefusedError("refused"), TimeoutError("timed out")],
    ids=["connection-refused", "timeout"],
)
def test_transport_errors_leave_event_pending_and_queue_unlocked(tmp_path, exc):
    q = SQLiteQueue(str(tmp_path / "q.db"), max_attempts=2)
    q.enqueue({"event_id": "e1"})

    class _Raising:
        def send_events(self, events, request_id=None):
            raise exc

    with pytest.raises(type(exc)):
        _bounded(BatchSender(queue=q, sender=_Raising()).flush_once)
    # Existing contract: transport errors propagate to the agent loop's crash
    # guard and neither consume an attempt nor drop the event.
    assert _attempts(q, "e1") == 0 and q.dead_count() == 0
    assert _bounded(q.enqueue, {"event_id": "e2"}) is True
    q.close()


# --- D: concurrent enqueue / retry / ack / read ------------------------------


def test_concurrent_operations_do_not_deadlock_or_lose_events(tmp_path):
    q = SQLiteQueue(str(tmp_path / "q.db"), max_attempts=3)
    workers, per_worker = 4, 24  # even: half acked, half exhausted
    start = threading.Barrier(workers + 1)
    stop = threading.Event()
    errors: list[BaseException] = []
    acked: set[str] = set()
    acked_lock = threading.Lock()

    def writer(w: int) -> None:
        try:
            start.wait()
            for i in range(per_worker):
                eid = f"w{w}-e{i}"
                assert q.enqueue({"event_id": eid})
                if i % 2:
                    q.ack([eid])
                    with acked_lock:
                        acked.add(eid)
                else:
                    for _ in range(3):  # exhausts max_attempts=3
                        q.retry_later([eid], 0)
        except BaseException as exc:
            errors.append(exc)

    def reader() -> None:
        try:
            start.wait()
            while not stop.is_set():
                q.due_batch(50)
                q.size()
                q.dead_count()
        except BaseException as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=writer, args=(w,), daemon=True) for w in range(workers)
    ]
    reader_thread = threading.Thread(target=reader, daemon=True)
    for t in [*threads, reader_thread]:
        t.start()
    for t in threads:
        t.join(BOUND_S)
    stop.set()
    reader_thread.join(BOUND_S)

    alive = [t.name for t in [*threads, reader_thread] if t.is_alive()]
    assert not alive, f"deadlocked threads: {alive}"
    assert not errors, errors

    total = workers * per_worker
    dead = {r[0] for r in q._conn.execute("SELECT event_id FROM dead_events")}
    pending = {r[0] for r in q._conn.execute("SELECT event_id FROM events")}
    assert pending == set()
    assert len(acked) == total // 2 and len(dead) == total - total // 2
    assert acked.isdisjoint(dead)
    assert {r[0] for r in q._conn.execute("SELECT attempts FROM dead_events")} == {3}
    q.close()


# --- E: SQLite failure during the dead-letter transfer -----------------------


def test_dead_letter_failure_rolls_back_and_releases_lock(queue):
    queue.enqueue({"event_id": "e1"})
    _bounded(queue.retry_later, ["e1"], 0)
    # Real SQLite failure (not a mock) inside the transfer transaction.
    queue._conn.executescript(
        """
        CREATE TRIGGER inject_dead_letter_failure BEFORE INSERT ON dead_events
        BEGIN SELECT RAISE(ABORT, 'injected dead-letter failure'); END;
        """
    )

    with pytest.raises(sqlite3.DatabaseError, match="injected"):
        _bounded(queue.retry_later, ["e1"], 0)

    # No half-moved event: still pending, attempt count rolled back, no dead row.
    assert _attempts(queue, "e1") == 1
    assert queue.dead_count() == 0
    assert not queue._conn.in_transaction
    # The lock was released: other operations proceed.
    assert _bounded(queue.enqueue, {"event_id": "e2"}) is True

    with pytest.raises(sqlite3.DatabaseError, match="injected"):
        _bounded(queue.dead_letter, "e2", "schema_invalid")
    assert _attempts(queue, "e2") == 0 and queue.dead_count() == 0

    # Recovery once the fault clears.
    queue._conn.execute("DROP TRIGGER inject_dead_letter_failure")
    _bounded(queue.retry_later, ["e1"], 0)
    assert _dead_row(queue, "e1")[:2] == ("max_attempts_exceeded", 2)
    assert queue.size() == 1  # e2 still pending, not lost


# --- F: restart persistence ---------------------------------------------------


def test_dead_letter_and_pending_state_survive_restart(tmp_path):
    path = str(tmp_path / "q.db")
    q = SQLiteQueue(path, max_attempts=2)
    q.enqueue({"event_id": "dead"})
    q.enqueue({"event_id": "pending"})
    _bounded(q.retry_later, ["dead"], 0)
    _bounded(q.retry_later, ["dead"], 0)
    _bounded(q.retry_later, ["pending"], 0)
    q.close()

    q2 = SQLiteQueue(path, max_attempts=2)
    try:
        assert q2.dead_count() == 1 and _dead_row(q2, "dead")[:2] == (
            "max_attempts_exceeded",
            2,
        )
        assert [r[0] for r in q2._conn.execute("SELECT event_id FROM events")] == [
            "pending"
        ]
        assert _attempts(q2, "pending") == 1  # retry state persisted, not reset
        assert q2.enqueue({"event_id": "pending"}) is False  # no duplicate
        assert q2.enqueue({"event_id": "new"}) is True
        _bounded(q2.retry_later, ["pending"], 0)
        assert q2.dead_count() == 2 and q2.size() == 1
    finally:
        _close(q2)
