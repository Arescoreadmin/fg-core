from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path


class SQLiteQueue:
    def __init__(
        self,
        path: str,
        max_size: int = 50000,
        max_attempts: int = 20,
        dead_letter_max: int | None = None,
    ):
        self.path = path
        self.max_size = max_size
        self.max_attempts = max_attempts
        env_cap = os.getenv("FG_DEAD_LETTER_MAX", "10000").strip()
        self.dead_letter_max = dead_letter_max if dead_letter_max is not None else int(env_cap)

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.Lock()
        self._closed = False
        self._init()

    def _init(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA temp_store=MEMORY")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL DEFAULT (strftime('%s', 'now'))
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dead_events (
                    event_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    first_seen_at REAL NOT NULL,
                    last_failed_at REAL NOT NULL
                )
                """
            )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._conn.close()

    def size(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def dead_count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM dead_events").fetchone()[0]

    def enqueue(self, event: dict) -> bool:
        payload_json = json.dumps(event, sort_keys=True)
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                self._conn.execute(
                    """
                    INSERT INTO events(event_id, payload)
                    SELECT ?, ?
                    WHERE (SELECT COUNT(*) FROM events) < ?
                    """,
                    (event["event_id"], payload_json, self.max_size),
                )
                changes = self._conn.execute("SELECT changes()").fetchone()[0]
                self._conn.commit()
                return changes == 1
            except sqlite3.IntegrityError:
                self._conn.rollback()
                return False
            except sqlite3.OperationalError as exc:
                self._conn.rollback()
                if "locked" in str(exc).lower():
                    return False
                raise
            except Exception:
                self._conn.rollback()
                raise

    def due_batch(self, limit: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT event_id,payload,attempts FROM events WHERE next_attempt_at <= ? ORDER BY created_at LIMIT ?",
                (time.time(), limit),
            ).fetchall()
        return [
            {"event_id": event_id, "payload": json.loads(payload), "attempts": attempts}
            for event_id, payload, attempts in rows
        ]

    def ack(self, event_ids: list[str]) -> None:
        if not event_ids:
            return
        with self._lock, self._conn:
            self._conn.executemany(
                "DELETE FROM events WHERE event_id=?",
                [(event_id,) for event_id in event_ids],
            )

    def dead_letter(self, event_id: str, reason: str, last_failed_at: float | None = None) -> None:
        failed_ts = time.time() if last_failed_at is None else float(last_failed_at)
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO dead_events(event_id,payload,reason,attempts,first_seen_at,last_failed_at)
                SELECT event_id,payload,?,attempts,created_at,?
                FROM events
                WHERE event_id=?
                ON CONFLICT(event_id) DO UPDATE SET
                    reason=excluded.reason,
                    attempts=excluded.attempts,
                    last_failed_at=excluded.last_failed_at
                """,
                (reason, failed_ts, event_id),
            )
            self._conn.execute("DELETE FROM events WHERE event_id=?", (event_id,))
            self._purge_dead_letter_overflow()

    def _purge_dead_letter_overflow(self) -> None:
        if self.dead_letter_max <= 0:
            return
        overflow = self._conn.execute("SELECT COUNT(*) FROM dead_events").fetchone()[0] - self.dead_letter_max
        if overflow <= 0:
            return
        self._conn.execute(
            """
            DELETE FROM dead_events
            WHERE event_id IN (
                SELECT event_id
                FROM dead_events
                ORDER BY last_failed_at ASC, event_id ASC
                LIMIT ?
            )
            """,
            (overflow,),
        )

    def retry_later(self, event_ids: list[str], next_attempt_at: float) -> None:
        if not event_ids:
            return
        for event_id in event_ids:
            with self._lock:
                attempts_row = self._conn.execute(
                    "SELECT attempts FROM events WHERE event_id=?",
                    (event_id,),
                ).fetchone()
            if not attempts_row:
                continue
            attempts = attempts_row[0] + 1
            if attempts >= self.max_attempts:
                self.dead_letter(event_id, "max_attempts_exceeded", last_failed_at=time.time())
                continue
            with self._lock, self._conn:
                self._conn.execute(
                    "UPDATE events SET attempts=?, next_attempt_at=? WHERE event_id=?",
                    (attempts, next_attempt_at, event_id),
                )
