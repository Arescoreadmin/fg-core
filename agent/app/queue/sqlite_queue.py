from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path


TERMINAL_REASONS = {"schema_invalid", "auth_invalid", "payload_too_large"}


class SQLiteQueue:
    def __init__(self, path: str, max_size: int = 50000, max_attempts: int = 20):
        self.path = path
        self.max_size = max_size
        self.max_attempts = max_attempts
        self.dead_letter_max = int(os.getenv("FG_DEAD_LETTER_MAX", "0"))
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=5.0)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA temp_store=MEMORY")
        self._init()

    def _init(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    first_seen_at REAL NOT NULL DEFAULT (strftime('%s','now')),
                    last_failed_at REAL,
                    created_at REAL NOT NULL DEFAULT (strftime('%s','now'))
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
                    last_failed_at REAL NOT NULL,
                    dead_lettered_at REAL NOT NULL DEFAULT (strftime('%s','now'))
                )
                """
            )
            self._conn.commit()

    def _purge_dead_letter(self) -> None:
        if self.dead_letter_max <= 0:
            return
        self._conn.execute(
            """
            DELETE FROM dead_events
            WHERE event_id IN (
              SELECT event_id FROM dead_events
              ORDER BY dead_lettered_at ASC
              LIMIT (
                SELECT CASE WHEN COUNT(*) > ? THEN COUNT(*) - ? ELSE 0 END FROM dead_events
              )
            )
            """,
            (self.dead_letter_max, self.dead_letter_max),
        )

    def size(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def dead_count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM dead_events").fetchone()[0]

    def dead_letter_count(self) -> int:
        return self.dead_count()

    def enqueue(self, event: dict) -> bool:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            size = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            if size >= self.max_size:
                self._conn.rollback()
                return False
            try:
                self._conn.execute(
                    "INSERT INTO events(event_id,payload) VALUES(?,?)",
                    (event["event_id"], json.dumps(event, sort_keys=True)),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                self._conn.rollback()
                return False

    def due_batch(self, limit: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT event_id,payload,attempts,first_seen_at,last_failed_at FROM events WHERE next_attempt_at <= ? ORDER BY created_at LIMIT ?",
                (time.time(), limit),
            ).fetchall()
        return [
            {
                "event_id": r[0],
                "payload": json.loads(r[1]),
                "attempts": r[2],
                "first_seen_at": r[3],
                "last_failed_at": r[4],
            }
            for r in rows
        ]

    def ack(self, event_ids: list[str]) -> None:
        with self._lock:
            self._conn.executemany(
                "DELETE FROM events WHERE event_id=?", [(event_id,) for event_id in event_ids]
            )
            self._conn.commit()

    def dead_letter(self, event_ids: list[str], reason: str) -> None:
        now = time.time()
        with self._lock:
            for event_id in event_ids:
                row = self._conn.execute(
                    "SELECT payload,attempts,first_seen_at FROM events WHERE event_id=?",
                    (event_id,),
                ).fetchone()
                if not row:
                    continue
                self._conn.execute(
                    "INSERT OR REPLACE INTO dead_events(event_id,payload,reason,attempts,first_seen_at,last_failed_at) VALUES(?,?,?,?,?,?)",
                    (event_id, row[0], reason, row[1], row[2], now),
                )
                self._conn.execute("DELETE FROM events WHERE event_id=?", (event_id,))
            self._purge_dead_letter()
            self._conn.commit()

    def retry_later(self, event_ids: list[str], next_attempt_at: float, reason: str = "retry") -> None:
        if reason in TERMINAL_REASONS:
            self.dead_letter(event_ids, reason)
            return
        with self._lock:
            now = time.time()
            self._conn.executemany(
                "UPDATE events SET attempts=attempts+1,next_attempt_at=?,last_failed_at=? WHERE event_id=?",
                [(next_attempt_at, now, event_id) for event_id in event_ids],
            )
            exhausted = self._conn.execute(
                "SELECT event_id FROM events WHERE attempts >= ?", (self.max_attempts,)
            ).fetchall()
            self._conn.commit()
        if exhausted:
            self.dead_letter([row[0] for row in exhausted], "max_attempts_exceeded")
