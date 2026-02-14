from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path


class SQLiteQueue:
    def __init__(self, path: str, max_size: int = 50000):
        self.path = path
        self.max_size = max_size
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _init(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL DEFAULT (strftime('%s', 'now'))
                )
            """)

    def size(self) -> int:
        with sqlite3.connect(self.path) as conn:
            return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def enqueue(self, event: dict) -> bool:
        if self.size() >= self.max_size:
            return False
        with sqlite3.connect(self.path) as conn:
            try:
                conn.execute(
                    "INSERT INTO events(event_id,payload) VALUES(?,?)",
                    (event["event_id"], json.dumps(event, sort_keys=True)),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def due_batch(self, limit: int) -> list[dict]:
        now = time.time()
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                "SELECT event_id,payload,attempts FROM events WHERE next_attempt_at <= ? ORDER BY created_at LIMIT ?",
                (now, limit),
            ).fetchall()
        return [
            {"event_id": r[0], "payload": json.loads(r[1]), "attempts": r[2]}
            for r in rows
        ]

    def ack(self, event_ids: list[str]) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.executemany(
                "DELETE FROM events WHERE event_id=?", [(e,) for e in event_ids]
            )

    def retry_later(self, event_ids: list[str], next_attempt_at: float) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.executemany(
                "UPDATE events SET attempts=attempts+1,next_attempt_at=? WHERE event_id=?",
                [(next_attempt_at, e) for e in event_ids],
            )
