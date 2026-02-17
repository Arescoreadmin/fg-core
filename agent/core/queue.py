from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


TERMINAL_REASONS = {
    "policy_denied",
    "invalid_config",
    "integrity_hash_mismatch",
    "auth_ambiguous",
    "max_attempts_exceeded",
    "handler_not_found",
}
QUEUE_CORRUPTION_REASON = "queue_corruption_detected"
QUARANTINE_SENTINEL_UNREADABLE = "quarantine_sentinel_unreadable"
QUARANTINE_SENTINEL_PERM_DEGRADED = "quarantine_sentinel_perm_degraded"


@dataclass(frozen=True)
class QueueJob:
    job_id: str
    task_type: str
    payload: dict
    attempts: int
    lease_id: str


class QueueCorruptionError(RuntimeError):
    pass


class SQLiteTaskQueue:
    def __init__(
        self,
        db_path: str,
        *,
        max_size: int = 1000,
        max_attempts: int = 5,
        lease_seconds: int = 30,
        busy_timeout_ms: int = 5000,
        clock: Callable[[], float] | None = None,
        audit_sink: Callable[[dict], None] | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.max_size = max_size
        self.max_attempts = max_attempts
        self.lease_seconds = lease_seconds
        self._clock = clock or time.time
        self._audit_sink = audit_sink
        self._quarantined = False
        self._quarantine_reason: str | None = None
        self._quarantine_path: str | None = None
        self._sentinel_perm_degraded = False
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._sentinel_path = self.db_path.with_suffix(
            self.db_path.suffix + ".quarantine.json"
        )
        self._load_quarantine_sentinel()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _load_quarantine_sentinel(self) -> None:
        if not self._sentinel_path.exists():
            return
        try:
            data = json.loads(self._sentinel_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            self._quarantined = True
            self._quarantine_reason = QUARANTINE_SENTINEL_UNREADABLE
            self._quarantine_path = None
            self._emit_startup_quarantine_audit(QUARANTINE_SENTINEL_UNREADABLE)
            return
        self._quarantined = True
        self._quarantine_reason = str(data.get("reason_code", QUEUE_CORRUPTION_REASON))
        qp = data.get("quarantine_path")
        self._quarantine_path = str(qp) if qp else None

    def _emit_startup_quarantine_audit(self, reason_code: str) -> None:
        if self._audit_sink is None:
            return
        material = f"{self.db_path}|{reason_code}|startup"
        event_id = hashlib.sha256(material.encode("utf-8")).hexdigest()
        self._audit_sink(
            {
                "event_id": event_id,
                "event": "queue_quarantine_startup",
                "reason_code": reason_code,
                "queue_path": str(self.db_path),
                "timestamp": self._clock(),
            }
        )

    def clear_quarantine(
        self,
        *,
        force: bool,
        reason: str,
        expected_sentinel_path: str | None = None,
    ) -> None:
        if not force:
            raise ValueError("clear_quarantine requires force=True")
        if not reason.strip():
            raise ValueError("clear_quarantine requires non-empty reason")
        if expected_sentinel_path is not None:
            if str(self._sentinel_path) != str(expected_sentinel_path):
                raise ValueError("expected_sentinel_path mismatch")

        if self._sentinel_path.exists():
            self._sentinel_path.unlink()

        self._quarantined = False
        self._quarantine_reason = None
        self._quarantine_path = None

        self._emit_quarantine_cleared_audit(reason=reason)

    def _ensure_not_quarantined(self) -> None:
        if self._quarantined:
            raise QueueCorruptionError(
                self._quarantine_reason or QUEUE_CORRUPTION_REASON
            )

    @property
    def quarantined(self) -> bool:
        return self._quarantined

    @property
    def quarantine_reason(self) -> str | None:
        return self._quarantine_reason

    @property
    def quarantine_path(self) -> str | None:
        return self._quarantine_path

    @property
    def sentinel_perm_degraded(self) -> bool:
        return self._sentinel_perm_degraded

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS queue_jobs (
                    job_id TEXT PRIMARY KEY,
                    task_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    visible_at REAL NOT NULL,
                    lease_id TEXT,
                    lease_expires_at REAL,
                    created_at REAL NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS deadletter_jobs (
                    job_id TEXT PRIMARY KEY,
                    task_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    terminal_reason TEXT NOT NULL,
                    failed_at REAL NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_queue_visible ON queue_jobs(visible_at, created_at)"
            )

    @staticmethod
    def deterministic_job_id(task_type: str, payload: dict, created_at: float) -> str:
        canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        material = f"{task_type}|{canonical_payload}|{int(created_at * 1000)}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def enqueue(
        self, task_type: str, payload: dict, *, created_at: float | None = None
    ) -> str:
        self._ensure_not_quarantined()
        now = self._clock() if created_at is None else created_at
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        job_id = self.deterministic_job_id(task_type, payload, now)
        with self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            count = self._conn.execute(
                "SELECT COUNT(*) AS c FROM queue_jobs"
            ).fetchone()["c"]
            if int(count) >= self.max_size:
                raise RuntimeError("queue_capacity_exceeded")
            self._conn.execute(
                """
                INSERT INTO queue_jobs(job_id, task_type, payload_json, visible_at, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (job_id, task_type, payload_json, now, now),
            )
        return job_id

    def lease_next(self) -> QueueJob | None:
        self._ensure_not_quarantined()
        for _ in range(4):
            now = self._clock()
            lease_id = hashlib.sha256(f"{now}|lease".encode("utf-8")).hexdigest()
            lease_expires = now + self.lease_seconds
            with self._conn:
                self._conn.execute("BEGIN IMMEDIATE")
                row = self._conn.execute(
                    """
                    SELECT job_id, task_type, payload_json, attempts
                    FROM queue_jobs
                    WHERE visible_at <= ?
                      AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                    ORDER BY created_at ASC
                    LIMIT 1
                    """,
                    (now, now),
                ).fetchone()
                if row is None:
                    self._conn.commit()
                    return None

                self._conn.execute(
                    """
                    UPDATE queue_jobs
                    SET lease_id = ?, lease_expires_at = ?, visible_at = ?
                    WHERE job_id = ?
                      AND visible_at <= ?
                      AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                    """,
                    (lease_id, lease_expires, lease_expires, row["job_id"], now, now),
                )
                updated = int(self._conn.execute("SELECT changes()").fetchone()[0])
                self._conn.commit()

                if updated == 1:
                    return QueueJob(
                        job_id=row["job_id"],
                        task_type=row["task_type"],
                        payload=json.loads(row["payload_json"]),
                        attempts=int(row["attempts"]),
                        lease_id=lease_id,
                    )
        return None

    def ack(self, job_id: str, lease_id: str) -> None:
        self._ensure_not_quarantined()
        with self._conn:
            self._conn.execute(
                "DELETE FROM queue_jobs WHERE job_id = ? AND lease_id = ?",
                (job_id, lease_id),
            )

    def fail(self, job: QueueJob, reason: str, *, retry_delay_seconds: float) -> None:
        self._ensure_not_quarantined()
        now = self._clock()
        attempts = job.attempts + 1
        if attempts >= self.max_attempts or reason in TERMINAL_REASONS:
            terminal_reason = (
                "max_attempts_exceeded" if attempts >= self.max_attempts else reason
            )
            self._deadletter(job, attempts, terminal_reason, now)
            return
        with self._conn:
            self._conn.execute(
                """
                UPDATE queue_jobs
                SET attempts = ?,
                    visible_at = ?,
                    lease_id = NULL,
                    lease_expires_at = NULL
                WHERE job_id = ? AND lease_id = ?
                """,
                (attempts, now + retry_delay_seconds, job.job_id, job.lease_id),
            )

    def _deadletter(
        self,
        job: QueueJob,
        attempts: int,
        terminal_reason: str,
        failed_at: float,
    ) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO deadletter_jobs(
                    job_id, task_type, payload_json, attempts, terminal_reason, failed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    job.job_id,
                    job.task_type,
                    json.dumps(job.payload, sort_keys=True, separators=(",", ":")),
                    attempts,
                    terminal_reason,
                    failed_at,
                ),
            )
            self._conn.execute(
                "DELETE FROM queue_jobs WHERE job_id = ? AND lease_id = ?",
                (job.job_id, job.lease_id),
            )

    def depth(self) -> int:
        self._ensure_not_quarantined()
        return int(self._conn.execute("SELECT COUNT(*) FROM queue_jobs").fetchone()[0])

    def deadletter_count(self) -> int:
        self._ensure_not_quarantined()
        return int(
            self._conn.execute("SELECT COUNT(*) FROM deadletter_jobs").fetchone()[0]
        )

    def detect_corruption(self) -> None:
        self._ensure_not_quarantined()
        row = self._conn.execute("PRAGMA integrity_check").fetchone()
        if row is not None and row[0] == "ok":
            return
        quarantine_path = self.db_path.with_suffix(
            f".corrupt.{int(self._clock())}.sqlite"
        )
        self._quarantined = True
        self._quarantine_reason = QUEUE_CORRUPTION_REASON
        self._quarantine_path = str(quarantine_path)
        sentinel_write_error: str | None = None
        try:
            self._write_quarantine_sentinel(quarantine_path)
        except Exception as exc:  # noqa: BLE001
            sentinel_write_error = type(exc).__name__

        self._emit_quarantine_audit(
            quarantine_path,
            sentinel_write_error=sentinel_write_error,
        )
        self._conn.close()
        self.db_path.rename(quarantine_path)
        raise QueueCorruptionError(str(quarantine_path))

    def _write_quarantine_sentinel(self, quarantine_path: Path) -> None:
        payload = {
            "reason_code": QUEUE_CORRUPTION_REASON,
            "timestamp": self._clock(),
            "quarantine_path": str(quarantine_path),
        }
        self._sentinel_path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        try:
            self._sentinel_path.chmod(0o600)
        except PermissionError:
            self._sentinel_perm_degraded = True
        except OSError:
            self._sentinel_perm_degraded = True

    def _emit_quarantine_audit(
        self,
        quarantine_path: Path,
        *,
        sentinel_write_error: str | None = None,
    ) -> None:
        if self._audit_sink is None:
            return
        material = f"{self.db_path}|{QUEUE_CORRUPTION_REASON}|{quarantine_path.name}"
        event_id = hashlib.sha256(material.encode("utf-8")).hexdigest()
        payload = {
            "event_id": event_id,
            "event": "queue_quarantine",
            "reason_code": QUEUE_CORRUPTION_REASON,
            "queue_path": str(self.db_path),
            "quarantine_path": str(quarantine_path),
            "timestamp": self._clock(),
        }
        if sentinel_write_error:
            payload["sentinel_write_error"] = sentinel_write_error
        if self._sentinel_perm_degraded:
            payload["sentinel_perm_degraded"] = True
            payload["reason_code"] = QUARANTINE_SENTINEL_PERM_DEGRADED
        self._audit_sink(payload)

    def _emit_quarantine_cleared_audit(self, *, reason: str) -> None:
        if self._audit_sink is None:
            return
        material = f"{self.db_path}|queue_quarantine_cleared|{reason.strip()}"
        event_id = hashlib.sha256(material.encode("utf-8")).hexdigest()
        self._audit_sink(
            {
                "event_id": event_id,
                "event": "queue_quarantine_cleared",
                "reason_code": "queue_quarantine_cleared",
                "queue_path": str(self.db_path),
                "clear_reason": reason.strip(),
                "timestamp": self._clock(),
            }
        )

    def get_deadletter_reason(self, job_id: str) -> str | None:
        self._ensure_not_quarantined()
        row = self._conn.execute(
            "SELECT terminal_reason FROM deadletter_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        return None if row is None else str(row[0])
