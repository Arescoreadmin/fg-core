from __future__ import annotations

import json
import os
import sqlite3
from statistics import mean
from typing import Any


def _db_path() -> str:
    return os.getenv("FG_SQLITE_PATH", "/tmp/frostgate/fg-control-tower.db")


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(_db_path())
    con.row_factory = sqlite3.Row
    return con


def ensure_tables() -> None:
    con = _connect()
    try:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS testing_runs (
              run_id TEXT PRIMARY KEY,
              tenant_id TEXT NOT NULL,
              lane TEXT NOT NULL,
              status TEXT NOT NULL,
              started_at TEXT NOT NULL,
              finished_at TEXT,
              duration_ms INTEGER NOT NULL,
              commit_sha TEXT NOT NULL,
              ref TEXT NOT NULL,
              triggered_by TEXT NOT NULL,
              triage_schema_version TEXT NOT NULL,
              triage_category_counts TEXT NOT NULL,
              artifact_hashes TEXT NOT NULL,
              artifact_paths TEXT NOT NULL,
              summary_md TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS testing_run_audit (
              audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
              run_id TEXT NOT NULL,
              tenant_id TEXT NOT NULL,
              action TEXT NOT NULL,
              actor TEXT NOT NULL,
              details TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS testing_health_snapshot (
              snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
              tenant_id TEXT NOT NULL,
              lane TEXT NOT NULL,
              mean_duration_ms REAL NOT NULL,
              flake_rate REAL NOT NULL,
              invariant_coverage_count INTEGER NOT NULL,
              category_frequency TEXT NOT NULL,
              sample_size INTEGER NOT NULL,
              created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            )
            """
        )
        con.execute(
            """
            CREATE TRIGGER IF NOT EXISTS testing_runs_no_update
            BEFORE UPDATE ON testing_runs
            BEGIN
              SELECT RAISE(ABORT, 'testing_runs rows are immutable');
            END;
            """
        )
        con.execute(
            """
            CREATE TRIGGER IF NOT EXISTS testing_runs_no_delete
            BEFORE DELETE ON testing_runs
            BEGIN
              SELECT RAISE(ABORT, 'testing_runs rows are immutable');
            END;
            """
        )
        con.commit()
    finally:
        con.close()


def register_run(payload: dict[str, Any], *, actor: str, policy_change_event: bool = False) -> None:
    ensure_tables()
    con = _connect()
    try:
        con.execute(
            """
            INSERT INTO testing_runs (
              run_id, tenant_id, lane, status, started_at, finished_at, duration_ms,
              commit_sha, ref, triggered_by, triage_schema_version, triage_category_counts,
              artifact_hashes, artifact_paths, summary_md
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload["run_id"],
                payload["tenant_id"],
                payload["lane"],
                payload["status"],
                payload["started_at"],
                payload.get("finished_at"),
                int(payload["duration_ms"]),
                payload["commit_sha"],
                payload["ref"],
                payload["triggered_by"],
                payload.get("triage_schema_version", "2.0"),
                json.dumps(payload.get("triage_category_counts", {}), sort_keys=True),
                json.dumps(payload.get("artifact_hashes", {}), sort_keys=True),
                json.dumps(payload.get("artifact_paths", [])),
                payload.get("summary_md", ""),
            ),
        )
        audit_details = {
            "lane": payload["lane"],
            "status": payload["status"],
            "commit_sha": payload["commit_sha"],
            "policy_change_event": bool(policy_change_event),
        }
        con.execute(
            "INSERT INTO testing_run_audit (run_id, tenant_id, action, actor, details) VALUES (?, ?, ?, ?, ?)",
            (payload["run_id"], payload["tenant_id"], "register", actor, json.dumps(audit_details, sort_keys=True)),
        )
        _write_health_snapshot(con, payload["tenant_id"], payload["lane"])
        con.commit()
    finally:
        con.close()


def _write_health_snapshot(con: sqlite3.Connection, tenant_id: str, lane: str) -> None:
    rows = con.execute(
        "SELECT duration_ms, status, triage_category_counts FROM testing_runs WHERE tenant_id=? AND lane=? ORDER BY started_at DESC LIMIT 20",
        (tenant_id, lane),
    ).fetchall()
    if not rows:
        return
    durations = [int(r["duration_ms"]) for r in rows]
    sample_size = len(rows)
    flaky_count = sum(1 for r in rows if str(r["status"]).lower() == "flaky")
    category_frequency: dict[str, int] = {}
    for row in rows:
        triage = json.loads(row["triage_category_counts"])
        for cat, count in triage.items():
            category_frequency[str(cat)] = category_frequency.get(str(cat), 0) + int(count)

    con.execute(
        """
        INSERT INTO testing_health_snapshot (
          tenant_id, lane, mean_duration_ms, flake_rate, invariant_coverage_count,
          category_frequency, sample_size
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            tenant_id,
            lane,
            float(mean(durations)),
            float(flaky_count) / float(sample_size),
            0,
            json.dumps(category_frequency, sort_keys=True),
            sample_size,
        ),
    )


def list_runs(tenant_id: str, limit: int) -> list[dict[str, Any]]:
    ensure_tables()
    con = _connect()
    try:
        rows = con.execute(
            "SELECT * FROM testing_runs WHERE tenant_id=? ORDER BY started_at DESC LIMIT ?",
            (tenant_id, int(limit)),
        ).fetchall()
        return [_row_to_dict(r) for r in rows]
    finally:
        con.close()


def get_run(tenant_id: str, run_id: str) -> dict[str, Any] | None:
    ensure_tables()
    con = _connect()
    try:
        row = con.execute(
            "SELECT * FROM testing_runs WHERE tenant_id=? AND run_id=?",
            (tenant_id, run_id),
        ).fetchone()
        return _row_to_dict(row) if row else None
    finally:
        con.close()


def latest_health(tenant_id: str, lane: str | None = None) -> list[dict[str, Any]]:
    ensure_tables()
    con = _connect()
    try:
        if lane:
            rows = con.execute(
                "SELECT * FROM testing_health_snapshot WHERE tenant_id=? AND lane=? ORDER BY created_at DESC LIMIT 20",
                (tenant_id, lane),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM testing_health_snapshot WHERE tenant_id=? ORDER BY created_at DESC LIMIT 50",
                (tenant_id,),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "tenant_id": r["tenant_id"],
                    "lane": r["lane"],
                    "mean_duration_ms": float(r["mean_duration_ms"]),
                    "flake_rate": float(r["flake_rate"]),
                    "invariant_coverage_count": int(r["invariant_coverage_count"]),
                    "category_frequency": json.loads(r["category_frequency"]),
                    "sample_size": int(r["sample_size"]),
                    "created_at": r["created_at"],
                }
            )
        return out
    finally:
        con.close()


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "run_id": row["run_id"],
        "lane": row["lane"],
        "status": row["status"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "duration_ms": int(row["duration_ms"]),
        "commit_sha": row["commit_sha"],
        "ref": row["ref"],
        "triggered_by": row["triggered_by"],
        "triage_schema_version": row["triage_schema_version"],
        "triage_category_counts": json.loads(row["triage_category_counts"]),
        "artifact_hashes": json.loads(row["artifact_hashes"]),
        "artifact_paths": json.loads(row["artifact_paths"]),
        "summary_md": row["summary_md"],
    }
