from __future__ import annotations

import sqlite3

import pytest

from services.testing_control_tower_store import ensure_tables


def test_testing_runs_rows_immutable(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    db = tmp_path / "immut.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db))
    ensure_tables()
    con = sqlite3.connect(str(db))
    con.execute(
        "INSERT INTO testing_runs (run_id, tenant_id, lane, status, started_at, finished_at, duration_ms, commit_sha, ref, triggered_by, triage_schema_version, triage_category_counts, artifact_hashes, artifact_paths, summary_md, canonical_payload_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("r1", "t1", "fg-fast", "passed", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", 1, "a", "r", "ci", "2.0", "{}", "{}", "[]", "", "h" * 64),
    )
    con.commit()
    with pytest.raises(sqlite3.DatabaseError):
        con.execute("UPDATE testing_runs SET status='failed' WHERE run_id='r1'")
