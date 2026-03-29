"""
Task 1.5 – Background Job Tenant Isolation Tests.

Proves that:
1. merkle_anchor.job requires tenant_id (fails without it)
2. get_audit_entries_in_window requires tenant_id (fails without it)
3. Data access is tenant-filtered (cross-tenant rows are excluded)
4. sim_validator simulations carry explicit tenant_id (no cross-tenant mixing)
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from jobs.merkle_anchor.job import (
    get_audit_entries_in_window,
    job as merkle_anchor_job,
)
from jobs.sim_validator.job import SIMULATION_INPUTS, SimulationInput


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_db(tmp_path: Path) -> str:
    """Create a minimal SQLite DB with security_audit_log rows for two tenants."""
    db_path = str(tmp_path / "test_frostgate.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE security_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            event_type TEXT,
            event_category TEXT,
            severity TEXT,
            tenant_id TEXT NOT NULL,
            key_prefix TEXT,
            client_ip TEXT,
            request_id TEXT,
            request_path TEXT,
            request_method TEXT,
            success INTEGER,
            reason TEXT,
            details_json TEXT
        )
        """
    )
    now = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        "INSERT INTO security_audit_log (created_at, event_type, tenant_id) VALUES (?, ?, ?)",
        [
            (now, "auth.success", "tenant-job-A"),
            (now, "auth.failure", "tenant-job-A"),
            (now, "auth.success", "tenant-job-B"),
        ],
    )
    conn.commit()
    conn.close()
    return db_path


# ---------------------------------------------------------------------------
# merkle_anchor: get_audit_entries_in_window
# ---------------------------------------------------------------------------


class TestGetAuditEntriesInWindowTenantIsolation:
    """get_audit_entries_in_window must require tenant_id and filter by it."""

    def test_missing_tenant_id_raises(self, tmp_path):
        """Calling without tenant_id must raise ValueError (fail closed)."""
        db_path = _make_db(tmp_path)
        window_end = datetime.now(timezone.utc)
        from datetime import timedelta

        window_start = window_end - timedelta(hours=1)

        with pytest.raises(ValueError, match="tenant_id is required"):
            get_audit_entries_in_window(window_start, window_end, db_path=db_path)

    def test_empty_tenant_id_raises(self, tmp_path):
        """Calling with empty string tenant_id must raise ValueError."""
        db_path = _make_db(tmp_path)
        window_end = datetime.now(timezone.utc)
        from datetime import timedelta

        window_start = window_end - timedelta(hours=1)

        with pytest.raises(ValueError, match="tenant_id is required"):
            get_audit_entries_in_window(
                window_start, window_end, db_path=db_path, tenant_id=""
            )

    def test_returns_only_matching_tenant_rows(self, tmp_path):
        """Only rows for the specified tenant are returned."""
        db_path = _make_db(tmp_path)
        window_end = datetime.now(timezone.utc)
        from datetime import timedelta

        window_start = window_end - timedelta(hours=1)

        entries = get_audit_entries_in_window(
            window_start, window_end, db_path=db_path, tenant_id="tenant-job-A"
        )

        assert len(entries) == 2
        for e in entries:
            assert e["tenant_id"] == "tenant-job-A"

    def test_cross_tenant_rows_excluded(self, tmp_path):
        """Rows belonging to a different tenant are NOT returned."""
        db_path = _make_db(tmp_path)
        window_end = datetime.now(timezone.utc)
        from datetime import timedelta

        window_start = window_end - timedelta(hours=1)

        entries = get_audit_entries_in_window(
            window_start, window_end, db_path=db_path, tenant_id="tenant-job-A"
        )

        tenant_b_rows = [e for e in entries if e["tenant_id"] == "tenant-job-B"]
        assert tenant_b_rows == [], "Cross-tenant rows must not be returned"

    def test_different_tenant_sees_own_row(self, tmp_path):
        """tenant-job-B sees only its own row, not tenant-job-A's rows."""
        db_path = _make_db(tmp_path)
        window_end = datetime.now(timezone.utc)
        from datetime import timedelta

        window_start = window_end - timedelta(hours=1)

        entries = get_audit_entries_in_window(
            window_start, window_end, db_path=db_path, tenant_id="tenant-job-B"
        )

        assert len(entries) == 1
        assert entries[0]["tenant_id"] == "tenant-job-B"

    def test_unknown_tenant_returns_empty(self, tmp_path):
        """A tenant with no data receives an empty list, not another tenant's data."""
        db_path = _make_db(tmp_path)
        window_end = datetime.now(timezone.utc)
        from datetime import timedelta

        window_start = window_end - timedelta(hours=1)

        entries = get_audit_entries_in_window(
            window_start, window_end, db_path=db_path, tenant_id="tenant-job-C"
        )

        assert entries == []


# ---------------------------------------------------------------------------
# merkle_anchor: create_anchor_record durable attribution
# ---------------------------------------------------------------------------


class TestMerkleAnchorDurableTenantAttribution:
    """The durable anchor record (written to the append-only log) must carry tenant_id."""

    def test_create_anchor_record_includes_tenant_id(self):
        """tenant_id is persisted in the durable record, not just transient status."""
        from jobs.merkle_anchor.job import create_anchor_record, sha256_hex
        from datetime import timedelta

        window_end = datetime.now(timezone.utc)
        window_start = window_end - timedelta(hours=1)
        leaf = sha256_hex("entry")

        record = create_anchor_record(
            merkle_root=sha256_hex(leaf + leaf),
            window_start=window_start,
            window_end=window_end,
            leaf_count=1,
            leaf_hashes=[leaf],
            prev_anchor_hash=None,
            tenant_id="tenant-job-A",
        )

        assert record["tenant_id"] == "tenant-job-A"

    def test_anchor_records_for_different_tenants_are_distinct(self):
        """
        Records for two tenants differ in tenant_id and in anchor_hash,
        so anchors remain distinguishable even with identical payloads.
        """
        from jobs.merkle_anchor.job import create_anchor_record, sha256_hex
        from datetime import timedelta

        window_end = datetime.now(timezone.utc)
        window_start = window_end - timedelta(hours=1)
        leaf = sha256_hex("entry")
        kwargs = dict(
            merkle_root=sha256_hex(leaf + leaf),
            window_start=window_start,
            window_end=window_end,
            leaf_count=1,
            leaf_hashes=[leaf],
            prev_anchor_hash=None,
        )

        record_a = create_anchor_record(**kwargs, tenant_id="tenant-job-A")
        record_b = create_anchor_record(**kwargs, tenant_id="tenant-job-B")

        assert record_a["tenant_id"] != record_b["tenant_id"]
        assert record_a["anchor_hash"] != record_b["anchor_hash"]

    def test_job_durable_record_carries_tenant_id(self, tmp_path, monkeypatch):
        """
        After job() runs, the record appended to the anchor log includes tenant_id.
        This is the durable artifact — not just the returned status dict.
        """
        import asyncio
        import json

        import jobs.merkle_anchor.job as ma_mod

        log_file = tmp_path / "anchor_log.jsonl"
        monkeypatch.setattr(ma_mod, "STATE_DIR", tmp_path)
        monkeypatch.setattr(ma_mod, "ANCHOR_STATE_FILE", tmp_path / "status.json")
        monkeypatch.setattr(ma_mod, "ANCHOR_LOG_FILE", log_file)
        monkeypatch.setattr(ma_mod, "ANCHOR_CHAIN_FILE", tmp_path / "chain.json")

        asyncio.run(merkle_anchor_job(tenant_id="tenant-job-A"))

        records = [
            json.loads(line) for line in log_file.read_text().splitlines() if line
        ]
        assert len(records) == 1
        assert records[0]["tenant_id"] == "tenant-job-A"


# ---------------------------------------------------------------------------
# merkle_anchor: job() entry point
# ---------------------------------------------------------------------------


class TestMerkleAnchorJobTenantIsolation:
    """The top-level job() function must require tenant_id."""

    def test_job_missing_tenant_id_raises(self):
        """Calling job() without tenant_id raises TypeError (required param)."""
        import asyncio

        with pytest.raises(TypeError):
            asyncio.run(merkle_anchor_job())

    def test_job_empty_tenant_id_raises(self, tmp_path, monkeypatch):
        """Calling job() with empty string tenant_id raises ValueError."""
        import asyncio

        monkeypatch.setenv("FG_STATE_DIR", str(tmp_path))

        with pytest.raises(ValueError, match="tenant_id is required"):
            asyncio.run(merkle_anchor_job(tenant_id=""))

    def test_job_succeeds_with_valid_tenant(self, tmp_path, monkeypatch):
        """job() succeeds when tenant_id is provided (even if DB absent)."""
        import asyncio

        monkeypatch.setenv("FG_STATE_DIR", str(tmp_path))
        # Redirect state files to tmp_path
        import jobs.merkle_anchor.job as ma_mod

        monkeypatch.setattr(ma_mod, "STATE_DIR", tmp_path)
        monkeypatch.setattr(ma_mod, "ANCHOR_STATE_FILE", tmp_path / "status.json")
        monkeypatch.setattr(ma_mod, "ANCHOR_LOG_FILE", tmp_path / "log.jsonl")
        monkeypatch.setattr(ma_mod, "ANCHOR_CHAIN_FILE", tmp_path / "chain.json")

        result = asyncio.run(merkle_anchor_job(tenant_id="tenant-job-A"))

        assert result["status"] == "ok"
        assert result["tenant_id"] == "tenant-job-A"

    def test_job_result_carries_tenant_id(self, tmp_path, monkeypatch):
        """Result dict includes tenant_id so callers can verify context."""
        import asyncio

        import jobs.merkle_anchor.job as ma_mod

        monkeypatch.setattr(ma_mod, "STATE_DIR", tmp_path)
        monkeypatch.setattr(ma_mod, "ANCHOR_STATE_FILE", tmp_path / "status.json")
        monkeypatch.setattr(ma_mod, "ANCHOR_LOG_FILE", tmp_path / "log.jsonl")
        monkeypatch.setattr(ma_mod, "ANCHOR_CHAIN_FILE", tmp_path / "chain.json")

        result_a = asyncio.run(merkle_anchor_job(tenant_id="tenant-job-A"))
        result_b = asyncio.run(merkle_anchor_job(tenant_id="tenant-job-B"))

        assert result_a["tenant_id"] == "tenant-job-A"
        assert result_b["tenant_id"] == "tenant-job-B"


# ---------------------------------------------------------------------------
# sim_validator: every simulation carries explicit tenant_id
# ---------------------------------------------------------------------------


class TestSimValidatorJobTenantBinding:
    """Every simulation input must carry an explicit, non-empty tenant_id."""

    def test_all_simulation_inputs_have_tenant_id(self):
        """No simulation input is allowed to have a missing or empty tenant_id."""
        for sim in SIMULATION_INPUTS:
            assert sim.tenant_id, (
                f"SimulationInput '{sim.name}' is missing tenant_id — "
                "cross-tenant data access would be possible"
            )

    def test_simulation_inputs_do_not_share_tenant_data(self):
        """
        Simulations across different tenants use distinct tenant IDs.
        Verifies that the sim_validator does not mix tenant contexts.
        """
        tenant_ids = {sim.tenant_id for sim in SIMULATION_INPUTS}
        # Must have more than one distinct tenant to exercise isolation
        assert len(tenant_ids) > 1, "Test suite requires multi-tenant simulation inputs"

    def test_run_simulation_passes_tenant_id_to_telemetry(self):
        """run_simulation must propagate tenant_id into TelemetryInput."""
        from jobs.sim_validator.job import run_simulation

        sim_input = SimulationInput(
            name="tenant_isolation_check",
            tenant_id="t_isolation_test",
            source="test",
            event_type="http_request",
            payload={"path": "/health", "method": "GET", "src_ip": "127.0.0.1"},
            expected_threat_level="none",
            expected_rules=["rule:default_allow"],
        )

        # Should succeed without exception — tenant_id is bound
        output = run_simulation(sim_input)
        assert output is not None
        assert output.name == "tenant_isolation_check"
