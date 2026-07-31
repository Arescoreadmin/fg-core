"""Inventory subcommand tests.

`fg_backup.sh inventory` produces a human-readable table (default) or JSON
(when FG_BACKUP_JSON_OUTPUT=true) summarising every backup on disk.
"""

from __future__ import annotations

import json


def test_inventory_with_no_backups_prints_empty_notice(run_fg_backup):
    result = run_fg_backup("inventory")
    assert result.returncode == 0
    combined = result.stdout + result.stderr
    assert "no backups found" in combined.lower() or "BACKUP INVENTORY" in combined


def test_inventory_reads_manifest_files(run_fg_backup, seed_backup):
    _archive, _manifest = seed_backup()
    result = run_fg_backup("inventory")
    assert result.returncode == 0
    assert "FG-BKP-" in result.stdout
    # Header row is always present.
    assert "BACKUP INVENTORY" in result.stdout
    assert "Verified" in result.stdout


def test_inventory_json_output_produces_valid_json(run_fg_backup, seed_backup):
    _archive, _manifest = seed_backup()
    result = run_fg_backup("inventory", env={"FG_BACKUP_JSON_OUTPUT": "true"})
    assert result.returncode == 0
    doc = json.loads(result.stdout)
    assert "backups" in doc and isinstance(doc["backups"], list)
    assert doc["count"] == len(doc["backups"]) == 1
    b = doc["backups"][0]
    for field in (
        "backup_id",
        "file",
        "age_hours",
        "verified",
        "encrypted",
        "offsite_uploaded",
        "bucket",
        "drilled",
        "size_bytes",
    ):
        assert field in b


def test_inventory_json_empty_is_still_valid(run_fg_backup):
    result = run_fg_backup("inventory", env={"FG_BACKUP_JSON_OUTPUT": "true"})
    assert result.returncode == 0
    doc = json.loads(result.stdout)
    assert doc["count"] == 0
    assert doc["backups"] == []


def test_inventory_bucket_classification(run_fg_backup, seed_backup):
    _archive, _manifest = seed_backup()
    result = run_fg_backup("inventory", env={"FG_BACKUP_JSON_OUTPUT": "true"})
    assert result.returncode == 0
    doc = json.loads(result.stdout)
    b = doc["backups"][0]
    assert b["bucket"] in {"hourly", "daily", "weekly", "monthly", "yearly"}
