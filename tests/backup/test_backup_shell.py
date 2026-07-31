"""End-to-end shell behavior tests for fg_backup.sh.

These are the safety-critical behaviors that fg_backup.sh must never
regress. They use subprocess execution with hermetic env, no live database,
no network, no Docker.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


def test_verify_nonexistent_file_exits_nonzero(run_fg_backup):
    result = run_fg_backup("verify", "/tmp/absolutely-not-a-real-backup.dump")
    assert result.returncode != 0


def test_verify_with_mismatched_checksum_exits_nonzero(
    run_fg_backup, seed_backup, backup_dir: Path
):
    archive, _manifest = seed_backup()
    archive.write_bytes(b"totally-different-content")
    result = run_fg_backup("verify", str(archive))
    assert result.returncode != 0
    assert "FAIL checksum_match" in result.stdout


def test_status_with_no_backups_returns_critical(run_fg_backup):
    result = run_fg_backup("status")
    assert result.returncode == 0  # status itself succeeded
    payload = json.loads(result.stdout)
    assert payload["backup_status"] == "critical"
    assert payload["backup_count"] == 0
    assert payload["latest_backup"] is None
    assert payload["errors"] and "no backups found" in payload["errors"]


def test_status_with_verified_backup_returns_ok(run_fg_backup, seed_backup):
    seed_backup()
    result = run_fg_backup("status")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["backup_count"] == 1
    assert payload["latest_backup_verified"] is True


def test_backup_missing_db_url_exits_nonzero(run_fg_backup):
    # Ensure no FG_BACKUP_DB_URL leaks in from the harness.
    env = {k: v for k, v in os.environ.items() if not k.startswith("FG_BACKUP_")}
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
    result = run_fg_backup("backup", env=env)
    assert result.returncode != 0
    assert "FG_BACKUP_DB_URL" in result.stderr


def test_backup_encryption_enabled_without_key_exits_code_2(run_fg_backup):
    env = {
        "FG_BACKUP_DB_URL": "postgres://user:pass@127.0.0.1:5432/db",
        "FG_BACKUP_ENCRYPT": "true",
        # No FG_BACKUP_ENCRYPTION_KEY
    }
    result = run_fg_backup("backup", env=env)
    assert result.returncode == 2
    assert "FG_BACKUP_ENCRYPTION_KEY" in result.stderr


def test_unknown_subcommand_exits_code_2(run_fg_backup):
    result = run_fg_backup("nonsense-subcommand")
    assert result.returncode == 2


def test_prune_unknown_flag_exits_code_2(run_fg_backup):
    result = run_fg_backup("prune", "--not-a-flag")
    assert result.returncode == 2


def test_backup_type_flag_validation(run_fg_backup):
    env = {"FG_BACKUP_DB_URL": "postgres://u:p@h:5432/d"}
    result = run_fg_backup("backup", "--type", "invalid-type", env=env)
    assert result.returncode == 2


def test_help_output_lists_all_subcommands(run_fg_backup):
    result = run_fg_backup("--help")
    combined = (result.stdout + result.stderr).lower()
    for sub in ("backup", "verify", "restore", "list", "prune", "drill", "status"):
        assert sub in combined
