"""Health dashboard tests.

`update_health_dashboard` writes a JSON snapshot to
`artifacts/operations/backup_health.json` (path controlled by
FG_BACKUP_HEALTH_DASHBOARD). It runs after every backup / verify / drill.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "backup" / "fg_backup.sh"


def _write_dashboard(
    backup_dir: Path, dashboard_path: Path, outcome: str = "ok", drill_result: str = ""
) -> None:
    script_body = (
        f'source "{SCRIPT}" >/dev/null 2>&1 || true; '
        f'update_health_dashboard "{outcome}" "{drill_result}"'
    )
    env = {
        "PATH": "/usr/bin:/bin",
        "FG_BACKUP_DIR": str(backup_dir),
        "FG_BACKUP_HEALTH_DASHBOARD": str(dashboard_path),
        "FG_BACKUP_RPO_WARN_HOURS": "25",
    }
    subprocess.run(
        ["bash", "-c", script_body],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )


REQUIRED_KEYS = {
    "generated_at",
    "backup_status",
    "last_success",
    "last_failure",
    "backup_age_hours",
    "rpo_hours",
    "rpo_ok",
    "verification_status",
    "last_restore_drill",
    "backup_count",
    "retention",
    "metrics",
}


def test_health_dashboard_is_valid_json(backup_dir: Path, tmp_path: Path, seed_backup):
    seed_backup()
    dashboard = tmp_path / "artifacts" / "operations" / "backup_health.json"
    _write_dashboard(backup_dir, dashboard)
    doc = json.loads(dashboard.read_text())
    assert isinstance(doc, dict)


def test_health_dashboard_has_all_required_keys(
    backup_dir: Path, tmp_path: Path, seed_backup
):
    seed_backup()
    dashboard = tmp_path / "artifacts" / "operations" / "backup_health.json"
    _write_dashboard(backup_dir, dashboard)
    doc = json.loads(dashboard.read_text())
    missing = REQUIRED_KEYS - set(doc.keys())
    assert not missing, f"dashboard missing keys: {sorted(missing)}"


def test_backup_status_is_ok_warning_or_critical(
    backup_dir: Path, tmp_path: Path, seed_backup
):
    seed_backup()
    dashboard = tmp_path / "artifacts" / "operations" / "backup_health.json"
    _write_dashboard(backup_dir, dashboard)
    doc = json.loads(dashboard.read_text())
    assert doc["backup_status"] in {"ok", "warning", "critical"}


def test_last_success_structure(backup_dir: Path, tmp_path: Path, seed_backup):
    seed_backup()
    dashboard = tmp_path / "artifacts" / "operations" / "backup_health.json"
    _write_dashboard(backup_dir, dashboard)
    doc = json.loads(dashboard.read_text())
    ls = doc["last_success"]
    assert ls is not None, "expected last_success populated from seeded verified backup"
    for field in (
        "backup_id",
        "timestamp",
        "size_bytes",
        "verified",
        "encrypted",
        "offsite_uploaded",
    ):
        assert field in ls, f"last_success missing {field}"


def test_no_backups_dashboard_is_critical(backup_dir: Path, tmp_path: Path):
    dashboard = tmp_path / "artifacts" / "operations" / "backup_health.json"
    _write_dashboard(backup_dir, dashboard)
    doc = json.loads(dashboard.read_text())
    assert doc["backup_status"] == "critical"
    assert doc["backup_count"] == 0
    assert doc["last_success"] is None


def test_failed_outcome_marks_last_failure(
    backup_dir: Path, tmp_path: Path, seed_backup
):
    seed_backup()
    dashboard = tmp_path / "artifacts" / "operations" / "backup_health.json"
    _write_dashboard(backup_dir, dashboard, outcome="failed")
    doc = json.loads(dashboard.read_text())
    assert doc["last_failure"] is not None
    assert "timestamp" in doc["last_failure"]
    assert doc["backup_status"] == "critical"
