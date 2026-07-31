"""Metrics subcommand tests.

`fg_backup.sh metrics` emits Prometheus text-exposition metrics by default and
a JSON object when FG_BACKUP_JSON_OUTPUT=true.
"""

from __future__ import annotations

import json

EXPECTED_METRICS = {
    "fg_backup_last_success_timestamp_seconds",
    "fg_backup_age_seconds",
    "fg_backup_count",
    "fg_backup_size_bytes",
    "fg_backup_last_duration_seconds",
    "fg_backup_last_restore_duration_seconds",
    "fg_backup_verification_failures_total",
    "fg_backup_rpo_ok",
}


def test_metrics_output_contains_all_expected_names(run_fg_backup, seed_backup):
    seed_backup()
    result = run_fg_backup("metrics")
    assert result.returncode == 0
    for name in EXPECTED_METRICS:
        assert name in result.stdout, f"missing metric {name}"


def test_metrics_prometheus_format_has_help_and_type_lines(run_fg_backup, seed_backup):
    seed_backup()
    result = run_fg_backup("metrics")
    assert result.returncode == 0
    for name in EXPECTED_METRICS:
        assert f"# HELP {name}" in result.stdout
        assert f"# TYPE {name}" in result.stdout


def test_metrics_json_output_is_valid(run_fg_backup, seed_backup):
    seed_backup()
    result = run_fg_backup("metrics", env={"FG_BACKUP_JSON_OUTPUT": "true"})
    assert result.returncode == 0
    doc = json.loads(result.stdout)
    for name in EXPECTED_METRICS:
        assert name in doc


def test_metrics_json_values_are_numeric(run_fg_backup, seed_backup):
    seed_backup()
    result = run_fg_backup("metrics", env={"FG_BACKUP_JSON_OUTPUT": "true"})
    assert result.returncode == 0
    doc = json.loads(result.stdout)
    for name, value in doc.items():
        assert isinstance(value, (int, float)), (
            f"metric {name}={value!r} is not numeric"
        )


def test_metrics_with_empty_backup_dir_exits_zero(run_fg_backup):
    result = run_fg_backup("metrics")
    assert result.returncode == 0
    # backup_count should be 0 in the emitted text
    assert "fg_backup_count 0" in result.stdout


def test_metrics_rpo_ok_is_binary(run_fg_backup, seed_backup):
    seed_backup()
    result = run_fg_backup("metrics", env={"FG_BACKUP_JSON_OUTPUT": "true"})
    doc = json.loads(result.stdout)
    assert doc["fg_backup_rpo_ok"] in (0, 1)
