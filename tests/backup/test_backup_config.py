"""Tests for scripts/backup/backup_config.sh.

Runs the config script inside a subshell and inspects the resulting
environment. The config script must:
  1. Provide safe defaults for every optional variable.
  2. Not overwrite values already set by the caller.
  3. Export every variable so downstream scripts see it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKUP_CONFIG_SH = REPO_ROOT / "scripts" / "backup" / "backup_config.sh"


def _source_and_dump(env: dict[str, str]) -> dict[str, str]:
    """Source backup_config.sh in a fresh bash and return env values."""
    keys = [
        "FG_BACKUP_DB_URL",
        "FG_BACKUP_DB_NAME",
        "FG_BACKUP_DIR",
        "FG_BACKUP_TMP_DIR",
        "FG_BACKUP_DOCKER_IMAGE",
        "FG_BACKUP_OFFSITE_PROVIDER",
        "FG_BACKUP_OFFSITE_LOCAL_PATH",
        "FG_BACKUP_S3_BUCKET",
        "FG_BACKUP_S3_ENDPOINT",
        "FG_BACKUP_S3_PREFIX",
        "FG_BACKUP_ENCRYPT",
        "FG_BACKUP_ENCRYPTION_KEY",
        "FG_BACKUP_RETAIN_HOURLY",
        "FG_BACKUP_RETAIN_DAILY",
        "FG_BACKUP_RETAIN_WEEKLY",
        "FG_BACKUP_RETAIN_MONTHLY",
        "FG_BACKUP_RETAIN_YEARLY",
        "FG_BACKUP_RPO_WARN_HOURS",
        "FG_BACKUP_RTO_ESTIMATE_MINUTES",
        "FG_BACKUP_OPERATOR",
        "FG_BACKUP_JSON_OUTPUT",
        "FG_BACKUP_RAILWAY_PLAN",
    ]
    script = f". {BACKUP_CONFIG_SH}\n"
    for k in keys:
        script += f'printf "%s=%s\\n" "{k}" "${{{k}}}"\n'
    proc = subprocess.run(
        ["bash", "-c", script],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    result: dict[str, str] = {}
    for line in proc.stdout.strip().splitlines():
        key, _, val = line.partition("=")
        result[key] = val
    return result


def _base_env() -> dict[str, str]:
    # Minimal, hermetic environment. bash needs PATH to find printf/etc.
    import os

    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}


def test_defaults_applied_when_env_empty():
    values = _source_and_dump(_base_env())
    assert values["FG_BACKUP_DB_NAME"] == "railway"
    assert values["FG_BACKUP_DIR"] == "/var/lib/frostgate/backups"
    assert values["FG_BACKUP_DOCKER_IMAGE"] == "pgvector/pgvector:pg18"
    assert values["FG_BACKUP_OFFSITE_PROVIDER"] == "local"
    assert values["FG_BACKUP_ENCRYPT"] == "false"
    assert values["FG_BACKUP_RETAIN_HOURLY"] == "24"
    assert values["FG_BACKUP_RETAIN_DAILY"] == "30"
    assert values["FG_BACKUP_RETAIN_WEEKLY"] == "12"
    assert values["FG_BACKUP_RETAIN_MONTHLY"] == "12"
    assert values["FG_BACKUP_RETAIN_YEARLY"] == "7"
    assert values["FG_BACKUP_RPO_WARN_HOURS"] == "25"
    assert values["FG_BACKUP_JSON_OUTPUT"] == "false"
    assert values["FG_BACKUP_RAILWAY_PLAN"] == "hobby"


def test_caller_env_overrides_defaults():
    env = _base_env()
    env["FG_BACKUP_DIR"] = "/mnt/custom/backups"
    env["FG_BACKUP_RETAIN_HOURLY"] = "6"
    env["FG_BACKUP_OFFSITE_PROVIDER"] = "s3"
    env["FG_BACKUP_ENCRYPT"] = "true"
    values = _source_and_dump(env)
    assert values["FG_BACKUP_DIR"] == "/mnt/custom/backups"
    assert values["FG_BACKUP_RETAIN_HOURLY"] == "6"
    assert values["FG_BACKUP_OFFSITE_PROVIDER"] == "s3"
    assert values["FG_BACKUP_ENCRYPT"] == "true"


def test_db_url_default_is_empty():
    """We must never bake a default DB URL into the config."""
    values = _source_and_dump(_base_env())
    assert values["FG_BACKUP_DB_URL"] == ""


def test_encryption_key_default_is_empty():
    values = _source_and_dump(_base_env())
    assert values["FG_BACKUP_ENCRYPTION_KEY"] == ""


def test_docker_image_matches_t1_proven_method():
    """Guard: the T1 proven method uses pgvector/pgvector:pg18. If this
    default changes, docs/operators/backup_restore.md §7 must change with it.
    """
    values = _source_and_dump(_base_env())
    assert values["FG_BACKUP_DOCKER_IMAGE"] == "pgvector/pgvector:pg18"
