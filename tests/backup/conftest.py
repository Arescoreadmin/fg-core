"""Shared fixtures for the backup automation test suite.

These tests exercise `scripts/backup/fg_backup.sh` and its Python helper
paths in isolation. They must not require a live database, network, or a
running Docker daemon.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = REPO_ROOT / "scripts" / "backup"
FG_BACKUP_SH = SCRIPT_DIR / "fg_backup.sh"
BACKUP_CONFIG_SH = SCRIPT_DIR / "backup_config.sh"


@pytest.fixture
def backup_dir(tmp_path: Path) -> Path:
    """Temp backup dir with mode 0700, no pre-existing archives."""
    d = tmp_path / "backups"
    d.mkdir(mode=0o700)
    return d


@pytest.fixture
def clean_env(monkeypatch, tmp_path: Path) -> None:
    """Reset all FG_BACKUP_* env vars so tests are hermetic."""
    for key in list(os.environ):
        if key.startswith("FG_BACKUP_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("FG_BACKUP_TMP_DIR", str(tmp_path))


@pytest.fixture
def run_fg_backup(backup_dir: Path, clean_env, monkeypatch):
    """Return a callable that runs fg_backup.sh with a controlled env."""

    def _run(
        *args: str,
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
        check: bool = False,
        timeout: int = 30,
    ) -> subprocess.CompletedProcess:
        run_env = os.environ.copy()
        run_env.setdefault("FG_BACKUP_DIR", str(backup_dir))
        if env:
            run_env.update(env)
        return subprocess.run(
            ["bash", str(FG_BACKUP_SH), *args],
            capture_output=True,
            text=True,
            env=run_env,
            cwd=str(cwd or REPO_ROOT),
            check=check,
            timeout=timeout,
        )

    return _run


def _write_manifest(archive: Path, checksum: str, **overrides) -> Path:
    import json

    data = {
        "manifest_schema_version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "backup_type": "scheduled",
        "db_version": "PostgreSQL 18.4",
        "migration_version": "0168",
        "backup_size_bytes": archive.stat().st_size,
        "dump_size_bytes": archive.stat().st_size,
        "compression": "pg_dump custom format",
        "checksum_sha256": checksum,
        "checksum_algorithm": "sha256",
        "storage_location": str(archive),
        "restore_compatibility": "pgvector/pgvector:pg18",
        "pg_dump_version": "pg_dump (PostgreSQL) 18.4",
        "pg_restore_version": "pg_dump (PostgreSQL) 18.4",
        "verification_status": "verified",
        "verified_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "operator": "test@frostgate.local",
        "encrypted": False,
        "offsite_uploaded": False,
        "offsite_provider": None,
        "duration_seconds": 42,
        "railway_plan": "hobby",
        "script_version": "1.0.0",
    }
    data.update(overrides)
    manifest = archive.with_suffix(archive.suffix + ".manifest.json")
    manifest.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return manifest


@pytest.fixture
def seed_backup(backup_dir: Path):
    """Create a fake backup archive + manifest inside backup_dir."""

    def _make(
        name: str = "frostgate_20260730_120000_scheduled.dump",
        contents: bytes = b"fake-dump-content",
        **manifest_overrides,
    ) -> tuple[Path, Path]:
        import hashlib

        archive = backup_dir / name
        archive.write_bytes(contents)
        checksum = hashlib.sha256(contents).hexdigest()
        manifest = _write_manifest(archive, checksum, **manifest_overrides)
        return archive, manifest

    return _make


@pytest.fixture
def python_bin() -> str:
    """The interpreter used to run pytest — reused for subprocess helpers."""
    return sys.executable


def _skip_if_no_bash() -> None:
    if shutil.which("bash") is None:
        pytest.skip("bash not available")


@pytest.fixture(autouse=True)
def _require_bash() -> None:
    _skip_if_no_bash()
