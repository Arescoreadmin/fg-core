"""Backup ID tests.

Every backup receives an immutable ID of shape `FG-BKP-YYYYMMDD-NNNNN`. The
sequence number is derived from the count of existing dump files with today's
date-stamp in FG_BACKUP_DIR.
"""

from __future__ import annotations

import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "backup" / "fg_backup.sh"

ID_RE = re.compile(r"^FG-BKP-\d{8}-\d{5}$")


def _gen_id(backup_dir: Path, date_str: str | None = None) -> str:
    date_str = date_str or datetime.now(timezone.utc).strftime("%Y%m%d")
    script_body = (
        f'source "{SCRIPT}" >/dev/null 2>&1 || true; generate_backup_id "{date_str}"'
    )
    env = {
        "PATH": "/usr/bin:/bin",
        "FG_BACKUP_DIR": str(backup_dir),
    }
    result = subprocess.run(
        ["bash", "-c", script_body],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    return result.stdout.strip()


def test_id_format_matches_spec(backup_dir: Path):
    bid = _gen_id(backup_dir)
    assert ID_RE.match(bid), f"backup ID {bid!r} does not match FG-BKP-YYYYMMDD-NNNNN"


def test_first_backup_gets_seq_00001(backup_dir: Path):
    bid = _gen_id(backup_dir, "20260730")
    assert bid == "FG-BKP-20260730-00001"


def test_sequential_ids_increment(backup_dir: Path):
    date_str = "20260730"
    # Simulate three existing backups for the same day.
    for i, hhmmss in enumerate(("120000", "130000", "140000")):
        (backup_dir / f"frostgate_{date_str}_{hhmmss}_scheduled.dump").write_bytes(b"x")
    bid = _gen_id(backup_dir, date_str)
    assert bid == "FG-BKP-20260730-00004"


def test_ids_are_unique_across_same_day_backups(backup_dir: Path):
    date_str = "20260730"
    ids = set()
    for i in range(5):
        (backup_dir / f"frostgate_{date_str}_{i:06d}_scheduled.dump").write_bytes(b"x")
        ids.add(_gen_id(backup_dir, date_str))
    # Each call after seeding N files returns FG-BKP-<date>-<N+1>.
    # After 1 file: 00002; after 2: 00003; ... after 5: 00006. So 5 distinct.
    assert len(ids) == 5, f"expected 5 unique IDs got {ids!r}"


def test_id_counts_encrypted_dumps_too(backup_dir: Path):
    date_str = "20260730"
    (backup_dir / f"frostgate_{date_str}_120000_scheduled.dump").write_bytes(b"x")
    (backup_dir / f"frostgate_{date_str}_130000_scheduled.dump.enc").write_bytes(b"x")
    bid = _gen_id(backup_dir, date_str)
    assert bid == "FG-BKP-20260730-00003"


def test_id_ignores_other_dates(backup_dir: Path):
    (backup_dir / "frostgate_20260729_120000_scheduled.dump").write_bytes(b"x")
    bid = _gen_id(backup_dir, "20260730")
    assert bid == "FG-BKP-20260730-00001"
