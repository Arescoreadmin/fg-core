"""Retention policy tests.

The prune logic must:
  - Bucket backups by age-range so archives graduate hourly -> daily -> weekly
    -> monthly -> yearly as they age (thresholds: 25h, 8d, 35d, 366d).
  - Keep the N newest in each bucket (competition is per-bucket, not global).
  - Never delete the single newest successful backup (invariant).
  - Honour --dry-run without mutating state.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _make_backup(backup_dir: Path, ts: datetime, btype: str = "scheduled") -> Path:
    name = f"frostgate_{ts.strftime('%Y%m%d_%H%M%S')}_{btype}.dump"
    path = backup_dir / name
    path.write_bytes(b"x")
    # Backdate mtime so status/list computations agree.
    epoch = ts.timestamp()
    os.utime(path, (epoch, epoch))
    return path


def test_prune_dry_run_does_not_delete(run_fg_backup, backup_dir: Path):
    now = datetime.now(timezone.utc)
    files = [
        _make_backup(backup_dir, now - timedelta(hours=1)),
        _make_backup(backup_dir, now - timedelta(hours=5)),
        _make_backup(backup_dir, now - timedelta(days=1)),
        _make_backup(backup_dir, now - timedelta(days=40)),
        _make_backup(backup_dir, now - timedelta(days=400)),
    ]
    env = {
        "FG_BACKUP_RETAIN_HOURLY": "1",
        "FG_BACKUP_RETAIN_DAILY": "1",
        "FG_BACKUP_RETAIN_WEEKLY": "0",
        "FG_BACKUP_RETAIN_MONTHLY": "1",
        "FG_BACKUP_RETAIN_YEARLY": "1",
    }
    result = run_fg_backup("prune", "--dry-run", env=env)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["dry_run"] is True
    # Files must still exist on disk.
    for f in files:
        assert f.exists()


def test_prune_never_deletes_single_newest(run_fg_backup, backup_dir: Path):
    now = datetime.now(timezone.utc)
    newest = _make_backup(backup_dir, now - timedelta(minutes=5))
    _make_backup(backup_dir, now - timedelta(days=5))
    _make_backup(backup_dir, now - timedelta(days=200))

    # Retention of 0 in every bucket — but newest is still protected.
    env = {
        "FG_BACKUP_RETAIN_HOURLY": "0",
        "FG_BACKUP_RETAIN_DAILY": "0",
        "FG_BACKUP_RETAIN_WEEKLY": "0",
        "FG_BACKUP_RETAIN_MONTHLY": "0",
        "FG_BACKUP_RETAIN_YEARLY": "0",
    }
    result = run_fg_backup("prune", env=env)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert newest.name in payload["kept"]
    assert newest.exists()


def test_prune_bucketing_respects_retention(run_fg_backup, backup_dir: Path):
    now = datetime.now(timezone.utc)
    # Five hourly backups all inside 48h
    hourly = [
        _make_backup(backup_dir, now - timedelta(hours=h)) for h in (1, 2, 3, 4, 5)
    ]
    env = {
        "FG_BACKUP_RETAIN_HOURLY": "2",
        "FG_BACKUP_RETAIN_DAILY": "10",
        "FG_BACKUP_RETAIN_WEEKLY": "10",
        "FG_BACKUP_RETAIN_MONTHLY": "10",
        "FG_BACKUP_RETAIN_YEARLY": "10",
    }
    result = run_fg_backup("prune", env=env)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    # 2 newest hourly kept + newest-protected already covers the newest.
    kept_names = set(payload["kept"])
    # Two most recent must be kept.
    assert hourly[0].name in kept_names
    assert hourly[1].name in kept_names
    # Two oldest of the hourly bucket must be dropped.
    dropped = set(payload["dropped"])
    assert hourly[3].name in dropped
    assert hourly[4].name in dropped


def test_prune_ignores_non_frostgate_files(run_fg_backup, backup_dir: Path):
    (backup_dir / "unrelated.txt").write_text("keep me")
    (backup_dir / "random.dump").write_bytes(b"foo")
    now = datetime.now(timezone.utc)
    _make_backup(backup_dir, now - timedelta(hours=1))
    result = run_fg_backup("prune", "--dry-run")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert all("frostgate_" in n for n in payload["kept"])
    assert (backup_dir / "unrelated.txt").exists()
    assert (backup_dir / "random.dump").exists()


def test_prune_bucket_graduation_uses_age_ranges(run_fg_backup, backup_dir: Path):
    """Archives should compete only within their own age-range bucket.

    Regression test for the pre-fix bug where the hourly bucket held any
    archive <48h old. With 24 hourly slots, the 25th hourly backup pruned
    the oldest (~24h) one before it could graduate to the daily bucket,
    so nothing ever survived to daily/weekly/monthly/yearly.

    Under age-range classification (hourly<25h, daily<8d, weekly<35d,
    monthly<366d, yearly>=366d) an archive at 26h old is already in the
    daily bucket and never competes against fresh hourly backups.
    """
    now = datetime.now(timezone.utc)
    # 3 fresh hourly + 1 that has aged into daily bucket (26h) + 1 weekly (10d).
    hourly = [_make_backup(backup_dir, now - timedelta(hours=h)) for h in (1, 2, 3)]
    daily_grad = _make_backup(backup_dir, now - timedelta(hours=26))
    weekly_grad = _make_backup(backup_dir, now - timedelta(days=10))
    env = {
        # Even with zero hourly-slot pressure, the 26h archive must not be
        # pruned when daily retention permits it — it's in a different bucket.
        "FG_BACKUP_RETAIN_HOURLY": "3",
        "FG_BACKUP_RETAIN_DAILY": "1",
        "FG_BACKUP_RETAIN_WEEKLY": "1",
        "FG_BACKUP_RETAIN_MONTHLY": "0",
        "FG_BACKUP_RETAIN_YEARLY": "0",
    }
    result = run_fg_backup("prune", env=env)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    kept = set(payload["kept"])
    for h in hourly:
        assert h.name in kept, f"hourly {h.name} should be kept"
    assert daily_grad.name in kept, "26h-old archive should have graduated to daily"
    assert weekly_grad.name in kept, "10d-old archive should have graduated to weekly"


def test_prune_bucket_boundaries_25h_8d_35d_366d(run_fg_backup, backup_dir: Path):
    """Boundary values around each threshold land in the expected bucket."""
    now = datetime.now(timezone.utc)
    # One backup just inside each bucket.
    b_hourly = _make_backup(backup_dir, now - timedelta(hours=24))  # <25h
    b_daily = _make_backup(backup_dir, now - timedelta(hours=26))  # 25h..8d
    b_weekly = _make_backup(backup_dir, now - timedelta(days=9))  # 8d..35d
    b_monthly = _make_backup(backup_dir, now - timedelta(days=40))  # 35d..366d
    b_yearly = _make_backup(backup_dir, now - timedelta(days=400))  # >=366d
    env = {
        "FG_BACKUP_RETAIN_HOURLY": "1",
        "FG_BACKUP_RETAIN_DAILY": "1",
        "FG_BACKUP_RETAIN_WEEKLY": "1",
        "FG_BACKUP_RETAIN_MONTHLY": "1",
        "FG_BACKUP_RETAIN_YEARLY": "1",
    }
    result = run_fg_backup("prune", env=env)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    kept = set(payload["kept"])
    for b in (b_hourly, b_daily, b_weekly, b_monthly, b_yearly):
        assert b.name in kept, f"{b.name} should be kept (one per bucket)"
    assert not payload["dropped"], "nothing to drop when each bucket has exactly one"


def test_prune_removes_manifest_alongside_archive(
    run_fg_backup, seed_backup, backup_dir: Path
):
    # Two seeded backups — retention 1, so one must be dropped along with
    # its manifest.
    now = datetime.now(timezone.utc)
    archive_new, manifest_new = seed_backup(
        name=f"frostgate_{(now - timedelta(hours=1)).strftime('%Y%m%d_%H%M%S')}_scheduled.dump",
    )
    archive_old, manifest_old = seed_backup(
        name=f"frostgate_{(now - timedelta(hours=10)).strftime('%Y%m%d_%H%M%S')}_scheduled.dump",
    )
    # Backdate to place both in the hourly bucket
    for p in (archive_new, manifest_new):
        os.utime(p, ((now - timedelta(hours=1)).timestamp(),) * 2)
    for p in (archive_old, manifest_old):
        os.utime(p, ((now - timedelta(hours=10)).timestamp(),) * 2)

    env = {
        "FG_BACKUP_RETAIN_HOURLY": "1",
        "FG_BACKUP_RETAIN_DAILY": "0",
        "FG_BACKUP_RETAIN_WEEKLY": "0",
        "FG_BACKUP_RETAIN_MONTHLY": "0",
        "FG_BACKUP_RETAIN_YEARLY": "0",
    }
    result = run_fg_backup("prune", env=env)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    # Newer kept, older dropped.
    assert archive_new.name in payload["kept"]
    assert archive_new.exists() and manifest_new.exists()
    assert archive_old.name in payload["dropped"]
    assert not archive_old.exists()
    assert not manifest_old.exists()
