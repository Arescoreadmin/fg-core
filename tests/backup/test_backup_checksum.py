"""Checksum verification tests.

Runs `fg_backup.sh verify` against synthetic backup files. Uses shell
execution rather than pure-python mocking so the actual code path is
exercised (this is the code that will run in production).
"""

from __future__ import annotations

import json
from pathlib import Path


def test_verify_missing_archive_returns_nonzero(run_fg_backup):
    result = run_fg_backup("verify", "/tmp/does-not-exist-xyz.dump")
    assert result.returncode != 0
    assert "FAIL archive_exists" in result.stdout


def test_verify_missing_manifest_returns_nonzero(run_fg_backup, backup_dir: Path):
    archive = backup_dir / "frostgate_20260730_120000_manual.dump"
    archive.write_bytes(b"dump-bytes")
    # No manifest written.
    result = run_fg_backup("verify", str(archive))
    assert result.returncode != 0
    assert "PASS archive_exists" in result.stdout
    assert "FAIL manifest_exists" in result.stdout


def test_verify_passes_with_correct_checksum(run_fg_backup, seed_backup):
    archive, _manifest = seed_backup()
    result = run_fg_backup("verify", str(archive))
    # Docker probably isn't available in CI; the checksum check must pass
    # regardless. pg_restore --list is best-effort and prints WARN when
    # docker is missing.
    assert "PASS archive_exists" in result.stdout
    assert "PASS manifest_exists" in result.stdout
    assert "PASS checksum_match" in result.stdout


def test_verify_detects_mismatched_checksum(
    run_fg_backup, seed_backup, backup_dir: Path
):
    archive, manifest_path = seed_backup()
    # Corrupt the archive AFTER the manifest was written — checksum mismatch.
    archive.write_bytes(b"tampered-bytes-different-length")
    result = run_fg_backup("verify", str(archive))
    assert result.returncode != 0
    assert "FAIL checksum_match" in result.stdout


def test_verify_encrypted_archive_skips_pg_restore_list(run_fg_backup, seed_backup):
    # Encrypted archives cannot be passed to pg_restore --list; the check
    # is intentionally skipped, but checksum must still pass.
    archive, _manifest = seed_backup(
        name="frostgate_20260730_120000_manual.dump.enc",
        contents=b"encrypted-bytes",
        encrypted=True,
    )
    result = run_fg_backup("verify", str(archive))
    assert "PASS checksum_match" in result.stdout
    assert "pg_restore_list" in result.stdout
    # Either PASS (skipped) or PASS (docker missing WARN); never FAIL for encrypted
    assert "FAIL pg_restore_list" not in result.stdout


def test_manifest_json_is_wellformed(seed_backup):
    _archive, manifest_path = seed_backup()
    doc = json.loads(manifest_path.read_text())
    assert doc["checksum_algorithm"] == "sha256"
    assert len(doc["checksum_sha256"]) == 64
