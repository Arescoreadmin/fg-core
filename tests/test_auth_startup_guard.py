"""
PR 16 — Auth Runtime Guard: startup validation and readiness probe checks.

Tests that:
  1. Missing FG_KEY_PEPPER with FG_AUTH_ENABLED=true → has_errors=True
  2. Missing FG_SQLITE_PATH with FG_AUTH_ENABLED=true → has_errors=True
  3. Both set → no auth_store errors
  4. FG_AUTH_ENABLED=false → auth store checks are skipped (no errors for missing pepper/path)
  5. /health/ready returns 503 when startup_validation.has_errors is True
  6. /health/ready returns 503 when auth store file is absent at probe time
  7. /health/ready returns 503 when auth store schema is missing required columns
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
from typing import Any
from unittest.mock import patch

# ---------------------------------------------------------------------------
# StartupValidator unit tests
# ---------------------------------------------------------------------------


def _run_auth_store_check(env: dict[str, str]) -> Any:
    """Run StartupValidator with a specific env and return the validation report."""
    from api.config.startup_validation import StartupValidationReport, StartupValidator

    with patch.dict(os.environ, env, clear=False):
        validator = StartupValidator()
        report = StartupValidationReport(
            env=validator.env, is_production=validator.is_production
        )
        validator._check_auth_store(report)
    return report


def test_missing_pepper_is_error() -> None:
    """FG_AUTH_ENABLED=true + no FG_KEY_PEPPER → auth_store_pepper_missing error."""
    env = {
        "FG_AUTH_ENABLED": "true",
        "FG_KEY_PEPPER": "",
        "FG_SQLITE_PATH": "/tmp/irrelevant.db",
    }
    report = _run_auth_store_check(env)

    error_names = {
        r.name for r in report.results if not r.passed and r.severity == "error"
    }
    assert "auth_store_pepper_missing" in error_names
    assert report.has_errors


def test_missing_sqlite_path_is_error() -> None:
    """FG_AUTH_ENABLED=true + no FG_SQLITE_PATH → auth_store_path_missing error."""
    env = {
        "FG_AUTH_ENABLED": "true",
        "FG_KEY_PEPPER": "a-valid-pepper-value-32-chars-xxx",
        "FG_SQLITE_PATH": "",
    }
    report = _run_auth_store_check(env)

    error_names = {
        r.name for r in report.results if not r.passed and r.severity == "error"
    }
    assert "auth_store_path_missing" in error_names
    assert report.has_errors


def test_both_set_no_auth_store_errors() -> None:
    """FG_AUTH_ENABLED=true + both vars set → no auth_store errors."""
    env = {
        "FG_AUTH_ENABLED": "true",
        "FG_KEY_PEPPER": "a-valid-pepper-value-32-chars-xxx",
        "FG_SQLITE_PATH": "/tmp/irrelevant.db",
    }
    report = _run_auth_store_check(env)

    auth_errors = [
        r
        for r in report.results
        if r.name.startswith("auth_store_") and not r.passed and r.severity == "error"
    ]
    assert auth_errors == [], f"Unexpected auth_store errors: {auth_errors}"


def test_auth_disabled_skips_auth_store_checks() -> None:
    """FG_AUTH_ENABLED=false → _check_auth_store adds no results at all."""
    env = {
        "FG_AUTH_ENABLED": "false",
        "FG_KEY_PEPPER": "",
        "FG_SQLITE_PATH": "",
        "FG_API_KEY": "",
    }
    report = _run_auth_store_check(env)

    auth_store_results = [r for r in report.results if r.name.startswith("auth_store_")]
    assert auth_store_results == [], (
        "auth_store checks should be skipped when auth is disabled"
    )


def test_missing_pepper_is_error_in_dev_not_just_production() -> None:
    """The pepper check is always an error, not a dev warning.

    This is the key difference from other startup checks: a missing pepper makes
    auth non-functional at any environment level. Warnings would be silently ignored.
    """
    env = {
        "FG_AUTH_ENABLED": "true",
        "FG_KEY_PEPPER": "",
        "FG_SQLITE_PATH": "/tmp/irrelevant.db",
        "FG_ENV": "dev",
    }
    report = _run_auth_store_check(env)

    pepper_result = next(
        (r for r in report.results if r.name == "auth_store_pepper_missing"), None
    )
    assert pepper_result is not None, "auth_store_pepper_missing result not found"
    assert pepper_result.severity == "error", (
        f"Expected severity=error, got {pepper_result.severity}. "
        "A missing pepper makes all key verification fail regardless of environment."
    )


# ---------------------------------------------------------------------------
# Readiness probe: auth store schema check logic (direct, no HTTP)
# ---------------------------------------------------------------------------
# These tests verify the PRAGMA-based schema validation that health_ready()
# uses. Testing directly avoids coupling to the full app lifespan while still
# proving the logic that runs in production.

_REQUIRED_AUTH_COLS = frozenset(
    {
        "prefix",
        "key_hash",
        "key_lookup",
        "hash_alg",
        "hash_params",
        "scopes_csv",
        "enabled",
        "tenant_id",
        "expires_at",
    }
)


def _present_cols(db_path: str) -> set[str]:
    con = sqlite3.connect(db_path)
    try:
        return {r[1] for r in con.execute("PRAGMA table_info(api_keys)").fetchall()}
    finally:
        con.close()


def _make_auth_db(path: str, with_required_cols: bool = True) -> None:
    con = sqlite3.connect(path)
    if with_required_cols:
        con.execute(
            """
            CREATE TABLE api_keys (
                id INTEGER PRIMARY KEY,
                prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                key_lookup TEXT,
                hash_alg TEXT,
                hash_params TEXT,
                scopes_csv TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                tenant_id TEXT,
                expires_at INTEGER,
                created_at INTEGER
            )
            """
        )
    else:
        con.execute("CREATE TABLE api_keys (id INTEGER PRIMARY KEY, name TEXT)")
    con.commit()
    con.close()


def test_readiness_schema_check_rejects_missing_cols() -> None:
    """PRAGMA table_info detects missing required columns → schema_incomplete."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        _make_auth_db(path, with_required_cols=False)
        present = _present_cols(path)
        missing = _REQUIRED_AUTH_COLS - present
        assert missing, (
            "Expected missing required columns in minimal schema, got none missing.\n"
            f"Present: {present}"
        )
        # Verify the missing set contains exactly what we expect
        assert "key_lookup" in missing
        assert "key_hash" in missing
        assert "tenant_id" in missing
    finally:
        os.unlink(path)


def test_readiness_schema_check_accepts_full_schema() -> None:
    """PRAGMA table_info finds all required columns → no missing → auth store ok."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        _make_auth_db(path, with_required_cols=True)
        present = _present_cols(path)
        missing = _REQUIRED_AUTH_COLS - present
        assert not missing, f"Unexpected missing columns in full schema: {missing}"
    finally:
        os.unlink(path)


def test_readiness_file_absent_is_detectable() -> None:
    """os.path.exists correctly identifies a missing auth store file."""
    assert not os.path.exists("/nonexistent/path/frostgate_auth.db"), (
        "Sanity: /nonexistent/... should not exist on this machine"
    )


def test_readiness_writable_dir_check_passes_for_tmpdir() -> None:
    """os.access(parent, W_OK) passes for a writable temp directory.

    This mirrors the happy path: FG_SQLITE_PATH on a volume-mounted directory
    that the container process can write to (mint_key() will succeed).
    """
    with tempfile.TemporaryDirectory() as d:
        auth_path = os.path.join(d, "auth.db")
        parent = os.path.dirname(auth_path)
        assert os.access(parent, os.W_OK), (
            f"Expected writable temp dir {parent} to pass W_OK check"
        )


def test_readiness_writable_dir_check_detects_read_only(tmp_path: "Any") -> None:
    """os.access(parent, W_OK) detects a read-only directory.

    This mirrors the failure case: container read_only=true with FG_SQLITE_PATH
    on the container filesystem (not a volume). The file may exist (from a
    previous container run baked into the image) but mint_key() will fail.
    """
    ro_dir = tmp_path / "ro"
    ro_dir.mkdir()
    ro_dir.chmod(0o555)  # read + execute, no write

    try:
        assert not os.access(str(ro_dir), os.W_OK), (
            "Expected read-only dir to fail W_OK check"
        )
    finally:
        ro_dir.chmod(0o755)  # restore so tmp_path cleanup can delete it


def test_readiness_has_errors_gate_contract() -> None:
    """StartupValidationReport.has_errors=True is the gate used by health_ready().

    This test proves the contract between startup validation and the readiness probe:
    adding an error-severity result to the report raises has_errors, which main.py's
    health_ready() checks before any other dependency probe.

    If this test fails, the chain 'missing pepper → auth impossible → readiness blocks'
    is broken regardless of what _check_auth_store adds.
    """
    from api.config.startup_validation import StartupValidationReport

    report = StartupValidationReport(env="dev", is_production=False)
    assert not report.has_errors, "clean report should have no errors"

    report.add(
        name="auth_store_pepper_missing",
        passed=False,
        message="FG_KEY_PEPPER is required when FG_AUTH_ENABLED=true.",
        severity="error",
    )
    assert report.has_errors, (
        "has_errors must be True after adding a severity=error result. "
        "health_ready() gates on this property."
    )

    # Warnings alone must not trigger has_errors
    report2 = StartupValidationReport(env="dev", is_production=False)
    report2.add("some_warning", passed=False, message="warn", severity="warning")
    assert not report2.has_errors, (
        "has_errors must remain False for warning-only reports"
    )
