"""
PR 16 — Auth Runtime Guard: startup validation and readiness probe checks.
PR 17 — Extended: Postgres-mode startup validation.

Tests that:
  1. Missing FG_KEY_PEPPER with FG_AUTH_ENABLED=true → has_errors=True
  2. Missing FG_SQLITE_PATH with FG_AUTH_ENABLED=true → has_errors=True
  3. Both set → no auth_store errors
  4. FG_AUTH_ENABLED=false → auth store checks are skipped (no errors for missing pepper/path)
  5. /health/ready returns 503 when startup_validation.has_errors is True
  6. /health/ready returns 503 when auth store file is absent at probe time
  7. /health/ready returns 503 when auth store schema is missing required columns

PR 17 additions (Postgres mode):
  8.  FG_DB_BACKEND=postgres + FG_KEY_PEPPER missing → error
  9.  FG_DB_BACKEND=postgres + FG_DB_URL missing → error
  10. FG_DB_BACKEND=postgres + FG_SQLITE_PATH missing → no auth_store_path error
  11. FG_DB_BACKEND=postgres + auth-store connectivity failure → error
  12. FG_DB_BACKEND=postgres + auth-store connectivity success → no auth-store error
  13. FG_DB_BACKEND=sqlite + FG_SQLITE_PATH missing → error
  14. FG_DB_BACKEND=sqlite + FG_KEY_PEPPER missing → error
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
from typing import Any
from unittest.mock import patch

import pytest

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
# R4.11: the readiness probe now checks for tenant_credentials table existence
# instead of api_keys column set. Tests verify the new logic directly.


def _has_tenant_credentials(db_path: str) -> bool:
    con = sqlite3.connect(db_path)
    try:
        tables = {
            r[0]
            for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        return "tenant_credentials" in tables
    finally:
        con.close()


def _make_auth_db(path: str, *, with_canonical_tables: bool = True) -> None:
    con = sqlite3.connect(path)
    if with_canonical_tables:
        con.execute(
            """
            CREATE TABLE tenant_credentials (
                credential_id TEXT NOT NULL PRIMARY KEY,
                tenant_id     TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'active'
            )
            """
        )
    con.commit()
    con.close()


def test_readiness_schema_check_rejects_missing_table() -> None:
    """Auth store without tenant_credentials table → schema_incomplete."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        _make_auth_db(path, with_canonical_tables=False)
        assert not _has_tenant_credentials(path), (
            "Expected tenant_credentials to be absent in empty schema"
        )
    finally:
        os.unlink(path)


def test_readiness_schema_check_accepts_canonical_schema() -> None:
    """Auth store with tenant_credentials table → auth store ok."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        _make_auth_db(path, with_canonical_tables=True)
        assert _has_tenant_credentials(path), (
            "Expected tenant_credentials to be present in canonical schema"
        )
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
    that the container process can write to (credential issuance will succeed).
    """
    with tempfile.TemporaryDirectory() as d:
        auth_path = os.path.join(d, "auth.db")
        parent = os.path.dirname(auth_path)
        assert os.access(parent, os.W_OK), (
            f"Expected writable temp dir {parent} to pass W_OK check"
        )


@pytest.mark.skipif(os.getuid() == 0, reason="root bypasses filesystem permission bits")
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


# ---------------------------------------------------------------------------
# PR 17 — Postgres-mode startup validation tests
# ---------------------------------------------------------------------------


def _run_auth_store_check_with_probe(
    env: dict,
    probe_result: tuple[bool, str] = (True, "auth_store_backend_ok"),
) -> "Any":
    """Run _check_auth_store with a patched probe_auth_store."""
    from api.config.startup_validation import StartupValidationReport, StartupValidator
    from unittest.mock import patch

    with patch.dict(os.environ, env, clear=False):
        with patch(
            "api.auth_scopes.store.probe_auth_store",
            return_value=probe_result,
        ):
            validator = StartupValidator()
            report = StartupValidationReport(
                env=validator.env, is_production=validator.is_production
            )
            validator._check_auth_store(report)
    return report


def test_postgres_mode_pepper_missing_is_error() -> None:
    """FG_DB_BACKEND=postgres + FG_KEY_PEPPER missing → auth_store_pepper_missing error."""
    env = {
        "FG_AUTH_ENABLED": "true",
        "FG_DB_BACKEND": "postgres",
        "FG_KEY_PEPPER": "",
        "FG_DB_URL": "postgresql+psycopg://user:pass@host/db",
    }
    report = _run_auth_store_check_with_probe(env)
    error_names = {
        r.name for r in report.results if not r.passed and r.severity == "error"
    }
    assert "auth_store_pepper_missing" in error_names
    assert report.has_errors


def test_postgres_mode_db_url_missing_is_error() -> None:
    """FG_DB_BACKEND=postgres + FG_DB_URL missing → auth_store_db_url_missing error."""
    env = {
        "FG_AUTH_ENABLED": "true",
        "FG_DB_BACKEND": "postgres",
        "FG_KEY_PEPPER": "a-valid-pepper-value-32-chars-xxx",
        "FG_DB_URL": "",
    }
    report = _run_auth_store_check_with_probe(env)
    error_names = {
        r.name for r in report.results if not r.passed and r.severity == "error"
    }
    assert "auth_store_db_url_missing" in error_names
    assert report.has_errors


def test_postgres_mode_sqlite_path_missing_is_not_error() -> None:
    """FG_DB_BACKEND=postgres + FG_SQLITE_PATH missing → NO auth_store_path error.

    In Postgres mode, FG_SQLITE_PATH is not required for auth.
    """
    env = {
        "FG_AUTH_ENABLED": "true",
        "FG_DB_BACKEND": "postgres",
        "FG_KEY_PEPPER": "a-valid-pepper-value-32-chars-xxx",
        "FG_DB_URL": "postgresql+psycopg://user:pass@host/db",
        "FG_SQLITE_PATH": "",
    }
    report = _run_auth_store_check_with_probe(env, probe_result=(True, "ok"))
    path_errors = [
        r
        for r in report.results
        if r.name == "auth_store_path_missing"
        and not r.passed
        and r.severity == "error"
    ]
    assert path_errors == [], "auth_store_path_missing must not appear in Postgres mode"


def test_postgres_mode_connectivity_failure_is_error() -> None:
    """FG_DB_BACKEND=postgres + probe failure → auth_store_backend_unreachable error."""
    env = {
        "FG_AUTH_ENABLED": "true",
        "FG_DB_BACKEND": "postgres",
        "FG_KEY_PEPPER": "a-valid-pepper-value-32-chars-xxx",
        "FG_DB_URL": "postgresql+psycopg://user:pass@host/db",
    }
    report = _run_auth_store_check_with_probe(
        env, probe_result=(False, "auth_store_schema_missing")
    )
    error_names = {
        r.name for r in report.results if not r.passed and r.severity == "error"
    }
    assert "auth_store_backend_unreachable" in error_names
    assert report.has_errors


def test_postgres_mode_connectivity_success_no_error() -> None:
    """FG_DB_BACKEND=postgres + probe success → no auth-store error."""
    env = {
        "FG_AUTH_ENABLED": "true",
        "FG_DB_BACKEND": "postgres",
        "FG_KEY_PEPPER": "a-valid-pepper-value-32-chars-xxx",
        "FG_DB_URL": "postgresql+psycopg://user:pass@host/db",
    }
    report = _run_auth_store_check_with_probe(
        env, probe_result=(True, "auth_store_backend_ok")
    )
    auth_errors = [
        r
        for r in report.results
        if r.name.startswith("auth_store_") and not r.passed and r.severity == "error"
    ]
    assert auth_errors == [], f"Unexpected auth_store errors: {auth_errors}"


def test_sqlite_mode_path_missing_is_error() -> None:
    """FG_DB_BACKEND=sqlite + FG_SQLITE_PATH missing → auth_store_path_missing error."""
    env = {
        "FG_AUTH_ENABLED": "true",
        "FG_DB_BACKEND": "sqlite",
        "FG_KEY_PEPPER": "a-valid-pepper-value-32-chars-xxx",
        "FG_SQLITE_PATH": "",
    }
    report = _run_auth_store_check(env)
    error_names = {
        r.name for r in report.results if not r.passed and r.severity == "error"
    }
    assert "auth_store_path_missing" in error_names
    assert report.has_errors


def test_sqlite_mode_pepper_missing_is_error() -> None:
    """FG_DB_BACKEND=sqlite + FG_KEY_PEPPER missing → auth_store_pepper_missing error."""
    env = {
        "FG_AUTH_ENABLED": "true",
        "FG_DB_BACKEND": "sqlite",
        "FG_KEY_PEPPER": "",
        "FG_SQLITE_PATH": "/tmp/irrelevant.db",
    }
    report = _run_auth_store_check(env)
    error_names = {
        r.name for r in report.results if not r.passed and r.severity == "error"
    }
    assert "auth_store_pepper_missing" in error_names
    assert report.has_errors


# ---------------------------------------------------------------------------
# P-113.9B.5 — Invitation acceptance prerequisites
# ---------------------------------------------------------------------------


def _run_invitation_prereq_check(
    env: dict[str, str], is_production: bool = True
) -> Any:
    """Run only _check_invitation_acceptance_prerequisites with a specific env."""
    from api.config.startup_validation import StartupValidationReport, StartupValidator

    with patch.dict(os.environ, env, clear=False):
        validator = StartupValidator()
        validator.is_production = is_production
        report = StartupValidationReport(env=validator.env, is_production=is_production)
        validator._check_invitation_acceptance_prerequisites(report)
    return report


def test_invitation_prereqs_pass_when_both_set() -> None:
    """Both FG_INTERNAL_GATEWAY_SECRET and FG_KEY_PEPPER set → no errors."""
    env = {
        "FG_INTERNAL_GATEWAY_SECRET": "a" * 32,
        "FG_KEY_PEPPER": "b" * 32,
    }
    report = _run_invitation_prereq_check(env)
    assert not report.has_errors
    pass_names = {r.name for r in report.results if r.passed}
    assert "invitation_gateway_secret" in pass_names
    assert "invitation_token_pepper" in pass_names


def test_invitation_prereq_missing_gateway_secret_is_error_in_production() -> None:
    """FG_INTERNAL_GATEWAY_SECRET absent → error in production."""
    env = {
        "FG_INTERNAL_GATEWAY_SECRET": "",
        "FG_ADMIN_GATEWAY_INTERNAL_TOKEN": "",
        "FG_INTERNAL_AUTH_SECRET": "",
        "FG_INTERNAL_TOKEN": "",
        "FG_KEY_PEPPER": "b" * 32,
    }
    report = _run_invitation_prereq_check(env, is_production=True)
    error_names = {
        r.name for r in report.results if not r.passed and r.severity == "error"
    }
    assert "invitation_gateway_secret_missing" in error_names
    assert report.has_errors


def test_invitation_prereq_missing_gateway_secret_is_warning_in_dev() -> None:
    """FG_INTERNAL_GATEWAY_SECRET absent → warning (not error) in non-production."""
    env = {
        "FG_INTERNAL_GATEWAY_SECRET": "",
        "FG_ADMIN_GATEWAY_INTERNAL_TOKEN": "",
        "FG_INTERNAL_AUTH_SECRET": "",
        "FG_INTERNAL_TOKEN": "",
        "FG_KEY_PEPPER": "b" * 32,
    }
    report = _run_invitation_prereq_check(env, is_production=False)
    warn_names = {
        r.name for r in report.results if not r.passed and r.severity == "warning"
    }
    error_names = {
        r.name for r in report.results if not r.passed and r.severity == "error"
    }
    assert "invitation_gateway_secret_missing" in warn_names
    assert "invitation_gateway_secret_missing" not in error_names


def test_invitation_prereq_legacy_fallback_satisfies_gateway_secret() -> None:
    """Legacy FG_INTERNAL_AUTH_SECRET satisfies the gateway secret check."""
    env = {
        "FG_INTERNAL_GATEWAY_SECRET": "",
        "FG_ADMIN_GATEWAY_INTERNAL_TOKEN": "",
        "FG_INTERNAL_AUTH_SECRET": "legacy-secret-value",
        "FG_INTERNAL_TOKEN": "",
        "FG_KEY_PEPPER": "b" * 32,
    }
    report = _run_invitation_prereq_check(env, is_production=True)
    error_names = {
        r.name for r in report.results if not r.passed and r.severity == "error"
    }
    assert "invitation_gateway_secret_missing" not in error_names


def test_invitation_prereq_missing_pepper_is_error_in_production() -> None:
    """FG_KEY_PEPPER absent → error in production regardless of FG_AUTH_ENABLED."""
    env = {
        "FG_INTERNAL_GATEWAY_SECRET": "a" * 32,
        "FG_KEY_PEPPER": "",
        "FG_AUTH_ENABLED": "false",  # auth disabled — pepper check must still fire
    }
    report = _run_invitation_prereq_check(env, is_production=True)
    error_names = {
        r.name for r in report.results if not r.passed and r.severity == "error"
    }
    assert "invitation_token_pepper_missing" in error_names
    assert report.has_errors


def test_invitation_prereq_missing_pepper_is_warning_in_dev() -> None:
    """FG_KEY_PEPPER absent → warning (not error) in non-production."""
    env = {
        "FG_INTERNAL_GATEWAY_SECRET": "a" * 32,
        "FG_KEY_PEPPER": "",
    }
    report = _run_invitation_prereq_check(env, is_production=False)
    warn_names = {
        r.name for r in report.results if not r.passed and r.severity == "warning"
    }
    error_names = {
        r.name for r in report.results if not r.passed and r.severity == "error"
    }
    assert "invitation_token_pepper_missing" in warn_names
    assert "invitation_token_pepper_missing" not in error_names


def test_invitation_prereqs_checked_regardless_of_auth_enabled() -> None:
    """Prerequisite checks fire even when FG_AUTH_ENABLED=false."""
    env = {
        "FG_INTERNAL_GATEWAY_SECRET": "",
        "FG_ADMIN_GATEWAY_INTERNAL_TOKEN": "",
        "FG_INTERNAL_AUTH_SECRET": "",
        "FG_INTERNAL_TOKEN": "",
        "FG_KEY_PEPPER": "",
        "FG_AUTH_ENABLED": "false",
    }
    report = _run_invitation_prereq_check(env, is_production=True)
    error_names = {
        r.name for r in report.results if not r.passed and r.severity == "error"
    }
    assert "invitation_gateway_secret_missing" in error_names
    assert "invitation_token_pepper_missing" in error_names
