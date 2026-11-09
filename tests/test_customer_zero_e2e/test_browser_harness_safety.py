"""Safety of the opt-in browser harness — L14-CUSTOMER-ZERO-E2E-001 review fixes.

1. Inherited database connection settings never reach the harness (the core
   subprocess's init_db() would prefer FG_DB_URL over the temp SQLite file).
2. The CZ-16B security verdict is derived from observed denials; regressions
   FAIL and missing observations are NOT_TESTED — never an unconditional PASS.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.test_customer_zero_e2e import browser_acceptance as B


def test_inherited_database_settings_are_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name, value in {
        "FG_DB_URL": "postgresql+psycopg://real/frostgate",
        "FG_DB_MIGRATION_URL": "postgresql+psycopg://real/frostgate",
        "DATABASE_URL": "postgresql://real/frostgate",
        "PGHOST": "db.internal",
        "PGPASSWORD": "not-a-real-password",
        "FG_POSTGRES_DSN": "postgresql://real",
    }.items():
        monkeypatch.setenv(name, value)
    env = B._base_env(tmp_path)
    leaked = [k for k in env if B._is_db_connection_var(k)]
    assert leaked == []
    assert env["FG_SQLITE_PATH"] == str(tmp_path / "customer-zero.db")
    assert env["FG_DB_BACKEND"] == "sqlite"
    assert env["FG_ENV"] == "test"


def test_unrelated_environment_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FG_SOMETHING_ELSE", "keep")
    assert B._base_env(tmp_path)["FG_SOMETHING_ELSE"] == "keep"


def _matrix_from(steps: list[dict[str, Any]], tmp_path: Path) -> dict[str, Any]:
    log = {"steps": steps, "console": [], "network": [], "pdf_via_portal": {}}
    B._browser_matrix(log, tmp_path)
    m = json.loads((tmp_path / "browser_acceptance_matrix.json").read_text())
    return next(s for s in m["steps"] if s["step_id"] == "CZ-16B")


def _steps(
    write: Any, other: Any, after: Any, logout_url: str | None
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = [
        {"name": "write_attempt_generate_report", "js_result": {"status": write}},
        {"name": "api_other_engagement_findings", "js_result": {"status": other}},
        {
            "name": "api_after_logout",
            "js_result": None if after is None else {"status": after},
        },
    ]
    if logout_url is not None:
        steps.append({"name": "after_logout_dashboard", "final_url": logout_url})
    return steps


def test_cz16b_passes_only_on_observed_denials(tmp_path: Path) -> None:
    entry = _matrix_from(
        _steps(403, 403, None, "http://127.0.0.1:1/login?next=%2Fdashboard"), tmp_path
    )
    assert entry["status"] == "PASS"


@pytest.mark.parametrize(
    "write,other,after,url",
    [
        (201, 403, None, "http://127.0.0.1:1/login"),  # write succeeded
        (403, 200, None, "http://127.0.0.1:1/login"),  # non-granted engagement served
        (403, 403, 200, "http://127.0.0.1:1/login"),  # data served after logout
        (403, 403, None, "http://127.0.0.1:1/dashboard"),  # dashboard after logout
    ],
)
def test_cz16b_fails_on_any_authorization_regression(
    tmp_path: Path, write, other, after, url
) -> None:
    entry = _matrix_from(_steps(write, other, after, url), tmp_path)
    assert entry["status"] == "FAIL" and entry["blocking"] == "P0"


def test_cz16b_missing_observations_are_not_tested(tmp_path: Path) -> None:
    entry = _matrix_from(
        [{"name": "write_attempt_generate_report", "js_result": {"status": 403}}],
        tmp_path,
    )
    assert entry["status"] == "NOT_TESTED"
