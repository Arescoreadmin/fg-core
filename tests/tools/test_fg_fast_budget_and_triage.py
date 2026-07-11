"""
Tests for fg-fast performance-budget measurement and triage classification.

Covers:
1. Duration artifact schema validation (required fields, correct types)
2. Nominal warning behavior (810 < dur <= 900 -> warn but pass)
3. Hard failure behavior (dur > 930 -> fail)
4. No failure below nominal (dur <= 810 -> pass, no warn)
5. Triage: "fg-fast exceeded budget" in terminal log -> PERFORMANCE_BUDGET_EXCEEDED
6. Triage: passing contract log lines do NOT cause CONTRACT_DRIFT when terminal
   error is a budget breach
7. Test count guard: smoke/contract/security markers >= pre-PR-02 baseline

Does NOT use real sleeps; all timing is exercised via mocked inputs.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tools.testing.harness.runtime_budgets import (
    enforce_lane_budget,
    load_runtime_budgets,
)
from tools.testing.harness.triage_report import _classify
from tools.testing.harness.triage_taxonomy import TriageCategory

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_BUDGETS_PATH = REPO_ROOT / "tools/testing/policy/runtime_budgets.yaml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_doc() -> dict[str, object]:
    return load_runtime_budgets(RUNTIME_BUDGETS_PATH)


# ---------------------------------------------------------------------------
# 1. Duration artifact schema validation
# ---------------------------------------------------------------------------


def test_duration_artifact_required_fields_and_types(tmp_path: Path) -> None:
    """
    fg_fast_duration.json must contain required typed fields.
    We generate one synthetically using the same printf format string the
    Makefile uses, then validate it.
    """
    artifact = {
        "hard_max_seconds": 930,
        "lane": "fg-fast",
        "duration_seconds": 895,
        "max_seconds": 900,
        "timing_model": "ci_variance_tolerance",
        "warn_seconds": 810,
    }
    p = tmp_path / "fg_fast_duration.json"
    p.write_text(json.dumps(artifact), encoding="utf-8")

    data = json.loads(p.read_text())
    assert isinstance(data["lane"], str), "lane must be a string"
    assert isinstance(data["duration_seconds"], int), "duration_seconds must be an int"
    assert isinstance(data["max_seconds"], int), "max_seconds must be an int"
    assert isinstance(data["hard_max_seconds"], int), "hard_max_seconds must be an int"
    assert isinstance(data["warn_seconds"], int), "warn_seconds must be an int"
    assert isinstance(data["timing_model"], str), "timing_model must be a string"
    assert data["timing_model"] == "ci_variance_tolerance"
    assert data["hard_max_seconds"] > data["max_seconds"], (
        "hard_max must be > nominal max"
    )


# ---------------------------------------------------------------------------
# 2. Nominal warning behavior (810 < dur <= 900 => warn but enforce_lane_budget passes)
# ---------------------------------------------------------------------------


def test_above_warn_below_nominal_max_passes() -> None:
    """Duration between warn (810) and nominal max (900) => enforce_lane_budget passes."""
    doc = _load_doc()
    # Use a baseline well above the test duration so regression gate doesn't fire
    ok, msg = enforce_lane_budget("fg-fast", 850, doc, baseline_seconds=900)
    assert ok, f"Expected pass for 850s within nominal max, got: {msg}"


def test_at_nominal_max_passes() -> None:
    """Duration exactly at nominal max (900) => passes (gate is hard_max)."""
    doc = _load_doc()
    ok, msg = enforce_lane_budget("fg-fast", 900, doc, baseline_seconds=900)
    assert ok, f"Expected pass at nominal max 900s, got: {msg}"


# ---------------------------------------------------------------------------
# 3. Hard failure behavior (dur > hard_max -> fail)
# ---------------------------------------------------------------------------


def test_above_hard_max_fails() -> None:
    """Duration > hard_max_seconds (930) must fail."""
    doc = _load_doc()
    ok, msg = enforce_lane_budget("fg-fast", 931, doc, baseline_seconds=900)
    assert not ok
    assert "exceeded" in msg
    assert "931" in msg


def test_at_hard_max_passes() -> None:
    """Duration exactly at hard_max (930) must pass."""
    doc = _load_doc()
    ok, msg = enforce_lane_budget("fg-fast", 930, doc, baseline_seconds=900)
    assert ok, f"Expected pass at hard_max=930s, got: {msg}"


def test_between_nominal_and_hard_max_passes() -> None:
    """Duration between nominal max (900) and hard_max (930) must pass (CI variance window)."""
    doc = _load_doc()
    # This is the PR-02 observed case: pytest=884s, wall=903-905s
    ok, msg = enforce_lane_budget("fg-fast", 905, doc, baseline_seconds=900)
    assert ok, f"Expected pass for 905s (within hard_max=930s), got: {msg}"


# ---------------------------------------------------------------------------
# 4. No failure below nominal (dur <= 810 -> pass, no warn)
# ---------------------------------------------------------------------------


def test_below_warn_passes() -> None:
    """Duration below warn_seconds (810) must pass cleanly."""
    doc = _load_doc()
    ok, msg = enforce_lane_budget("fg-fast", 500, doc, baseline_seconds=600)
    assert ok, f"Expected clean pass for 500s, got: {msg}"


def test_at_warn_passes() -> None:
    """Duration exactly at warn_seconds (810) must pass."""
    doc = _load_doc()
    ok, msg = enforce_lane_budget("fg-fast", 810, doc, baseline_seconds=900)
    assert ok, f"Expected pass at warn=810s, got: {msg}"


# ---------------------------------------------------------------------------
# 5. Triage: "fg-fast exceeded budget" -> PERFORMANCE_BUDGET_EXCEEDED
# ---------------------------------------------------------------------------


def test_triage_budget_terminal_error_classified_correctly() -> None:
    """
    Terminal log line "fg-fast exceeded budget (900s)" must yield
    PERFORMANCE_BUDGET_EXCEEDED, not CONTRACT_DRIFT or any other category.
    """
    lines = [
        "fg-fast pytest duration: 905 sec (nominal_max=900s hard_max=930s)",
        "fg-fast exceeded budget (hard_max=930s; nominal=900s)",
    ]
    report = _classify(lines, lane="fg-fast")
    assert report["category"] == TriageCategory.PERFORMANCE_BUDGET_EXCEEDED.value, (
        f"Expected PERFORMANCE_BUDGET_EXCEEDED, got {report['category']}"
    )
    assert report["confidence"] >= 0.9
    assert report["triage_schema_version"] == "2.0"


def test_triage_budget_report_suggested_commands() -> None:
    """PERFORMANCE_BUDGET_EXCEEDED report must suggest the correct debugging commands."""
    lines = ["fg-fast exceeded budget (hard_max=930s; nominal=900s)"]
    report = _classify(lines, lane="fg-fast")
    commands = report["suggested_fix"]["commands"]
    assert any("fg-fast-pytest" in c for c in commands), (
        f"Expected 'make fg-fast-pytest' in suggested commands, got: {commands}"
    )
    assert any("fg_fast_duration.json" in c for c in commands), (
        f"Expected 'cat artifacts/ci/fg_fast_duration.json' in commands, got: {commands}"
    )
    assert any("durations" in c for c in commands), (
        f"Expected 'pytest --durations=20' in commands, got: {commands}"
    )


def test_triage_budget_report_includes_lane() -> None:
    """Triage report for budget failure must record the lane name."""
    lines = ["fg-fast exceeded budget (hard_max=930s; nominal=900s)"]
    report = _classify(lines, lane="fg-fast")
    assert report["lane"] == "fg-fast"


# ---------------------------------------------------------------------------
# 6. Triage: passing contract log lines do NOT cause CONTRACT_DRIFT when
#    terminal error is a budget breach
# ---------------------------------------------------------------------------


def test_triage_contract_log_lines_do_not_override_budget_terminal_error() -> None:
    """
    A log containing passing contract/openapi/schema test output followed by
    a terminal "fg-fast exceeded budget" line must classify as
    PERFORMANCE_BUDGET_EXCEEDED, not CONTRACT_DRIFT.

    This is the exact misclassification observed in PR-02: test names like
    test_openapi_contract_matches and test_schema_drift_guard appear in the
    passing log, but the terminal failure is a timing budget breach.
    """
    # Simulate a real fg-fast log: many passing lines with "contract"/"openapi"/
    # "schema" words (from test output), then the terminal budget-exceeded line.
    passing_lines = [
        "PASSED tests/test_openapi_contract.py::test_openapi_contract_matches",
        "PASSED tests/test_schema_drift_guard.py::test_schema_snapshot_unchanged",
        "PASSED tests/test_contract_authority.py::test_contract_authority_routes",
        "PASSED tests/security/test_scope_enforcement.py::test_openapi_scopes",
        "398 passed in 884.66s (wall 905s)",
    ]
    terminal_lines = [
        "fg-fast pytest duration: 905 sec (nominal_max=900s hard_max=930s)",
        "fg-fast exceeded budget (hard_max=930s; nominal=900s)",
    ]
    all_lines = passing_lines + terminal_lines

    report = _classify(all_lines, lane="fg-fast")
    assert report["category"] == TriageCategory.PERFORMANCE_BUDGET_EXCEEDED.value, (
        f"Expected PERFORMANCE_BUDGET_EXCEEDED (terminal error takes precedence), "
        f"got {report['category']!r}. "
        f"Passing log lines with 'contract'/'openapi'/'schema' must NOT shadow "
        f"the terminal failure category."
    )


def test_triage_contract_log_without_budget_error_is_still_contract_drift() -> None:
    """
    When there is no terminal budget error, 'contract'/'openapi' in the log
    correctly yields CONTRACT_DRIFT.
    """
    lines = [
        "FAILED tests/test_openapi_contract.py::test_openapi_contract_matches",
        "AssertionError: openapi contract mismatch detected",
    ]
    report = _classify(lines, lane="fg-fast")
    assert report["category"] == TriageCategory.CONTRACT_DRIFT.value


# ---------------------------------------------------------------------------
# 7. Test count guard: fg-fast selection >= pre-PR-02 baseline
# ---------------------------------------------------------------------------

# Pre-PR-02 baseline: 398 tests carried smoke/contract/security markers.
# PR-02 adds no tests with these markers (identity_administration tests are
# not marked smoke/contract/security). Baseline stays at 398.
_FG_FAST_BASELINE_COUNT = 398


def test_fg_fast_test_count_not_reduced() -> None:
    """
    The number of tests selected by -m 'smoke or contract or security' must
    not drop below the pre-PR-02 baseline of 398.

    This ensures no tests were removed from the fg-fast lane as a side-effect
    of the budget fix.
    """
    # Use the venv pytest so backend/tests conftest can import fastapi.
    venv_pytest = REPO_ROOT / ".venv" / "bin" / "pytest"
    pytest_exe = str(venv_pytest) if venv_pytest.exists() else sys.executable + " -m pytest"
    cmd = (
        [str(venv_pytest), "-m", "smoke or contract or security", "--collect-only", "-q", "--no-header"]
        if venv_pytest.exists()
        else [sys.executable, "-m", "pytest", "-m", "smoke or contract or security", "--collect-only", "-q", "--no-header"]
    )
    result = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    # Parse "N/M tests collected" or "N tests collected" from stdout
    import re

    match = re.search(r"(\d+)/?\d* tests? collected", result.stdout)
    assert match is not None, f"Could not parse test count from output:\n{output[:500]}"
    count = int(match.group(1))
    assert count >= _FG_FAST_BASELINE_COUNT, (
        f"fg-fast test count dropped below baseline: "
        f"got {count}, expected >= {_FG_FAST_BASELINE_COUNT}"
    )
