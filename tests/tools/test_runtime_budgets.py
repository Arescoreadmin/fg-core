from __future__ import annotations

from pathlib import Path

from tools.testing.harness.runtime_budgets import (
    enforce_lane_budget,
    load_runtime_budgets,
)


def test_runtime_budget_overrun_fails() -> None:
    doc = load_runtime_budgets(Path("tools/testing/policy/runtime_budgets.yaml"))
    ok, msg = enforce_lane_budget("fg-fast", 181, doc, baseline_seconds=150)
    assert not ok
    assert "exceeded" in msg


def test_runtime_budget_regression_fail_pct_enforced() -> None:
    doc = load_runtime_budgets(Path("tools/testing/policy/runtime_budgets.yaml"))
    ok, msg = enforce_lane_budget("fg-security", 200, doc, baseline_seconds=100)
    assert not ok
    assert "regression" in msg
