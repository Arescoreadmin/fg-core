from __future__ import annotations

from pathlib import Path

from tools.testing.harness.runtime_budgets import (
    enforce_lane_budget,
    load_runtime_budgets,
)


def test_runtime_budget_overrun_fails() -> None:
    doc = load_runtime_budgets(Path("tools/testing/policy/runtime_budgets.yaml"))
    # 931 > hard_max_seconds=930; must fail with "exceeded"
    ok, msg = enforce_lane_budget("fg-fast", 931, doc, baseline_seconds=600)
    assert not ok
    assert "exceeded" in msg


def test_runtime_budget_nominal_overrun_within_hard_max_passes() -> None:
    """901-930s exceeds nominal max (900) but is within hard_max (930): must pass."""
    doc = load_runtime_budgets(Path("tools/testing/policy/runtime_budgets.yaml"))
    # Use a high baseline so the regression gate doesn't fire independently
    ok, _msg = enforce_lane_budget("fg-fast", 905, doc, baseline_seconds=900)
    assert ok


def test_runtime_budget_regression_fail_pct_enforced() -> None:
    doc = load_runtime_budgets(Path("tools/testing/policy/runtime_budgets.yaml"))
    ok, msg = enforce_lane_budget("fg-security", 200, doc, baseline_seconds=100)
    assert not ok
    assert "regression" in msg
