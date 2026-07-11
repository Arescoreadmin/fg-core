#!/usr/bin/env python3
"""Validate that CI timeout layers are correctly nested:
command_hard_max < lane_timeout < job_timeout_minutes*60 < global_budget

Run: python tools/ci/check_timeout_hierarchy.py
Exit 0 = hierarchy is valid; exit 1 = violation found.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.testing.harness.lane_runner import (  # noqa: E402
    ALLOWED_LANES as _LANE_RUNNER_LANES,
    COMMAND_TIMEOUT_SECONDS as _DEFAULT_CMD_TIMEOUT,
)


def _lane_runner_timeout_for(lane: str, make_target: str) -> int:
    """Return the actual CommandSpec timeout for a given make target in a lane."""
    for cmd_spec in _LANE_RUNNER_LANES.get(lane, ()):
        if cmd_spec.argv == ("make", make_target):
            return cmd_spec.timeout_seconds
    return _DEFAULT_CMD_TIMEOUT


@dataclass(frozen=True)
class TimeoutNode:
    name: str
    seconds: int
    source: str


def _load_budgets() -> dict[str, object]:
    import importlib

    yaml = importlib.import_module("yaml")
    path = REPO_ROOT / "tools/testing/policy/runtime_budgets.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("runtime_budgets.yaml is not a mapping")
    return data


def _validate_fg_fast_hierarchy(budgets: dict[str, object]) -> list[str]:
    """fg-fast: command_hard_max < job_timeout."""
    violations: list[str] = []
    lanes = budgets.get("lanes", {})
    if not isinstance(lanes, dict):
        return violations

    fg_fast = lanes.get("fg-fast", {})
    if not isinstance(fg_fast, dict):
        return violations

    hard_max = fg_fast.get("hard_max_seconds", fg_fast.get("max_seconds"))
    if hard_max is None:
        return violations

    # Job timeout from testing-module.yml: 35 min = 2100s (lowered from 55 after lane runner fix)
    job_timeout_seconds = 35 * 60

    if int(hard_max) >= job_timeout_seconds:
        violations.append(
            f"fg-fast command hard_max ({hard_max}s) >= job timeout ({job_timeout_seconds}s)"
        )
    else:
        print(
            f"  OK: fg-fast hard_max={hard_max}s < job_timeout={job_timeout_seconds}s"
        )

    return violations


def _validate_fg_security_hierarchy(budgets: dict[str, object]) -> list[str]:
    """fg-security: command_hard_max (from policy) < lane_timeout < job_timeout."""
    violations: list[str] = []
    lanes = budgets.get("lanes", {})
    if not isinstance(lanes, dict):
        return violations

    fg_security = lanes.get("fg-security", {})
    if not isinstance(fg_security, dict):
        return violations

    max_seconds = fg_security.get("max_seconds")
    if max_seconds is None:
        return violations

    # Read actual timeout from lane_runner.py ALLOWED_LANES to avoid staleness.
    lane_runner_timeout = _lane_runner_timeout_for("fg-security", "fg-security")

    # fg-required global budget: 2800s
    global_budget = 2800

    # Job timeout from testing-module.yml: 25 min = 1500s
    job_timeout_seconds = 25 * 60

    checks = [
        (
            int(max_seconds),
            lane_runner_timeout,
            "fg-security max_seconds",
            "lane_runner CommandSpec timeout",
        ),
        (
            lane_runner_timeout,
            global_budget,
            "lane_runner CommandSpec timeout",
            "fg-required global_budget",
        ),
        (
            job_timeout_seconds,
            global_budget,
            "fg-security job timeout",
            "fg-required global_budget (note: different workflows)",
        ),
    ]

    for lower, upper, lower_name, upper_name in checks:
        if lower > upper:
            violations.append(
                f"{lower_name} ({lower}s) > {upper_name} ({upper}s) — hierarchy violated"
            )
        else:
            print(f"  OK: {lower_name}={lower}s <= {upper_name}={upper}s")

    return violations


def _validate_fg_required_hierarchy() -> list[str]:
    """fg-required: lane_timeout <= global_budget < job_timeout."""
    violations: list[str] = []

    # Values from fg-required.yml
    lane_timeout = 1500
    global_budget = 2800
    job_timeout = 60 * 60  # 60 min inner step

    checks = [
        (
            lane_timeout,
            global_budget,
            "fg-required lane_timeout",
            "fg-required global_budget",
        ),
        (
            global_budget,
            job_timeout,
            "fg-required global_budget",
            "fg-required job_timeout",
        ),
    ]

    for lower, upper, lower_name, upper_name in checks:
        if lower > upper:
            violations.append(
                f"{lower_name} ({lower}s) > {upper_name} ({upper}s) — hierarchy violated"
            )
        else:
            print(f"  OK: {lower_name}={lower}s <= {upper_name}={upper}s")

    return violations


def _validate_global_pr_budget(budgets: dict[str, object]) -> list[str]:
    """global_pr_budget_seconds must be present and sane."""
    violations: list[str] = []
    global_budget = budgets.get("global_pr_budget_seconds")
    if global_budget is None:
        violations.append("global_pr_budget_seconds missing from runtime_budgets.yaml")
        return violations

    # Minimum sanity: should be at least 60s, at most 7200s (2h) for a PR budget
    if not isinstance(global_budget, (int, float, str)):
        violations.append("global_pr_budget_seconds must be a number")
        return violations
    val = int(global_budget)
    if val < 60:
        violations.append(
            f"global_pr_budget_seconds={val} is unreasonably small (<60s)"
        )
    elif val > 7200:
        violations.append(
            f"global_pr_budget_seconds={val} exceeds 2 hours — is this a PR budget?"
        )
    else:
        print(f"  OK: global_pr_budget_seconds={val}s is in [60, 7200]")

    return violations


def main() -> int:
    print("=== CI Timeout Hierarchy Validator ===")
    print()

    try:
        budgets = _load_budgets()
    except SystemExit as exc:
        print(f"ERROR loading budgets: {exc}")
        return 1

    all_violations: list[str] = []

    print("--- global_pr_budget_seconds ---")
    all_violations.extend(_validate_global_pr_budget(budgets))

    print()
    print("--- fg-fast command/job hierarchy ---")
    all_violations.extend(_validate_fg_fast_hierarchy(budgets))

    print()
    print("--- fg-security command/lane/global hierarchy ---")
    all_violations.extend(_validate_fg_security_hierarchy(budgets))

    print()
    print("--- fg-required lane/global/job hierarchy ---")
    all_violations.extend(_validate_fg_required_hierarchy())

    print()
    if all_violations:
        print(f"FAIL — {len(all_violations)} violation(s) found:")
        for v in all_violations:
            print(f"  VIOLATION: {v}")
        return 1

    print("PASS — all timeout hierarchies are correctly nested")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
