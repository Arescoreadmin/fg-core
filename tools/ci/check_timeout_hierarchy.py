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


FG_REQUIRED_WORKFLOW = REPO_ROOT / ".github/workflows/fg-required.yml"
FG_REQUIRED_JOB = "fg-required"
FG_REQUIRED_STEP = "Run fg-required harness"

# The harness must be able to reach its own global budget, stop its lanes and
# write fg-required-summary.json before Actions kills the step.
MIN_STEP_HEADROOM_SECONDS = 60
# Setup (checkout, Python, venv, pip-audit) plus artifact collection, upload
# and teardown run outside the harness step but inside the job timeout.
MIN_JOB_OVERHEAD_SECONDS = 600


@dataclass(frozen=True)
class FgRequiredTimeouts:
    job_timeout_minutes: int
    step_timeout_minutes: int
    global_budget_seconds: int
    lane_timeout_seconds: int


def load_fg_required_timeouts(
    path: Path = FG_REQUIRED_WORKFLOW,
) -> FgRequiredTimeouts:
    """Read the real timeout values from the fg-required workflow."""
    import importlib
    import re

    yaml = importlib.import_module("yaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    job = data["jobs"][FG_REQUIRED_JOB]
    steps = [s for s in job["steps"] if s.get("name") == FG_REQUIRED_STEP]
    if len(steps) != 1:
        raise ValueError(f"expected one {FG_REQUIRED_STEP!r} step, found {len(steps)}")
    step = steps[0]

    def flag(name: str) -> int:
        found = re.findall(rf"--{name}\s+(\d+)\b", step["run"])
        if len(found) != 1:
            raise ValueError(f"expected one --{name} in {FG_REQUIRED_STEP!r}")
        return int(found[0])

    return FgRequiredTimeouts(
        job_timeout_minutes=int(job["timeout-minutes"]),
        step_timeout_minutes=int(step["timeout-minutes"]),
        global_budget_seconds=flag("global-budget-seconds"),
        lane_timeout_seconds=flag("lane-timeout-seconds"),
    )


def fg_required_violations(t: FgRequiredTimeouts) -> list[str]:
    """lane_timeout <= global_budget < step_timeout < job_timeout, with headroom."""
    step = t.step_timeout_minutes * 60
    job = t.job_timeout_minutes * 60
    violations: list[str] = []
    if t.lane_timeout_seconds > t.global_budget_seconds:
        violations.append(
            f"fg-required lane_timeout ({t.lane_timeout_seconds}s) > "
            f"global_budget ({t.global_budget_seconds}s)"
        )
    if step < t.global_budget_seconds + MIN_STEP_HEADROOM_SECONDS:
        violations.append(
            f"fg-required harness step timeout ({step}s) is shorter than "
            f"global_budget ({t.global_budget_seconds}s) + "
            f"{MIN_STEP_HEADROOM_SECONDS}s: Actions would kill the harness "
            "before its own budget applies and before it writes its summary"
        )
    if job < step + MIN_JOB_OVERHEAD_SECONDS:
        violations.append(
            f"fg-required job timeout ({job}s) leaves less than "
            f"{MIN_JOB_OVERHEAD_SECONDS}s beyond the harness step ({step}s) "
            "for setup, artifact collection, upload and teardown"
        )
    return violations


def _validate_fg_required_hierarchy() -> list[str]:
    """fg-required: values are read from fg-required.yml, never hard-coded."""
    try:
        t = load_fg_required_timeouts(FG_REQUIRED_WORKFLOW)
    except (KeyError, TypeError, ValueError) as exc:
        return [f"fg-required workflow timeouts unreadable: {exc}"]
    violations = fg_required_violations(t)
    if not violations:
        print(
            f"  OK: lane_timeout={t.lane_timeout_seconds}s <= "
            f"global_budget={t.global_budget_seconds}s < "
            f"step_timeout={t.step_timeout_minutes * 60}s < "
            f"job_timeout={t.job_timeout_minutes * 60}s"
        )
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
