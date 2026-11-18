"""fg-required timeout alignment: the harness step must outlast the harness budget.

Regression for #893, #894 and #899: the "Run fg-required harness" step had a
60-minute timeout (3600s) while the harness was given --global-budget-seconds
4400. Actions killed the step mid-lane before the harness's own budget could
stop it, so no summary artifact recorded the outcome.

The values are read from the real workflow file; nothing here is hard-coded
except the currently approved configuration.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from tools.ci import check_timeout_hierarchy as cth

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github/workflows/fg-required.yml"

GOOD = cth.FgRequiredTimeouts(
    job_timeout_minutes=90,
    step_timeout_minutes=75,
    global_budget_seconds=4400,
    lane_timeout_seconds=2400,
)


def test_repository_workflow_has_the_approved_values():
    assert cth.load_fg_required_timeouts(WORKFLOW) == GOOD


def test_repository_workflow_satisfies_the_hierarchy():
    assert cth.fg_required_violations(cth.load_fg_required_timeouts(WORKFLOW)) == []
    assert cth.main() == 0


def test_previous_configuration_is_rejected():
    old = replace(GOOD, job_timeout_minutes=80, step_timeout_minutes=60)
    (violation,) = cth.fg_required_violations(old)
    assert "step timeout (3600s) is shorter than global_budget (4400s)" in violation


@pytest.mark.parametrize(
    "change,needle",
    [
        ({"step_timeout_minutes": 73}, "step timeout (4380s) is shorter"),
        ({"step_timeout_minutes": 74}, "step timeout (4440s) is shorter"),
        ({"global_budget_seconds": 4500}, "is shorter than global_budget (4500s)"),
        ({"job_timeout_minutes": 80}, "job timeout (4800s) leaves less than"),
        ({"job_timeout_minutes": 75}, "job timeout (4500s) leaves less than"),
        (
            {"lane_timeout_seconds": 4500, "global_budget_seconds": 4400},
            "lane_timeout (4500s) > global_budget (4400s)",
        ),
    ],
    ids=[
        "step-below-budget",
        "step-inside-headroom",
        "budget-raised-alone",
        "job-overhead-too-small",
        "job-equals-step",
        "lane-above-budget",
    ],
)
def test_misaligned_configuration_is_rejected(change, needle):
    violations = cth.fg_required_violations(replace(GOOD, **change))
    assert any(needle in v for v in violations), violations


def test_minimum_headroom_boundaries_are_accepted():
    budget = GOOD.global_budget_seconds + cth.MIN_STEP_HEADROOM_SECONDS
    exact = replace(GOOD, step_timeout_minutes=budget // 60 + (budget % 60 > 0))
    exact = replace(
        exact,
        job_timeout_minutes=exact.step_timeout_minutes
        + cth.MIN_JOB_OVERHEAD_SECONDS // 60,
    )
    assert cth.fg_required_violations(exact) == []


def _write(tmp_path: Path, edit) -> Path:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    edit(data)
    out = tmp_path / "fg-required.yml"
    out.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return out


def _harness_step(data: dict) -> dict:
    (step,) = [
        s
        for s in data["jobs"]["fg-required"]["steps"]
        if s.get("name") == cth.FG_REQUIRED_STEP
    ]
    return step


def test_loader_reads_values_from_the_workflow_file(tmp_path):
    def shorten(d):
        _harness_step(d)["timeout-minutes"] = 60

    t = cth.load_fg_required_timeouts(_write(tmp_path, shorten))
    assert t.step_timeout_minutes == 60
    assert cth.fg_required_violations(t)


@pytest.mark.parametrize(
    "edit",
    [
        lambda d: _harness_step(d).pop("timeout-minutes"),
        lambda d: d["jobs"]["fg-required"].pop("timeout-minutes"),
        lambda d: _harness_step(d).__setitem__(
            "run", _harness_step(d)["run"].replace("--global-budget-seconds 4400", "")
        ),
        lambda d: _harness_step(d).__setitem__("name", "Run harness"),
    ],
    ids=["no-step-timeout", "no-job-timeout", "no-budget-flag", "step-renamed"],
)
def test_unreadable_workflow_fails_closed(tmp_path, monkeypatch, edit):
    path = _write(tmp_path, edit)
    with pytest.raises((KeyError, TypeError, ValueError)):
        cth.load_fg_required_timeouts(path)
    monkeypatch.setattr(cth, "FG_REQUIRED_WORKFLOW", path)
    (violation,) = cth._validate_fg_required_hierarchy()
    assert "unreadable" in violation
