"""FG-CI-NIGHTLY-REPAIR-001 — the testing-module verdict never reports a false green."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.ci import testing_module_verdict as tv

pytestmark = pytest.mark.contract

MIN = 1650


def _needs(**overrides: str) -> dict[str, dict[str, str]]:
    needs = {job: {"result": "success"} for job in tv.ALL_JOBS}
    for job, result in overrides.items():
        needs[job.replace("_", "-")] = {"result": result}
    return needs


def _security(
    tmp_path: Path, tests: int = 1673, failures: int = 0, errors: int = 0
) -> Path:
    d = tmp_path / "sec" / "ci" / "junit"
    d.mkdir(parents=True)
    (d / "fg-security.xml").write_text(
        f'<testsuites><testsuite name="pytest" tests="{tests}" failures="{failures}" '
        f'errors="{errors}" skipped="1"/></testsuites>'
    )
    return tmp_path / "sec"


def _eval(needs, event="schedule", suite="all", sec=None):
    return tv.evaluate(needs, event, suite, sec, MIN)


def test_complete_scheduled_run_passes(tmp_path: Path) -> None:
    v = _eval(_needs(), sec=_security(tmp_path))
    assert v["result"] == "PASS", v["errors"]
    assert v["security_junit"]["tests"] == 1673


@pytest.mark.parametrize("result", ["skipped", "cancelled", "failure", "missing"])
@pytest.mark.parametrize("job", tv.ALL_JOBS)
def test_scheduled_run_fails_unless_every_job_succeeds(
    tmp_path: Path, job: str, result: str
) -> None:
    needs = _needs()
    if result == "missing":
        del needs[job]
    else:
        needs[job] = {"result": result}
    v = _eval(needs, sec=_security(tmp_path))
    assert v["result"] == "FAIL"
    assert any(e.startswith(job) for e in v["errors"]), v["errors"]


def test_security_timeout_is_a_failure_not_a_skip(tmp_path: Path) -> None:
    # The gap-011 shape: fg-security cancelled by its job timeout, shards skipped.
    needs = _needs(fg_security="cancelled")
    for job in tv.FULL_JOBS:
        needs[job] = {"result": "skipped"}
    v = _eval(needs)
    assert v["result"] == "FAIL"
    assert "fg-security: required to succeed, got 'cancelled'" in v["errors"]
    assert len(v["errors"]) == 1 + len(tv.FULL_JOBS)


@pytest.mark.parametrize(
    ("kwargs", "needle"),
    [
        ({"tests": 10}, "< minimum"),
        ({"failures": 1}, "1 failure(s)"),
        ({"errors": 2}, "2 error(s)"),
    ],
)
def test_security_junit_must_prove_execution(
    tmp_path: Path, kwargs, needle: str
) -> None:
    v = _eval(_needs(), sec=_security(tmp_path, **kwargs))
    assert v["result"] == "FAIL"
    assert any(needle in e for e in v["errors"]), v["errors"]


def test_missing_security_junit_fails(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    v = _eval(_needs(), sec=tmp_path / "empty")
    assert any("found 0" in e for e in v["errors"]), v["errors"]
    assert _eval(_needs(), sec=None)["result"] == "FAIL"


def test_dispatch_security_only(tmp_path: Path) -> None:
    needs = _needs(**{j.replace("-", "_"): "skipped" for j in tv.FULL_JOBS})
    v = _eval(needs, "workflow_dispatch", "security", _security(tmp_path))
    assert v["result"] == "PASS", v["errors"]
    # A selected-out lane that ran anyway is reported, not silently accepted.
    needs["fg-full-shard"] = {"result": "failure"}
    assert (
        _eval(needs, "workflow_dispatch", "security", _security(tmp_path / "b"))[
            "result"
        ]
        == "FAIL"
    )


def test_dispatch_full_only() -> None:
    needs = _needs(fg_security="skipped")
    v = _eval(needs, "workflow_dispatch", "full")
    assert v["result"] == "PASS", v["errors"]
    needs["fg-full-complete"] = {"result": "skipped"}
    assert _eval(needs, "workflow_dispatch", "full")["result"] == "FAIL"


def test_suite_input_ignored_for_schedule(tmp_path: Path) -> None:
    needs = _needs(fg_security="skipped")
    assert _eval(needs, "schedule", "full")["result"] == "FAIL"


def test_pull_request_full_suite_is_optional_but_all_or_nothing(tmp_path: Path) -> None:
    sec = _security(tmp_path)
    skipped = _needs(**{j.replace("-", "_"): "skipped" for j in tv.FULL_JOBS})
    assert _eval(skipped, "pull_request", sec=sec)["result"] == "PASS"
    partial = _needs(fg_full_complete="skipped", fg_flake_detect="skipped")
    v = _eval(partial, "pull_request", sec=sec)
    assert v["result"] == "FAIL"
    assert any("full suite started" in e for e in v["errors"]), v["errors"]


def test_unknown_job_is_reported(tmp_path: Path) -> None:
    needs = _needs()
    needs["fg-new"] = {"result": "success"}
    assert any(
        "unexpected jobs" in e for e in _eval(needs, sec=_security(tmp_path))["errors"]
    )


def test_bad_input_exits_2(tmp_path: Path) -> None:
    p = tmp_path / "needs.json"
    p.write_text("[]")
    assert (
        tv.main(
            ["--needs-json", str(p), "--event", "schedule", "--security-min-tests", "1"]
        )
        == 2
    )
    p.write_text("{}")
    assert (
        tv.main(
            ["--needs-json", str(p), "--event", "push", "--security-min-tests", "1"]
        )
        == 2
    )


def test_cli_writes_verdict_and_summary(tmp_path: Path) -> None:
    p = tmp_path / "needs.json"
    p.write_text(json.dumps(_needs()))
    out, summary = tmp_path / "v.json", tmp_path / "summary.md"
    rc = tv.main(
        [
            "--needs-json", str(p), "--event", "schedule", "--suite", "all",
            "--security-artifacts", str(_security(tmp_path)),
            "--security-min-tests", str(MIN),
            "--out-json", str(out), "--summary", str(summary),
        ]
    )  # fmt: skip
    assert rc == 0
    assert json.loads(out.read_text())["result"] == "PASS"
    assert "testing-module verdict: PASS" in summary.read_text()
