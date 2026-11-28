"""FG-CI-NIGHTLY-REPAIR-001 — regression guard for the scheduled testing-module.

Each case copies the real testing-module.yml and Makefile into a throwaway
repo, re-introduces one way a scheduled lane could be cancelled, skipped or
lost (including the exact pre-repair shape from audit gap 011), and proves
tools/ci/check_testing_module_workflow.py fails closed on it.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from tools.ci import check_testing_module_workflow as chk

pytestmark = pytest.mark.contract

REPO = Path(__file__).resolve().parents[2]
WF = Path(".github/workflows/testing-module.yml")


@pytest.fixture
def fake_repo(tmp_path: Path) -> Path:
    shutil.copy(REPO / "Makefile", tmp_path / "Makefile")
    (tmp_path / WF).parent.mkdir(parents=True)
    shutil.copy(REPO / WF, tmp_path / WF)
    return tmp_path


def _edit(repo: Path, mutate: Callable[[dict[Any, Any]], None]) -> None:
    data = yaml.safe_load((repo / WF).read_text())
    mutate(data)
    (repo / WF).write_text(yaml.safe_dump(data, sort_keys=False))


def _errors(repo: Path, needle: str) -> list[str]:
    errors = chk.check(repo)
    assert any(needle in e for e in errors), errors
    return errors


def test_real_repository_passes() -> None:
    assert chk.check(REPO) == []


def test_yaml_round_trip_keeps_passing(fake_repo: Path) -> None:
    _edit(fake_repo, lambda d: None)
    assert chk.check(fake_repo) == []


def test_pre_repair_shape_is_rejected(fake_repo: Path) -> None:
    """The workflow as it was on main before the repair (gap 011)."""

    def mutate(d: dict[Any, Any]) -> None:
        d["concurrency"] = {
            "group": "testing-module-${{ github.event.pull_request.number || github.ref }}",
            "cancel-in-progress": True,
        }
        d["jobs"]["fg-security"]["timeout-minutes"] = 25
        gates = d["jobs"]["fg-full-gates"]
        gates["needs"] = [
            "fg-fast",
            "fg-contract",
            "fg-security",
            "detect-high-risk-paths",
        ]
        del d["jobs"][chk.VERDICT_JOB]

    _edit(fake_repo, mutate)
    errors = chk.check(fake_repo)
    for needle in (
        "cancel-in-progress",
        "github.run_id",
        "fg-security: timeout-minutes",
        "fg-full-gates: must not depend on fg-security",
        f"{chk.VERDICT_JOB}: job is required",
    ):
        assert any(needle in e for e in errors), (needle, errors)


def test_gates_condition_on_security_result_is_rejected(fake_repo: Path) -> None:
    def mutate(d: dict[Any, Any]) -> None:
        g = d["jobs"]["fg-full-gates"]
        g["if"] = "${{ needs.fg-security.result == 'success' }}"

    _edit(fake_repo, mutate)
    _errors(fake_repo, "fg-full-gates: must not depend on fg-security")


def test_missing_schedule_is_rejected(fake_repo: Path) -> None:
    _edit(fake_repo, lambda d: d[True].pop("schedule"))
    _errors(fake_repo, "on.schedule")


def test_dispatch_without_suite_choice_is_rejected(fake_repo: Path) -> None:
    _edit(fake_repo, lambda d: d[True].update({"workflow_dispatch": None}))
    _errors(fake_repo, "workflow_dispatch.inputs.suite")


def test_security_timeout_above_hierarchy_ceiling_is_rejected(fake_repo: Path) -> None:
    _edit(fake_repo, lambda d: d["jobs"]["fg-security"].update({"timeout-minutes": 60}))
    _errors(fake_repo, "fg-security: timeout-minutes")


@pytest.mark.parametrize(
    ("where", "needle"),
    [("job", "fg-full-shard: continue-on-error"), ("step", "continue-on-error")],
)
def test_continue_on_error_is_rejected(
    fake_repo: Path, where: str, needle: str
) -> None:
    def mutate(d: dict[Any, Any]) -> None:
        job = d["jobs"]["fg-full-shard"]
        if where == "job":
            job["continue-on-error"] = True
        else:
            job["steps"][-2]["continue-on-error"] = True

    _edit(fake_repo, mutate)
    _errors(fake_repo, needle)


def test_shard_fail_fast_is_rejected(fake_repo: Path) -> None:
    _edit(
        fake_repo,
        lambda d: d["jobs"]["fg-full-shard"]["strategy"].update({"fail-fast": True}),
    )
    _errors(fake_repo, "fail-fast")


def test_dropped_shard_is_rejected(fake_repo: Path) -> None:
    def mutate(d: dict[Any, Any]) -> None:
        d["jobs"]["fg-full-shard"]["strategy"]["matrix"]["shard_index"].remove(7)

    _edit(fake_repo, mutate)
    _errors(fake_repo, "matrix.shard_index must be exactly")


def test_shard_count_mismatch_with_aggregate_is_rejected(fake_repo: Path) -> None:
    def mutate(d: dict[Any, Any]) -> None:
        for step in d["jobs"]["fg-full-complete"]["steps"]:
            if "fg_full_aggregate.py" in str(step.get("run", "")):
                step["run"] = step["run"].replace(
                    "--total-shards 10", "--total-shards 9"
                )

    _edit(fake_repo, mutate)
    _errors(fake_repo, "aggregate must use --total-shards")


@pytest.mark.parametrize(
    ("old", "new", "needle"),
    [
        ("--require-collection \\\n", "", "--require-collection"),
        (
            "--expected-min-tests 25000",
            "--expected-min-tests 1000",
            "--expected-min-tests",
        ),
    ],
)
def test_weakened_aggregate_is_rejected(
    fake_repo: Path, old: str, new: str, needle: str
) -> None:
    def mutate(d: dict[Any, Any]) -> None:
        for step in d["jobs"]["fg-full-complete"]["steps"]:
            run = str(step.get("run", ""))
            if "fg_full_aggregate.py" in run:
                assert old in run
                step["run"] = run.replace(old, new)

    _edit(fake_repo, mutate)
    _errors(fake_repo, needle)


def test_upload_without_always_is_rejected(fake_repo: Path) -> None:
    def mutate(d: dict[Any, Any]) -> None:
        for step in d["jobs"]["fg-security"]["steps"]:
            if str(step.get("uses", "")).startswith("actions/upload-artifact"):
                step.pop("if")

    _edit(fake_repo, mutate)
    _errors(fake_repo, "upload-artifact must run if: always()")


def test_short_retention_is_rejected(fake_repo: Path) -> None:
    def mutate(d: dict[Any, Any]) -> None:
        for step in d["jobs"]["fg-full-shard"]["steps"]:
            if str(step.get("uses", "")).startswith("actions/upload-artifact"):
                step["with"]["retention-days"] = 7

    _edit(fake_repo, mutate)
    _errors(fake_repo, "retention-days")


@pytest.mark.parametrize("job", chk.TIMEOUT_JOBS)
def test_per_test_timeout_disabled_is_rejected(fake_repo: Path, job: str) -> None:
    _edit(
        fake_repo, lambda d: d["jobs"][job]["env"].pop("NIGHTLY_TEST_TIMEOUT_SECONDS")
    )
    _errors(fake_repo, f"{job}: env.NIGHTLY_TEST_TIMEOUT_SECONDS")


def test_verdict_missing_a_need_is_rejected(fake_repo: Path) -> None:
    _edit(
        fake_repo, lambda d: d["jobs"][chk.VERDICT_JOB]["needs"].remove("fg-security")
    )
    _errors(fake_repo, "needs must list every other job")


def test_verdict_without_always_is_rejected(fake_repo: Path) -> None:
    _edit(fake_repo, lambda d: d["jobs"][chk.VERDICT_JOB].pop("if"))
    _errors(fake_repo, "must run if:")


def test_new_job_without_verdict_update_is_rejected(fake_repo: Path) -> None:
    def mutate(d: dict[Any, Any]) -> None:
        d["jobs"]["fg-extra"] = {"runs-on": "ubuntu-latest", "steps": [{"run": "true"}]}
        d["jobs"][chk.VERDICT_JOB]["needs"].append("fg-extra")

    _edit(fake_repo, mutate)
    _errors(fake_repo, "ALL_JOBS must match")


@pytest.mark.parametrize(
    ("old", "needle"),
    [
        (
            '> "$(dir $(SHARD_JUNIT))shard-collection.json"',
            "must write shard-collection.json",
        ),
        (
            "$(NIGHTLY_TIMEOUT_ARGS) --junitxml $(JUNIT_DIR)/fg-security.xml",
            "fg-security-pytest",
        ),
    ],
)
def test_makefile_regressions_are_rejected(
    fake_repo: Path, old: str, needle: str
) -> None:
    mk = fake_repo / "Makefile"
    text = mk.read_text()
    assert old in text
    replacement = (
        "> /dev/null"
        if "collection" in needle
        else "--junitxml $(JUNIT_DIR)/fg-security.xml"
    )
    mk.write_text(text.replace(old, replacement))
    _errors(fake_repo, needle)


def test_verdict_download_by_run_attempt_is_rejected(fake_repo: Path) -> None:
    # Codex review of #925: "Re-run failed jobs" keeps a successful
    # fg-security's attempt-1 artifact while run_attempt increments.
    def mutate(d: dict[Any, Any]) -> None:
        for step in d["jobs"][chk.VERDICT_JOB]["steps"]:
            if str(step.get("uses", "")).startswith("actions/download-artifact"):
                step["with"] = {
                    "name": "fg-security-artifacts-${{ github.run_attempt }}",
                    "path": "artifacts/verdict/fg-security",
                }

    _edit(fake_repo, mutate)
    _errors(fake_repo, "never the run_attempt")


def test_security_artifact_id_output_is_required(fake_repo: Path) -> None:
    _edit(fake_repo, lambda d: d["jobs"]["fg-security"].pop("outputs"))
    _errors(fake_repo, "outputs.security_artifact_id")


# --- Evidence provenance (Codex review of #925, extended to shards) ---------


def _job_steps(d: dict[Any, Any], job: str) -> list[dict[str, Any]]:
    return d["jobs"][job]["steps"]


def _find(steps: list[dict[str, Any]], needle: str) -> int:
    return next(
        i
        for i, s in enumerate(steps)
        if needle in str(s.get("run", "")) + str(s.get("uses", ""))
    )


def _set_download(job: str, with_: dict[str, Any]) -> Callable[[dict[Any, Any]], None]:
    def mutate(d: dict[Any, Any]) -> None:
        for step in _job_steps(d, job):
            if str(step.get("uses", "")).startswith("actions/download-artifact"):
                step["with"] = with_

    return mutate


@pytest.mark.parametrize(
    ("job", "with_"),
    [
        # The pre-fix shard download: misses every shard not re-run.
        (
            "fg-full-complete",
            {
                "pattern": "fg-full-shard-*-${{ github.run_attempt }}",
                "path": "artifacts/fg-full-shards",
                "merge-multiple": True,
            },
        ),
        # A wildcard over every attempt could mix stale evidence in.
        ("fg-full-complete", {"pattern": "fg-full-shard-*", "path": "x"}),
        (
            "fg-flake-detect",
            {
                "name": "fg-full-complete-artifacts-${{ github.run_attempt }}",
                "path": "x",
            },
        ),
        ("fg-flake-detect", {"artifact-ids": "${{ github.run_attempt }}", "path": "x"}),
    ],
)
def test_download_by_name_pattern_or_attempt_is_rejected(
    fake_repo: Path, job: str, with_: dict[str, Any]
) -> None:
    _edit(fake_repo, _set_download(job, with_))
    _errors(fake_repo, f"{job}: download-artifact must")


@pytest.mark.parametrize("job", ["fg-security", "fg-full-shard"])
def test_missing_provenance_write_is_rejected(fake_repo: Path, job: str) -> None:
    def mutate(d: dict[Any, Any]) -> None:
        steps = _job_steps(d, job)
        del steps[_find(steps, "testing_module_evidence.py write")]

    _edit(fake_repo, mutate)
    _errors(fake_repo, f"{job}: must write evidence provenance")


@pytest.mark.parametrize("job", ["fg-security", "fg-full-shard"])
def test_provenance_write_without_always_is_rejected(fake_repo: Path, job: str) -> None:
    # A failed or timed-out lane must still upload verifiable partial evidence.
    def mutate(d: dict[Any, Any]) -> None:
        steps = _job_steps(d, job)
        steps[_find(steps, "testing_module_evidence.py write")].pop("if")

    _edit(fake_repo, mutate)
    _errors(fake_repo, f"{job}: must write evidence provenance")


@pytest.mark.parametrize("job", ["fg-security", "fg-full-shard"])
def test_provenance_written_after_upload_is_rejected(fake_repo: Path, job: str) -> None:
    def mutate(d: dict[Any, Any]) -> None:
        steps = _job_steps(d, job)
        steps.append(steps.pop(_find(steps, "testing_module_evidence.py write")))

    _edit(fake_repo, mutate)
    _errors(fake_repo, f"{job}: evidence provenance must be written before upload")


def test_security_upload_outside_staged_evidence_is_rejected(fake_repo: Path) -> None:
    # Unhashed files would ride along with the hashed evidence.
    def mutate(d: dict[Any, Any]) -> None:
        steps = _job_steps(d, "fg-security")
        steps[_find(steps, "actions/upload-artifact")]["with"]["path"] = "artifacts/**"

    _edit(fake_repo, mutate)
    _errors(fake_repo, "fg-security: upload exactly the provenance-staged")


@pytest.mark.parametrize(
    ("job", "step_needle"),
    [
        (chk.VERDICT_JOB, "testing_module_evidence.py verify"),
        (chk.VERDICT_JOB, "testing_module_evidence.py resolve"),
        ("fg-full-complete", "testing_module_evidence.py verify"),
        ("fg-full-complete", "testing_module_evidence.py resolve"),
    ],
)
def test_missing_resolve_or_verify_is_rejected(
    fake_repo: Path, job: str, step_needle: str
) -> None:
    def mutate(d: dict[Any, Any]) -> None:
        steps = _job_steps(d, job)
        del steps[_find(steps, step_needle)]

    _edit(fake_repo, mutate)
    _errors(fake_repo, f"{job}: must resolve")


@pytest.mark.parametrize("job", [chk.VERDICT_JOB, "fg-full-complete"])
def test_consumer_without_actions_read_is_rejected(fake_repo: Path, job: str) -> None:
    _edit(fake_repo, lambda d: d["jobs"][job]["permissions"].pop("actions"))
    _errors(fake_repo, f"{job}: needs permissions.actions: read")


def test_security_resolve_without_output_cross_check_is_rejected(
    fake_repo: Path,
) -> None:
    def mutate(d: dict[Any, Any]) -> None:
        steps = _job_steps(d, chk.VERDICT_JOB)
        step = steps[_find(steps, "testing_module_evidence.py resolve")]
        step["env"].pop("OUTPUT_ID")
        step["run"] = step["run"].replace('--artifact-id "$OUTPUT_ID"', "")

    _edit(fake_repo, mutate)
    _errors(fake_repo, "resolve must cross-check fg-security's artifact-id output")


def test_shard_resolve_count_mismatch_is_rejected(fake_repo: Path) -> None:
    def mutate(d: dict[Any, Any]) -> None:
        steps = _job_steps(d, "fg-full-complete")
        step = steps[_find(steps, "testing_module_evidence.py resolve")]
        step["run"] = step["run"].replace("--total-shards 10", "--total-shards 9")

    _edit(fake_repo, mutate)
    _errors(fake_repo, "fg-full-complete: resolve must use --total-shards 10")


@pytest.mark.parametrize(
    ("job", "needle", "message"),
    [
        (
            "fg-full-complete",
            "fg_full_aggregate.py",
            "aggregate must run after provenance verify",
        ),
        (
            chk.VERDICT_JOB,
            "testing_module_verdict.py",
            "verdict must run after provenance verify",
        ),
    ],
)
def test_evidence_used_before_verify_is_rejected(
    fake_repo: Path, job: str, needle: str, message: str
) -> None:
    def mutate(d: dict[Any, Any]) -> None:
        steps = _job_steps(d, job)
        moved = steps.pop(_find(steps, needle))
        steps.insert(_find(steps, "testing_module_evidence.py resolve"), moved)

    _edit(fake_repo, mutate)
    _errors(fake_repo, message)


@pytest.mark.parametrize(
    "job", [chk.VERDICT_JOB, "fg-full-complete", "fg-flake-detect"]
)
def test_download_by_id_without_merge_multiple_is_rejected(
    fake_repo: Path, job: str
) -> None:
    # Run 46105295520: the verdict's by-id download landed in
    # artifacts/verdict/fg-security/fg-security-artifacts-1/ and verify (correctly)
    # found no provenance at the expected root.
    def mutate(d: dict[Any, Any]) -> None:
        for step in _job_steps(d, job):
            if str(step.get("uses", "")).startswith("actions/download-artifact"):
                step["with"].pop("merge-multiple", None)

    _edit(fake_repo, mutate)
    _errors(
        fake_repo,
        f"{job}: download-artifact by artifact-ids must set merge-multiple: true",
    )
