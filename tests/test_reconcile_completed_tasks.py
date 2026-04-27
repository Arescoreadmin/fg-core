"""
Tests for tools/plan/reconcile_completed_tasks.py

Proves:
1)  Reconciles a completed task with passing validation command
2)  Does not write pass artifact when command fails
3)  Updates state validation artifact on pass
4)  Dry-run does not write artifact or state
5)  Missing task id in plan fails with exit code 2
6)  Completed task with no validation_commands fails clearly (status=no_commands)
7)  --task only reconciles the selected task
8)  Artifact JSON includes all required fields
9)  taskctl validate_state_integrity recognises generated artifact
10) --continue-on-fail processes all tasks even after failure
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

# Make tools/plan importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "plan"))

from reconcile_completed_tasks import (  # noqa: E402
    GENERATED_BY,
    reconcile_task,
    update_state_validation,
)
from taskctl import validate_state_integrity  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PASS_CMD = "true"  # shell built-in that always exits 0
_FAIL_CMD = "false"  # shell built-in that always exits 1


def _make_task(
    task_id: str,
    *,
    title: str = "Test task",
    validation_commands: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": task_id,
        "title": title,
        "status": "pending",
        "depends_on": [],
        "definition_of_done": [],
        "validation": [],
        "validation_commands": validation_commands
        if validation_commands is not None
        else [],
    }


def _make_plan(*tasks: dict[str, Any]) -> dict[str, Any]:
    return {
        "plan_id": "test-plan",
        "version": 1,
        "phases": [
            {
                "id": "phase-1",
                "name": "Phase 1",
                "modules": [
                    {
                        "id": "1.0",
                        "name": "Module 1",
                        "tasks": list(tasks),
                    }
                ],
            }
        ],
    }


def _make_state(
    completed_tasks: list[str],
    validations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "plan_id": "test-plan",
        "version": 1,
        "current_task_id": completed_tasks[-1] if completed_tasks else "",
        "completed_tasks": completed_tasks,
        "blocked": False,
        "blocked_reason": None,
        "validations": validations or {},
        "history": [],
    }


# ---------------------------------------------------------------------------
# 1) Reconcile a passing task
# ---------------------------------------------------------------------------


def test_reconcile_task_pass(tmp_path: Path) -> None:
    """reconcile_task returns status=pass and writes an artifact on success."""
    task = _make_task("1.1", validation_commands=[_PASS_CMD])
    artifacts_dir = tmp_path / "artifacts" / "plan"
    artifacts_dir.mkdir(parents=True)

    # Patch ROOT and ARTIFACTS_DIR for the duration of this test
    import reconcile_completed_tasks as rct

    orig_root = rct.ROOT
    orig_artifacts = rct.ARTIFACTS_DIR
    rct.ROOT = tmp_path
    rct.ARTIFACTS_DIR = artifacts_dir
    try:
        result = reconcile_task(
            "1.1",
            task,
            dry_run=False,
            git_commit="abc1234",
            dirty=False,
            verbose=False,
        )
    finally:
        rct.ROOT = orig_root
        rct.ARTIFACTS_DIR = orig_artifacts

    assert result["status"] == "pass"
    assert result["artifact_path"] is not None
    # artifact_path is relative to ROOT (tmp_path), so resolves correctly
    artifact_file = tmp_path / result["artifact_path"]
    assert artifact_file.exists()
    payload = json.loads(artifact_file.read_text())
    assert payload["status"] == "pass"


# ---------------------------------------------------------------------------
# 2) Does not write artifact when command fails
# ---------------------------------------------------------------------------


def test_reconcile_task_fail_does_not_write_pass(tmp_path: Path) -> None:
    """reconcile_task returns status=fail and artifact marks status=fail."""
    task = _make_task("1.1", validation_commands=[_FAIL_CMD])
    artifacts_dir = tmp_path / "artifacts" / "plan"
    artifacts_dir.mkdir(parents=True)

    import reconcile_completed_tasks as rct

    orig_root = rct.ROOT
    orig_artifacts = rct.ARTIFACTS_DIR
    rct.ROOT = tmp_path
    rct.ARTIFACTS_DIR = artifacts_dir
    try:
        result = reconcile_task(
            "1.1",
            task,
            dry_run=False,
            git_commit="abc1234",
            dirty=False,
            verbose=False,
        )
    finally:
        rct.ROOT = orig_root
        rct.ARTIFACTS_DIR = orig_artifacts

    assert result["status"] == "fail"
    latest = artifacts_dir / "1.1_validate_latest.json"
    assert latest.exists()
    payload = json.loads(latest.read_text())
    # Artifact must NOT claim pass
    assert payload["status"] == "fail"


# ---------------------------------------------------------------------------
# 3) Updates state validation on pass
# ---------------------------------------------------------------------------


def test_update_state_validation_on_pass() -> None:
    """update_state_validation sets status=pass and correct artifact path."""
    state = _make_state(["1.1"])
    update_state_validation(
        state, "1.1", "artifacts/plan/1.1_validate_latest.json", "20260101T000000Z"
    )

    v = state["validations"]["1.1"]
    assert v["status"] == "pass"
    assert v["artifact"] == "artifacts/plan/1.1_validate_latest.json"
    assert v["timestamp"] == "20260101T000000Z"


# ---------------------------------------------------------------------------
# 4) Dry-run does not write artifact or state
# ---------------------------------------------------------------------------


def test_reconcile_task_dry_run_no_artifact(tmp_path: Path) -> None:
    """Dry-run returns status=dry_run and writes nothing to disk."""
    task = _make_task("1.1", validation_commands=[_PASS_CMD])
    artifacts_dir = tmp_path / "artifacts" / "plan"
    artifacts_dir.mkdir(parents=True)

    import reconcile_completed_tasks as rct

    orig_root = rct.ROOT
    orig_artifacts = rct.ARTIFACTS_DIR
    rct.ROOT = tmp_path
    rct.ARTIFACTS_DIR = artifacts_dir
    try:
        result = reconcile_task(
            "1.1",
            task,
            dry_run=True,
            git_commit="abc1234",
            dirty=False,
            verbose=False,
        )
    finally:
        rct.ROOT = orig_root
        rct.ARTIFACTS_DIR = orig_artifacts

    assert result["status"] == "dry_run"
    assert result["artifact_path"] is None
    assert not any(artifacts_dir.iterdir())


# ---------------------------------------------------------------------------
# 5) Missing task id in plan returns error status
# ---------------------------------------------------------------------------


def test_reconcile_missing_task_in_plan(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """A task_id not in the plan index produces a clear error in the result."""
    # We test this at the CLI level by invoking main() with a mocked state
    import reconcile_completed_tasks as rct

    orig_plan = rct.PLAN_PATH
    orig_state = rct.STATE_PATH

    plan_file = tmp_path / "plan.yaml"
    state_file = tmp_path / "state.yaml"

    import yaml as yaml_mod

    plan_file.write_text(yaml_mod.safe_dump(_make_plan(_make_task("1.1"))))
    state_file.write_text(yaml_mod.safe_dump(_make_state(["NONEXISTENT"])))

    orig_root = rct.ROOT
    orig_artifacts = rct.ARTIFACTS_DIR
    artifacts_dir = tmp_path / "artifacts" / "plan"
    artifacts_dir.mkdir(parents=True)

    rct.PLAN_PATH = plan_file
    rct.STATE_PATH = state_file
    rct.ROOT = tmp_path
    rct.ARTIFACTS_DIR = artifacts_dir

    try:
        sys.argv = ["reconcile_completed_tasks.py", "--task", "NONEXISTENT"]
        exit_code = rct.main()
        assert exit_code == 2
    finally:
        rct.PLAN_PATH = orig_plan
        rct.STATE_PATH = orig_state
        rct.ROOT = orig_root
        rct.ARTIFACTS_DIR = orig_artifacts


# ---------------------------------------------------------------------------
# 6) No validation_commands fails clearly
# ---------------------------------------------------------------------------


def test_reconcile_task_no_commands() -> None:
    """A task with no validation_commands returns status=no_commands, not pass."""
    task = _make_task("1.1", validation_commands=[])
    result = reconcile_task(
        "1.1",
        task,
        dry_run=False,
        git_commit="abc1234",
        dirty=False,
        verbose=False,
    )
    assert result["status"] == "no_commands"
    assert result["artifact_path"] is None
    assert result["error"] is not None
    assert "no validation_commands" in result["error"]


# ---------------------------------------------------------------------------
# 7) --task only reconciles selected task
# ---------------------------------------------------------------------------


def test_reconcile_only_selected_task(tmp_path: Path) -> None:
    """--task runs only for the specified task; others are untouched."""
    import yaml as yaml_mod
    import reconcile_completed_tasks as rct

    orig_plan, orig_state, orig_artifacts, orig_root = (
        rct.PLAN_PATH,
        rct.STATE_PATH,
        rct.ARTIFACTS_DIR,
        rct.ROOT,
    )

    plan_file = tmp_path / "plan.yaml"
    state_file = tmp_path / "state.yaml"
    artifacts_dir = tmp_path / "artifacts" / "plan"
    artifacts_dir.mkdir(parents=True)

    plan_file.write_text(
        yaml_mod.safe_dump(
            _make_plan(
                _make_task("1.1", validation_commands=[_PASS_CMD]),
                _make_task("1.2", validation_commands=[_PASS_CMD]),
            )
        )
    )
    state_file.write_text(yaml_mod.safe_dump(_make_state(["1.1", "1.2"])))

    rct.PLAN_PATH = plan_file
    rct.STATE_PATH = state_file
    rct.ARTIFACTS_DIR = artifacts_dir
    rct.ROOT = tmp_path

    try:
        sys.argv = ["reconcile_completed_tasks.py", "--task", "1.1"]
        exit_code = rct.main()
    finally:
        rct.PLAN_PATH = orig_plan
        rct.STATE_PATH = orig_state
        rct.ARTIFACTS_DIR = orig_artifacts
        rct.ROOT = orig_root

    assert exit_code == 0
    assert (artifacts_dir / "1.1_validate_latest.json").exists()
    assert not (artifacts_dir / "1.2_validate_latest.json").exists()


# ---------------------------------------------------------------------------
# 8) Artifact JSON includes required fields
# ---------------------------------------------------------------------------


def test_artifact_contains_required_fields(tmp_path: Path) -> None:
    """Generated artifact must include all required fields."""
    task = _make_task("1.1", validation_commands=[_PASS_CMD])
    artifacts_dir = tmp_path / "artifacts" / "plan"
    artifacts_dir.mkdir(parents=True)

    import reconcile_completed_tasks as rct

    orig_root = rct.ROOT
    orig_artifacts = rct.ARTIFACTS_DIR
    rct.ROOT = tmp_path
    rct.ARTIFACTS_DIR = artifacts_dir
    try:
        reconcile_task(
            "1.1",
            task,
            dry_run=False,
            git_commit="abc1234",
            dirty=True,
            verbose=False,
        )
    finally:
        rct.ROOT = orig_root
        rct.ARTIFACTS_DIR = orig_artifacts

    payload = json.loads((artifacts_dir / "1.1_validate_latest.json").read_text())
    required = [
        "task_id",
        "title",
        "status",
        "timestamp",
        "validation_commands",
        "command_results",
        "repo_git_commit",
        "dirty_working_tree",
        "generated_by",
    ]
    for field in required:
        assert field in payload, f"Artifact missing required field: {field!r}"

    assert payload["task_id"] == "1.1"
    assert payload["repo_git_commit"] == "abc1234"
    assert payload["dirty_working_tree"] is True
    assert payload["generated_by"] == GENERATED_BY
    assert isinstance(payload["command_results"], list)


# ---------------------------------------------------------------------------
# 9) taskctl validate_state_integrity recognises generated artifact
# ---------------------------------------------------------------------------


def test_generated_artifact_recognised_by_state_integrity(tmp_path: Path) -> None:
    """validate_state_integrity must not flag a reconciler-generated artifact as missing."""
    task = _make_task("1.1", validation_commands=[_PASS_CMD])
    artifacts_dir = tmp_path / "artifacts" / "plan"
    artifacts_dir.mkdir(parents=True)

    import reconcile_completed_tasks as rct
    import taskctl as tc_mod

    orig_root = rct.ROOT
    orig_artifacts = rct.ARTIFACTS_DIR
    orig_root_tc = tc_mod.ROOT
    rct.ROOT = tmp_path
    rct.ARTIFACTS_DIR = artifacts_dir
    tc_mod.ROOT = tmp_path
    try:
        result = reconcile_task(
            "1.1",
            task,
            dry_run=False,
            git_commit="abc1234",
            dirty=False,
            verbose=False,
        )
    finally:
        rct.ROOT = orig_root
        rct.ARTIFACTS_DIR = orig_artifacts
        tc_mod.ROOT = orig_root_tc

    assert result["status"] == "pass"

    # Build a minimal plan + state that references the artifact
    plan = _make_plan(_make_task("1.1"))
    # Artifact was written to artifacts_dir = tmp_path/artifacts/plan/
    # result["artifact_path"] is now relative to tmp_path.
    import taskctl as tc_mod  # re-import for clarity

    orig_root_tc2 = tc_mod.ROOT
    tc_mod.ROOT = tmp_path
    try:
        state = _make_state(
            ["1.1"],
            validations={
                "1.1": {
                    "status": "pass",
                    "timestamp": "20260101T000000Z",
                    "artifact": result["artifact_path"],
                }
            },
        )
        errors = validate_state_integrity(plan, state)
        artifact_errors = [e for e in errors if "1.1_validate_latest" in e]
        assert artifact_errors == [], f"Unexpected artifact errors: {artifact_errors}"
    finally:
        tc_mod.ROOT = orig_root_tc2


# ---------------------------------------------------------------------------
# 10) --continue-on-fail processes all tasks
# ---------------------------------------------------------------------------


def test_continue_on_fail_processes_all_tasks(tmp_path: Path) -> None:
    """--continue-on-fail must run all tasks even after one fails."""
    import yaml as yaml_mod
    import reconcile_completed_tasks as rct

    orig_plan, orig_state, orig_artifacts, orig_root = (
        rct.PLAN_PATH,
        rct.STATE_PATH,
        rct.ARTIFACTS_DIR,
        rct.ROOT,
    )

    plan_file = tmp_path / "plan.yaml"
    state_file = tmp_path / "state.yaml"
    artifacts_dir = tmp_path / "artifacts" / "plan"
    artifacts_dir.mkdir(parents=True)

    plan_file.write_text(
        yaml_mod.safe_dump(
            _make_plan(
                _make_task("1.1", validation_commands=[_FAIL_CMD]),
                _make_task("1.2", validation_commands=[_PASS_CMD]),
            )
        )
    )
    state_file.write_text(yaml_mod.safe_dump(_make_state(["1.1", "1.2"])))

    rct.PLAN_PATH = plan_file
    rct.STATE_PATH = state_file
    rct.ARTIFACTS_DIR = artifacts_dir
    rct.ROOT = tmp_path

    try:
        sys.argv = [
            "reconcile_completed_tasks.py",
            "--all",
            "--continue-on-fail",
            "--no-write-state",
        ]
        exit_code = rct.main()
    finally:
        rct.PLAN_PATH = orig_plan
        rct.STATE_PATH = orig_state
        rct.ARTIFACTS_DIR = orig_artifacts
        rct.ROOT = orig_root

    # Exit 1 because 1.1 failed
    assert exit_code == 1
    # Both tasks must have artifacts
    assert (artifacts_dir / "1.1_validate_latest.json").exists()
    assert (artifacts_dir / "1.2_validate_latest.json").exists()

    payload_1 = json.loads((artifacts_dir / "1.1_validate_latest.json").read_text())
    payload_2 = json.loads((artifacts_dir / "1.2_validate_latest.json").read_text())
    assert payload_1["status"] == "fail"
    assert payload_2["status"] == "pass"
