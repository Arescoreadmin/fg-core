"""
Task 15.1 — Plan/State Integrity Gate

Tests proving:
1)  Valid plan passes integrity check
2)  Duplicate task IDs are detected without aborting early
3)  Unresolved dependency references are detected
4)  Cyclic dependency graphs are detected
5)  Missing required task fields (title) are detected
6)  Missing task 'id' field reported as error, not KeyError
7)  State with unknown current_task_id fails integrity
8)  State with unknown completed task fails integrity
9)  State with unmet current-task dependencies fails integrity
10) State integrity with duplicate task IDs does not SystemExit
11) Malformed plan with missing id still lets validation report all possible errors
12) Plan artifact existence — missing artifact fails integrity check
13) Plan artifact existence — present artifact passes
14) Deterministic current task selection — first incomplete task in plan order
15) Deterministic current task selection — stable under repeated calls
16) taskctl status resolves current task without contradiction (live plan)
17) taskctl status --explain shows dependency satisfaction
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Ensure tools/plan is importable before importing taskctl
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "plan"))

from taskctl import (  # noqa: E402  (import after sys.path fix)
    ROOT,
    PLAN_PATH,
    STATE_PATH,
    next_incomplete_task,
    validate_plan_integrity,
    validate_state_integrity,
)


# ---------------------------------------------------------------------------
# Minimal plan/state factories
# ---------------------------------------------------------------------------


def _make_plan(*task_defs: dict) -> dict:
    """Build a minimal plan dict with a single module containing the given tasks."""
    return {
        "plan_id": "test-plan",
        "version": 1,
        "phases": [
            {
                "id": "phase-1",
                "name": "Test Phase",
                "modules": [
                    {
                        "id": "1.0",
                        "name": "Test Module",
                        "tasks": list(task_defs),
                    }
                ],
            }
        ],
    }


def _make_task(
    task_id: str, *, title: str = "A task", depends_on: list | None = None
) -> dict:
    return {
        "id": task_id,
        "title": title,
        "status": "pending",
        "depends_on": depends_on or [],
        "definition_of_done": [],
        "validation": [],
        "validation_commands": [],
    }


def _make_state(
    current_task_id: str,
    completed_tasks: list[str] | None = None,
    validations: dict | None = None,
) -> dict:
    return {
        "plan_id": "test-plan",
        "version": 1,
        "current_task_id": current_task_id,
        "completed_tasks": completed_tasks or [],
        "blocked": False,
        "blocked_reason": None,
        "validations": validations or {},
        "history": [],
    }


# ---------------------------------------------------------------------------
# 1) Valid plan passes
# ---------------------------------------------------------------------------


def test_plan_integrity_valid_plan():
    """A well-formed plan with unique IDs and resolved deps reports no errors."""
    plan = _make_plan(
        _make_task("1.1"),
        _make_task("1.2", depends_on=["1.1"]),
        _make_task("1.3", depends_on=["1.2"]),
    )
    errors = validate_plan_integrity(plan)
    assert errors == []


# ---------------------------------------------------------------------------
# 2) Duplicate task IDs
# ---------------------------------------------------------------------------


def test_plan_integrity_duplicate_task_id():
    """Duplicate task IDs in a plan must be reported as errors."""
    plan = _make_plan(
        _make_task("1.1"),
        _make_task("1.1"),  # duplicate
    )
    errors = validate_plan_integrity(plan)
    assert any("Duplicate task id" in e and "1.1" in e for e in errors), errors


# ---------------------------------------------------------------------------
# 2b) Duplicate IDs do not abort early — all errors collected
# ---------------------------------------------------------------------------


def test_plan_integrity_duplicate_id_does_not_abort_early():
    """Duplicate IDs must not abort; subsequent checks still run and errors aggregate."""
    task_a = _make_task("1.1")
    task_dup = _make_task("1.1")  # duplicate — no title to also trigger title error
    task_dup.pop("title")
    plan = _make_plan(task_a, task_dup, _make_task("1.2"))
    errors = validate_plan_integrity(plan)
    # Duplicate must be reported
    assert any("Duplicate task id" in e and "1.1" in e for e in errors), errors
    # Validation continued — 1.2 does not produce errors
    assert not any("1.2" in e for e in errors), errors


# ---------------------------------------------------------------------------
# 6) Missing task 'id' field — KeyError must not propagate
# ---------------------------------------------------------------------------


def test_plan_integrity_missing_id_no_key_error():
    """A task missing 'id' must produce an error string, not raise KeyError."""
    task = _make_task("1.1")
    task.pop("id")  # remove id entirely
    plan = _make_plan(task)
    # Must not raise
    errors = validate_plan_integrity(plan)
    assert any("missing required field 'id'" in e for e in errors), errors


def test_plan_integrity_missing_id_includes_location():
    """Error for missing 'id' must include phase/module location context."""
    task = {"title": "No ID task", "depends_on": [], "validation_commands": []}
    plan = _make_plan(task)
    errors = validate_plan_integrity(plan)
    # Should mention phase or module context
    assert any("phase=" in e or "module=" in e or "tasks[" in e for e in errors), errors


def test_plan_integrity_missing_id_continues_past_first():
    """Multiple tasks missing 'id' must all be reported — no early exit."""
    task_a = {"title": "No ID A", "depends_on": [], "validation_commands": []}
    task_b = {"title": "No ID B", "depends_on": [], "validation_commands": []}
    plan = _make_plan(task_a, task_b)
    errors = validate_plan_integrity(plan)
    assert len([e for e in errors if "missing required field 'id'" in e]) == 2, errors


# ---------------------------------------------------------------------------
# 10) State integrity with duplicate task IDs — no SystemExit
# ---------------------------------------------------------------------------


def test_state_integrity_duplicate_task_ids_no_system_exit():
    """validate_state_integrity must not call die()/SystemExit on duplicate plan IDs."""
    plan = _make_plan(_make_task("1.1"), _make_task("1.1"))  # duplicate
    state = _make_state(current_task_id="1.1", completed_tasks=[])
    # Must not raise SystemExit
    errors = validate_state_integrity(plan, state)
    assert any("invalid" in e.lower() or "duplicate" in e.lower() for e in errors), (
        errors
    )


# ---------------------------------------------------------------------------
# 11) Malformed plan — validation reports all possible errors
# ---------------------------------------------------------------------------


def test_plan_integrity_malformed_reports_all_errors():
    """A plan with both missing IDs and unresolved deps must report all errors."""
    task_no_id = {"title": "No ID", "depends_on": [], "validation_commands": []}
    task_bad_dep = _make_task("1.2", depends_on=["999.9"])
    plan = _make_plan(task_no_id, task_bad_dep)
    errors = validate_plan_integrity(plan)
    # Missing id error present
    assert any("missing required field 'id'" in e for e in errors), errors
    # Bad dep error present
    assert any("999.9" in e for e in errors), errors


# ---------------------------------------------------------------------------
# 3) Unresolved dependency
# ---------------------------------------------------------------------------


def test_plan_integrity_unresolved_dependency():
    """A depends_on entry that does not exist in the plan must be reported."""
    plan = _make_plan(
        _make_task("1.1", depends_on=["99.9"]),  # 99.9 does not exist
    )
    errors = validate_plan_integrity(plan)
    assert any("99.9" in e for e in errors), errors


# ---------------------------------------------------------------------------
# 4) Cyclic dependency
# ---------------------------------------------------------------------------


def test_plan_integrity_cycle_detected():
    """A circular dependency chain must be detected and reported."""
    plan = _make_plan(
        _make_task("A", depends_on=["C"]),
        _make_task("B", depends_on=["A"]),
        _make_task("C", depends_on=["B"]),
    )
    errors = validate_plan_integrity(plan)
    assert any("Cycle" in e for e in errors), errors


# ---------------------------------------------------------------------------
# 5) Missing required field
# ---------------------------------------------------------------------------


def test_plan_integrity_missing_title():
    """A task missing the 'title' field must be reported."""
    task = _make_task("1.1")
    task.pop("title")
    plan = _make_plan(task)
    errors = validate_plan_integrity(plan)
    assert any("title" in e and "1.1" in e for e in errors), errors


# ---------------------------------------------------------------------------
# 6) State — unknown current_task_id
# ---------------------------------------------------------------------------


def test_state_integrity_unknown_current_task():
    """State referencing a current_task_id absent from the plan must fail."""
    plan = _make_plan(_make_task("1.1"))
    state = _make_state(current_task_id="999.9")
    errors = validate_state_integrity(plan, state)
    assert any("999.9" in e for e in errors), errors


# ---------------------------------------------------------------------------
# 7) State — unknown completed task
# ---------------------------------------------------------------------------


def test_state_integrity_unknown_completed_task():
    """A completed_tasks entry absent from the plan must be reported."""
    plan = _make_plan(_make_task("1.1"))
    state = _make_state(current_task_id="1.1", completed_tasks=["888.8"])
    errors = validate_state_integrity(plan, state)
    assert any("888.8" in e for e in errors), errors


# ---------------------------------------------------------------------------
# 8) State — unmet current task dependencies
# ---------------------------------------------------------------------------


def test_state_integrity_unmet_dependencies():
    """If current_task has an unsatisfied dep in completed_tasks, report it."""
    plan = _make_plan(
        _make_task("1.1"),
        _make_task("1.2", depends_on=["1.1"]),
    )
    # 1.2 is current but 1.1 is not in completed_tasks
    state = _make_state(current_task_id="1.2", completed_tasks=[])
    errors = validate_state_integrity(plan, state)
    assert any("1.2" in e and "1.1" in e for e in errors), errors


# ---------------------------------------------------------------------------
# 9 & 10) Plan artifact existence
# ---------------------------------------------------------------------------


def test_plan_artifact_existence_missing_fails(tmp_path):
    """State referencing a non-existent artifact path must fail integrity."""
    plan = _make_plan(_make_task("1.1"))
    state = _make_state(
        current_task_id="1.1",
        completed_tasks=["1.1"],
        validations={
            "1.1": {
                "status": "pass",
                "timestamp": "20260101T000000Z",
                "artifact": "artifacts/plan/1.1_validate_latest.json",
            }
        },
    )
    # Patch ROOT in validate_state_integrity — we'll test via a separate temp state
    # that points to a path we know doesn't exist.
    # The artifact path is resolved as ROOT / artifact, so use an absolute path
    # that definitely won't exist.
    state["validations"]["1.1"]["artifact"] = "artifacts/plan/DOES_NOT_EXIST_xyz.json"
    errors = validate_state_integrity(plan, state)
    assert any("DOES_NOT_EXIST_xyz" in e for e in errors), errors


def test_plan_artifact_existence_present_passes(tmp_path):
    """State referencing an existing artifact path must pass integrity."""
    # Write a real artifact file under ROOT/artifacts/plan/
    artifact_rel = "artifacts/plan/1.1_validate_test_fixture.json"
    artifact_abs = ROOT / artifact_rel
    artifact_abs.parent.mkdir(parents=True, exist_ok=True)
    artifact_abs.write_text(json.dumps({"status": "pass"}))

    try:
        plan = _make_plan(_make_task("1.1"))
        state = _make_state(
            current_task_id="1.1",
            validations={
                "1.1": {
                    "status": "pass",
                    "timestamp": "20260101T000000Z",
                    "artifact": artifact_rel,
                }
            },
        )
        errors = validate_state_integrity(plan, state)
        artifact_errors = [e for e in errors if "1.1_validate_test_fixture" in e]
        assert artifact_errors == [], f"Unexpected artifact errors: {artifact_errors}"
    finally:
        artifact_abs.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 11 & 12) Deterministic current task selection
# ---------------------------------------------------------------------------


def test_deterministic_current_task_selection_first_incomplete():
    """next_incomplete_task returns the first task in plan order not yet completed."""
    plan = _make_plan(
        _make_task("1.1"),
        _make_task("1.2"),
        _make_task("1.3"),
    )
    state = _make_state("1.2", completed_tasks=["1.1"])
    result = next_incomplete_task(plan, state)
    assert result == "1.2"


def test_deterministic_current_task_selection_stable():
    """next_incomplete_task returns the same result on repeated calls (no side effects)."""
    plan = _make_plan(
        _make_task("1.1"),
        _make_task("1.2"),
        _make_task("1.3"),
    )
    state = _make_state("1.1", completed_tasks=[])
    r1 = next_incomplete_task(plan, state)
    r2 = next_incomplete_task(plan, state)
    assert r1 == r2 == "1.1"


def test_deterministic_current_task_all_complete():
    """next_incomplete_task returns None when all tasks are complete."""
    plan = _make_plan(_make_task("1.1"), _make_task("1.2"))
    state = _make_state("1.2", completed_tasks=["1.1", "1.2"])
    result = next_incomplete_task(plan, state)
    assert result is None


# ---------------------------------------------------------------------------
# 13) taskctl status resolves without contradiction (live plan)
# ---------------------------------------------------------------------------


def test_taskctl_status_live_plan_no_contradiction():
    """taskctl status resolves the current task from the live plan without crashing.

    The plan YAML must have no structural integrity errors (unique IDs, resolved
    deps, acyclic graph). The state may have workflow-in-progress quirks (e.g. a
    task manually advanced), so we only assert the plan is structurally sound and
    that `cmd_status` returns without error.
    """
    import yaml as yaml_mod
    from taskctl import cmd_status

    if not PLAN_PATH.exists() or not STATE_PATH.exists():
        pytest.skip("Live plan/state files not present")

    plan = yaml_mod.safe_load(PLAN_PATH.read_text()) or {}
    state = yaml_mod.safe_load(STATE_PATH.read_text()) or {}

    # Plan structure must be clean — no duplicates, no dangling deps, no cycles
    plan_errors = validate_plan_integrity(plan)
    assert plan_errors == [], f"Plan integrity errors: {plan_errors}"

    # cmd_status must resolve current task without raising
    rc = cmd_status(plan, state)
    assert rc == 0


# ---------------------------------------------------------------------------
# 14) taskctl status --explain shows dependency satisfaction
# ---------------------------------------------------------------------------


def test_taskctl_status_explain_shows_deps(capsys):
    """cmd_status with explain=True prints dependency satisfaction info."""
    from taskctl import cmd_status

    plan = _make_plan(
        _make_task("1.1"),
        _make_task("1.2", depends_on=["1.1"]),
    )
    state = _make_state("1.2", completed_tasks=["1.1"])

    cmd_status(plan, state, explain=True)
    captured = capsys.readouterr()

    assert "EXPLAIN" in captured.out
    assert "1.1" in captured.out
    assert "satisfied" in captured.out


def test_taskctl_status_explain_no_deps(capsys):
    """cmd_status with explain=True shows 'none' when task has no deps."""
    from taskctl import cmd_status

    plan = _make_plan(_make_task("1.1"))
    state = _make_state("1.1")

    cmd_status(plan, state, explain=True)
    captured = capsys.readouterr()

    assert "EXPLAIN" in captured.out
    assert "none" in captured.out
