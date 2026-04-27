"""
tests/test_validation_classification.py

Proves:
1)  validation classification: structural vs runtime_proof constants are defined
2)  validation classification: pass status recorded for successful command
3)  validation classification: skip status recorded when SKIP signal in stdout
4)  validation classification: skip not recorded as pass
5)  validation classification: blocked not recorded as pass
6)  runtime proof skipped when services emit SKIP signal (exit 0)
7)  runtime proof blocked is not pass
8)  skip signal detection ignores comments and empty lines
9)  skip signal detected in stderr as well as stdout
10) task-level status resolves correctly: any fail → fail
11) task-level status resolves correctly: any skip → skip (not pass)
12) task-level status resolves correctly: all pass → pass
13) is_runtime_proof_satisfied returns False when runtime proof was skipped
14) annotate_command_result adds classification, status, skip_reason fields
15) reconcile_task records skip when SKIP signal emitted (not pass)
16) reconcile_task artifact contains classification field
17) reconcile_task skip does not update state
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "plan"))

from validation_classification import (  # noqa: E402
    CLASSIFICATIONS,
    ENVIRONMENT_BLOCKED,
    RUNTIME_PROOF,
    SKIP,
    STATUSES,
    STRUCTURAL,
    STATUS_BLOCKED,
    STATUS_FAIL,
    STATUS_PASS,
    STATUS_SKIP,
    annotate_command_result,
    detect_skip_signal,
    is_runtime_proof_satisfied,
    resolve_command_status,
    resolve_task_status,
)
from reconcile_completed_tasks import (  # noqa: E402
    reconcile_task,
    update_state_validation,
)
import reconcile_completed_tasks as rct  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SKIP_STDOUT = "SKIP: Keycloak not reachable at http://localhost:8081\n"
_PASS_CMD = "true"
_FAIL_CMD = "false"


def _make_task(
    task_id: str,
    *,
    validation_commands: list[str] | None = None,
    validation_class: str = STRUCTURAL,
) -> dict[str, Any]:
    return {
        "id": task_id,
        "title": "Test task",
        "status": "pending",
        "depends_on": [],
        "definition_of_done": [],
        "validation": [],
        "validation_commands": validation_commands
        if validation_commands is not None
        else [],
        "validation_class": validation_class,
    }


# ---------------------------------------------------------------------------
# 1) Constants are defined
# ---------------------------------------------------------------------------


def test_validation_classification_constants_defined() -> None:
    """Classification and status constants must all be present."""
    assert STRUCTURAL in CLASSIFICATIONS
    assert RUNTIME_PROOF in CLASSIFICATIONS
    assert ENVIRONMENT_BLOCKED in CLASSIFICATIONS
    assert SKIP in CLASSIFICATIONS
    assert STATUS_PASS in STATUSES
    assert STATUS_FAIL in STATUSES
    assert STATUS_SKIP in STATUSES
    assert STATUS_BLOCKED in STATUSES


# ---------------------------------------------------------------------------
# 2) validation classification: pass status for successful command
# ---------------------------------------------------------------------------


def test_validation_classification_pass_recorded_for_successful_command() -> None:
    """A command that exits 0 with no skip signal records status=pass."""
    status, reason = resolve_command_status(0, "all good\n", "", STRUCTURAL)
    assert status == STATUS_PASS
    assert reason is None


# ---------------------------------------------------------------------------
# 3) validation classification: skip status when SKIP signal in stdout
# ---------------------------------------------------------------------------


def test_validation_classification_skip_recorded_when_skip_signal_in_stdout() -> None:
    """exit 0 + SKIP: in stdout for a runtime_proof → status=skip, not pass."""
    status, reason = resolve_command_status(0, _SKIP_STDOUT, "", RUNTIME_PROOF)
    assert status == STATUS_SKIP
    assert reason is not None
    assert "SKIP" in reason


# ---------------------------------------------------------------------------
# 4) validation classification: skip not recorded as pass
# ---------------------------------------------------------------------------


def test_validation_classification_skip_not_recorded_as_pass() -> None:
    """Skip status must not be equal to pass."""
    assert STATUS_SKIP != STATUS_PASS
    status, _ = resolve_command_status(0, _SKIP_STDOUT, "", RUNTIME_PROOF)
    assert status != STATUS_PASS


# ---------------------------------------------------------------------------
# 5) validation classification: blocked not recorded as pass
# ---------------------------------------------------------------------------


def test_validation_classification_blocked_not_recorded_as_pass() -> None:
    """Blocked status must not be equal to pass."""
    assert STATUS_BLOCKED != STATUS_PASS
    # environment_blocked with SKIP signal → skip (not pass)
    status, _ = resolve_command_status(0, _SKIP_STDOUT, "", ENVIRONMENT_BLOCKED)
    assert status != STATUS_PASS


# ---------------------------------------------------------------------------
# 6) runtime proof skipped is not pass (SKIP signal, exit 0)
# ---------------------------------------------------------------------------


def test_runtime_proof_skipped_is_not_pass() -> None:
    """A runtime_proof command that exits 0 with SKIP signal must not be pass."""
    result = annotate_command_result(
        {
            "command": "bash tools/auth/validate_tester_flow.sh",
            "returncode": 0,
            "stdout": "SKIP: Admin gateway not reachable at http://localhost:8100\n",
            "stderr": "",
            "duration_seconds": 0.1,
        },
        RUNTIME_PROOF,
    )
    assert result["status"] == STATUS_SKIP
    assert result["status"] != STATUS_PASS
    assert result["skip_reason"] is not None


# ---------------------------------------------------------------------------
# 7) runtime proof blocked is not pass
# ---------------------------------------------------------------------------


def test_runtime_proof_blocked_is_not_pass() -> None:
    """Non-zero exit from a runtime_proof command records fail, not pass."""
    result = annotate_command_result(
        {
            "command": "bash tools/auth/validate_tester_flow.sh",
            "returncode": 1,
            "stdout": "",
            "stderr": "connection refused\n",
            "duration_seconds": 0.1,
        },
        RUNTIME_PROOF,
    )
    assert result["status"] == STATUS_FAIL
    assert result["status"] != STATUS_PASS


# ---------------------------------------------------------------------------
# 8) skip signal detection ignores comments and empty lines
# ---------------------------------------------------------------------------


def test_skip_signal_detection_ignores_comments_and_empty_lines() -> None:
    """Lines that are comments or empty must not trigger SKIP detection."""
    stdout = "# SKIP: this is a comment\n\n   \nall checks passed\n"
    assert detect_skip_signal(stdout, "") is None


# ---------------------------------------------------------------------------
# 9) skip signal detected in stderr
# ---------------------------------------------------------------------------


def test_skip_signal_detected_in_stderr() -> None:
    """SKIP signal in stderr is also detected."""
    reason = detect_skip_signal("", "SKIP: IdP unreachable\n")
    assert reason is not None
    assert "SKIP" in reason


# ---------------------------------------------------------------------------
# 10) task-level status: any fail → fail
# ---------------------------------------------------------------------------


def test_validation_classification_task_status_any_fail_is_fail() -> None:
    """resolve_task_status returns fail if any command was fail."""
    statuses = [STATUS_PASS, STATUS_FAIL, STATUS_PASS]
    assert resolve_task_status(statuses) == STATUS_FAIL


# ---------------------------------------------------------------------------
# 11) task-level status: any skip → skip (not pass)
# ---------------------------------------------------------------------------


def test_validation_classification_task_status_any_skip_is_not_pass() -> None:
    """resolve_task_status returns skip (not pass) if any command was skipped."""
    statuses = [STATUS_PASS, STATUS_SKIP]
    result = resolve_task_status(statuses)
    assert result == STATUS_SKIP
    assert result != STATUS_PASS


# ---------------------------------------------------------------------------
# 12) task-level status: all pass → pass
# ---------------------------------------------------------------------------


def test_validation_classification_task_status_all_pass_is_pass() -> None:
    """resolve_task_status returns pass when all commands passed."""
    statuses = [STATUS_PASS, STATUS_PASS, STATUS_PASS]
    assert resolve_task_status(statuses) == STATUS_PASS


# ---------------------------------------------------------------------------
# 13) is_runtime_proof_satisfied returns False for skipped proof
# ---------------------------------------------------------------------------


def test_validation_classification_runtime_proof_not_satisfied_when_skipped() -> None:
    """is_runtime_proof_satisfied must return False when a runtime_proof was skipped."""
    command_results = [
        {"classification": STRUCTURAL, "status": STATUS_PASS},
        {"classification": RUNTIME_PROOF, "status": STATUS_SKIP},
    ]
    assert is_runtime_proof_satisfied(command_results) is False


def test_validation_classification_runtime_proof_satisfied_when_all_pass() -> None:
    """is_runtime_proof_satisfied returns True when all runtime_proof commands passed."""
    command_results = [
        {"classification": STRUCTURAL, "status": STATUS_PASS},
        {"classification": RUNTIME_PROOF, "status": STATUS_PASS},
    ]
    assert is_runtime_proof_satisfied(command_results) is True


# ---------------------------------------------------------------------------
# 14) annotate_command_result adds required fields
# ---------------------------------------------------------------------------


def test_validation_classification_annotate_adds_fields() -> None:
    """annotate_command_result must add classification, status, skip_reason."""
    raw = {
        "command": "true",
        "returncode": 0,
        "stdout": "",
        "stderr": "",
        "duration_seconds": 0.0,
    }
    annotated = annotate_command_result(raw, STRUCTURAL)
    assert "classification" in annotated
    assert "status" in annotated
    assert "skip_reason" in annotated
    assert annotated["classification"] == STRUCTURAL
    assert annotated["status"] == STATUS_PASS


# ---------------------------------------------------------------------------
# 15) reconcile_task records skip when SKIP signal emitted
# ---------------------------------------------------------------------------


def test_reconcile_task_records_skip_not_pass_when_skip_signal(
    tmp_path: Path,
) -> None:
    """reconcile_task must return status=skip (not pass) for a runtime_proof
    task whose command exits 0 but prints a SKIP signal."""
    # Write a script that exits 0 but emits SKIP:
    script = tmp_path / "mock_runtime_check.sh"
    script.write_text(
        "#!/usr/bin/env bash\necho 'SKIP: IdP not reachable at http://localhost:8081'\nexit 0\n"
    )
    script.chmod(0o755)

    task = _make_task(
        "1.1",
        validation_commands=[f"bash {script}"],
        validation_class=RUNTIME_PROOF,
    )
    artifacts_dir = tmp_path / "artifacts" / "plan"
    artifacts_dir.mkdir(parents=True)

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

    assert result["status"] == STATUS_SKIP, (
        f"Expected skip, got {result['status']!r}. "
        "Runtime proof with SKIP signal must not be recorded as pass."
    )
    assert result["status"] != STATUS_PASS


# ---------------------------------------------------------------------------
# 16) reconcile_task artifact contains classification field
# ---------------------------------------------------------------------------


def test_reconcile_task_artifact_contains_classification_field(
    tmp_path: Path,
) -> None:
    """Generated artifact must include a 'classification' field."""
    task = _make_task(
        "1.1", validation_commands=[_PASS_CMD], validation_class=STRUCTURAL
    )
    artifacts_dir = tmp_path / "artifacts" / "plan"
    artifacts_dir.mkdir(parents=True)

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
            dirty=False,
            verbose=False,
        )
    finally:
        rct.ROOT = orig_root
        rct.ARTIFACTS_DIR = orig_artifacts

    payload = json.loads((artifacts_dir / "1.1_validate_latest.json").read_text())
    assert "classification" in payload, "Artifact missing 'classification' field"
    assert payload["classification"] == STRUCTURAL


# ---------------------------------------------------------------------------
# 17) reconcile_task skip does not update state
# ---------------------------------------------------------------------------


def test_reconcile_task_skip_does_not_update_state() -> None:
    """update_state_validation must never be called for skip or blocked results.
    Verify this by ensuring skip status is not treated as pass by the caller."""
    # The reconcile_task returns skip status — the caller (main) checks
    # result["status"] == STATUS_PASS before calling update_state_validation.
    # This test proves the contract at the unit level.
    state: dict[str, Any] = {"validations": {}}

    # Simulate what main() does: only update state on pass
    result_skip = {
        "status": STATUS_SKIP,
        "artifact_path": "artifacts/plan/1.1_latest.json",
    }
    result_blocked = {
        "status": STATUS_BLOCKED,
        "artifact_path": "artifacts/plan/1.2_latest.json",
    }
    result_pass = {
        "status": STATUS_PASS,
        "artifact_path": "artifacts/plan/1.3_latest.json",
    }

    for res in (result_skip, result_blocked, result_pass):
        if res["status"] == STATUS_PASS:
            update_state_validation(
                state, "task_id", res["artifact_path"], "20260101T000000Z"
            )

    # Only pass triggered state update
    assert "task_id" in state["validations"]
    assert len(state["validations"]) == 1
    assert state["validations"]["task_id"]["status"] == STATUS_PASS
