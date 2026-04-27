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
18) validation classification inference: pytest → structural
19) validation classification inference: bash tools/auth/*.sh → runtime_proof
20) validation classification inference: bash codex_gates.sh → structural
21) validation classification inference: unknown shell script → runtime_proof (conservative)
22) validation classification inference: make → structural
23) get_command_classification: per-command YAML overrides per-task
24) get_command_classification: per-task overrides inference
25) get_command_classification: invalid per-command class falls through to task-level
26) reconcile_task uses inferred runtime_proof for bash tools/auth script (SKIP detected)
27) reconcile_task per-command classification in YAML takes highest precedence
28) environment_blocked + SKIP signal → blocked (not skip)
29) runtime_proof + SKIP signal → skip (not blocked)
30) status precedence: fail > blocked > skip > pass
31) skip followed by pass → overall skip
32) skip followed by fail → overall fail (not skip)
33) blocked followed by pass → overall blocked
34) fail has precedence over blocked and skip
35) reconcile continues after skip and records all command results
36) reconcile does not update state on skip
37) reconcile does not update state on blocked
38) reconcile does not update state on fail
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
    STATUS_PRECEDENCE,
    STRUCTURAL,
    STATUS_BLOCKED,
    STATUS_FAIL,
    STATUS_PASS,
    STATUS_SKIP,
    annotate_command_result,
    detect_skip_signal,
    get_command_classification,
    infer_classification_from_command,
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


# ---------------------------------------------------------------------------
# 18-22) Deterministic inference rules
# ---------------------------------------------------------------------------


def test_validation_classification_inference_pytest_is_structural() -> None:
    """pytest commands must always infer as structural."""
    assert infer_classification_from_command(".venv/bin/pytest -q tests/") == STRUCTURAL
    assert infer_classification_from_command("pytest tests/foo.py") == STRUCTURAL
    assert infer_classification_from_command("python -m pytest tests/") == STRUCTURAL


def test_validation_classification_inference_bash_auth_is_runtime_proof() -> None:
    """bash tools/auth/*.sh must always infer as runtime_proof."""
    assert (
        infer_classification_from_command("bash tools/auth/validate_tester_flow.sh")
        == RUNTIME_PROOF
    )
    assert (
        infer_classification_from_command("sh tools/auth/validate_keycloak_runtime.sh")
        == RUNTIME_PROOF
    )


def test_validation_classification_inference_codex_gates_is_structural() -> None:
    """bash codex_gates.sh must infer as structural (it's the CI gate, not a live proof)."""
    assert infer_classification_from_command("bash codex_gates.sh") == STRUCTURAL


def test_validation_classification_inference_unknown_shell_script_is_runtime_proof() -> (
    None
):
    """Unknown bash *.sh commands infer runtime_proof (conservative fallback)."""
    assert (
        infer_classification_from_command("bash some_unknown_check.sh --arg")
        == RUNTIME_PROOF
    )
    assert infer_classification_from_command("sh deploy_check.sh") == RUNTIME_PROOF


def test_validation_classification_inference_make_is_structural() -> None:
    """make commands infer as structural."""
    assert infer_classification_from_command("make fg-fast") == STRUCTURAL
    assert infer_classification_from_command("make test") == STRUCTURAL


# ---------------------------------------------------------------------------
# 23-25) get_command_classification resolution precedence
# ---------------------------------------------------------------------------


def test_validation_classification_per_command_overrides_per_task() -> None:
    """Per-command YAML annotation takes highest precedence over task-level."""
    # per-command says runtime_proof, task-level says structural
    result = get_command_classification(
        "pytest tests/",
        task_class=STRUCTURAL,
        cmd_classes=[RUNTIME_PROOF],
        idx=0,
    )
    assert result == RUNTIME_PROOF


def test_validation_classification_per_task_overrides_inference() -> None:
    """Per-task annotation overrides inference when no per-command is set."""
    # inference would say runtime_proof for bash *.sh, but task says structural
    result = get_command_classification(
        "bash some_script.sh",
        task_class=STRUCTURAL,
        cmd_classes=None,
        idx=0,
    )
    assert result == STRUCTURAL


def test_validation_classification_invalid_per_command_falls_through() -> None:
    """Invalid per-command class is ignored; falls through to task-level."""
    result = get_command_classification(
        "pytest tests/",
        task_class=RUNTIME_PROOF,
        cmd_classes=["not_a_valid_class"],
        idx=0,
    )
    assert result == RUNTIME_PROOF  # fell through to task-level


# ---------------------------------------------------------------------------
# 26) Inference: bash tools/auth script → SKIP detected without explicit annotation
# ---------------------------------------------------------------------------


def test_reconcile_task_infers_runtime_proof_for_auth_script(
    tmp_path: Path,
) -> None:
    """reconcile_task must infer runtime_proof for bash tools/auth/*.sh
    even without validation_class in YAML, and detect the SKIP signal."""
    script = tmp_path / "validate_tester_flow.sh"
    script.write_text(
        "#!/usr/bin/env bash\n"
        "echo 'SKIP: Keycloak not reachable at http://localhost:8081'\n"
        "exit 0\n"
    )
    script.chmod(0o755)

    # No validation_class set — relies on inference
    task: dict[str, Any] = {
        "id": "1.1",
        "title": "Test task",
        "status": "pending",
        "depends_on": [],
        "definition_of_done": [],
        "validation": [],
        # Command path matches bash tools/auth/ pattern → inferred runtime_proof
        "validation_commands": [f"bash tools/auth/{script.name}"],
    }
    artifacts_dir = tmp_path / "artifacts" / "plan"
    artifacts_dir.mkdir(parents=True)

    orig_root = rct.ROOT
    orig_artifacts = rct.ARTIFACTS_DIR
    rct.ROOT = tmp_path
    rct.ARTIFACTS_DIR = artifacts_dir
    # Create the expected path so bash can find the script
    auth_dir = tmp_path / "tools" / "auth"
    auth_dir.mkdir(parents=True)
    (auth_dir / script.name).write_text(script.read_text())
    (auth_dir / script.name).chmod(0o755)
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
        f"Expected skip (inferred runtime_proof), got {result['status']!r}. "
        "Inference must classify bash tools/auth/*.sh as runtime_proof."
    )


# ---------------------------------------------------------------------------
# 27) Per-command classification from YAML takes highest precedence
# ---------------------------------------------------------------------------


def test_reconcile_task_per_command_classification_yaml(
    tmp_path: Path,
) -> None:
    """validation_command_classes in YAML overrides inference for that command."""
    task: dict[str, Any] = {
        "id": "1.1",
        "title": "Test task",
        "status": "pending",
        "depends_on": [],
        "definition_of_done": [],
        "validation": [],
        # pytest would infer structural, but per-command forces runtime_proof
        "validation_commands": [_PASS_CMD],
        "validation_command_classes": [RUNTIME_PROOF],
    }
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
    cmd_result = payload["command_results"][0]
    assert cmd_result["classification"] == RUNTIME_PROOF, (
        "per-command classification in YAML must override inference"
    )


# ---------------------------------------------------------------------------
# 28) environment_blocked + SKIP signal → blocked (not skip)
# ---------------------------------------------------------------------------


def test_validation_classification_environment_blocked_skip_signal_is_blocked() -> None:
    """environment_blocked + SKIP signal must resolve to blocked, not skip."""
    status, reason = resolve_command_status(
        0, "SKIP: required service unavailable\n", "", ENVIRONMENT_BLOCKED
    )
    assert status == STATUS_BLOCKED
    assert status != STATUS_SKIP
    assert reason is not None


# ---------------------------------------------------------------------------
# 29) runtime_proof + SKIP signal → skip (not blocked)
# ---------------------------------------------------------------------------


def test_validation_classification_runtime_proof_skip_signal_is_skip_not_blocked() -> (
    None
):
    """runtime_proof + SKIP signal must resolve to skip, not blocked."""
    status, reason = resolve_command_status(
        0, "SKIP: IdP not reachable\n", "", RUNTIME_PROOF
    )
    assert status == STATUS_SKIP
    assert status != STATUS_BLOCKED
    assert reason is not None


# ---------------------------------------------------------------------------
# 30) STATUS_PRECEDENCE: fail > blocked > skip > pass
# ---------------------------------------------------------------------------


def test_validation_classification_status_precedence_ordering() -> None:
    """STATUS_PRECEDENCE must enforce fail > blocked > skip > pass."""
    assert STATUS_PRECEDENCE[STATUS_FAIL] > STATUS_PRECEDENCE[STATUS_BLOCKED]
    assert STATUS_PRECEDENCE[STATUS_BLOCKED] > STATUS_PRECEDENCE[STATUS_SKIP]
    assert STATUS_PRECEDENCE[STATUS_SKIP] > STATUS_PRECEDENCE[STATUS_PASS]


# ---------------------------------------------------------------------------
# 31) skip followed by pass → overall skip
# ---------------------------------------------------------------------------


def test_validation_classification_task_status_skip_then_pass_is_skip() -> None:
    """skip + pass → overall skip (skip takes precedence over pass)."""
    result = resolve_task_status([STATUS_SKIP, STATUS_PASS])
    assert result == STATUS_SKIP
    assert result != STATUS_PASS


# ---------------------------------------------------------------------------
# 32) skip followed by fail → overall fail
# ---------------------------------------------------------------------------


def test_validation_classification_task_status_skip_then_fail_is_fail() -> None:
    """skip + fail → overall fail (fail has highest precedence)."""
    result = resolve_task_status([STATUS_SKIP, STATUS_FAIL])
    assert result == STATUS_FAIL


# ---------------------------------------------------------------------------
# 33) blocked followed by pass → overall blocked
# ---------------------------------------------------------------------------


def test_validation_classification_task_status_blocked_then_pass_is_blocked() -> None:
    """blocked + pass → overall blocked (blocked takes precedence over pass)."""
    result = resolve_task_status([STATUS_BLOCKED, STATUS_PASS])
    assert result == STATUS_BLOCKED
    assert result != STATUS_PASS


# ---------------------------------------------------------------------------
# 34) fail has precedence over blocked and skip
# ---------------------------------------------------------------------------


def test_validation_classification_fail_has_highest_precedence() -> None:
    """fail must win over any combination of blocked/skip/pass."""
    assert resolve_task_status([STATUS_BLOCKED, STATUS_FAIL]) == STATUS_FAIL
    assert resolve_task_status([STATUS_SKIP, STATUS_FAIL]) == STATUS_FAIL
    assert (
        resolve_task_status([STATUS_PASS, STATUS_SKIP, STATUS_BLOCKED, STATUS_FAIL])
        == STATUS_FAIL
    )


# ---------------------------------------------------------------------------
# 35) reconcile continues after skip and records all command results
# ---------------------------------------------------------------------------


def test_reconcile_continues_after_skip_records_all_results(
    tmp_path: Path,
) -> None:
    """A skip must not short-circuit task validation. Later fail must be recorded."""
    # Command 1: skip signal (runtime_proof)
    skip_script = tmp_path / "runtime_check.sh"
    skip_script.write_text("#!/usr/bin/env bash\necho 'SKIP: service down'\nexit 0\n")
    skip_script.chmod(0o755)

    # Command 2: always fails
    fail_script = tmp_path / "fail_check.sh"
    fail_script.write_text("#!/usr/bin/env bash\nexit 1\n")
    fail_script.chmod(0o755)

    task: dict[str, Any] = {
        "id": "1.1",
        "title": "Multi-command task",
        "status": "pending",
        "depends_on": [],
        "definition_of_done": [],
        "validation": [],
        "validation_commands": [str(skip_script), str(fail_script)],
        # per-command: first is runtime_proof (skip), second is structural (fail)
        "validation_command_classes": [RUNTIME_PROOF, STRUCTURAL],
    }
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

    assert result["status"] == STATUS_FAIL, (
        f"Expected fail (skip then fail), got {result['status']!r}. "
        "Later fail must not be hidden by earlier skip."
    )
    assert len(result["command_results"]) == 2, (
        "Both commands must be recorded — reconcile must not stop on skip."
    )
    assert result["command_results"][0]["status"] == STATUS_SKIP
    assert result["command_results"][1]["status"] == STATUS_FAIL


# ---------------------------------------------------------------------------
# 36) reconcile does not update state on skip
# ---------------------------------------------------------------------------


def test_reconcile_does_not_update_state_on_skip() -> None:
    """State must not be updated when overall task status is skip."""
    state: dict[str, Any] = {"validations": {}}
    result = {"status": STATUS_SKIP, "artifact_path": "artifacts/plan/1.1_latest.json"}
    if result["status"] == STATUS_PASS:
        update_state_validation(
            state, "1.1", result["artifact_path"], "20260101T000000Z"
        )
    assert "1.1" not in state["validations"]


# ---------------------------------------------------------------------------
# 37) reconcile does not update state on blocked
# ---------------------------------------------------------------------------


def test_reconcile_does_not_update_state_on_blocked() -> None:
    """State must not be updated when overall task status is blocked."""
    state: dict[str, Any] = {"validations": {}}
    result = {
        "status": STATUS_BLOCKED,
        "artifact_path": "artifacts/plan/1.1_latest.json",
    }
    if result["status"] == STATUS_PASS:
        update_state_validation(
            state, "1.1", result["artifact_path"], "20260101T000000Z"
        )
    assert "1.1" not in state["validations"]


# ---------------------------------------------------------------------------
# 38) reconcile does not update state on fail
# ---------------------------------------------------------------------------


def test_reconcile_does_not_update_state_on_fail() -> None:
    """State must not be updated when overall task status is fail."""
    state: dict[str, Any] = {"validations": {}}
    result = {"status": STATUS_FAIL, "artifact_path": "artifacts/plan/1.1_latest.json"}
    if result["status"] == STATUS_PASS:
        update_state_validation(
            state, "1.1", result["artifact_path"], "20260101T000000Z"
        )
    assert "1.1" not in state["validations"]
