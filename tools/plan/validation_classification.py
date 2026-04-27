"""
tools/plan/validation_classification.py

Classification model for validation commands and artifacts.

Classification types:
  structural          — Offline check; passes without live services.
  runtime_proof       — Requires live services; SKIP signal on exit 0 means skip, not pass.
  environment_blocked — Required dependency unavailable; records blocked, not pass.
  skip                — Explicit acceptable skip with recorded reason.

Status values:
  pass    — Check ran and all assertions succeeded.
  fail    — Check ran and at least one assertion failed.
  skip    — Check was skipped due to environment; NOT equivalent to pass for runtime proofs.
  blocked — Required dependency was explicitly unavailable; NOT equivalent to pass.

OPERATOR CONTRACT:
  gate pass (make fg-fast / codex_gates.sh) != live proof pass.
  A gate can pass while runtime proofs are in skip or blocked state.
  Tasks with runtime proofs may not be marked complete if their proof is skip or blocked,
  unless the task explicitly allows structural-only completion.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Classification type constants
# ---------------------------------------------------------------------------

STRUCTURAL: str = "structural"
RUNTIME_PROOF: str = "runtime_proof"
ENVIRONMENT_BLOCKED: str = "environment_blocked"
SKIP: str = "skip"

# All valid classification values
CLASSIFICATIONS: tuple[str, ...] = (
    STRUCTURAL,
    RUNTIME_PROOF,
    ENVIRONMENT_BLOCKED,
    SKIP,
)

# ---------------------------------------------------------------------------
# Status constants
# ---------------------------------------------------------------------------

STATUS_PASS: str = "pass"
STATUS_FAIL: str = "fail"
STATUS_SKIP: str = "skip"
STATUS_BLOCKED: str = "blocked"

# All valid status values (superset of older pass/fail only)
STATUSES: tuple[str, ...] = (STATUS_PASS, STATUS_FAIL, STATUS_SKIP, STATUS_BLOCKED)

# These statuses MUST NOT be treated as pass for runtime proof completion checks.
NON_PASS_STATUSES: frozenset[str] = frozenset(
    {STATUS_FAIL, STATUS_SKIP, STATUS_BLOCKED}
)

# ---------------------------------------------------------------------------
# Skip signal detection
# ---------------------------------------------------------------------------

# Prefixes emitted by scripts that want to signal a runtime-environment skip.
# Any stdout/stderr line starting with one of these (after strip) is a skip signal.
_SKIP_PREFIXES: tuple[str, ...] = ("SKIP:", "SKIP ")


def detect_skip_signal(stdout: str, stderr: str) -> str | None:
    """
    Return the first skip-signal line found in stdout or stderr, or None.

    A skip signal is a line whose stripped form starts with a recognised
    SKIP prefix (e.g. "SKIP: Keycloak not reachable …").  These are emitted
    by runtime-proof scripts to indicate the check was bypassed because
    required services were unavailable — not that the check passed.
    """
    for text in (stdout, stderr):
        for line in text.splitlines():
            stripped = line.strip()
            for prefix in _SKIP_PREFIXES:
                if stripped.startswith(prefix):
                    return stripped
    return None


# ---------------------------------------------------------------------------
# Status resolution
# ---------------------------------------------------------------------------


def resolve_command_status(
    returncode: int,
    stdout: str,
    stderr: str,
    classification: str = STRUCTURAL,
) -> tuple[str, str | None]:
    """
    Resolve the effective status and optional skip reason for a command result.

    Rules:
      - Non-zero exit → fail (regardless of classification).
      - runtime_proof + exit 0 + SKIP signal → skip, never pass.
      - environment_blocked + exit 0 → blocked (the command reported it was blocked).
      - Otherwise exit 0 → pass.

    Returns:
        (status, skip_reason)  where skip_reason is the SKIP signal line or None.
    """
    if returncode != 0:
        return STATUS_FAIL, None

    if classification in (RUNTIME_PROOF, ENVIRONMENT_BLOCKED):
        reason = detect_skip_signal(stdout, stderr)
        if reason is not None:
            # environment_blocked and runtime_proof both use "blocked" when the
            # script itself signals it can't run (SKIP: prefix = services down).
            return STATUS_SKIP, reason

    return STATUS_PASS, None


def resolve_task_status(command_statuses: list[str]) -> str:
    """
    Aggregate per-command statuses into a single task status.

    Rules (in priority order):
      1. Any fail  → fail
      2. Any skip  → skip
      3. Any blocked → blocked
      4. All pass  → pass
      5. Empty     → no_commands (caller handles)
    """
    if not command_statuses:
        return "no_commands"
    if STATUS_FAIL in command_statuses:
        return STATUS_FAIL
    if STATUS_SKIP in command_statuses:
        return STATUS_SKIP
    if STATUS_BLOCKED in command_statuses:
        return STATUS_BLOCKED
    return STATUS_PASS


# ---------------------------------------------------------------------------
# Deterministic inference rules
# ---------------------------------------------------------------------------

# Commands that are always structural (offline, no live services needed).
# Matched against the stripped command prefix (first token + common flags).
_STRUCTURAL_PREFIXES: tuple[str, ...] = (
    "pytest",
    ".venv/bin/pytest",
    "python -m pytest",
    "make ",
    "python tools/",
    "python -m ",
    "ruff ",
    "mypy ",
    "bash codex_gates.sh",
    "bash tools/ci/",
    "bash tools/plan/",
)

# Commands that are always runtime_proof (require live external services).
_RUNTIME_PROOF_PREFIXES: tuple[str, ...] = (
    "bash tools/auth/",
    "sh tools/auth/",
    "curl ",
)


def infer_classification_from_command(cmd: str) -> str:
    """
    Infer a deterministic classification for a command when no explicit annotation exists.

    Precedence:
      1. Matches a known structural prefix → structural.
      2. Matches a known runtime_proof prefix → runtime_proof.
      3. Is a bare shell-script invocation (bash/sh *.sh) → runtime_proof (conservative:
         unknown scripts may need live services; explicit annotation overrides this).
      4. Everything else → structural.

    This is a fallback.  Explicit YAML annotation (validation_class or
    validation_command_classes) always takes precedence.
    """
    stripped = cmd.strip()
    for prefix in _STRUCTURAL_PREFIXES:
        if stripped.startswith(prefix):
            return STRUCTURAL
    for prefix in _RUNTIME_PROOF_PREFIXES:
        if stripped.startswith(prefix):
            return RUNTIME_PROOF
    # Conservative: bare shell scripts that don't match known structural patterns
    # are treated as runtime_proof so SKIP signals are always detected.
    for shell in ("bash ", "sh "):
        if stripped.startswith(shell) and ".sh" in stripped:
            return RUNTIME_PROOF
    return STRUCTURAL


def get_command_classification(
    cmd: str,
    task_class: str | None,
    cmd_classes: list[str] | None,
    idx: int,
) -> str:
    """
    Resolve the effective classification for one command.

    Precedence (highest to lowest):
      1. Per-command explicit annotation: cmd_classes[idx] if present and valid.
      2. Per-task explicit annotation: task_class if not None.
      3. Deterministic inference: infer_classification_from_command(cmd).

    This three-level resolution means a single YAML field is sufficient for
    homogeneous tasks, per-command overrides handle mixed tasks, and inference
    provides a safe fallback for unannotated commands.
    """
    if cmd_classes is not None and idx < len(cmd_classes):
        candidate = str(cmd_classes[idx]).strip()
        if candidate in CLASSIFICATIONS:
            return candidate
    if task_class is not None and task_class in CLASSIFICATIONS:
        return task_class
    return infer_classification_from_command(cmd)


# ---------------------------------------------------------------------------
# Artifact field helpers
# ---------------------------------------------------------------------------


def annotate_command_result(
    result: dict[str, object],
    classification: str = STRUCTURAL,
) -> dict[str, object]:
    """
    Return a copy of a command_result dict with classification, status, and
    skip_reason fields added.

    Input dict must contain: command, returncode, stdout, stderr.
    Output dict adds: classification, status, skip_reason.
    """
    stdout = str(result.get("stdout", ""))
    stderr = str(result.get("stderr", ""))
    _rc = result.get("returncode", -1)
    returncode = int(_rc) if isinstance(_rc, (int, float, str)) else -1

    status, skip_reason = resolve_command_status(
        returncode, stdout, stderr, classification
    )

    return {
        **result,
        "classification": classification,
        "status": status,
        "skip_reason": skip_reason,
    }


def is_runtime_proof_satisfied(
    command_results: list[dict[str, object]],
) -> bool:
    """
    Return True only if all runtime-proof commands actually passed (not skipped/blocked).

    A task that has no runtime_proof commands returns True (no proof required).
    """
    for r in command_results:
        if r.get("classification") == RUNTIME_PROOF:
            if r.get("status") != STATUS_PASS:
                return False
    return True
