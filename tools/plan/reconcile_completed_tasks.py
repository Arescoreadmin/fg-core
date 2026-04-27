#!/usr/bin/env python3
"""
tools/plan/reconcile_completed_tasks.py

Validate every task marked complete in plans/30_day_repo_blitz.state.yaml
by re-running its validation_commands and generating/repairing validation
artifacts so that `taskctl integrity` becomes truthful again.

This is NOT artifact fabrication.
Every artifact produced here reflects a real command execution result.

Usage:
    python tools/plan/reconcile_completed_tasks.py --all
    python tools/plan/reconcile_completed_tasks.py --task 15.2
    python tools/plan/reconcile_completed_tasks.py --all --dry-run
    python tools/plan/reconcile_completed_tasks.py --all --continue-on-fail
    python tools/plan/reconcile_completed_tasks.py --all --no-write-state

Exit codes:
    0 — all selected tasks reconciled (pass)
    1 — one or more validation commands failed
    2 — plan/state/tooling error (missing task, corrupt YAML, etc.)
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

yaml = importlib.import_module("yaml")

# Ensure tools/plan is importable (sibling modules)
_TOOLS_PLAN = str(Path(__file__).resolve().parent)
if _TOOLS_PLAN not in sys.path:
    sys.path.insert(0, _TOOLS_PLAN)

from validation_classification import (  # noqa: E402
    STRUCTURAL,
    STATUS_PASS,
    STATUS_FAIL,
    STATUS_SKIP,
    STATUS_BLOCKED,
    annotate_command_result,
    get_command_classification,
    resolve_task_status,
)

ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = ROOT / "plans" / "30_day_repo_blitz.yaml"
STATE_PATH = ROOT / "plans" / "30_day_repo_blitz.state.yaml"
ARTIFACTS_DIR = ROOT / "artifacts" / "plan"
GENERATED_BY = "tools/plan/reconcile_completed_tasks.py"

# Maximum bytes of stdout/stderr tail stored per command
_OUTPUT_TAIL = 8_192


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        _die(f"File not found: {path}", code=2)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        _die(f"Invalid YAML root in {path}", code=2)
    return data


def _save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def _die(msg: str, code: int = 2) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def _utc_stamp() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")


# ---------------------------------------------------------------------------
# Plan helpers
# ---------------------------------------------------------------------------


def _build_task_index(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return task_id → task dict (no die on duplicates — report only)."""
    idx: dict[str, dict[str, Any]] = {}
    for phase in plan.get("phases", []) or []:
        if not isinstance(phase, dict):
            continue
        for module in phase.get("modules", []) or []:
            if not isinstance(module, dict):
                continue
            for task in module.get("tasks", []) or []:
                if not isinstance(task, dict):
                    continue
                tid = task.get("id")
                if tid and str(tid) not in idx:
                    idx[str(tid)] = task
    return idx


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------


def _git_commit() -> str:
    cp = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    return cp.stdout.strip() if cp.returncode == 0 else "unknown"


def _is_dirty() -> bool:
    cp = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    return bool(cp.stdout.strip()) if cp.returncode == 0 else False


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------


def _run_command(cmd: str) -> dict[str, Any]:
    """Run a single shell command, return result dict."""
    start = time.monotonic()
    cp = subprocess.run(
        cmd,
        shell=True,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    elapsed = time.monotonic() - start

    def _tail(text: str) -> str:
        if len(text.encode()) <= _OUTPUT_TAIL:
            return text
        return "[truncated]\n" + text[-_OUTPUT_TAIL:]

    return {
        "command": cmd,
        "returncode": cp.returncode,
        "stdout": _tail(cp.stdout),
        "stderr": _tail(cp.stderr),
        "duration_seconds": round(elapsed, 3),
    }


# ---------------------------------------------------------------------------
# Artifact generation
# ---------------------------------------------------------------------------


def _write_artifact(task_id: str, payload: dict[str, Any]) -> Path:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    latest = ARTIFACTS_DIR / f"{task_id}_validate_latest.json"
    stamped = ARTIFACTS_DIR / f"{task_id}_validate_{payload['timestamp']}.json"
    text = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    latest.write_text(text, encoding="utf-8")
    stamped.write_text(text, encoding="utf-8")
    return latest


# ---------------------------------------------------------------------------
# Single-task reconciliation
# ---------------------------------------------------------------------------


def reconcile_task(
    task_id: str,
    task: dict[str, Any],
    *,
    dry_run: bool,
    git_commit: str,
    dirty: bool,
    verbose: bool = True,
) -> dict[str, Any]:
    """Run validation_commands for one task and return a result dict.

    Returns:
        {
          "task_id": str,
          "title": str,
          "status": "pass" | "fail" | "skip" | "blocked" | "no_commands" | "dry_run" | "error",
          "artifact_path": str | None,  (relative to ROOT)
          "command_results": list[dict],
          "error": str | None,
        }

    Safety:
    - Never returns status="pass" if any command failed.
    - Never returns status="pass" if any runtime-proof command emitted a SKIP signal.
    - Never writes an artifact on dry_run.
    - Never marks no_commands as pass.
    - skip and blocked are never treated as pass for state updates.
    """
    title = task.get("title", "")
    cmds = [str(c) for c in (task.get("validation_commands") or [])]
    # Per-task classification — tasks may declare validation_class: runtime_proof.
    # None means "not explicitly set" — falls through to inference.
    raw_task_class = task.get("validation_class")
    task_classification: str | None = (
        str(raw_task_class) if raw_task_class is not None else None
    )
    # Per-command classification overrides — parallel list to validation_commands.
    # If absent, per-task or inferred classification is used per command.
    raw_cmd_classes = task.get("validation_command_classes")
    cmd_classes: list[str] | None = (
        [str(c) for c in raw_cmd_classes] if raw_cmd_classes else None
    )

    if verbose:
        print(f"\n{'=' * 60}")
        print(f"TASK {task_id}: {title}")
        print(f"{'=' * 60}")

    if not cmds:
        if verbose:
            print(f"  [SKIP] No validation_commands defined for {task_id!r}")
        return {
            "task_id": task_id,
            "title": title,
            "status": "no_commands",
            "artifact_path": None,
            "command_results": [],
            "error": f"Task {task_id!r} has no validation_commands — cannot reconcile",
        }

    if dry_run:
        if verbose:
            print(f"  [DRY-RUN] Would run {len(cmds)} command(s):")
            for cmd in cmds:
                print(f"    $ {cmd}")
        return {
            "task_id": task_id,
            "title": title,
            "status": "dry_run",
            "artifact_path": None,
            "command_results": [],
            "error": None,
        }

    command_results: list[dict[str, Any]] = []

    for idx, cmd in enumerate(cmds):
        if verbose:
            print(f"\n  >>> {cmd}")
        raw = _run_command(cmd)
        # Resolve classification: per-command YAML > per-task YAML > inferred.
        cmd_class = get_command_classification(
            cmd, task_classification, cmd_classes, idx
        )
        # Annotate with resolved classification + status (detects SKIP signals).
        result = annotate_command_result(raw, cmd_class)
        command_results.append(result)
        if result["stdout"] and verbose:
            print(result["stdout"], end="")
        if result["stderr"] and verbose:
            print(result["stderr"], end="", file=sys.stderr)
        if result["status"] == STATUS_FAIL:
            if verbose:
                print(
                    f"  [FAIL] Command exited {result['returncode']}: {cmd}",
                    file=sys.stderr,
                )
            break  # fail-fast per task
        if result["status"] == STATUS_SKIP:
            if verbose:
                reason = result.get("skip_reason") or "SKIP signal detected"
                print(
                    f"  [SKIP] Runtime proof skipped (not pass): {reason}",
                    file=sys.stderr,
                )
            break  # skip propagates immediately

    cmd_statuses = [str(r["status"]) for r in command_results]
    status = resolve_task_status(cmd_statuses) if cmd_statuses else "no_commands"
    timestamp = _utc_stamp()

    # Top-level classification: explicit task annotation if set, otherwise
    # "mixed" when commands have different inferred classifications, else the
    # single inferred classification.
    cmd_classes_used = [
        str(r.get("classification", STRUCTURAL)) for r in command_results
    ]
    if task_classification is not None:
        artifact_classification: str = task_classification
    elif len(set(cmd_classes_used)) == 1:
        artifact_classification = cmd_classes_used[0]
    else:
        artifact_classification = "mixed"

    artifact_payload: dict[str, Any] = {
        "task_id": task_id,
        "title": title,
        "status": status,
        "classification": artifact_classification,
        "timestamp": timestamp,
        "validation_commands": cmds,
        "command_results": command_results,
        "repo_git_commit": git_commit,
        "dirty_working_tree": dirty,
        "generated_by": GENERATED_BY,
    }

    artifact_path = _write_artifact(task_id, artifact_payload)
    rel_path = str(artifact_path.relative_to(ROOT))

    if verbose:
        icon = {
            STATUS_PASS: "PASS",
            STATUS_FAIL: "FAIL",
            STATUS_SKIP: "SKIP",
            STATUS_BLOCKED: "BLOCKED",
        }.get(status, status.upper())
        print(f"\n  [{icon}] artifact: {rel_path}")

    return {
        "task_id": task_id,
        "title": title,
        "status": status,
        "artifact_path": rel_path,
        "command_results": command_results,
        "error": None,
    }


# ---------------------------------------------------------------------------
# State update
# ---------------------------------------------------------------------------


def update_state_validation(
    state: dict[str, Any],
    task_id: str,
    artifact_rel: str,
    timestamp: str,
) -> None:
    """Update state.validations for a task that passed. Never called on failure."""
    state.setdefault("validations", {})[task_id] = {
        "status": "pass",
        "timestamp": timestamp,
        "artifact": artifact_rel,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def _print_report(results: list[dict[str, Any]]) -> None:
    print("\n" + "=" * 60)
    print("RECONCILIATION REPORT")
    print("=" * 60)

    categories: dict[str, list[str]] = {
        "pass": [],
        "fail": [],
        "skip": [],
        "blocked": [],
        "no_commands": [],
        "dry_run": [],
        "error": [],
    }
    for r in results:
        categories.setdefault(r["status"], []).append(r["task_id"])

    for status, ids in categories.items():
        if ids:
            print(f"  {status.upper():<14} {', '.join(ids)}")

    total = len(results)
    passed = len(categories["pass"]) + len(categories["dry_run"])
    skipped = len(categories["skip"]) + len(categories["blocked"])
    print(
        f"\n  Total: {total}  Pass: {passed}  Fail: {len(categories['fail'])}"
        f"  Skip/Blocked: {skipped}  No-commands: {len(categories['no_commands'])}"
    )
    if skipped:
        print(
            "  NOTE: skip/blocked != pass. "
            "Runtime proof evidence is absent for skipped/blocked tasks."
        )
    print("=" * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Reconcile completed tasks: re-run validation_commands and repair artifacts.",
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--all", action="store_true", help="Reconcile all completed tasks"
    )
    group.add_argument("--task", metavar="TASK_ID", help="Reconcile one specific task")

    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would run without writing artifacts or state",
    )
    p.add_argument(
        "--no-write-state",
        action="store_true",
        help="Generate artifacts but do not update state YAML",
    )
    p.add_argument(
        "--continue-on-fail",
        action="store_true",
        help="Continue reconciling remaining tasks after a failure",
    )
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    plan = _load_yaml(PLAN_PATH)
    state = _load_yaml(STATE_PATH)

    task_index = _build_task_index(plan)
    completed: list[str] = [str(t) for t in state.get("completed_tasks", [])]

    # Determine which tasks to reconcile
    if args.task:
        if args.task not in completed:
            _die(
                f"Task {args.task!r} is not in state.completed_tasks — "
                f"only completed tasks can be reconciled",
                code=2,
            )
        targets = [args.task]
    else:
        targets = list(completed)

    if not targets:
        print("No completed tasks to reconcile.")
        return 0

    git_commit = _git_commit()
    dirty = _is_dirty()

    print(f"Reconciling {len(targets)} task(s) | commit={git_commit} dirty={dirty}")

    results: list[dict[str, Any]] = []
    any_fail = False
    any_tooling_error = False

    for task_id in targets:
        if task_id not in task_index:
            msg = f"Task {task_id!r} is in completed_tasks but not found in plan"
            print(f"\n  [ERROR] {msg}", file=sys.stderr)
            results.append(
                {
                    "task_id": task_id,
                    "title": "",
                    "status": "error",
                    "artifact_path": None,
                    "command_results": [],
                    "error": msg,
                }
            )
            any_tooling_error = True
            if not args.continue_on_fail:
                break
            continue

        task = task_index[task_id]
        result = reconcile_task(
            task_id,
            task,
            dry_run=args.dry_run,
            git_commit=git_commit,
            dirty=dirty,
        )
        results.append(result)

        if result["status"] == STATUS_FAIL:
            any_fail = True
            if not args.continue_on_fail:
                # Still print report for what ran so far
                break

        if result["status"] in (STATUS_SKIP, STATUS_BLOCKED):
            # skip/blocked are not failures but also not passes.
            # Do not update state — runtime proof was not completed.
            any_tooling_error = True
            if not args.continue_on_fail:
                break
            continue

        if result["status"] == "no_commands":
            any_tooling_error = True

        # Update state only for genuine pass results — never for skip/blocked/fail
        if (
            result["status"] == STATUS_PASS
            and not args.dry_run
            and not args.no_write_state
        ):
            # Read timestamp from artifact file rather than re-generating
            artifact_abs = ROOT / result["artifact_path"]
            ts = _utc_stamp()
            try:
                payload = json.loads(artifact_abs.read_text(encoding="utf-8"))
                ts = payload.get("timestamp", ts)
            except Exception:
                pass
            update_state_validation(state, task_id, result["artifact_path"], ts)
            _save_yaml(STATE_PATH, state)

    _print_report(results)

    if any_tooling_error:
        return 2
    if any_fail:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
