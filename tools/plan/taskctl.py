#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception as e:  # pragma: no cover
    print(
        "ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr
    )
    raise

ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = ROOT / "plans" / "30_day_repo_blitz.yaml"
STATE_PATH = ROOT / "plans" / "30_day_repo_blitz.state.yaml"
ARTIFACTS_DIR = ROOT / "artifacts" / "plan"


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"Missing file: {path}")
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data or {}


def save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)


def build_indexes(
    plan: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, str], list[str]]:
    task_index: dict[str, Any] = {}
    module_by_task: dict[str, str] = {}
    ordered_task_ids: list[str] = []
    for phase in plan.get("phases", []):
        for module in phase.get("modules", []):
            module_id = module["id"]
            for task in module.get("tasks", []):
                task_id = task["id"]
                task_index[task_id] = task
                module_by_task[task_id] = module_id
                ordered_task_ids.append(task_id)
    return task_index, module_by_task, ordered_task_ids


def find_phase_for_module(plan: dict[str, Any], module_id: str) -> str:
    for phase in plan.get("phases", []):
        for module in phase.get("modules", []):
            if module.get("id") == module_id:
                return phase.get("id", "")
    return ""


def find_next_task_id(ordered_task_ids: list[str], current_task_id: str) -> str:
    try:
        idx = ordered_task_ids.index(current_task_id)
    except ValueError:
        return ""
    return ordered_task_ids[idx + 1] if idx + 1 < len(ordered_task_ids) else ""


def get_current(
    plan: dict[str, Any], state: dict[str, Any]
) -> tuple[dict[str, Any], str, str]:
    task_index, module_by_task, ordered_task_ids = build_indexes(plan)
    current_task_id = state.get("current_task_id")
    if not current_task_id:
        raise SystemExit("Missing current_task_id in state file.")
    task = task_index.get(current_task_id)
    if not task:
        raise SystemExit(f"Task not found in plan: {current_task_id}")
    module_id = module_by_task[current_task_id]
    phase_id = find_phase_for_module(plan, module_id)
    return task, module_id, phase_id


def status_cmd(args: argparse.Namespace) -> int:
    plan = load_yaml(PLAN_PATH)
    state = load_yaml(STATE_PATH)
    task, module_id, phase_id = get_current(plan, state)

    print(f"PHASE: {phase_id}")
    print(f"MODULE: {module_id}")
    print(f"TASK: {task['id']}")
    print(f"TITLE: {task.get('title', '')}")
    print(f"BLOCKED: {state.get('blocked', False)}")
    if state.get("blocked"):
        print(f"BLOCKER_REASON: {state.get('blocker_reason', '')}")

    for key in ("definition_of_done", "validation", "validation_commands"):
        values = task.get(key, [])
        if values:
            print(f"\n{key.upper()}:")
            for item in values:
                print(f"- {item}")
    return 0


def validate_cmd(args: argparse.Namespace) -> int:
    plan = load_yaml(PLAN_PATH)
    state = load_yaml(STATE_PATH)
    task, _, _ = get_current(plan, state)

    commands = task.get("validation_commands", [])
    if not commands:
        print(
            "No validation_commands defined for current task.\n"
            "Add validation_commands in plans/30_day_repo_blitz.yaml to use automated validation.",
            file=sys.stderr,
        )
        return 2

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    log_path = ARTIFACTS_DIR / f"{task['id']}_validate_{stamp}.log"
    summary_path = ARTIFACTS_DIR / f"{task['id']}_validate_latest.json"

    failures: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    with log_path.open("w", encoding="utf-8") as log:
        for command in commands:
            print(f"\n>>> {command}")
            log.write(f"\n>>> {command}\n")
            proc = subprocess.run(
                command,
                shell=True,
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            if proc.stdout:
                print(proc.stdout, end="")
                log.write(proc.stdout)
            if proc.stderr:
                print(proc.stderr, end="", file=sys.stderr)
                log.write(proc.stderr)

            result = {
                "command": command,
                "returncode": proc.returncode,
            }
            results.append(result)
            if proc.returncode != 0:
                failures.append(result)

    summary = {
        "task_id": task["id"],
        "validated_at_utc": stamp,
        "log_path": str(log_path.relative_to(ROOT)),
        "results": results,
        "success": not failures,
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if failures:
        print(
            f"\nValidation failed. See {summary_path.relative_to(ROOT)}",
            file=sys.stderr,
        )
        return 1

    print(f"\nValidation passed. See {summary_path.relative_to(ROOT)}")
    return 0


def complete_cmd(args: argparse.Namespace) -> int:
    plan = load_yaml(PLAN_PATH)
    state = load_yaml(STATE_PATH)
    task_index, module_by_task, ordered_task_ids = build_indexes(plan)

    current_task_id = state.get("current_task_id")
    if not current_task_id or current_task_id not in task_index:
        raise SystemExit("Current task missing or invalid in state file.")

    # Require latest validation artifact when asked.
    if args.require_validation:
        latest = ARTIFACTS_DIR / f"{current_task_id}_validate_latest.json"
        if not latest.exists():
            raise SystemExit(
                f"Cannot complete {current_task_id}: missing validation artifact {latest.relative_to(ROOT)}"
            )
        summary = json.loads(latest.read_text(encoding="utf-8"))
        if not summary.get("success"):
            raise SystemExit(
                f"Cannot complete {current_task_id}: latest validation did not pass."
            )

    # Mark task done in plan.
    for phase in plan.get("phases", []):
        for module in phase.get("modules", []):
            for task in module.get("tasks", []):
                if task.get("id") == current_task_id:
                    task["status"] = "done"

    completed_tasks = state.setdefault("completed_tasks", [])
    if current_task_id not in completed_tasks:
        completed_tasks.append(current_task_id)

    state["last_completed_task_id"] = current_task_id
    state["blocked"] = False
    state["blocker_reason"] = ""
    state["notes"] = args.notes or state.get("notes", "")

    next_task_id = find_next_task_id(ordered_task_ids, current_task_id)
    state["current_task_id"] = next_task_id or ""
    if next_task_id:
        next_module_id = module_by_task[next_task_id]
        state["current_module_id"] = next_module_id
        state["current_phase_id"] = find_phase_for_module(plan, next_module_id)
    state["last_updated"] = dt.date.today().isoformat()

    save_yaml(PLAN_PATH, plan)
    save_yaml(STATE_PATH, state)

    print(f"Completed {current_task_id}")
    if next_task_id:
        print(f"Advanced to {next_task_id}")
    else:
        print("Plan complete")
    return 0


def block_cmd(args: argparse.Namespace) -> int:
    if not args.reason.strip():
        raise SystemExit("Block reason is required.")
    state = load_yaml(STATE_PATH)
    state["blocked"] = True
    state["blocker_reason"] = args.reason.strip()
    state["last_updated"] = dt.date.today().isoformat()
    save_yaml(STATE_PATH, state)
    print(f"Blocked current task: {state.get('current_task_id', '')}")
    return 0


def unblock_cmd(args: argparse.Namespace) -> int:
    state = load_yaml(STATE_PATH)
    state["blocked"] = False
    state["blocker_reason"] = ""
    state["last_updated"] = dt.date.today().isoformat()
    save_yaml(STATE_PATH, state)
    print(f"Unblocked current task: {state.get('current_task_id', '')}")
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="FrostGate task plan controller")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="Show current phase/module/task")

    sub.add_parser("validate", help="Run validation_commands for current task")

    c = sub.add_parser("complete", help="Mark current task complete and advance")
    c.add_argument(
        "--require-validation",
        action="store_true",
        help="Require latest validation artifact to pass",
    )
    c.add_argument("--notes", default="", help="Optional completion notes")

    b = sub.add_parser("block", help="Block current task with reason")
    b.add_argument("reason", help="Concrete blocker reason")

    sub.add_parser("unblock", help="Clear blocked state")
    return p


def main() -> int:
    args = parser().parse_args()
    if args.cmd == "status":
        return status_cmd(args)
    if args.cmd == "validate":
        return validate_cmd(args)
    if args.cmd == "complete":
        return complete_cmd(args)
    if args.cmd == "block":
        return block_cmd(args)
    if args.cmd == "unblock":
        return unblock_cmd(args)
    raise SystemExit("Unknown command")


if __name__ == "__main__":
    raise SystemExit(main())
