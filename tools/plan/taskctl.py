#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import fnmatch
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = ROOT / "plans" / "30_day_repo_blitz.yaml"
STATE_PATH = ROOT / "plans" / "30_day_repo_blitz.state.yaml"
ARTIFACTS_DIR = ROOT / "artifacts" / "plan"


def utc_now_stamp() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")


def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def run_shell(cmd: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        shell=True,
        cwd=str(ROOT),
        text=True,
        capture_output=True,
    )


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        die(f"Missing file: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        die(f"Invalid YAML root in {path}")
    return data


def save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


@dataclasses.dataclass
class TaskRef:
    phase_id: str
    phase_name: str
    module_id: str
    module_name: str
    task_id: str
    task: dict[str, Any]


def flatten_tasks(plan: dict[str, Any]) -> list[TaskRef]:
    out: list[TaskRef] = []
    for phase in plan.get("phases", []):
        for module in phase.get("modules", []):
            for task in module.get("tasks", []):
                out.append(
                    TaskRef(
                        phase_id=str(phase["id"]),
                        phase_name=str(phase["name"]),
                        module_id=str(module["id"]),
                        module_name=str(module["name"]),
                        task_id=str(task["id"]),
                        task=task,
                    )
                )
    return out


def index_tasks(plan: dict[str, Any]) -> dict[str, TaskRef]:
    idx = {}
    for ref in flatten_tasks(plan):
        if ref.task_id in idx:
            die(f"Duplicate task id in plan: {ref.task_id}")
        idx[ref.task_id] = ref
    return idx


def default_state(plan: dict[str, Any]) -> dict[str, Any]:
    tasks = flatten_tasks(plan)
    if not tasks:
        die("Plan contains no tasks")
    return {
        "plan_id": plan.get("plan_id"),
        "version": plan.get("version"),
        "current_task_id": tasks[0].task_id,
        "completed_tasks": [],
        "blocked": False,
        "blocked_reason": None,
        "validations": {},
        "history": [],
    }


def load_state(plan: dict[str, Any]) -> dict[str, Any]:
    if not STATE_PATH.exists():
        state = default_state(plan)
        save_yaml(STATE_PATH, state)
        return state

    state = load_yaml(STATE_PATH)

    changed = False
    defaults = default_state(plan)
    for k, v in defaults.items():
        if k not in state:
            state[k] = v
            changed = True

    if changed:
        save_yaml(STATE_PATH, state)

    return state


def save_state(state: dict[str, Any]) -> None:
    save_yaml(STATE_PATH, state)


def get_current_task(plan: dict[str, Any], state: dict[str, Any]) -> TaskRef:
    idx = index_tasks(plan)
    current_id = state.get("current_task_id")
    if current_id not in idx:
        die(f"Current task id not found in plan: {current_id}")
    return idx[current_id]


def completed_set(state: dict[str, Any]) -> set[str]:
    return set(str(x) for x in state.get("completed_tasks", []))


def ensure_dependencies_done(ref: TaskRef, state: dict[str, Any]) -> None:
    done = completed_set(state)
    missing = [dep for dep in ref.task.get("depends_on", []) if dep not in done]
    if missing:
        die(
            f"Task {ref.task_id} cannot proceed; unmet dependencies: {', '.join(missing)}"
        )


def git_changed_files() -> list[str]:
    files: set[str] = set()

    cmds = [
        "git diff --name-only",
        "git diff --cached --name-only",
        "git ls-files --others --exclude-standard",
    ]

    for cmd in cmds:
        cp = run_shell(cmd)
        if cp.returncode != 0:
            continue
        for line in cp.stdout.splitlines():
            line = line.strip()
            if line:
                files.add(line)

    return sorted(files)


def working_tree_fingerprint() -> str:
    files = git_changed_files()
    h = hashlib.sha256()
    for rel in files:
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        p = ROOT / rel
        if p.exists() and p.is_file():
            try:
                h.update(p.read_bytes())
            except Exception:
                h.update(b"<unreadable>")
        else:
            h.update(b"<missing>")
        h.update(b"\0")
    return h.hexdigest()


def path_matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pat) for pat in patterns)


def enforce_file_guards(ref: TaskRef) -> dict[str, Any]:
    changed = git_changed_files()
    task = ref.task

    allowed_files = [str(x) for x in task.get("allowed_files", [])]
    forbidden_files = [str(x) for x in task.get("forbidden_files", [])]
    max_files_changed = task.get("max_files_changed")
    require_clean = bool(task.get("require_clean_worktree", False))

    errors: list[str] = []

    if require_clean and changed:
        errors.append("Working tree must be clean for this task")

    if max_files_changed is not None and len(changed) > int(max_files_changed):
        errors.append(
            f"Changed file count {len(changed)} exceeds max_files_changed={max_files_changed}"
        )

    if allowed_files:
        outside = [p for p in changed if not path_matches_any(p, allowed_files)]
        if outside:
            errors.append(
                "Changed files outside allowed_files:\n- " + "\n- ".join(outside)
            )

    if forbidden_files:
        hit = [p for p in changed if path_matches_any(p, forbidden_files)]
        if hit:
            errors.append("Forbidden changed files:\n- " + "\n- ".join(hit))

    return {
        "changed_files": changed,
        "allowed_files": allowed_files,
        "forbidden_files": forbidden_files,
        "max_files_changed": max_files_changed,
        "require_clean_worktree": require_clean,
        "errors": errors,
    }


def run_validation(ref: TaskRef, state: dict[str, Any]) -> dict[str, Any]:
    ensure_dependencies_done(ref, state)

    if state.get("blocked"):
        die(f"Task is blocked: {state.get('blocked_reason') or 'no reason provided'}")

    guards = enforce_file_guards(ref)
    if guards["errors"]:
        result = {
            "task_id": ref.task_id,
            "phase_id": ref.phase_id,
            "module_id": ref.module_id,
            "status": "fail",
            "timestamp": utc_now_stamp(),
            "reason": "file_guards_failed",
            "file_guards": guards,
            "command_results": [],
            "working_tree_fingerprint": working_tree_fingerprint(),
        }
        write_validation_artifacts(ref.task_id, result)
        state.setdefault("validations", {})[ref.task_id] = {
            "status": result["status"],
            "timestamp": result["timestamp"],
            "artifact": str(
                (ARTIFACTS_DIR / f"{ref.task_id}_validate_latest.json").relative_to(ROOT)
            ),
            "working_tree_fingerprint": result["working_tree_fingerprint"],
        }
        save_state(state)
        print("Validation failed before commands:\n")
        for err in guards["errors"]:
            print(f"- {err}")
        return result

    command_results: list[dict[str, Any]] = []
    failed = False

    for cmd in ref.task.get("validation_commands", []):
        print(f"\n>>> {cmd}")
        cp = run_shell(str(cmd))
        if cp.stdout:
            print(cp.stdout, end="")
        if cp.stderr:
            print(cp.stderr, end="", file=sys.stderr)

        command_results.append(
            {
                "command": str(cmd),
                "returncode": cp.returncode,
                "stdout": cp.stdout,
                "stderr": cp.stderr,
            }
        )
        if cp.returncode != 0:
            failed = True
            break

    result = {
        "task_id": ref.task_id,
        "phase_id": ref.phase_id,
        "module_id": ref.module_id,
        "status": "pass" if not failed else "fail",
        "timestamp": utc_now_stamp(),
        "file_guards": guards,
        "command_results": command_results,
        "working_tree_fingerprint": working_tree_fingerprint(),
    }

    write_validation_artifacts(ref.task_id, result)

    state.setdefault("validations", {})[ref.task_id] = {
        "status": result["status"],
        "timestamp": result["timestamp"],
        "artifact": str(
            (ARTIFACTS_DIR / f"{ref.task_id}_validate_latest.json").relative_to(ROOT)
        ),
        "working_tree_fingerprint": result["working_tree_fingerprint"],
    }
    save_state(state)

    if result["status"] == "pass":
        print(
            f"\nValidation passed. See artifacts/plan/{ref.task_id}_validate_latest.json"
        )
    else:
        print(
            f"\nValidation failed. See artifacts/plan/{ref.task_id}_validate_latest.json"
        )

    return result


def write_validation_artifacts(task_id: str, result: dict[str, Any]) -> None:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    latest = ARTIFACTS_DIR / f"{task_id}_validate_latest.json"
    stamped = ARTIFACTS_DIR / f"{task_id}_validate_{result['timestamp']}.json"
    payload = json.dumps(result, indent=2, sort_keys=False)
    latest.write_text(payload + "\n", encoding="utf-8")
    stamped.write_text(payload + "\n", encoding="utf-8")


def next_incomplete_task(plan: dict[str, Any], state: dict[str, Any]) -> str | None:
    done = completed_set(state)
    for ref in flatten_tasks(plan):
        if ref.task_id not in done:
            return ref.task_id
    return None


def cmd_status(plan: dict[str, Any], state: dict[str, Any]) -> int:
    ref = get_current_task(plan, state)
    print(f"PHASE: {ref.phase_id}")
    print(f"MODULE: {ref.module_id}")
    print(f"TASK: {ref.task_id}")
    print(f"TITLE: {ref.task.get('title', '')}")
    print(f"BLOCKED: {bool(state.get('blocked'))}")
    if state.get("blocked"):
        print(f"BLOCKED_REASON: {state.get('blocked_reason')}")
    print()

    print("DEFINITION_OF_DONE:")
    for item in ref.task.get("definition_of_done", []):
        print(f"- {item}")
    print()

    print("VALIDATION:")
    for item in ref.task.get("validation", []):
        print(f"- {item}")
    print()

    print("VALIDATION_COMMANDS:")
    for item in ref.task.get("validation_commands", []):
        print(f"- {item}")

    if ref.task.get("allowed_files"):
        print("\nALLOWED_FILES:")
        for item in ref.task.get("allowed_files", []):
            print(f"- {item}")

    if ref.task.get("forbidden_files"):
        print("\nFORBIDDEN_FILES:")
        for item in ref.task.get("forbidden_files", []):
            print(f"- {item}")

    if ref.task.get("max_files_changed") is not None:
        print(f"\nMAX_FILES_CHANGED: {ref.task.get('max_files_changed')}")

    return 0


def cmd_validate(plan: dict[str, Any], state: dict[str, Any]) -> int:
    ref = get_current_task(plan, state)
    result = run_validation(ref, state)
    return 0 if result["status"] == "pass" else 2


def cmd_complete(plan: dict[str, Any], state: dict[str, Any]) -> int:
    ref = get_current_task(plan, state)
    ensure_dependencies_done(ref, state)

    validations = state.get("validations", {})
    v = validations.get(ref.task_id)
    if not v:
        die(f"Cannot complete {ref.task_id}; no validation recorded for current task")

    if v.get("status") != "pass":
        die(f"Cannot complete {ref.task_id}; latest validation did not pass")

    current_fp = working_tree_fingerprint()
    if v.get("working_tree_fingerprint") != current_fp:
        die(
            "Cannot complete task; working tree changed since latest successful validation"
        )

    done = completed_set(state)
    if ref.task_id not in done:
        state.setdefault("completed_tasks", []).append(ref.task_id)

    state.setdefault("history", []).append(
        {
            "event": "complete",
            "task_id": ref.task_id,
            "timestamp": utc_now_stamp(),
        }
    )

    nxt = next_incomplete_task(plan, state)
    if nxt is None:
        state["current_task_id"] = ref.task_id
        save_state(state)
        print(f"Completed {ref.task_id}. Plan is fully complete.")
        return 0

    state["current_task_id"] = nxt
    save_state(state)
    print(f"Completed {ref.task_id}. Advanced to {nxt}.")
    return 0


def cmd_block(plan: dict[str, Any], state: dict[str, Any], reason: str) -> int:
    if not reason.strip():
        die("Block reason is required")
    state["blocked"] = True
    state["blocked_reason"] = reason.strip()
    state.setdefault("history", []).append(
        {
            "event": "block",
            "task_id": state.get("current_task_id"),
            "reason": state["blocked_reason"],
            "timestamp": utc_now_stamp(),
        }
    )
    save_state(state)
    print(f"Blocked {state.get('current_task_id')}: {state['blocked_reason']}")
    return 0


def cmd_unblock(plan: dict[str, Any], state: dict[str, Any]) -> int:
    state["blocked"] = False
    state["blocked_reason"] = None
    state.setdefault("history", []).append(
        {
            "event": "unblock",
            "task_id": state.get("current_task_id"),
            "timestamp": utc_now_stamp(),
        }
    )
    save_state(state)
    print(f"Unblocked {state.get('current_task_id')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="FrostGate task plan controller")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Show current phase/module/task")
    sub.add_parser("validate", help="Run validation_commands for current task")
    sub.add_parser("complete", help="Mark current task complete and advance")

    p_block = sub.add_parser("block", help="Block current task with reason")
    p_block.add_argument("reason", help="Human-readable block reason")

    sub.add_parser("unblock", help="Clear blocked state")
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    plan = load_yaml(PLAN_PATH)
    state = load_state(plan)

    match args.command:
        case "status":
            return cmd_status(plan, state)
        case "validate":
            return cmd_validate(plan, state)
        case "complete":
            return cmd_complete(plan, state)
        case "block":
            return cmd_block(plan, state, args.reason)
        case "unblock":
            return cmd_unblock(plan, state)
        case _:
            die(f"Unknown command: {args.command}")
            return 1


if __name__ == "__main__":
    raise SystemExit(main())