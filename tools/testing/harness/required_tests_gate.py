#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
POLICY_DIR = REPO_ROOT / "tools/testing/policy"


@dataclass(frozen=True)
class ChangedFile:
    status: str
    path: str
    previous_path: str | None = None


@dataclass(frozen=True)
class GateFailure:
    category: str
    reason: str
    next_command: str


def _json_dumps(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"invalid policy format: {path}")
    return data


def _run_git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=REPO_ROOT, check=False, text=True, capture_output=True)


def _resolve_diff_range(base_ref: str | None, base_sha: str | None, head_sha: str | None) -> tuple[str, str]:
    if base_sha and head_sha:
        return base_sha, head_sha

    if base_ref:
        _run_git(["git", "fetch", "origin", base_ref, "--depth=200"])

    mb = _run_git(["git", "merge-base", "origin/main", "HEAD"])
    if mb.returncode == 0 and mb.stdout.strip():
        return mb.stdout.strip(), "HEAD"

    mb_local = _run_git(["git", "merge-base", "main", "HEAD"])
    if mb_local.returncode == 0 and mb_local.stdout.strip():
        return mb_local.stdout.strip(), "HEAD"

    return "HEAD~1", "HEAD"


def _event_pr_shas() -> tuple[str | None, str | None]:
    event_path = (os.getenv("GITHUB_EVENT_PATH") or "").strip()
    if not event_path:
        return None, None
    path = Path(event_path)
    if not path.exists():
        return None, None
    payload = json.loads(path.read_text(encoding="utf-8"))
    pr = payload.get("pull_request")
    if not isinstance(pr, dict):
        return None, None
    base_sha = pr.get("base", {}).get("sha") if isinstance(pr.get("base"), dict) else None
    head_sha = pr.get("head", {}).get("sha") if isinstance(pr.get("head"), dict) else None
    if isinstance(base_sha, str) and isinstance(head_sha, str):
        return base_sha, head_sha
    return None, None


def _parse_name_status(diff_text: str) -> list[ChangedFile]:
    changed: list[ChangedFile] = []
    for raw in diff_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split("\t")
        status = parts[0]
        code = status[0]
        if code == "R" and len(parts) >= 3:
            changed.append(ChangedFile(status=status, path=parts[2], previous_path=parts[1]))
        elif code in {"A", "M", "T", "C"} and len(parts) >= 2:
            changed.append(ChangedFile(status=status, path=parts[1]))
        elif code == "D" and len(parts) >= 2:
            # deletions are tracked for report only; do not trigger required test updates
            changed.append(ChangedFile(status=status, path=parts[1]))
    return sorted(changed, key=lambda x: (x.path, x.status, x.previous_path or ""))


def _changed_files(base_ref: str | None) -> list[ChangedFile]:
    event_base_sha, event_head_sha = _event_pr_shas()
    base, head = _resolve_diff_range(base_ref, event_base_sha, event_head_sha)

    result = _run_git(["git", "diff", "--name-status", "--find-renames", f"{base}...{head}"])
    if result.returncode != 0:
        raise SystemExit("unable to compute changed files with --name-status; fail-closed")
    return _parse_name_status(result.stdout)


def _match_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def _category_input_paths(changed: list[ChangedFile]) -> list[str]:
    paths: list[str] = []
    for item in changed:
        if item.status.startswith("D"):
            continue
        paths.append(item.path)
        if item.previous_path:
            paths.append(item.previous_path)
    return sorted(set(paths))


def _required_categories(changed_paths: list[str], ownership: dict[str, Any]) -> set[str]:
    required: set[str] = set()
    for owner in ownership.get("owners", []):
        path_globs = owner.get("path_globs", [])
        if any(_match_any(path, path_globs) for path in changed_paths):
            required.update(owner.get("required_categories", []))
    return required


def _detect_new_modules(changed_paths: list[str]) -> list[str]:
    modules: list[str] = []
    for path in changed_paths:
        p = Path(path)
        if len(p.parts) >= 2 and p.parts[0] == "services" and p.parts[1].endswith("_extension"):
            modules.append(p.parts[1])
    return sorted(set(modules))


def _verify_required_tests_changed(changed_paths: list[str], required: set[str], policy: dict[str, Any]) -> list[GateFailure]:
    failures: list[GateFailure] = []
    categories = policy.get("categories", {})
    for category in sorted(required):
        patterns = categories.get(category, {}).get("required_test_globs", [])
        if not patterns:
            failures.append(
                GateFailure(
                    category=category,
                    reason=f"category {category} missing required_test_globs policy",
                    next_command="python tools/testing/harness/required_tests_gate.py --explain",
                )
            )
            continue
        if not any(_match_any(path, patterns) for path in changed_paths):
            failures.append(
                GateFailure(
                    category=category,
                    reason=f"missing test updates for category={category}",
                    next_command=f"git diff --name-status --find-renames | sort && make fg-{category if category != 'unit' else 'fast'}",
                )
            )
    return failures


def _verify_module_registration(changed_paths: list[str], new_modules: list[str], policy: dict[str, Any]) -> list[GateFailure]:
    failures: list[GateFailure] = []
    registration = policy.get("module_registration", {})
    required_registry = registration.get("registry_files", [])
    required_skeleton = registration.get("required_skeleton_globs", [])
    changed_set = set(changed_paths)

    if new_modules:
        for file_path in required_registry:
            if file_path not in changed_set:
                failures.append(
                    GateFailure(
                        category="module-registration",
                        reason=f"new module requires policy update: {file_path}",
                        next_command=f"git add {file_path}",
                    )
                )

    for module_id in new_modules:
        for skeleton in required_skeleton:
            expected = skeleton.format(module_id=module_id)
            if expected not in changed_set:
                failures.append(
                    GateFailure(
                        category="module-onboarding",
                        reason=f"new module {module_id} missing skeleton test: {expected}",
                        next_command=f"python tools/dev/new_spine_module.py --module-id {module_id} --plane control",
                    )
                )

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail-closed required-tests gate")
    parser.add_argument("--base-ref", default=None)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--explain", action="store_true")
    args = parser.parse_args()

    ownership = _load_yaml(POLICY_DIR / "ownership_map.yaml")
    required_tests = _load_yaml(POLICY_DIR / "required_tests.yaml")
    changed = _changed_files(args.base_ref)
    changed_paths = _category_input_paths(changed)

    categories = _required_categories(changed_paths, ownership)
    new_modules = _detect_new_modules(changed_paths)

    failures = []
    failures.extend(_verify_required_tests_changed(changed_paths, categories, required_tests))
    failures.extend(_verify_module_registration(changed_paths, new_modules, required_tests))

    report = {
        "changed_files": [{"status": c.status, "path": c.path, "previous_path": c.previous_path} for c in changed],
        "required_categories": sorted(categories),
        "new_modules": new_modules,
        "failures": [failure.__dict__ for failure in failures],
    }

    if args.explain or args.json:
        print(_json_dumps(report))

    if failures:
        for failure in failures:
            print(f"[FAIL][{failure.category}] {failure.reason}")
            print(f"  next: {failure.next_command}")
        return 1

    print("required-tests gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
