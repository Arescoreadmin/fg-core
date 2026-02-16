#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CRITICAL_PREFIXES = (
    ".github/workflows/",
    "api/security",
    "api/middleware",
    "api/auth",
    "admin_gateway/auth",
    "policy/opa",
    "tools/ci",
)
SOC_DOCS = {
    "docs/SOC_ARCH_REVIEW_2026-02-15.md",
    "docs/SOC_EXECUTION_GATES_2026-02-15.md",
}


def _run_git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=REPO,
        check=False,
        capture_output=True,
        text=True,
    )


def _changed_files_ci(base_ref: str) -> tuple[list[str], str | None]:
    fetch = _run_git(["fetch", "origin", base_ref, "--depth=1"])
    if fetch.returncode != 0:
        return [], f"git fetch failed for origin/{base_ref}: {fetch.stderr.strip() or fetch.stdout.strip()}"

    diff = _run_git(["diff", "--name-only", f"origin/{base_ref}...HEAD"])
    if diff.returncode != 0:
        return [], f"git diff failed for origin/{base_ref}...HEAD: {diff.stderr.strip() or diff.stdout.strip()}"

    files = [line.strip() for line in diff.stdout.splitlines() if line.strip()]
    return sorted(set(files)), None


def _changed_files_local() -> list[str]:
    status = _run_git(["status", "--porcelain"])
    if status.returncode != 0:
        return []

    files: set[str] = set()
    for line in status.stdout.splitlines():
        if not line.strip() or len(line) < 4:
            continue
        path = line[3:].strip()
        if " -> " in path:
            path = path.split(" -> ", 1)[1].strip()
        files.add(path)
    return sorted(files)


def _is_critical(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in CRITICAL_PREFIXES)


def main() -> int:
    base_ref = (os.getenv("GITHUB_BASE_REF") or "").strip()

    if base_ref:
        changed, err = _changed_files_ci(base_ref)
        if err:
            print("soc-review-sync: FAILED")
            print(f"Unable to compute CI diff: {err}")
            return 1
    else:
        changed = _changed_files_local()

    if not changed:
        print("soc-review-sync: no changed files detected")
        return 0

    critical_changed = [p for p in changed if _is_critical(p)]
    docs_changed = any(p in SOC_DOCS for p in changed)

    if critical_changed and not docs_changed:
        print("soc-review-sync: FAILED")
        print("Critical files changed without SOC review update:")
        for p in critical_changed:
            print(f" - {p}")
        return 1

    print("soc-review-sync: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
