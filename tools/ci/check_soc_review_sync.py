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


def _repo_is_shallow() -> bool:
    probe = _run_git(["rev-parse", "--is-shallow-repository"])
    return probe.returncode == 0 and probe.stdout.strip().lower() == "true"


def _has_merge_base(base_ref: str) -> bool:
    mb = _run_git(["merge-base", f"origin/{base_ref}", "HEAD"])
    return mb.returncode == 0


def _ensure_merge_base(base_ref: str) -> str | None:
    # Initial base fetch from CI base ref.
    initial_fetch = _run_git(["fetch", "origin", base_ref, "--depth=200"])
    if initial_fetch.returncode != 0:
        return (
            f"git fetch failed for origin/{base_ref}: "
            f"{initial_fetch.stderr.strip() or initial_fetch.stdout.strip()}"
        )

    if _has_merge_base(base_ref):
        return None

    # If repository is shallow, progressively deepen to recover merge base.
    if _repo_is_shallow():
        for depth in (200, 400, 800, 1600):
            deepen = _run_git(["fetch", "--deepen", str(depth), "origin"])
            if deepen.returncode != 0:
                return (
                    "failed to deepen git history while searching for merge base: "
                    f"{deepen.stderr.strip() or deepen.stdout.strip()}"
                )
            if _has_merge_base(base_ref):
                return None

        unshallow = _run_git(["fetch", "--unshallow", "origin"])
        if unshallow.returncode == 0 and _has_merge_base(base_ref):
            return None

    return f"no merge base between origin/{base_ref} and HEAD"


def _changed_files_ci(base_ref: str) -> tuple[list[str], str | None]:
    merge_base_err = _ensure_merge_base(base_ref)
    if merge_base_err:
        return [], merge_base_err

    diff = _run_git(["diff", "--name-only", f"origin/{base_ref}...HEAD"])
    if diff.returncode != 0:
        return (
            [],
            f"git diff failed for origin/{base_ref}...HEAD: "
            f"{diff.stderr.strip() or diff.stdout.strip()}",
        )

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
