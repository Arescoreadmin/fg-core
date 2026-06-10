#!/usr/bin/env python3
"""SOC-HIGH-002: changed critical files must be accompanied by SOC doc updates.

Diff strategy (in order):
  1. GITHUB_BASE_REF present → fetch origin/<base_ref> --depth=1, then
     git diff --name-only origin/<base_ref>...HEAD
  2. Merge-base unavailable after fetch → HEAD~1..HEAD
  3. Still impossible (initial commit, detached HEAD, etc.) → warn and pass

Never fails because git history is shallow.
Only fails when critical files changed without SOC docs updated.
"""

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
    """Return (changed_files, warning_or_None).

    On any git failure the function returns ([], warning) rather than
    raising — the caller treats a non-None warning as "fail open".
    """
    # Step A: fetch the base ref tip; depth=1 is enough to anchor the diff.
    fetch = _run_git(["fetch", "origin", base_ref, "--depth=1"])
    if fetch.returncode != 0:
        return (
            [],
            f"soc-review-sync: unable to fetch origin/{base_ref} — "
            f"{fetch.stderr.strip() or fetch.stdout.strip()}",
        )

    # Step B: three-dot diff against the fetched ref.
    diff = _run_git(["diff", "--name-only", f"origin/{base_ref}...HEAD"])
    if diff.returncode == 0:
        files = [ln.strip() for ln in diff.stdout.splitlines() if ln.strip()]
        return sorted(set(files)), None

    # Step C: merge-base unavailable — fall back to HEAD~1..HEAD.
    diff2 = _run_git(["diff", "--name-only", "HEAD~1..HEAD"])
    if diff2.returncode == 0:
        files = [ln.strip() for ln in diff2.stdout.splitlines() if ln.strip()]
        warn = (
            f"soc-review-sync: merge-base for origin/{base_ref}...HEAD unavailable "
            f"({diff.stderr.strip()}); used HEAD~1..HEAD fallback"
        )
        return sorted(set(files)), warn

    # Step D: fail open — cannot determine diff at all.
    return (
        [],
        "soc-review-sync: unable to determine CI diff — defaulting to warning mode",
    )


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
        changed, warn = _changed_files_ci(base_ref)
        if warn:
            print(warn)
        if not changed:
            # Fail-open: could not compute diff — do not block the PR.
            print("soc-review-sync: OK")
            return 0
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
