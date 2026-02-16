#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SOC_REVIEW_PATH = "docs/SOC_ARCH_REVIEW_2026-02-15.md"


def _run_git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=REPO,
        check=False,
        capture_output=True,
        text=True,
    )


def _base_has_soc_review(base_ref: str) -> tuple[bool, str | None]:
    probe = _run_git(["cat-file", "-e", f"origin/{base_ref}:{SOC_REVIEW_PATH}"])
    if probe.returncode == 0:
        return True, None
    if probe.returncode == 128:
        return False, None
    return False, probe.stderr.strip() or probe.stdout.strip() or "cat-file probe failed"


def main() -> int:
    base_ref = (os.getenv("GITHUB_BASE_REF") or "").strip()
    is_ci = (os.getenv("CI") or "").strip().lower() in {"1", "true", "yes"}

    if not base_ref:
        if is_ci:
            print("pr-base-mainline: FAILED")
            print(" - GITHUB_BASE_REF is missing in CI; cannot validate PR base diff")
            return 1
        print("pr-base-mainline: local mode (no GITHUB_BASE_REF), skipping")
        return 0

    fetch = _run_git(["fetch", "origin", base_ref, "--depth=1"])
    if fetch.returncode != 0:
        print("pr-base-mainline: FAILED")
        print(
            f" - cannot fetch origin/{base_ref}; run local rebase workflow."
            f" Details: {fetch.stderr.strip() or fetch.stdout.strip()}"
        )
        return 1

    diff = _run_git(["diff", "--name-status", f"origin/{base_ref}...HEAD"])
    if diff.returncode != 0:
        print("pr-base-mainline: FAILED")
        print(
            f" - cannot compute diff origin/{base_ref}...HEAD; run local rebase workflow."
            f" Details: {diff.stderr.strip() or diff.stdout.strip()}"
        )
        return 1

    base_has_file, probe_err = _base_has_soc_review(base_ref)
    if probe_err:
        print("pr-base-mainline: FAILED")
        print(f" - unable to verify base tree contains {SOC_REVIEW_PATH}: {probe_err}")
        return 1

    for raw in diff.stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status, path = parts[0], parts[-1]
        if status.startswith("A") and path == SOC_REVIEW_PATH and base_has_file:
            print("pr-base-mainline: FAILED")
            print(
                f" - {SOC_REVIEW_PATH} is added in PR diff but already exists on origin/{base_ref}."
            )
            print(" - Rebase onto latest mainline to avoid re-adding existing SOC review docs:")
            print("   git remote -v")
            print("   git fetch origin")
            print("   git rebase origin/main")
            print("   git push --force-with-lease")
            return 1

    print("pr-base-mainline: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
