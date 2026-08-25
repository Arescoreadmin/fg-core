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


def _object_exists(spec: str) -> tuple[bool, str | None]:
    """Return (exists, error_detail). spec: 'sha:path' or 'ref:path'."""
    probe = _run_git(["cat-file", "-e", spec])
    if probe.returncode == 0:
        return True, None
    if probe.returncode == 128:
        return False, None
    return (
        False,
        probe.stderr.strip() or probe.stdout.strip() or "cat-file probe failed",
    )


def _resolve_base_sha(sha: str) -> bool:
    """Return True iff sha resolves to a commit; fetch from origin if needed."""
    result = _run_git(["cat-file", "-t", sha])
    if result.returncode == 0 and result.stdout.strip() == "commit":
        return True
    # Not locally available — attempt a targeted fetch.
    _run_git(["fetch", "origin", sha])
    result2 = _run_git(["cat-file", "-t", sha])
    return result2.returncode == 0 and result2.stdout.strip() == "commit"


def main() -> int:
    base_ref = (os.getenv("GITHUB_BASE_REF") or "").strip()
    is_ci = (os.getenv("CI") or "").strip().lower() in {"1", "true", "yes"}

    if not base_ref:
        # Push events (direct push to main) have no GITHUB_BASE_REF.
        is_push = (os.getenv("GITHUB_EVENT_NAME") or "").strip() == "push"
        if is_ci and not is_push:
            print("pr-base-mainline: FAILED")
            print(" - GITHUB_BASE_REF is missing in CI; cannot validate PR base diff")
            return 1
        print("pr-base-mainline: skipped (no base ref)")
        return 0

    if is_ci:
        # PR CI: require the immutable base SHA supplied by the workflow.
        # github.event.pull_request.base.sha is the commit the PR branched from
        # at creation time — it never moves even if origin/main advances.
        base_sha = (os.getenv("GITHUB_PR_BASE_SHA") or "").strip()
        if not base_sha:
            print("pr-base-mainline: FAILED")
            print(" - GITHUB_PR_BASE_SHA is required in PR CI but is not set.")
            print(
                "   Ensure the workflow passes github.event.pull_request.base.sha"
                " as GITHUB_PR_BASE_SHA."
            )
            return 1

        if not _resolve_base_sha(base_sha):
            print("pr-base-mainline: FAILED")
            print(
                f" - GITHUB_PR_BASE_SHA={base_sha!r} does not resolve to a commit"
                " after fetch."
            )
            return 1

        base_spec = base_sha  # immutable; never races against origin/main

    else:
        # Local / non-CI dev: fetch and use origin/<base_ref> as before.
        fetch = _run_git(["fetch", "origin", base_ref, "--prune"])
        if fetch.returncode != 0:
            print("pr-base-mainline: FAILED")
            print(
                f" - cannot fetch origin/{base_ref}; run local rebase workflow."
                f" Details: {fetch.stderr.strip() or fetch.stdout.strip()}"
            )
            return 1
        base_spec = f"origin/{base_ref}"

    diff = _run_git(["diff", "--name-status", f"{base_spec}...HEAD"])
    if diff.returncode != 0:
        print("pr-base-mainline: FAILED")
        print(
            f" - cannot compute diff {base_spec}...HEAD; run local rebase workflow."
            f" Details: {diff.stderr.strip() or diff.stdout.strip()}"
        )
        return 1

    base_has_file, probe_err = _object_exists(f"{base_spec}:{SOC_REVIEW_PATH}")
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
                f" - {SOC_REVIEW_PATH} is added in PR diff but already exists in"
                f" base {base_spec}."
            )
            print(
                " - Rebase onto latest mainline to avoid re-adding existing SOC"
                " review docs:"
            )
            print("   git remote -v")
            print("   git fetch origin")
            print("   git rebase origin/main")
            print("   git push --force-with-lease")
            return 1

    print("pr-base-mainline: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
