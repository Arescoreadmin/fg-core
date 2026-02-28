#!/usr/bin/env python3
"""
guard_pr_fix_log.py — Enforce PR_FIX_LOG writeback for high-risk changes.

Policy:
- If certain "high-risk" paths change, PR must update docs/ai/PR_FIX_LOG.md
  OR include an explicit override marker in PR context (best-effort local).
- This script is CI-first, deterministic, and has no external deps.

Usage:
  python -m tools.ci.guard_pr_fix_log --base origin/main --head HEAD

Exit codes:
  0 = pass
  2 = policy violation
  3 = git/evidence missing
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple


EXIT_POLICY = 2
EXIT_EVIDENCE = 3


HIGH_RISK_PATH_PREFIXES: Tuple[str, ...] = (
    "api/",
    "engine/",
    "services/",
    "migrations/",
    "tools/testing/",
    "tools/ci/",
)

# Files that, if modified, are themselves the memory/log infra and shouldn't self-require a log.
EXEMPT_PATHS: Tuple[str, ...] = (
    "docs/ai/PR_FIX_LOG.md",
    "docs/ai/GOTCHAS.md",
    "docs/ai/runbook.md",
    "CODEX.md",
    "CLAUDE.md",
    "codex_definitions.md",
    "claude_commands.md",
    "claude_pr_review.md",
)

# If any of these paths change, we *always* require PR_FIX_LOG unless explicitly overridden.
ALWAYS_REQUIRE_LOG_IF_TOUCHED: Tuple[str, ...] = (
    "api/auth",
    "api/security",
    "api/db",
    "api/decisions",
    "api/evidence",
    "api/config",
    "services/audit",
    "services/event",
    "migrations/",
)

# Override marker:
# - Preferred in PR body/commit message, but locally we best-effort scan recent commits.
OVERRIDE_MARKER = "NO_FIX_LOG_REQUIRED:"  # must match runbook wording


@dataclass(frozen=True)
class GitChangedFile:
    path: str
    status: str  # e.g., M, A, D, R


def run(cmd: Sequence[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return out
    except subprocess.CalledProcessError as e:
        sys.stderr.write(e.output or "")
        raise


def git_exists() -> bool:
    try:
        run(["git", "rev-parse", "--git-dir"])
        return True
    except Exception:
        return False


def list_changed_files(base: str, head: str) -> List[GitChangedFile]:
    # --name-status gives lines like: "M\tpath" or "R100\told\tnew"
    out = run(["git", "diff", "--name-status", f"{base}...{head}"])
    changed: List[GitChangedFile] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0].strip()
        if status.startswith("R") and len(parts) >= 3:
            path = parts[2].strip()  # new path
            changed.append(GitChangedFile(path=path, status="R"))
        elif len(parts) >= 2:
            path = parts[1].strip()
            changed.append(GitChangedFile(path=path, status=status))
    return changed


def any_path_prefix(path: str, prefixes: Iterable[str]) -> bool:
    return any(path.startswith(p) for p in prefixes)


def touched_any(path: str, needles: Iterable[str]) -> bool:
    # needles can be prefixes or exact-ish fragments; treat as "starts with" for dirs.
    for n in needles:
        if n.endswith("/"):
            if path.startswith(n):
                return True
        else:
            if path.startswith(n):
                return True
    return False


def pr_fix_log_updated(changed: List[GitChangedFile]) -> bool:
    return any(cf.path == "docs/ai/PR_FIX_LOG.md" for cf in changed)


def is_exempt(path: str) -> bool:
    return path in EXEMPT_PATHS


def scan_recent_commit_messages_for_override(base: str, head: str) -> bool:
    # Best-effort: scan commit messages in range for override marker.
    # In GitHub Actions, this still helps; PR body scan is handled in workflow.
    try:
        out = run(["git", "log", "--format=%B", f"{base}..{head}"])
    except Exception:
        return False
    return OVERRIDE_MARKER in out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="Base ref, e.g., origin/main")
    ap.add_argument("--head", required=True, help="Head ref, e.g., HEAD")
    ap.add_argument(
        "--allow-override",
        action="store_true",
        help="Allow override marker NO_FIX_LOG_REQUIRED: in commit messages",
    )
    args = ap.parse_args()

    if not git_exists():
        sys.stderr.write(
            "ERROR: git repo not detected; cannot enforce PR_FIX_LOG policy.\n"
        )
        return EXIT_EVIDENCE

    changed = list_changed_files(args.base, args.head)
    if not changed:
        print("OK: no changes detected.")
        return 0

    # Filter out purely exempt doc edits from "risk".
    non_exempt = [cf for cf in changed if not is_exempt(cf.path)]

    # If only exempt files changed, no need for PR fix log.
    if not non_exempt:
        print("OK: only exempt governance/docs changed.")
        return 0

    # Determine if we have any high-risk changes.
    high_risk = [
        cf for cf in non_exempt if any_path_prefix(cf.path, HIGH_RISK_PATH_PREFIXES)
    ]
    # Additionally enforce always-require list.
    always_require = [
        cf for cf in non_exempt if touched_any(cf.path, ALWAYS_REQUIRE_LOG_IF_TOUCHED)
    ]

    requires_log = bool(high_risk) and (
        bool(always_require) or True
    )  # any high_risk triggers requirement
    # In practice: any high-risk path change requires log (unless overridden).
    # If you want to be looser later, change this.

    if not requires_log:
        print("OK: no high-risk paths changed.")
        return 0

    if pr_fix_log_updated(changed):
        print("OK: PR_FIX_LOG updated.")
        return 0

    if args.allow_override and scan_recent_commit_messages_for_override(
        args.base, args.head
    ):
        print(f"OK: override marker found in commit messages: {OVERRIDE_MARKER}")
        return 0

    # Fail with useful evidence.
    sys.stderr.write(
        "\nBLOCKED: High-risk changes detected but docs/ai/PR_FIX_LOG.md was not updated.\n\n"
    )
    sys.stderr.write("Changed high-risk files:\n")
    for cf in high_risk:
        sys.stderr.write(f"  - {cf.status}\t{cf.path}\n")
    sys.stderr.write("\nRequired action:\n")
    sys.stderr.write("  - Append a structured entry to docs/ai/PR_FIX_LOG.md\n")
    sys.stderr.write("    OR include override marker in PR description:\n")
    sys.stderr.write(f"      {OVERRIDE_MARKER} <one-line reason>\n\n")
    sys.stderr.write(
        "This gate exists to prevent rediscovery and enforce institutional memory.\n\n"
    )
    return EXIT_POLICY


if __name__ == "__main__":
    raise SystemExit(main())
