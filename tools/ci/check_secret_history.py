"""
tools/ci/check_secret_history.py

Git-history audit for known-leaked credentials.

Behaviour
---------
- Scans the git log for every literal in BLOCKED_LITERALS.
- Prints the commit hash, date, and subject for every matching commit.
- FAILS (exit 1) if any blocked literal is found anywhere in the current
  working tree (belt-and-suspenders — check_no_plaintext_secrets.py also
  does this for env files, this catches the whole tree).
- WARNS but does NOT fail when the literal is found only in history (the
  secret has already been removed from HEAD, but rotation is still required).

Rationale for warn-not-fail on history
---------------------------------------
Rewriting git history is a destructive, coordinated operation that cannot be
done in-band with a normal PR gate.  Blocking CI indefinitely because the
credential exists in old commits would be counter-productive.  The correct
response is external rotation (which this script demands), not blocking CI.

Exit codes
----------
  0  no violations in current working tree (historical presence → warning only)
  1  blocked literal found in current working tree (must remove before merging)
  2  git not available or repository not found
"""

from __future__ import annotations

import subprocess
import sys
import os as _os
from pathlib import Path

# ---------------------------------------------------------------------------
# Blocked literals — must match tools/ci/check_no_plaintext_secrets.py
# ---------------------------------------------------------------------------
BLOCKED_LITERALS: list[str] = [
    "VD_6zx6nD4JJg3APEhNVAIBPSlqlGQao",  # postgres password — confirmed leaked
]

# Paths that are permitted to reference a blocked literal for audit/tracking
# purposes (scanner source itself, incident post-mortems, fix logs).
# These are NOT exempted from history scanning — only from the HEAD grep.
EXEMPT_PATHS: frozenset[str] = frozenset(
    {
        "tools/ci/check_no_plaintext_secrets.py",
        "tools/ci/check_secret_history.py",
        "docs/ai/PR_FIX_LOG.md",
    }
)

# How many recent commits to scan in history (0 = full history).
# Full history is O(n) on repo size; the default is kept at 0 because the
# repo is small.  Operators may override via HISTORY_DEPTH env var.
_HISTORY_DEPTH: int = int(_os.environ.get("HISTORY_DEPTH", "0"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def _git_available(repo_root: Path) -> bool:
    result = _run("git", "rev-parse", "--git-dir", cwd=repo_root)
    return result.returncode == 0


def _head_contains(literal: str, repo_root: Path) -> list[str]:
    """Return non-exempt repo-relative paths that contain *literal* in HEAD."""
    result = _run(
        "git",
        "grep",
        "--fixed-strings",
        "-l",
        "--",
        literal,
        cwd=repo_root,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return []
    found = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return [p for p in found if p not in EXEMPT_PATHS]


def _history_commits(literal: str, repo_root: Path) -> list[str]:
    """Return formatted commit lines where *literal* was introduced or removed."""
    depth_args: list[str] = []
    if _HISTORY_DEPTH > 0:
        depth_args = [f"-{_HISTORY_DEPTH}"]

    result = _run(
        "git",
        "log",
        "--all",
        *depth_args,
        f"-S{literal}",
        "--format=%H %as %s",
        cwd=repo_root,
    )
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]

    if not _git_available(repo_root):
        print(
            "check_secret_history: git not available or not a git repo — skipping",
            file=sys.stderr,
        )
        return 2

    head_violations: dict[str, list[str]] = {}  # literal → [paths]
    history_hits: dict[str, list[str]] = {}  # literal → [commit lines]

    for literal in BLOCKED_LITERALS:
        paths = _head_contains(literal, repo_root)
        if paths:
            head_violations[literal] = paths

        commits = _history_commits(literal, repo_root)
        if commits:
            history_hits[literal] = commits

    # ---- Report current-HEAD violations (hard failure) --------------------
    if head_violations:
        print("FAIL: known-leaked credentials found in current HEAD:", file=sys.stderr)
        for literal, paths in head_violations.items():
            short = literal[:8] + "..."
            for p in paths:
                print(f"  {p}: contains blocked literal {short!r}", file=sys.stderr)
        print(
            "\nRemove the credential from all listed files and replace with "
            "CHANGE_ME_<VAR_NAME>.\nSee tools/ci/check_no_plaintext_secrets.py.",
            file=sys.stderr,
        )
        return 1

    # ---- Report history warnings (non-blocking) ---------------------------
    if history_hits:
        print("WARN: known-leaked credentials found in git history:")
        print("  These secrets were previously committed and MUST be rotated")
        print("  even though they have been removed from the current HEAD.")
        print()
        for literal, commits in history_hits.items():
            short = literal[:8] + "..."
            depth_label = (
                f"last {_HISTORY_DEPTH} commits" if _HISTORY_DEPTH else "full history"
            )
            print(
                f"  Literal {short!r} — found in {len(commits)} commit(s) ({depth_label}):"
            )
            for c in commits[:10]:  # cap display at 10 commits
                print(f"    {c}")
            if len(commits) > 10:
                print(f"    ... and {len(commits) - 10} more")
        print()
        print("  REQUIRED ACTION: Rotate every credential listed in")
        print("  docs/security/secret_handling.md#rotation-checklist")
        print("  OPTIONAL:  Rewrite git history (git filter-repo / BFG) to")
        print("  eliminate the leaked value from past commits.")

    if not history_hits:
        print("check_secret_history: OK — no blocked literals in HEAD or history")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
