#!/usr/bin/env python3
"""Visibility report for rag_stub references in the codebase.

This script greps for rag_stub imports and usage and prints a summary report.
It is a visibility tool only — it never fails CI (always exits 0).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

_EXCLUDE_DIRS = ["__pycache__", ".venv", ".git", ".mypy_cache", "node_modules", ".next"]

_PATTERNS = [
    "rag_stub",
    "retrieval_id.*stub",
]

# Historical/migration references — intentionally present; NOT a scan gap.
# These are classified as historical because they live in immutable migration
# history and must not be rewritten.  Any future RAG removal PR must address
# the data-migration concern they represent separately from runtime code removal.
_HISTORICAL_ALLOWLIST: dict[str, str] = {
    "migrations/postgres/0017_ai_plane_policy_hardening.sql": (
        "COALESCE(retrieval_id, 'stub') — historical migration; "
        "preserves stub sentinel for legacy rows inserted before real RAG was wired"
    ),
}


def _grep(pattern: str) -> list[str]:
    try:
        result = subprocess.run(
            [
                "grep",
                "-rn",
                "--include=*.py",
                "--include=*.md",
                "--include=*.json",
                "--include=*.sql",
                pattern,
                str(REPO),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return []

    lines = []
    for line in result.stdout.splitlines():
        skip = False
        for excl in _EXCLUDE_DIRS:
            if f"/{excl}/" in line or line.startswith(str(REPO / excl)):
                skip = True
                break
        if not skip:
            lines.append(line)
    return lines


def main() -> int:
    print("=== RAG Stub Reference Visibility Report ===")
    print(f"Repo: {REPO}")
    print()

    total = 0
    for pattern in _PATTERNS:
        hits = _grep(pattern)
        print(f"Pattern: {pattern!r}  ({len(hits)} match(es))")
        for hit in hits:
            try:
                rel = hit.replace(str(REPO) + "/", "", 1)
            except Exception:
                rel = hit
            print(f"  {rel}")
        print()
        total += len(hits)

    print(f"Total matches: {total}")
    if total == 0:
        print("Status: clean — no rag_stub references found")
    else:
        print(
            "Status: rag_stub references present (see inventory: docs/ai/RAG_STUB_INVENTORY.md)"
        )

    print()
    print("=== Historical/Migration Allowlist (intentional — do not remove) ===")
    for path, note in _HISTORICAL_ALLOWLIST.items():
        print(f"  {path}")
        print(f"    Note: {note}")

    # Always exit 0 — this is a visibility tool, not a CI enforcer.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
