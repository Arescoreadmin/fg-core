#!/usr/bin/env python3
from __future__ import annotations

import fnmatch
import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

FILTERS: dict[str, tuple[str, ...]] = {
    "python": (
        "**/*.py",
        "pyproject.toml",
        "requirements*.txt",
        "uv.lock",
        "poetry.lock",
    ),
    "core": (
        "api/**",
        "engine/**",
        "tests/**",
        "Makefile",
        ".github/**",
        "CONTRACT.md",
        "README.md",
        "policy/**",
        "migrations/**",
        "scripts/**",
    ),
    "console": (
        "console/**",
        "package.json",
        "package-lock.json",
        ".github/**",
    ),
    "compliance": (
        "compliance/**",
        "Makefile",
        ".github/**",
        "pyproject.toml",
        "requirements*.txt",
        "uv.lock",
        "poetry.lock",
    ),
}


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=REPO, text=True, capture_output=True, check=False)


def _changed_files() -> list[str]:
    event_name = (os.getenv("GITHUB_EVENT_NAME") or "").strip()
    base_ref = (os.getenv("GITHUB_BASE_REF") or "").strip()

    if event_name == "pull_request" and base_ref:
        _run(["git", "fetch", "origin", base_ref, "--depth=200"])
        diff = _run(["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"])
        if diff.returncode == 0:
            return sorted({x.strip() for x in diff.stdout.splitlines() if x.strip()})

    diff = _run(["git", "diff", "--name-only", "HEAD~1..HEAD"])
    if diff.returncode == 0:
        return sorted({x.strip() for x in diff.stdout.splitlines() if x.strip()})

    # Fail-safe: if diff cannot be computed, mark all as changed.
    return ["*"]


def _matches(path: str, pattern: str) -> bool:
    return fnmatch.fnmatch(path, pattern)


def _filter_hit(paths: list[str], patterns: tuple[str, ...]) -> bool:
    if paths == ["*"]:
        return True
    for p in paths:
        for pat in patterns:
            if _matches(p, pat):
                return True
    return False


def main() -> int:
    changed = _changed_files()
    outputs = {k: _filter_hit(changed, pats) for k, pats in FILTERS.items()}

    out_file = (os.getenv("GITHUB_OUTPUT") or "").strip()
    if out_file:
        with open(out_file, "a", encoding="utf-8") as fh:
            for k, v in outputs.items():
                fh.write(f"{k}={'true' if v else 'false'}\n")

    for k, v in outputs.items():
        print(f"{k}={'true' if v else 'false'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
