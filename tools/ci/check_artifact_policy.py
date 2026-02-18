#!/usr/bin/env python3
from __future__ import annotations

import fnmatch
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
POLICY = REPO / "tools/ci/artifact_policy_allowlist.json"


def _git_tracked() -> list[str]:
    import subprocess

    proc = subprocess.run(["git", "ls-files"], cwd=REPO, check=True, text=True, capture_output=True)
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def main() -> int:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    allow = set(policy.get("allowed_committed_artifacts", []))
    prohibited = list(policy.get("generated_patterns_prohibited", []))

    tracked = _git_tracked()
    failures: list[str] = []

    for path in tracked:
        if not path.startswith("artifacts/"):
            continue
        if path in allow:
            continue
        if any(fnmatch.fnmatch(path, pat) for pat in prohibited):
            failures.append(f"ARTIFACT_POLICY_PROHIBITED_COMMITTED {path}")

    if failures:
        print("artifact policy: FAILED")
        for f in sorted(failures):
            print(f" - {f}")
        return 1

    print("artifact policy: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
