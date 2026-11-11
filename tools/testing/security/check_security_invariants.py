#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# Run every check with the SAME interpreter that runs this script (the
# harness passes the project venv). A bare "python" resolves through PATH,
# which in CI is the setup-python interpreter without the project's
# dependencies (P0-REPO-SECURITY-ENFORCEMENT-001: "No module named 'yaml'").
COMMANDS = [
    [sys.executable, "tools/ci/check_agent_phase2_rls.py"],
    [sys.executable, "tools/ci/check_connectors_rls.py"],
    [sys.executable, "tools/ci/check_security_regression_gates.py"],
]


def main() -> int:
    repo = Path(__file__).resolve().parents[3]
    for command in COMMANDS:
        env = os.environ.copy()
        env.setdefault("PYTHONPATH", ".")
        proc = subprocess.run(command, cwd=repo, check=False, env=env)
        if proc.returncode != 0:
            return proc.returncode
    print("security invariant checks: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
