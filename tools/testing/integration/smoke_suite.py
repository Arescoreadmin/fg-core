#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
from pathlib import Path

COMMANDS = [
    [".venv/bin/pytest", "-q", "tests/test_e2e_http_local.py", "-k", "not slow"],
    [".venv/bin/pytest", "-q", "tests/control_plane/test_control_plane_v2.py"],
]


def main() -> int:
    repo = Path(__file__).resolve().parents[3]
    for command in COMMANDS:
        env = os.environ.copy()
        env.setdefault("PYTHONPATH", ".")
        proc = subprocess.run(command, cwd=repo, check=False, env=env)
        if proc.returncode != 0:
            return proc.returncode
    print("integration smoke: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
