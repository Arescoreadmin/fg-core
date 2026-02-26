#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
from pathlib import Path

COMMANDS = [
    ["python", "tools/ci/check_route_inventory.py"],
    ["python", "tools/ci/check_openapi_security_diff.py"],
    ["python", "tools/ci/check_plane_registry.py"],
]


def main() -> int:
    repo = Path(__file__).resolve().parents[3]
    for command in COMMANDS:
        env = os.environ.copy()
        env.setdefault("PYTHONPATH", ".")
        proc = subprocess.run(command, cwd=repo, check=False, env=env)
        if proc.returncode != 0:
            return proc.returncode
    print("contract drift checks: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
