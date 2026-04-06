#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# Use the running interpreter so CI always invokes the venv Python, not
# whatever bare "python" resolves to in the stripped safe-env PATH.
_PY = sys.executable

COMMANDS = [
    [_PY, "tools/ci/check_route_inventory.py"],
    [_PY, "tools/ci/check_openapi_security_diff.py"],
    [_PY, "tools/ci/check_plane_registry.py"],
]

# Conservative per-command ceiling.  Each script completes in <5s normally;
# 120s gives headroom for slow CI runners without allowing an indefinite hang.
_COMMAND_TIMEOUT = 120


def main() -> int:
    repo = Path(__file__).resolve().parents[3]
    for command in COMMANDS:
        env = os.environ.copy()
        env.setdefault("PYTHONPATH", str(repo))
        try:
            proc = subprocess.run(
                command,
                cwd=repo,
                check=False,
                env=env,
                stdin=subprocess.DEVNULL,
                timeout=_COMMAND_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            print(
                f"check_contract_drift: TIMEOUT after {_COMMAND_TIMEOUT}s: {' '.join(command)}",
                flush=True,
            )
            return 1
        if proc.returncode != 0:
            return proc.returncode
    print("contract drift checks: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
