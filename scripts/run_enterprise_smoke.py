from __future__ import annotations

import subprocess
import sys


CMDS = [
    ["ruff", "check"],
    [sys.executable, "-m", "pytest", "-q"],
    ["make", "route-inventory-generate"],
    ["make", "route-inventory-audit"],
    ["make", "contract-authority-refresh"],
    ["make", "fg-contract"],
    ["make", "enterprise-ext-spot"],
    ["make", "plane-registry-spot"],
    ["make", "evidence-index-spot"],
    ["make", "resilience-smoke"],
    ["make", "ai-plane-spot"],
]


def main() -> int:
    for cmd in CMDS:
        proc = subprocess.run(cmd, check=False)
        if proc.returncode != 0:
            return proc.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
