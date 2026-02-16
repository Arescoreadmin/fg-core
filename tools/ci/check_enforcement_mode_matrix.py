#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys

CASES = (
    ("prod", "enforce", True),
    ("prod", "observe", False),
    ("prod", "", False),
    ("staging", "enforce", True),
    ("staging", "observe", False),
    ("staging", "", False),
)


def run_case(env_name: str, mode: str) -> tuple[int, str]:
    code = "from api.config.prod_invariants import assert_prod_invariants; assert_prod_invariants()"
    env = os.environ.copy()
    env["FG_ENV"] = env_name
    env["FG_AUTH_ENABLED"] = "1"
    env["FG_DB_URL"] = "postgresql+psycopg://user:pass@localhost:5432/frostgate"
    env["FG_DB_BACKEND"] = "postgres"
    if mode:
        env["FG_ENFORCEMENT_MODE"] = mode
    else:
        env.pop("FG_ENFORCEMENT_MODE", None)

    proc = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    detail = (proc.stderr or proc.stdout or "").strip()
    return proc.returncode, detail


def main() -> int:
    failures: list[str] = []
    for env_name, mode, expect_success in CASES:
        rc, detail = run_case(env_name, mode)
        succeeded = rc == 0
        if succeeded != expect_success:
            mode_disp = mode or "<unset>"
            reason = detail.splitlines()[-1] if detail else "no error details"
            failures.append(
                f"FG_ENV={env_name} FG_ENFORCEMENT_MODE={mode_disp}: expected "
                f"{'success' if expect_success else 'failure'} but got rc={rc} ({reason})"
            )

    if failures:
        print("enforcement-mode matrix: FAILED")
        for line in failures:
            print(f" - {line}")
        return 1

    print("enforcement-mode matrix: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
