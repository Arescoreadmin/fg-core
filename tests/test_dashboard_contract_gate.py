from __future__ import annotations

import subprocess
import sys


def test_dashboard_contract_ci_gate_script_runs() -> None:
    proc = subprocess.run(
        [sys.executable, "tools/ci/check_dashboard_contracts.py"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
