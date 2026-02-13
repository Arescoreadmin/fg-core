from __future__ import annotations

import subprocess
import sys


def test_prod_unsafe_config_gate_runs() -> None:
    proc = subprocess.run(
        [sys.executable, "tools/ci/check_prod_unsafe_config.py"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
