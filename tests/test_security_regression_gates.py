from __future__ import annotations

from pathlib import Path
import subprocess
import sys


def test_security_regression_gate_script_passes() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "tools/ci/check_security_regression_gates.py"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "security regression gates: OK" in result.stdout
