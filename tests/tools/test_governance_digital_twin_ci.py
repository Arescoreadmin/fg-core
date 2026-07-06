from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_governance_digital_twin_ci_gate_passes() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    proc = subprocess.run(
        [sys.executable, "tools/ci/check_governance_digital_twin.py"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASS — Governance Digital Twin foundation check passed." in proc.stdout
