from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, f"tools/ci/{script}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_plane_boundary_check_passes() -> None:
    res = _run("check_plane_boundaries.py")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "plane boundaries: OK" in res.stdout


def test_security_exception_swallowing_check_passes() -> None:
    res = _run("check_security_exception_swallowing.py")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "security exception swallowing: OK" in res.stdout
