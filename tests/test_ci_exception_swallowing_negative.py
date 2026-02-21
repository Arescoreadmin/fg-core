from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def test_security_exception_swallowing_check_fails_on_pass(tmp_path: Path) -> None:
    target = tmp_path / "tools" / "ci"
    target.mkdir(parents=True)
    (tmp_path / "api" / "security").mkdir(parents=True)
    shutil.copy(
        Path("tools/ci/check_security_exception_swallowing.py"),
        target / "check_security_exception_swallowing.py",
    )
    (tmp_path / "api" / "security" / "bad.py").write_text(
        "def f():\n    try:\n        x = 1\n    except Exception:\n        pass\n",
        encoding="utf-8",
    )

    proc = subprocess.run(
        [sys.executable, "tools/ci/check_security_exception_swallowing.py"],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "forbidden exception swallowing" in proc.stdout
