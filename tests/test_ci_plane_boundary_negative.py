from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def test_plane_boundary_check_fails_on_forbidden_import(tmp_path: Path) -> None:
    (tmp_path / "tools" / "ci").mkdir(parents=True)
    (tmp_path / "services").mkdir()
    src = Path("tools/ci/check_plane_boundaries.py")
    shutil.copy(src, tmp_path / "tools" / "ci" / "check_plane_boundaries.py")
    (tmp_path / "services" / "bad.py").write_text(
        "from api.main import build_app\n", encoding="utf-8"
    )

    proc = subprocess.run(
        [sys.executable, "tools/ci/check_plane_boundaries.py"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    assert "forbidden import api.main" in proc.stdout
