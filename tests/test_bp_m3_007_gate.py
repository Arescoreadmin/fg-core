from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_bp_m3_007.py"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _run(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(
        repo / "tools/align_score_map.json",
        json.dumps({"BP-M3-007": "make bp-m3-007-gate"}) + "\n",
    )
    _write(repo / "scripts/cis_check.py", "ok\n")
    _write(repo / "scripts/scap_scan.py", "ok\n")
    _write(repo / "scripts/cis_check.py", "CIS" + "\n")
    _write(repo / "scripts/scap_scan.py", "SCAP" + "\n")
    return repo


def test_happy_path(tmp_path: Path) -> None:
    assert _run(_repo(tmp_path)).returncode == 0


def test_negative_proof(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _write(repo / "scripts/cis_check.py", "broken\n")
    result = _run(repo)
    assert result.returncode == 1
    report = json.loads(
        (repo / "artifacts/gates/bp_m3_007_report.json").read_text(encoding="utf-8")
    )
    assert any("missing CIS control mapping scanner" in e for e in report["errors"])
