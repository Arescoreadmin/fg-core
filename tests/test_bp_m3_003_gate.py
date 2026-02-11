from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_bp_m3_003.py"


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
        json.dumps({"BP-M3-003": "make bp-m3-003-gate"}) + "\n",
    )
    _write(repo / "contracts/core/openapi.json", "ok\n")
    _write(repo / "api/evidence_chain.py", "ok\n")
    _write(repo / "contracts/core/openapi.json", "/forensics/chain/verify" + "\n")
    _write(repo / "api/evidence_chain.py", "verify_chain_for_tenant" + "\n")
    return repo


def test_happy_path(tmp_path: Path) -> None:
    assert _run(_repo(tmp_path)).returncode == 0


def test_negative_proof(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _write(repo / "contracts/core/openapi.json", "broken\n")
    result = _run(repo)
    assert result.returncode == 1
    report = json.loads(
        (repo / "artifacts/gates/bp_m3_003_report.json").read_text(encoding="utf-8")
    )
    assert any("missing evidence verification API" in e for e in report["errors"])
