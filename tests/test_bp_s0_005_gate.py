from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_bp_s0_005.py"


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
        json.dumps({"BP-S0-005": "make bp-s0-005-gate"}) + "\n",
    )
    _write(
        repo / "contracts/core/openapi.json",
        json.dumps(
            {
                "openapi": "3.1.0",
                "paths": {"/forensics/audit_trail/{event_id}": {"get": {}}},
            }
        )
        + "\n",
    )
    _write(
        repo / "migrations/postgres/0001_base.sql",
        "CREATE TABLE IF NOT EXISTS security_audit_log(id int);\n",
    )
    return repo


def test_bp_s0_005_happy(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    r = _run(repo)
    assert r.returncode == 0


def test_bp_s0_005_negative_missing_audit_path(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _write(
        repo / "contracts/core/openapi.json",
        json.dumps({"openapi": "3.1.0", "paths": {}}) + "\n",
    )
    r = _run(repo)
    assert r.returncode == 1
    report = json.loads(
        (repo / "artifacts/gates/bp_s0_005_report.json").read_text(encoding="utf-8")
    )
    assert any("missing forensics audit trail API path" in e for e in report["errors"])
