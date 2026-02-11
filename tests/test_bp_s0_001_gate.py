from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_bp_s0_001.py"


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


def _setup_base_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(
        repo / "tools/align_score_map.json",
        json.dumps({"BP-S0-001": "make bp-s0-001-gate"}, indent=2) + "\n",
    )
    openapi = {
        "openapi": "3.1.0",
        "info": {"title": "x", "version": "1"},
        "paths": {"/health/live": {"get": {}}, "/health/ready": {"get": {}}},
    }
    _write(repo / "contracts/core/openapi.json", json.dumps(openapi, indent=2) + "\n")
    _write(
        repo / "scripts/wait_core_ready.sh", "#!/usr/bin/env bash\ncurl /health/ready\n"
    )
    return repo


def test_bp_s0_001_happy_path(tmp_path: Path) -> None:
    repo = _setup_base_repo(tmp_path)
    result = _run(repo)
    assert result.returncode == 0
    report = json.loads(
        (repo / "artifacts/gates/bp_s0_001_report.json").read_text(encoding="utf-8")
    )
    assert report["passed"] is True


def test_bp_s0_001_negative_missing_probe_path(tmp_path: Path) -> None:
    repo = _setup_base_repo(tmp_path)
    openapi = {
        "openapi": "3.1.0",
        "info": {"title": "x", "version": "1"},
        "paths": {"/health/live": {"get": {}}},
    }
    _write(repo / "contracts/core/openapi.json", json.dumps(openapi, indent=2) + "\n")
    result = _run(repo)
    assert result.returncode == 1
    report = json.loads(
        (repo / "artifacts/gates/bp_s0_001_report.json").read_text(encoding="utf-8")
    )
    assert any(
        "missing probe path in contract: /health/ready" in e for e in report["errors"]
    )
