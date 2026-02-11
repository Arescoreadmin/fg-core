from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_bp_c_003.py"


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
        json.dumps({"BP-C-003": "make bp-c-003-gate"}, indent=2) + "\n",
    )
    openapi = {
        "openapi": "3.1.0",
        "info": {"title": "x", "version": "1"},
        "paths": {},
        "components": {"schemas": {"Thing": {"$ref": "schemas/api/thing.schema.json"}}},
    }
    _write(repo / "contracts/core/openapi.json", json.dumps(openapi, indent=2) + "\n")
    _write(repo / "schemas/api/openapi.json", json.dumps(openapi, indent=2) + "\n")
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"id": {"type": "string"}},
        "required": ["id"],
    }
    _write(repo / "schemas/api/thing.schema.json", json.dumps(schema, indent=2) + "\n")
    return repo


def test_bp_c_003_happy_path(tmp_path: Path) -> None:
    repo = _setup_base_repo(tmp_path)
    result = _run(repo)
    assert result.returncode == 0, result.stderr
    report = json.loads(
        (repo / "artifacts/gates/bp_c_003_report.json").read_text(encoding="utf-8")
    )
    assert report["passed"] is True
    assert report["errors"] == []


def test_bp_c_003_single_invariant_violation(tmp_path: Path) -> None:
    repo = _setup_base_repo(tmp_path)
    _write(repo / "schemas/api/thing.schema.json", '{"type": 1}\n')
    result = _run(repo)
    assert result.returncode == 1
    report = json.loads(
        (repo / "artifacts/gates/bp_c_003_report.json").read_text(encoding="utf-8")
    )
    assert any("invalid schema for Draft 2020-12" in err for err in report["errors"])


def test_bp_c_003_align_score_map_mismatch(tmp_path: Path) -> None:
    repo = _setup_base_repo(tmp_path)
    _write(
        repo / "tools/align_score_map.json",
        json.dumps({"BP-C-003": "make wrong-target"}, indent=2) + "\n",
    )
    result = _run(repo)
    assert result.returncode == 1
    report = json.loads(
        (repo / "artifacts/gates/bp_c_003_report.json").read_text(encoding="utf-8")
    )
    assert any("align_score_map mismatch" in err for err in report["errors"])


def test_bp_c_003_missing_required_file(tmp_path: Path) -> None:
    repo = _setup_base_repo(tmp_path)
    os.remove(repo / "contracts/core/openapi.json")
    result = _run(repo)
    assert result.returncode == 1
    report = json.loads(
        (repo / "artifacts/gates/bp_c_003_report.json").read_text(encoding="utf-8")
    )
    assert any("missing required file" in err for err in report["errors"])
