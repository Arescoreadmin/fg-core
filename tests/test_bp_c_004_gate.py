from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_bp_c_004.py"


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
        json.dumps({"BP-C-004": "make bp-c-004-gate"}, indent=2) + "\n",
    )
    openapi_content = '{"openapi":"3.1.0","info":{"title":"x","version":"1"}}\n'
    _write(repo / "contracts/core/openapi.json", openapi_content)
    digest = hashlib.sha256(openapi_content.encode("utf-8")).hexdigest()
    _write(repo / "CONTRACT.md", f"Contract-Authority-SHA256: {digest}\n")
    _write(repo / "BLUEPRINT_STAGED.md", f"Contract-Authority-SHA256: {digest}\n")
    return repo


def test_bp_c_004_happy_path(tmp_path: Path) -> None:
    repo = _setup_base_repo(tmp_path)
    result = _run(repo)
    assert result.returncode == 0
    report = json.loads(
        (repo / "artifacts/gates/bp_c_004_report.json").read_text(encoding="utf-8")
    )
    assert report["passed"] is True
    assert report["errors"] == []


def test_bp_c_004_single_invariant_violation(tmp_path: Path) -> None:
    repo = _setup_base_repo(tmp_path)
    _write(repo / "CONTRACT.md", "Contract-Authority-SHA256: " + "0" * 64 + "\n")
    result = _run(repo)
    assert result.returncode == 1
    report = json.loads(
        (repo / "artifacts/gates/bp_c_004_report.json").read_text(encoding="utf-8")
    )
    assert any("hash mismatch" in err for err in report["errors"])


def test_bp_c_004_align_score_map_mismatch(tmp_path: Path) -> None:
    repo = _setup_base_repo(tmp_path)
    _write(
        repo / "tools/align_score_map.json",
        json.dumps({"BP-C-004": "make wrong-target"}, indent=2) + "\n",
    )
    result = _run(repo)
    assert result.returncode == 1
    report = json.loads(
        (repo / "artifacts/gates/bp_c_004_report.json").read_text(encoding="utf-8")
    )
    assert any("align_score_map mismatch" in err for err in report["errors"])


def test_bp_c_004_missing_required_file(tmp_path: Path) -> None:
    repo = _setup_base_repo(tmp_path)
    os.remove(repo / "CONTRACT.md")
    result = _run(repo)
    assert result.returncode == 1
    report = json.loads(
        (repo / "artifacts/gates/bp_c_004_report.json").read_text(encoding="utf-8")
    )
    assert any("missing required file" in err for err in report["errors"])
