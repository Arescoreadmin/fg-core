from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_bp_c_002.py"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _init_git_repo(repo: Path) -> None:
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"], cwd=repo, check=True
    )
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo, check=True)


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
    _init_git_repo(repo)
    _write(
        repo / "tools/align_score_map.json",
        json.dumps({"BP-C-002": "make bp-c-002-gate"}, indent=2) + "\n",
    )
    _write(
        repo / "contracts/core/openapi.json",
        '{"openapi":"3.1.0","info":{"title":"x","version":"1"}}\n',
    )
    _write(
        repo / "schemas/api/openapi.json",
        '{"openapi":"3.1.0","info":{"title":"x","version":"1"}}\n',
    )
    _write(repo / "scripts/contracts_gen_core.py", "print('noop')\n")
    _write(
        repo / "Makefile",
        "contracts-core-gen:\n\t@python scripts/contracts_gen_core.py\n",
    )
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True
    )
    return repo


def test_bp_c_002_happy_path(tmp_path: Path) -> None:
    repo = _setup_base_repo(tmp_path)
    result = _run(repo)
    assert result.returncode == 0, result.stderr
    report = json.loads(
        (repo / "artifacts/gates/bp_c_002_report.json").read_text(encoding="utf-8")
    )
    assert report["gate_id"] == "BP-C-002"
    assert report["passed"] is True
    assert report["errors"] == []


def test_bp_c_002_single_invariant_violation(tmp_path: Path) -> None:
    repo = _setup_base_repo(tmp_path)
    _write(
        repo / "scripts/contracts_gen_core.py",
        "from pathlib import Path\nPath('contracts/core/openapi.json').write_text('{\"changed\":true}\\n', encoding='utf-8')\n",
    )
    result = _run(repo)
    assert result.returncode == 1
    report = json.loads(
        (repo / "artifacts/gates/bp_c_002_report.json").read_text(encoding="utf-8")
    )
    assert report["passed"] is False
    assert any("drift detected" in err for err in report["errors"])


def test_bp_c_002_align_score_map_mismatch(tmp_path: Path) -> None:
    repo = _setup_base_repo(tmp_path)
    _write(
        repo / "tools/align_score_map.json",
        json.dumps({"BP-C-002": "make wrong-target"}, indent=2) + "\n",
    )
    result = _run(repo)
    assert result.returncode == 1
    report = json.loads(
        (repo / "artifacts/gates/bp_c_002_report.json").read_text(encoding="utf-8")
    )
    assert any("align_score_map mismatch" in err for err in report["errors"])


def test_bp_c_002_missing_required_file(tmp_path: Path) -> None:
    repo = _setup_base_repo(tmp_path)
    os.remove(repo / "contracts/core/openapi.json")
    result = _run(repo)
    assert result.returncode == 1
    report = json.loads(
        (repo / "artifacts/gates/bp_c_002_report.json").read_text(encoding="utf-8")
    )
    assert any("missing required file" in err for err in report["errors"])
