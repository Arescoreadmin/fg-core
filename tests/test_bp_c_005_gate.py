from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_bp_c_005.py"


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
        json.dumps({"BP-C-005": "make bp-c-005-gate"}) + "\n",
    )
    _write(
        repo / "migrations/postgres/0001_base.sql",
        "\n".join(
            [
                "idx_decisions_tenant_id",
                "idx_decision_evidence_tenant_id",
                "idx_security_audit_log_tenant_id",
            ]
        ),
    )
    _write(repo / "tests/test_tenant_invariant.py", "def test_x():\n    pass\n")
    _write(repo / "tests/test_dos_guard.py", "def test_x():\n    pass\n")
    return repo


def test_bp_c_005_happy(tmp_path: Path) -> None:
    assert _run(_repo(tmp_path)).returncode == 0


def test_bp_c_005_negative_missing_index(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _write(repo / "migrations/postgres/0001_base.sql", "idx_decisions_tenant_id\n")
    r = _run(repo)
    assert r.returncode == 1
    report = json.loads(
        (repo / "artifacts/gates/bp_c_005_report.json").read_text(encoding="utf-8")
    )
    assert any("missing tenant sharding index" in e for e in report["errors"])
