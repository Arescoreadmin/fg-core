from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def test_trust_proof_writes_failure_artifact_without_base_url(tmp_path: Path) -> None:
    env = os.environ.copy()
    env.pop("FG_CONTROL_TOWER_BASE_URL", None)
    env["PYTHONPATH"] = str(Path.cwd())

    artifact = Path("artifacts/control_tower_trust_proof.json")
    if artifact.exists():
        artifact.unlink()

    proc = subprocess.run(
        [sys.executable, "tools/testing/control_tower_trust_proof.py"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert proc.returncode == 2
    assert artifact.exists()
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["status"] == "fail"
    assert "FG_CONTROL_TOWER_BASE_URL" in payload["reason"]
