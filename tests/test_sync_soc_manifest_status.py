from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.ci import sync_soc_manifest_status as module


def _write_manifest(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _base_manifest() -> dict[str, object]:
    return {
        "findings": [
            {
                "id": "SOC-P0-001",
                "severity": "P0",
                "status": "open",
                "gate": "soc-gate",
                "evidence": ["evidence.txt"],
            }
        ]
    }


def test_manifest_schema_validation_missing_field(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    _write_manifest(
        manifest,
        {
            "findings": [
                {
                    "id": "SOC-P0-001",
                    "severity": "P0",
                    "status": "open",
                    "gate": "soc-gate",
                }
            ]
        },
    )

    exit_code = module.execute(
        ["--mode", "verify", "--manifest", str(manifest)], repo_root=tmp_path
    )

    assert exit_code == 2


def test_evidence_missing_causes_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest, _base_manifest())

    called: list[str] = []

    def fake_run_gate(*args: object, **kwargs: object) -> module.GateResult:
        called.append("yes")
        return module.GateResult("soc-gate", True, 0, "", False)

    monkeypatch.setattr(module, "run_gate", fake_run_gate)

    exit_code = module.execute(
        ["--mode", "verify", "--manifest", str(manifest)], repo_root=tmp_path
    )

    assert exit_code == 1
    assert called == ["yes"]


def test_gate_execution_is_cached_by_gate_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "evidence.txt").write_text("ok", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    _write_manifest(
        manifest,
        {
            "findings": [
                {
                    "id": "SOC-P1-001",
                    "severity": "P1",
                    "status": "open",
                    "gate": "shared-gate",
                    "evidence": ["evidence.txt"],
                },
                {
                    "id": "SOC-P1-002",
                    "severity": "P1",
                    "status": "open",
                    "gate": "shared-gate",
                    "evidence": ["evidence.txt"],
                },
            ]
        },
    )

    calls: list[list[str]] = []

    class Result:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_subprocess_run(cmd: list[str], **kwargs: object) -> Result:
        calls.append(cmd)
        return Result()

    monkeypatch.setattr(module.subprocess, "run", fake_subprocess_run)

    exit_code = module.execute(
        ["--mode", "verify", "--manifest", str(manifest)], repo_root=tmp_path
    )

    assert exit_code == 0
    assert calls == [["make", "shared-gate"]]


def test_sync_mode_writes_only_when_updates_occur(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "evidence.txt").write_text("ok", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    _write_manifest(
        manifest,
        {
            "findings": [
                {
                    "id": "SOC-P1-001",
                    "severity": "P1",
                    "status": "mitigated",
                    "gate": "shared-gate",
                    "evidence": ["evidence.txt"],
                }
            ]
        },
    )
    before = manifest.read_text(encoding="utf-8")

    writes: list[str] = []
    real_write = module.write_manifest_atomic

    def fake_run_gate(*args: object, **kwargs: object) -> module.GateResult:
        return module.GateResult("shared-gate", True, 0, "", False)

    def spy_write(path: Path, payload: object, trailing_newline: bool) -> None:
        writes.append(str(path))
        real_write(path, payload, trailing_newline)

    monkeypatch.setattr(module, "run_gate", fake_run_gate)
    monkeypatch.setattr(module, "write_manifest_atomic", spy_write)

    exit_code = module.execute(
        ["--mode", "sync", "--manifest", str(manifest)], repo_root=tmp_path
    )

    after = manifest.read_text(encoding="utf-8")
    assert exit_code == 0
    assert writes == []
    assert before == after


def test_verify_mode_never_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "evidence.txt").write_text("ok", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    _write_manifest(_path := manifest, _base_manifest())

    def fake_run_gate(*args: object, **kwargs: object) -> module.GateResult:
        return module.GateResult("soc-gate", True, 0, "", False)

    monkeypatch.setattr(module, "run_gate", fake_run_gate)

    called = False

    def fail_write(*args: object, **kwargs: object) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(module, "write_manifest_atomic", fail_write)

    before = _path.read_text(encoding="utf-8")
    exit_code = module.execute(
        ["--mode", "verify", "--manifest", str(_path)], repo_root=tmp_path
    )
    after = _path.read_text(encoding="utf-8")

    assert exit_code == 1
    assert called is False
    assert before == after


def test_unresolved_p0_causes_verify_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "evidence.txt").write_text("ok", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest, _base_manifest())

    def fake_run_gate(*args: object, **kwargs: object) -> module.GateResult:
        return module.GateResult("soc-gate", False, 2, "bad", False)

    monkeypatch.setattr(module, "run_gate", fake_run_gate)

    exit_code = module.execute(
        ["--mode", "verify", "--manifest", str(manifest)], repo_root=tmp_path
    )

    assert exit_code == 1
