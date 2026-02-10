"""Tests for BP-C-002 gate: Contract Drift Gate.

All tests use tmp_path to create isolated repo-like structures.
Never depend on real repo state.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from verify_bp_c_002 import (
    GATE_ID,
    INVARIANT,
    run_gate,
    sha256_bytes,
    validate_align_map,
)

SAMPLE_OPENAPI = json.dumps({"openapi": "3.1.0", "info": {"title": "test"}}, indent=2, sort_keys=True) + "\n"
SAMPLE_OPENAPI_BYTES = SAMPLE_OPENAPI.encode("utf-8")
SAMPLE_OPENAPI_HASH = sha256_bytes(SAMPLE_OPENAPI_BYTES)

DRIFTED_OPENAPI = json.dumps({"openapi": "3.1.0", "info": {"title": "drifted"}}, indent=2, sort_keys=True) + "\n"
DRIFTED_OPENAPI_BYTES = DRIFTED_OPENAPI.encode("utf-8")


def _setup_repo(
    tmp_path: Path,
    *,
    core_content: bytes = SAMPLE_OPENAPI_BYTES,
    schemas_content: bytes = SAMPLE_OPENAPI_BYTES,
    align_value: str = "make bp-c-002-gate",
    skip_core: bool = False,
    skip_schemas: bool = False,
    skip_align: bool = False,
) -> Path:
    """Create a minimal fake repo structure for BP-C-002 testing."""
    if not skip_core:
        core_path = tmp_path / "contracts" / "core" / "openapi.json"
        core_path.parent.mkdir(parents=True, exist_ok=True)
        core_path.write_bytes(core_content)

    if not skip_schemas:
        schemas_path = tmp_path / "schemas" / "api" / "openapi.json"
        schemas_path.parent.mkdir(parents=True, exist_ok=True)
        schemas_path.write_bytes(schemas_content)

    if not skip_align:
        align_path = tmp_path / "tools" / "align_score_map.json"
        align_path.parent.mkdir(parents=True, exist_ok=True)
        align_path.write_text(
            json.dumps({GATE_ID: align_value}, indent=2) + "\n",
            encoding="utf-8",
        )

    return tmp_path


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_matching_contracts_pass(self, tmp_path: Path) -> None:
        """Committed contracts matching generated content -> PASS."""
        _setup_repo(tmp_path)

        passed, report = run_gate(
            repo_root=tmp_path, generated_bytes=SAMPLE_OPENAPI_BYTES
        )
        assert passed is True
        assert report["gate_id"] == GATE_ID
        assert report["passed"] is True
        assert report["errors"] == []
        assert len(report["notes"]) == 2

    def test_report_structure_exact(self, tmp_path: Path) -> None:
        """Report JSON has exactly the required keys, no more, no less."""
        _setup_repo(tmp_path)
        passed, report = run_gate(
            repo_root=tmp_path, generated_bytes=SAMPLE_OPENAPI_BYTES
        )
        required_keys = {
            "gate_id",
            "passed",
            "generated_at_utc",
            "invariant",
            "checked_files",
            "errors",
            "notes",
        }
        assert set(report.keys()) == required_keys
        assert report["invariant"] == INVARIANT
        assert report["gate_id"] == GATE_ID


# ---------------------------------------------------------------------------
# Single invariant violation: contract drift
# ---------------------------------------------------------------------------


class TestContractDrift:
    def test_core_drift_fails(self, tmp_path: Path) -> None:
        """Core contract differs from generated -> FAIL."""
        _setup_repo(tmp_path, core_content=DRIFTED_OPENAPI_BYTES)

        passed, report = run_gate(
            repo_root=tmp_path, generated_bytes=SAMPLE_OPENAPI_BYTES
        )
        assert passed is False
        assert any("Contract drift" in e and "core" in e for e in report["errors"])

    def test_schemas_drift_fails(self, tmp_path: Path) -> None:
        """Schemas contract differs from generated -> FAIL."""
        _setup_repo(tmp_path, schemas_content=DRIFTED_OPENAPI_BYTES)

        passed, report = run_gate(
            repo_root=tmp_path, generated_bytes=SAMPLE_OPENAPI_BYTES
        )
        assert passed is False
        assert any(
            "Contract drift" in e and "schemas" in e for e in report["errors"]
        )

    def test_both_drifted_reports_both(self, tmp_path: Path) -> None:
        """Both contracts drifted -> two drift errors."""
        _setup_repo(
            tmp_path,
            core_content=DRIFTED_OPENAPI_BYTES,
            schemas_content=DRIFTED_OPENAPI_BYTES,
        )

        passed, report = run_gate(
            repo_root=tmp_path, generated_bytes=SAMPLE_OPENAPI_BYTES
        )
        assert passed is False
        drift_errors = [e for e in report["errors"] if "Contract drift" in e]
        assert len(drift_errors) == 2


# ---------------------------------------------------------------------------
# Align score map mismatch
# ---------------------------------------------------------------------------


class TestAlignMapMismatch:
    def test_wrong_align_value_fails(self, tmp_path: Path) -> None:
        """Incorrect align_score_map.json mapping -> FAIL."""
        _setup_repo(tmp_path, align_value="MISSING")

        passed, report = run_gate(
            repo_root=tmp_path, generated_bytes=SAMPLE_OPENAPI_BYTES
        )
        assert passed is False
        assert any(GATE_ID in e for e in report["errors"])

    def test_missing_align_file_fails(self, tmp_path: Path) -> None:
        """Missing align_score_map.json -> FAIL."""
        _setup_repo(tmp_path, skip_align=True)

        passed, report = run_gate(
            repo_root=tmp_path, generated_bytes=SAMPLE_OPENAPI_BYTES
        )
        assert passed is False
        assert any("not found" in e for e in report["errors"])


# ---------------------------------------------------------------------------
# Missing required file
# ---------------------------------------------------------------------------


class TestMissingRequiredFile:
    def test_missing_core_contract_fails(self, tmp_path: Path) -> None:
        """Missing contracts/core/openapi.json -> FAIL."""
        _setup_repo(tmp_path, skip_core=True)

        passed, report = run_gate(
            repo_root=tmp_path, generated_bytes=SAMPLE_OPENAPI_BYTES
        )
        assert passed is False
        assert any("not found" in e and "core" in e for e in report["errors"])

    def test_missing_schemas_contract_fails(self, tmp_path: Path) -> None:
        """Missing schemas/api/openapi.json -> FAIL."""
        _setup_repo(tmp_path, skip_schemas=True)

        passed, report = run_gate(
            repo_root=tmp_path, generated_bytes=SAMPLE_OPENAPI_BYTES
        )
        assert passed is False
        assert any("not found" in e and "schemas" in e for e in report["errors"])


# ---------------------------------------------------------------------------
# Validate align_map unit
# ---------------------------------------------------------------------------


class TestValidateAlignMap:
    def test_correct_passes(self, tmp_path: Path) -> None:
        p = tmp_path / "tools" / "align_score_map.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({GATE_ID: "make bp-c-002-gate"}), encoding="utf-8")
        assert validate_align_map(p) == []

    def test_wrong_value_fails(self, tmp_path: Path) -> None:
        p = tmp_path / "tools" / "align_score_map.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({GATE_ID: "wrong"}), encoding="utf-8")
        errors = validate_align_map(p)
        assert len(errors) == 1
        assert GATE_ID in errors[0]

    def test_missing_file_fails(self, tmp_path: Path) -> None:
        p = tmp_path / "tools" / "align_score_map.json"
        errors = validate_align_map(p)
        assert len(errors) == 1
        assert "not found" in errors[0]
