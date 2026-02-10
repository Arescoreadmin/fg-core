"""Tests for BP-C-004 gate: Authority & Provenance Gate.

All tests use tmp_path to create isolated repo-like structures.
Never depend on real repo state.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from verify_bp_c_004 import (
    GATE_ID,
    INVARIANT,
    extract_sha256_hashes,
    run_gate,
    validate_align_map,
)

SAMPLE_CONTRACT = '{"openapi": "3.1.0"}\n'
SAMPLE_CONTRACT_BYTES = SAMPLE_CONTRACT.encode("utf-8")
SAMPLE_HASH = hashlib.sha256(SAMPLE_CONTRACT_BYTES).hexdigest()


def _setup_repo(
    tmp_path: Path,
    *,
    contract_content: bytes = SAMPLE_CONTRACT_BYTES,
    contract_md_hash: str | None = None,
    blueprint_md_hash: str | None = None,
    contract_md_hashes_count: int = 1,
    blueprint_md_hashes_count: int = 1,
    align_value: str = "make bp-c-004-gate",
    skip_contract: bool = False,
    skip_contract_md: bool = False,
    skip_blueprint_md: bool = False,
    skip_align: bool = False,
) -> Path:
    """Create a minimal fake repo for BP-C-004 testing."""
    if not skip_contract:
        contract_path = tmp_path / "contracts" / "core" / "openapi.json"
        contract_path.parent.mkdir(parents=True, exist_ok=True)
        contract_path.write_bytes(contract_content)

    if contract_md_hash is None:
        contract_md_hash = SAMPLE_HASH

    if blueprint_md_hash is None:
        blueprint_md_hash = SAMPLE_HASH

    if not skip_contract_md:
        hash_lines = "\n".join(
            [f"Contract-Authority-SHA256: {contract_md_hash}"]
            * contract_md_hashes_count
        )
        contract_md = tmp_path / "CONTRACT.md"
        contract_md.write_text(
            f"# CONTRACT\n\n{hash_lines}\n\nBody text.\n",
            encoding="utf-8",
        )

    if not skip_blueprint_md:
        hash_lines = "\n".join(
            [f"Contract-Authority-SHA256: {blueprint_md_hash}"]
            * blueprint_md_hashes_count
        )
        blueprint_md = tmp_path / "BLUEPRINT_STAGED.md"
        blueprint_md.write_text(
            f"# BLUEPRINT\n\n{hash_lines}\n\nBody text.\n",
            encoding="utf-8",
        )

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
    def test_matching_hashes_pass(self, tmp_path: Path) -> None:
        """SHA256 matches in both anchor docs -> PASS."""
        _setup_repo(tmp_path)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is True
        assert report["gate_id"] == GATE_ID
        assert report["passed"] is True
        assert report["errors"] == []
        assert len(report["notes"]) >= 3  # contract hash + 2 match notes

    def test_report_structure_exact(self, tmp_path: Path) -> None:
        """Report JSON has exactly the required keys."""
        _setup_repo(tmp_path)
        passed, report = run_gate(repo_root=tmp_path)
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
# Single invariant violation: hash mismatch
# ---------------------------------------------------------------------------


class TestHashMismatch:
    def test_contract_md_mismatch_fails(self, tmp_path: Path) -> None:
        """CONTRACT.md has wrong hash -> FAIL."""
        wrong_hash = "a" * 64
        _setup_repo(tmp_path, contract_md_hash=wrong_hash)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any(
            "CONTRACT.md" in e and "mismatch" in e for e in report["errors"]
        )

    def test_blueprint_md_mismatch_fails(self, tmp_path: Path) -> None:
        """BLUEPRINT_STAGED.md has wrong hash -> FAIL."""
        wrong_hash = "b" * 64
        _setup_repo(tmp_path, blueprint_md_hash=wrong_hash)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any(
            "BLUEPRINT_STAGED.md" in e and "mismatch" in e
            for e in report["errors"]
        )

    def test_multiple_hashes_in_contract_md_fails(self, tmp_path: Path) -> None:
        """CONTRACT.md with multiple SHA256 values -> FAIL."""
        _setup_repo(tmp_path, contract_md_hashes_count=2)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any(
            "CONTRACT.md" in e and "multiple" in e.lower()
            for e in report["errors"]
        )

    def test_multiple_hashes_in_blueprint_md_fails(self, tmp_path: Path) -> None:
        """BLUEPRINT_STAGED.md with multiple SHA256 values -> FAIL."""
        _setup_repo(tmp_path, blueprint_md_hashes_count=2)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any(
            "BLUEPRINT_STAGED.md" in e and "multiple" in e.lower()
            for e in report["errors"]
        )

    def test_missing_hash_in_contract_md_fails(self, tmp_path: Path) -> None:
        """CONTRACT.md with no SHA256 line -> FAIL."""
        _setup_repo(tmp_path, contract_md_hashes_count=0)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any(
            "CONTRACT.md" in e and "no Contract-Authority-SHA256" in e
            for e in report["errors"]
        )


# ---------------------------------------------------------------------------
# Align score map mismatch
# ---------------------------------------------------------------------------


class TestAlignMapMismatch:
    def test_wrong_align_value_fails(self, tmp_path: Path) -> None:
        """Incorrect align_score_map.json mapping -> FAIL."""
        _setup_repo(tmp_path, align_value="MISSING")

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any(GATE_ID in e for e in report["errors"])

    def test_missing_align_file_fails(self, tmp_path: Path) -> None:
        """Missing align_score_map.json -> FAIL."""
        _setup_repo(tmp_path, skip_align=True)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any("not found" in e for e in report["errors"])


# ---------------------------------------------------------------------------
# Missing required file
# ---------------------------------------------------------------------------


class TestMissingRequiredFile:
    def test_missing_contract_artifact_fails(self, tmp_path: Path) -> None:
        """Missing contracts/core/openapi.json -> FAIL."""
        _setup_repo(tmp_path, skip_contract=True)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any("not found" in e.lower() for e in report["errors"])

    def test_missing_contract_md_fails(self, tmp_path: Path) -> None:
        """Missing CONTRACT.md -> FAIL."""
        _setup_repo(tmp_path, skip_contract_md=True)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any("CONTRACT.md" in e and "not found" in e.lower() for e in report["errors"])

    def test_missing_blueprint_md_fails(self, tmp_path: Path) -> None:
        """Missing BLUEPRINT_STAGED.md -> FAIL."""
        _setup_repo(tmp_path, skip_blueprint_md=True)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any(
            "BLUEPRINT_STAGED.md" in e and "not found" in e.lower()
            for e in report["errors"]
        )


# ---------------------------------------------------------------------------
# Unit tests: helpers
# ---------------------------------------------------------------------------


class TestExtractSha256Hashes:
    def test_extracts_hash(self) -> None:
        text = f"Contract-Authority-SHA256: {'a' * 64}\n"
        assert extract_sha256_hashes(text) == ["a" * 64]

    def test_extracts_multiple(self) -> None:
        text = (
            f"Contract-Authority-SHA256: {'a' * 64}\n"
            f"Contract-Authority-SHA256: {'b' * 64}\n"
        )
        assert extract_sha256_hashes(text) == ["a" * 64, "b" * 64]

    def test_no_hash(self) -> None:
        text = "No hash here.\n"
        assert extract_sha256_hashes(text) == []

    def test_partial_hash_ignored(self) -> None:
        text = "Contract-Authority-SHA256: tooshort\n"
        assert extract_sha256_hashes(text) == []


class TestValidateAlignMap:
    def test_correct_passes(self, tmp_path: Path) -> None:
        p = tmp_path / "tools" / "align_score_map.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({GATE_ID: "make bp-c-004-gate"}), encoding="utf-8")
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
