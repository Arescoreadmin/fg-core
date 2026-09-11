"""Tests for the Customer-One roadmap authority checker."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_CHECKER = str(
    Path(__file__).parent.parent / "tools" / "ci" / "check_customer_one_roadmap.py"
)
_AUTHORITY = str(
    Path(__file__).parent.parent / "customer_one" / "roadmap_authority.yaml"
)


def _run_item(
    work_item: str, authority: str = _AUTHORITY
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, _CHECKER, "--authority", authority, "--work-item", work_item],
        capture_output=True,
        text=True,
        check=False,
    )


def _run_class(
    work_class: str, authority: str = _AUTHORITY
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            _CHECKER,
            "--authority",
            authority,
            "--work-class",
            work_class,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


class TestAuthorizedItems:
    def test_next_sequence_item_authorized(self) -> None:
        # FGA-027 is in next_sequence — must be authorized
        result = _run_item("FGA-027")
        assert result.returncode == 0, result.stderr

    def test_l14_authorized(self) -> None:
        result = _run_item("L14")
        assert result.returncode == 0, result.stderr

    def test_repair_class_authorized(self) -> None:
        # REPAIR is a class-level authorization — always open, no item ID needed
        result = _run_class("REPAIR")
        assert result.returncode == 0, result.stderr


class TestBlockedItems:
    def test_p1_01_pr2_completed_blocked(self) -> None:
        # P1-01-PR2 was completed in #690 — must be blocked with COMPLETED message
        result = _run_item("P1-01-PR2")
        assert result.returncode == 1
        assert "COMPLETED" in result.stderr

    def test_completed_item_pr_recorded(self) -> None:
        # The COMPLETED message must include the PR reference (#690)
        result = _run_item("P1-01-PR2")
        assert result.returncode == 1
        assert "#690" in result.stderr

    def test_completed_item_blocked(self) -> None:
        # P0-ID-CUTOVER is in completed — must be blocked
        result = _run_item("P0-ID-CUTOVER")
        assert result.returncode == 1

    def test_deferred_item_blocked(self) -> None:
        # SAML is in deferred — must be blocked
        result = _run_item("SAML")
        assert result.returncode == 1

    def test_another_deferred_item_blocked(self) -> None:
        result = _run_item("FEDRAMP")
        assert result.returncode == 1

    def test_unknown_item_blocked(self) -> None:
        # Not in next_sequence or deferred — fail-closed
        result = _run_item("SPECULATIVE_FUTURE_WORK")
        assert result.returncode == 1
        assert "fail-closed" in result.stderr


class TestAuthorityFileErrors:
    def test_path_mismatch_blocked(self) -> None:
        result = _run_item("FGA-027", authority="nonexistent_authority.yaml")
        assert result.returncode == 1
        assert "not found" in result.stderr

    def test_malformed_yaml_blocked(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("[unclosed bracket\n")
        result = _run_item("FGA-027", authority=str(bad))
        assert result.returncode == 1

    def test_missing_required_keys_blocked(self, tmp_path: Path) -> None:
        incomplete = tmp_path / "incomplete.yaml"
        incomplete.write_text("schema_version: '1.0'\ngoal: test\n")
        result = _run_item("FGA-027", authority=str(incomplete))
        assert result.returncode == 1
        assert "next_sequence" in result.stderr or "deferred" in result.stderr

    def test_non_mapping_yaml_blocked(self, tmp_path: Path) -> None:
        list_yaml = tmp_path / "list.yaml"
        list_yaml.write_text("- item1\n- item2\n")
        result = _run_item("FGA-027", authority=str(list_yaml))
        assert result.returncode == 1
