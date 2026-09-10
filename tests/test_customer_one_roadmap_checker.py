"""Tests for the Customer-One roadmap authority checker."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_CHECKER = str(Path(__file__).parent.parent / "tools" / "ci" / "check_customer_one_roadmap.py")
_AUTHORITY = str(Path(__file__).parent.parent / "customer_one" / "roadmap_authority.yaml")


def _run(work_class: str, authority: str = _AUTHORITY) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, _CHECKER, "--authority", authority, "--work-class", work_class],
        capture_output=True,
        text=True,
    )


class TestAuthorizedClasses:
    def test_next_authorized(self) -> None:
        result = _run("NEXT")
        assert result.returncode == 0, result.stderr

    def test_repair_authorized(self) -> None:
        result = _run("REPAIR")
        assert result.returncode == 0, result.stderr


class TestBlockedClasses:
    def test_deferred_blocked(self) -> None:
        result = _run("DEFERRED")
        assert result.returncode == 1

    def test_unknown_class_blocked(self) -> None:
        result = _run("UNKNOWN")
        assert result.returncode == 1

    def test_undeclared_class_blocked(self) -> None:
        result = _run("SPECULATIVE_FUTURE_WORK")
        assert result.returncode == 1


class TestAuthorityFileErrors:
    def test_path_mismatch_blocked(self) -> None:
        result = _run("NEXT", authority="nonexistent_authority.yaml")
        assert result.returncode == 1
        assert "not found" in result.stderr

    def test_malformed_yaml_blocked(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("[unclosed bracket\n")
        result = _run("NEXT", authority=str(bad))
        assert result.returncode == 1

    def test_missing_work_classes_key_blocked(self, tmp_path: Path) -> None:
        incomplete = tmp_path / "incomplete.yaml"
        incomplete.write_text("schema_version: '1.0'\ngoal: test\n")
        result = _run("NEXT", authority=str(incomplete))
        assert result.returncode == 1
        assert "work_classes" in result.stderr

    def test_non_mapping_yaml_blocked(self, tmp_path: Path) -> None:
        list_yaml = tmp_path / "list.yaml"
        list_yaml.write_text("- item1\n- item2\n")
        result = _run("NEXT", authority=str(list_yaml))
        assert result.returncode == 1
