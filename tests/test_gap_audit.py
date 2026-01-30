"""Tests for gap_audit.py enforcement.

These tests verify:
- gap-audit fails with Production-blocking gaps
- gap-audit passes when no Production-blocking gaps exist
- waivers suppress only Launch-risk and Post-launch gaps
- expired waivers fail CI
- Production-blocking gaps cannot be waived
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path
from textwrap import dedent

import pytest

# Add scripts to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from gap_audit import (
    Gap,
    Waiver,
    parse_gap_matrix,
    parse_waivers,
    run_gap_audit,
    validate_gap,
    is_waiver_valid,
    is_waiver_expiring_soon,
    WAIVER_WARNING_DAYS,
)


class TestParseGapMatrix:
    """Tests for GAP_MATRIX.md parsing."""

    def test_parse_valid_matrix(self, tmp_path: Path) -> None:
        """Parse a valid gap matrix with multiple entries."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            # Gap Matrix

            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | Test gap one | Production-blocking | test_file.py | repo | V2 | Tests pass |
            | GAP-002 | Test gap two | Launch-risk | ci.yml | infra | V2 | CI green |
        """)
        )

        gaps = parse_gap_matrix(matrix)

        assert len(gaps) == 2
        assert gaps[0].id == "GAP-001"
        assert gaps[0].severity == "Production-blocking"
        assert gaps[0].owner == "repo"
        assert gaps[1].id == "GAP-002"
        assert gaps[1].severity == "Launch-risk"

    def test_parse_empty_matrix(self, tmp_path: Path) -> None:
        """Parse an empty matrix returns empty list."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text("# No gaps yet")

        gaps = parse_gap_matrix(matrix)
        assert gaps == []

    def test_parse_missing_file(self, tmp_path: Path) -> None:
        """Missing matrix file returns empty list."""
        matrix = tmp_path / "missing.md"

        gaps = parse_gap_matrix(matrix)
        assert gaps == []


class TestParseWaivers:
    """Tests for RISK_WAIVERS.md parsing."""

    def test_parse_valid_waivers(self, tmp_path: Path) -> None:
        """Parse a valid waivers file."""
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text(
            dedent("""
            # Risk Waivers

            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | GAP-002 | Launch-risk | Business decision | Alice | 2099-12-31 | 2099-12-01 |
        """)
        )

        result = parse_waivers(waivers)

        assert len(result) == 1
        assert result[0].gap_id == "GAP-002"
        assert result[0].approved_by == "Alice"
        assert result[0].expiration == "2099-12-31"

    def test_parse_empty_waivers(self, tmp_path: Path) -> None:
        """Empty waivers file returns empty list."""
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        result = parse_waivers(waivers)
        assert result == []


class TestValidateGap:
    """Tests for gap validation."""

    def test_valid_gap(self) -> None:
        """Valid gap passes validation."""
        gap = Gap(
            id="GAP-001",
            description="Test",
            severity="Production-blocking",
            evidence="test.py",
            owner="repo",
            eta="V2",
            definition_of_done="Tests pass",
        )
        errors = validate_gap(gap)
        assert errors == []

    def test_invalid_severity(self) -> None:
        """Invalid severity fails validation."""
        gap = Gap(
            id="GAP-001",
            description="Test",
            severity="Critical",  # Invalid
            evidence="test.py",
            owner="repo",
            eta="V2",
            definition_of_done="Tests pass",
        )
        errors = validate_gap(gap)
        assert len(errors) == 1
        assert "Invalid severity" in errors[0]

    def test_invalid_owner(self) -> None:
        """Invalid owner fails validation."""
        gap = Gap(
            id="GAP-001",
            description="Test",
            severity="Launch-risk",
            evidence="test.py",
            owner="team-alpha",  # Invalid
            eta="V2",
            definition_of_done="Tests pass",
        )
        errors = validate_gap(gap)
        assert len(errors) == 1
        assert "Invalid owner" in errors[0]

    def test_missing_evidence(self) -> None:
        """Missing evidence fails validation."""
        gap = Gap(
            id="GAP-001",
            description="Test",
            severity="Launch-risk",
            evidence="",  # Missing
            owner="repo",
            eta="V2",
            definition_of_done="Tests pass",
        )
        errors = validate_gap(gap)
        assert len(errors) == 1
        assert "Evidence is required" in errors[0]


class TestWaiverValidity:
    """Tests for waiver validity checks."""

    def test_valid_waiver(self) -> None:
        """Waiver with future expiration is valid."""
        waiver = Waiver(
            gap_id="GAP-001",
            severity="Launch-risk",
            reason="Test",
            approved_by="Alice",
            expiration="2099-12-31",
            review_date="2099-12-01",
        )
        today = datetime(2024, 1, 1)
        assert is_waiver_valid(waiver, today) is True

    def test_expired_waiver(self) -> None:
        """Waiver with past expiration is invalid."""
        waiver = Waiver(
            gap_id="GAP-001",
            severity="Launch-risk",
            reason="Test",
            approved_by="Alice",
            expiration="2020-01-01",
            review_date="2019-12-01",
        )
        today = datetime(2024, 1, 1)
        assert is_waiver_valid(waiver, today) is False

    def test_waiver_expiring_soon(self) -> None:
        """Waiver expiring within threshold triggers warning."""
        today = datetime(2024, 1, 1)
        soon = today + timedelta(days=WAIVER_WARNING_DAYS - 1)
        waiver = Waiver(
            gap_id="GAP-001",
            severity="Launch-risk",
            reason="Test",
            approved_by="Alice",
            expiration=soon.strftime("%Y-%m-%d"),
            review_date="2024-01-01",
        )
        assert is_waiver_expiring_soon(waiver, today) is True

    def test_waiver_not_expiring_soon(self) -> None:
        """Waiver expiring far in future does not trigger warning."""
        waiver = Waiver(
            gap_id="GAP-001",
            severity="Launch-risk",
            reason="Test",
            approved_by="Alice",
            expiration="2099-12-31",
            review_date="2099-12-01",
        )
        today = datetime(2024, 1, 1)
        assert is_waiver_expiring_soon(waiver, today) is False


class TestRunGapAudit:
    """Integration tests for run_gap_audit."""

    def test_fails_with_production_blocking_gaps(self, tmp_path: Path) -> None:
        """Audit fails when Production-blocking gaps exist."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | Cross-tenant access | Production-blocking | test.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        result = run_gap_audit(matrix, waivers)

        assert len(result.blocking_gaps) == 1
        assert result.blocking_gaps[0].id == "GAP-001"

    def test_passes_with_no_production_blocking_gaps(self, tmp_path: Path) -> None:
        """Audit passes when no Production-blocking gaps exist."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | Minor issue | Launch-risk | test.py | repo | V2 | Fixed |
            | GAP-002 | UX tweak | Post-launch | ui.py | docs | V2+ | Done |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        result = run_gap_audit(matrix, waivers)

        assert len(result.blocking_gaps) == 0
        assert len(result.launch_risk_gaps) == 1
        assert len(result.post_launch_gaps) == 1

    def test_waiver_suppresses_launch_risk_gap(self, tmp_path: Path) -> None:
        """Valid waiver suppresses Launch-risk gap."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | Waivable issue | Launch-risk | test.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text(
            dedent("""
            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | GAP-001 | Launch-risk | Business | Alice | 2099-12-31 | 2099-12-01 |
        """)
        )

        result = run_gap_audit(matrix, waivers, today=datetime(2024, 1, 1))

        assert len(result.launch_risk_gaps) == 0
        assert len(result.waived_gaps) == 1
        assert result.waived_gaps[0][0].id == "GAP-001"

    def test_waiver_cannot_suppress_production_blocking(self, tmp_path: Path) -> None:
        """Production-blocking gaps cannot be waived."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | Critical issue | Production-blocking | test.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text(
            dedent("""
            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | GAP-001 | Production-blocking | Attempted waiver | Bob | 2099-12-31 | 2099-12-01 |
        """)
        )

        result = run_gap_audit(matrix, waivers, today=datetime(2024, 1, 1))

        # Gap should still be blocking
        assert len(result.blocking_gaps) == 1
        # Waiver attempt should be flagged as invalid
        assert len(result.invalid_waiver_attempts) == 1

    def test_expired_waiver_fails(self, tmp_path: Path) -> None:
        """Expired waivers are flagged."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | Issue | Launch-risk | test.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text(
            dedent("""
            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | GAP-001 | Launch-risk | Old waiver | Alice | 2020-01-01 | 2019-12-01 |
        """)
        )

        result = run_gap_audit(matrix, waivers, today=datetime(2024, 1, 1))

        # Gap should NOT be waived (waiver expired)
        assert len(result.launch_risk_gaps) == 1
        assert len(result.waived_gaps) == 0
        # Expired waiver should be flagged
        assert len(result.expired_waivers) == 1

    def test_expiring_soon_waiver_warns(self, tmp_path: Path) -> None:
        """Waivers expiring soon trigger warnings."""
        today = datetime(2024, 1, 1)
        soon = today + timedelta(days=7)

        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | Issue | Launch-risk | test.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text(
            dedent(f"""
            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | GAP-001 | Launch-risk | Expiring | Alice | {soon.strftime("%Y-%m-%d")} | 2024-01-01 |
        """)
        )

        result = run_gap_audit(matrix, waivers, today=today)

        # Waiver still valid
        assert len(result.waived_gaps) == 1
        # But flagged as expiring soon
        assert len(result.expiring_soon_waivers) == 1


class TestGapAuditCLI:
    """Tests for gap_audit.py CLI behavior."""

    def test_cli_returns_nonzero_on_blocking_gaps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CLI returns non-zero exit code when blocking gaps exist."""
        # Create test matrix with blocking gap
        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()

        matrix = docs_dir / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | Blocker | Production-blocking | test.py | repo | V2 | Fixed |
        """)
        )

        waivers = docs_dir / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        # Change to tmp_path so relative paths work
        monkeypatch.chdir(tmp_path)

        from gap_audit import main

        exit_code = main()

        assert exit_code == 1

    def test_cli_returns_zero_when_no_blocking_gaps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CLI returns zero exit code when no blocking gaps exist."""
        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()

        matrix = docs_dir / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | Minor | Launch-risk | test.py | repo | V2 | Fixed |
        """)
        )

        waivers = docs_dir / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        monkeypatch.chdir(tmp_path)

        from gap_audit import main

        exit_code = main()

        assert exit_code == 0
