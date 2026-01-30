"""Tests for gap_audit.py enforcement.

These tests verify:
- gap-audit fails with Production-blocking gaps
- gap-audit passes when no Production-blocking gaps exist
- waivers suppress only Launch-risk and Post-launch gaps
- expired waivers fail CI
- Production-blocking gaps cannot be waived
- ID format validation (G[0-9]{3})
- Evidence artifact validation
- Phantom waiver detection
- Severity mismatch detection
- Approver format validation
- Scorecard determinism (no timestamps, stable output)
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
    validate_waiver,
    validate_matrix_header,
    validate_evidence_artifact,
    is_waiver_valid,
    is_waiver_expiring_soon,
    normalize_gap_id,
    WAIVER_WARNING_DAYS,
    GAP_ID_PATTERN,
    LEGACY_GAP_ID_PATTERN,
)
from generate_scorecard import generate_scorecard


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
            | G001 | Test gap one | Production-blocking | test/test_file.py | repo | V2 | Tests pass |
            | G002 | Test gap two | Launch-risk | .github/workflows/ci.yml | infra | V2 | CI green |
        """)
        )

        gaps = parse_gap_matrix(matrix)

        assert len(gaps) == 2
        assert gaps[0].id == "G001"
        assert gaps[0].severity == "Production-blocking"
        assert gaps[0].owner == "repo"
        assert gaps[1].id == "G002"
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


class TestMatrixHeaderValidation:
    """Tests for GAP_MATRIX.md header validation."""

    def test_valid_header(self) -> None:
        """Valid header passes validation."""
        content = dedent("""
            # Gap Matrix

            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
        """)
        errors = validate_matrix_header(content)
        assert errors == []

    def test_missing_header(self) -> None:
        """Missing header triggers error."""
        content = "# Just a title\nNo table here."
        errors = validate_matrix_header(content)
        assert len(errors) == 1
        assert "No table header found" in errors[0]

    def test_wrong_column_name(self) -> None:
        """Wrong column name triggers error."""
        content = dedent("""
            | ID | Gap | Priority | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
        """)
        errors = validate_matrix_header(content)
        assert len(errors) == 1
        assert "Column 3 is 'Priority'" in errors[0]


class TestEvidenceValidation:
    """Tests for evidence artifact validation."""

    def test_file_path_valid(self) -> None:
        """File path with / and . is valid."""
        assert validate_evidence_artifact("api/auth.py") is True
        assert validate_evidence_artifact("tests/test_auth.py") is True
        assert validate_evidence_artifact(".github/workflows/ci.yml") is True

    def test_test_name_valid(self) -> None:
        """Test name with test_ is valid."""
        assert validate_evidence_artifact("test_auth") is True
        assert validate_evidence_artifact("tests/test_auth.py::test_foo") is True

    def test_ci_lane_valid(self) -> None:
        """Known CI lane names are valid."""
        assert validate_evidence_artifact("ci.yml:unit") is True
        assert validate_evidence_artifact("fg-fast") is True
        assert validate_evidence_artifact("ci-integration") is True

    def test_empty_invalid(self) -> None:
        """Empty evidence is invalid."""
        assert validate_evidence_artifact("") is False
        assert validate_evidence_artifact("   ") is False

    def test_plain_text_invalid(self) -> None:
        """Plain text without artifact reference is invalid."""
        assert validate_evidence_artifact("TODO") is False
        assert validate_evidence_artifact("needs implementation") is False


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
            | G002 | Launch-risk | Business decision | Alice Smith | 2099-12-31 | 2099-12-01 |
        """)
        )

        result = parse_waivers(waivers)

        assert len(result) == 1
        assert result[0].gap_id == "G002"
        assert result[0].approved_by == "Alice Smith"
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
            id="G001",
            description="Test",
            severity="Production-blocking",
            evidence="tests/test_auth.py",
            owner="repo",
            eta="V2",
            definition_of_done="Tests pass",
        )
        errors = validate_gap(gap)
        assert errors == []

    def test_invalid_id_format(self) -> None:
        """Invalid ID format fails validation."""
        gap = Gap(
            id="GAP-001",  # Invalid: should be G001
            description="Test",
            severity="Production-blocking",
            evidence="tests/test_auth.py",
            owner="repo",
            eta="V2",
            definition_of_done="Tests pass",
        )
        errors = validate_gap(gap)
        assert len(errors) >= 1
        assert any("Invalid ID format" in e for e in errors)

    def test_invalid_severity(self) -> None:
        """Invalid severity fails validation."""
        gap = Gap(
            id="G001",
            description="Test",
            severity="Critical",  # Invalid
            evidence="tests/test_auth.py",
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
            id="G001",
            description="Test",
            severity="Launch-risk",
            evidence="tests/test_auth.py",
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
            id="G001",
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

    def test_invalid_evidence_artifact(self) -> None:
        """Evidence without repo artifact fails validation."""
        gap = Gap(
            id="G001",
            description="Test",
            severity="Launch-risk",
            evidence="TODO",  # Invalid: no file path, test name, or CI lane
            owner="repo",
            eta="V2",
            definition_of_done="Tests pass",
        )
        errors = validate_gap(gap)
        assert len(errors) == 1
        assert "repo-backed artifact" in errors[0]

    def test_missing_description(self) -> None:
        """Missing description fails validation."""
        gap = Gap(
            id="G001",
            description="",  # Missing
            severity="Launch-risk",
            evidence="tests/test_auth.py",
            owner="repo",
            eta="V2",
            definition_of_done="Tests pass",
        )
        errors = validate_gap(gap)
        assert len(errors) == 1
        assert "description is required" in errors[0]

    def test_missing_eta(self) -> None:
        """Missing ETA fails validation."""
        gap = Gap(
            id="G001",
            description="Test",
            severity="Launch-risk",
            evidence="tests/test_auth.py",
            owner="repo",
            eta="",  # Missing
            definition_of_done="Tests pass",
        )
        errors = validate_gap(gap)
        assert len(errors) == 1
        assert "ETA / Milestone is required" in errors[0]


class TestValidateWaiver:
    """Tests for waiver validation."""

    def test_phantom_waiver_fails(self) -> None:
        """Waiver for non-existent gap fails validation."""
        waiver = Waiver(
            gap_id="G999",  # Does not exist
            severity="Launch-risk",
            reason="Business",
            approved_by="Alice Smith",
            expiration="2099-12-31",
            review_date="2099-12-01",
        )
        gap_lookup: dict[str, Gap] = {}  # Empty - no gaps
        errors = validate_waiver(waiver, gap_lookup)
        assert len(errors) == 1
        assert "does not exist" in errors[0]
        assert "phantom waiver" in errors[0]

    def test_severity_mismatch_fails(self) -> None:
        """Waiver with mismatched severity fails validation."""
        gap = Gap(
            id="G001",
            description="Test",
            severity="Post-launch",  # Gap is Post-launch
            evidence="tests/test_auth.py",
            owner="repo",
            eta="V2",
            definition_of_done="Tests pass",
        )
        waiver = Waiver(
            gap_id="G001",
            severity="Launch-risk",  # Waiver says Launch-risk
            reason="Business",
            approved_by="Alice Smith",
            expiration="2099-12-31",
            review_date="2099-12-01",
        )
        gap_lookup = {"G001": gap}
        errors = validate_waiver(waiver, gap_lookup)
        assert len(errors) == 1
        assert "Severity mismatch" in errors[0]

    def test_invalid_approver_format(self) -> None:
        """Approver without @, /, or space fails validation."""
        gap = Gap(
            id="G001",
            description="Test",
            severity="Launch-risk",
            evidence="tests/test_auth.py",
            owner="repo",
            eta="V2",
            definition_of_done="Tests pass",
        )
        waiver = Waiver(
            gap_id="G001",
            severity="Launch-risk",
            reason="Business",
            approved_by="alice",  # No @, /, or space
            expiration="2099-12-31",
            review_date="2099-12-01",
        )
        gap_lookup = {"G001": gap}
        errors = validate_waiver(waiver, gap_lookup)
        assert len(errors) == 1
        assert "human identifier format" in errors[0]

    def test_valid_approver_formats(self) -> None:
        """Valid approver formats pass validation."""
        gap = Gap(
            id="G001",
            description="Test",
            severity="Launch-risk",
            evidence="tests/test_auth.py",
            owner="repo",
            eta="V2",
            definition_of_done="Tests pass",
        )

        # Test with @
        waiver = Waiver(
            gap_id="G001",
            severity="Launch-risk",
            reason="Business",
            approved_by="alice@company.com",
            expiration="2099-12-31",
            review_date="2099-12-01",
        )
        errors = validate_waiver(waiver, {"G001": gap})
        assert errors == []

        # Test with /
        waiver.approved_by = "security/alice"
        errors = validate_waiver(waiver, {"G001": gap})
        assert errors == []

        # Test with space
        waiver.approved_by = "Alice Smith"
        errors = validate_waiver(waiver, {"G001": gap})
        assert errors == []

    def test_invalid_expiration_date(self) -> None:
        """Invalid expiration date format fails validation."""
        gap = Gap(
            id="G001",
            description="Test",
            severity="Launch-risk",
            evidence="tests/test_auth.py",
            owner="repo",
            eta="V2",
            definition_of_done="Tests pass",
        )
        waiver = Waiver(
            gap_id="G001",
            severity="Launch-risk",
            reason="Business",
            approved_by="Alice Smith",
            expiration="12/31/2099",  # Invalid format
            review_date="2099-12-01",
        )
        gap_lookup = {"G001": gap}
        errors = validate_waiver(waiver, gap_lookup)
        assert len(errors) == 1
        assert "not a valid ISO date" in errors[0]


class TestWaiverValidity:
    """Tests for waiver validity checks."""

    def test_valid_waiver(self) -> None:
        """Waiver with future expiration is valid."""
        waiver = Waiver(
            gap_id="G001",
            severity="Launch-risk",
            reason="Test",
            approved_by="Alice Smith",
            expiration="2099-12-31",
            review_date="2099-12-01",
        )
        today = datetime(2024, 1, 1)
        assert is_waiver_valid(waiver, today) is True

    def test_expired_waiver(self) -> None:
        """Waiver with past expiration is invalid."""
        waiver = Waiver(
            gap_id="G001",
            severity="Launch-risk",
            reason="Test",
            approved_by="Alice Smith",
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
            gap_id="G001",
            severity="Launch-risk",
            reason="Test",
            approved_by="Alice Smith",
            expiration=soon.strftime("%Y-%m-%d"),
            review_date="2024-01-01",
        )
        assert is_waiver_expiring_soon(waiver, today) is True

    def test_waiver_not_expiring_soon(self) -> None:
        """Waiver expiring far in future does not trigger warning."""
        waiver = Waiver(
            gap_id="G001",
            severity="Launch-risk",
            reason="Test",
            approved_by="Alice Smith",
            expiration="2099-12-31",
            review_date="2099-12-01",
        )
        today = datetime(2024, 1, 1)
        assert is_waiver_expiring_soon(waiver, today) is False


class TestRunGapAudit:
    """Integration tests for run_gap_audit."""

    def test_production_blocking_gap_fails(self, tmp_path: Path) -> None:
        """Production-blocking gap causes audit failure (CI MUST fail)."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | G001 | Cross-tenant access | Production-blocking | tests/test_tenant.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        result = run_gap_audit(matrix, waivers)

        assert len(result.blocking_gaps) == 1
        assert result.blocking_gaps[0].id == "G001"
        # This MUST cause CI to fail (exit code 1)

    def test_launch_risk_gap_warns(self, tmp_path: Path) -> None:
        """Launch-risk gap passes with warning (assert warning text)."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | G001 | Minor issue | Launch-risk | tests/test_minor.py | repo | V2 | Fixed |
            | G002 | UX tweak | Post-launch | console/ui.tsx | docs | V2+ | Done |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        result = run_gap_audit(matrix, waivers)

        # Does NOT block
        assert len(result.blocking_gaps) == 0
        # Warning only for launch-risk
        assert len(result.launch_risk_gaps) == 1
        assert result.launch_risk_gaps[0].id == "G001"
        assert result.launch_risk_gaps[0].severity == "Launch-risk"

    def test_post_launch_gaps_informational(self, tmp_path: Path) -> None:
        """Post-launch gaps are informational only."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | G001 | Future improvement | Post-launch | tests/test_future.py | repo | V2+ | Done |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        result = run_gap_audit(matrix, waivers)

        assert len(result.blocking_gaps) == 0
        assert len(result.launch_risk_gaps) == 0
        assert len(result.post_launch_gaps) == 1
        assert result.post_launch_gaps[0].id == "G001"

    def test_phantom_waiver_fails(self, tmp_path: Path) -> None:
        """Waiver for non-existent gap triggers validation error (CI MUST fail)."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | G001 | Real gap | Launch-risk | tests/test_real.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text(
            dedent("""
            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | G999 | Launch-risk | Phantom | Alice Smith | 2099-12-31 | 2099-12-01 |
        """)
        )

        result = run_gap_audit(matrix, waivers)

        assert len(result.validation_errors) >= 1
        assert any("does not exist" in e for e in result.validation_errors)
        assert any("phantom" in e.lower() for e in result.validation_errors)

    def test_mismatched_severity_waiver_fails(self, tmp_path: Path) -> None:
        """Waiver with severity mismatch triggers validation error (CI MUST fail)."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | G001 | Test gap | Post-launch | tests/test_gap.py | repo | V2+ | Done |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text(
            dedent("""
            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | G001 | Launch-risk | Business | Alice Smith | 2099-12-31 | 2099-12-01 |
        """)
        )

        result = run_gap_audit(matrix, waivers)

        assert len(result.validation_errors) >= 1
        assert any("Severity mismatch" in e for e in result.validation_errors)

    def test_expired_waiver_fails(self, tmp_path: Path) -> None:
        """Expired waiver causes audit failure (CI MUST fail)."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | G001 | Issue | Launch-risk | tests/test_issue.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text(
            dedent("""
            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | G001 | Launch-risk | Old waiver | Alice Smith | 2020-01-01 | 2019-12-01 |
        """)
        )

        result = run_gap_audit(matrix, waivers, today=datetime(2024, 1, 1))

        # Gap should NOT be waived (waiver expired)
        assert len(result.launch_risk_gaps) == 1
        assert len(result.waived_gaps) == 0
        # Expired waiver should be flagged
        assert len(result.expired_waivers) == 1
        assert result.expired_waivers[0].gap_id == "G001"

    def test_valid_waiver_suppresses_gap(self, tmp_path: Path) -> None:
        """Valid waiver suppresses allowed gaps."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | G001 | Waivable issue | Launch-risk | tests/test_waivable.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text(
            dedent("""
            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | G001 | Launch-risk | Business decision | Alice Smith | 2099-12-31 | 2099-12-01 |
        """)
        )

        result = run_gap_audit(matrix, waivers, today=datetime(2024, 1, 1))

        assert len(result.launch_risk_gaps) == 0  # Suppressed
        assert len(result.waived_gaps) == 1
        assert result.waived_gaps[0][0].id == "G001"

    def test_production_blocking_waiver_rejected(self, tmp_path: Path) -> None:
        """Production-blocking gaps cannot be waived (CI MUST fail)."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | G001 | Critical issue | Production-blocking | tests/test_critical.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text(
            dedent("""
            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | G001 | Production-blocking | Attempted waiver | Bob Jones | 2099-12-31 | 2099-12-01 |
        """)
        )

        result = run_gap_audit(matrix, waivers, today=datetime(2024, 1, 1))

        # Gap should still be blocking
        assert len(result.blocking_gaps) == 1
        # Waiver attempt should be flagged as invalid
        assert len(result.invalid_waiver_attempts) == 1

    def test_expiring_soon_waiver_warns(self, tmp_path: Path) -> None:
        """Waivers expiring within 14 days trigger warnings (do not fail)."""
        today = datetime(2024, 1, 1)
        soon = today + timedelta(days=7)

        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | G001 | Issue | Launch-risk | tests/test_issue.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text(
            dedent(f"""
            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | G001 | Launch-risk | Expiring soon | Alice Smith | {soon.strftime("%Y-%m-%d")} | 2024-01-01 |
        """)
        )

        result = run_gap_audit(matrix, waivers, today=today)

        # Waiver still valid
        assert len(result.waived_gaps) == 1
        # But flagged as expiring soon (warning, not failure)
        assert len(result.expiring_soon_waivers) == 1

    def test_duplicate_gap_id_fails(self, tmp_path: Path) -> None:
        """Duplicate gap IDs trigger validation error (CI MUST fail)."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | G001 | First gap | Launch-risk | tests/test_first.py | repo | V2 | Fixed |
            | G001 | Duplicate | Launch-risk | tests/test_dup.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        result = run_gap_audit(matrix, waivers)

        assert len(result.validation_errors) >= 1
        assert any("Duplicate gap ID" in e for e in result.validation_errors)


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
            | G001 | Blocker | Production-blocking | tests/test_blocker.py | repo | V2 | Fixed |
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
            | G001 | Minor | Launch-risk | tests/test_minor.py | repo | V2 | Fixed |
        """)
        )

        waivers = docs_dir / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        monkeypatch.chdir(tmp_path)

        from gap_audit import main

        exit_code = main()

        assert exit_code == 0


class TestGapIdPattern:
    """Tests for gap ID pattern validation."""

    def test_valid_ids(self) -> None:
        """Valid G001-G999 IDs match pattern."""
        assert GAP_ID_PATTERN.match("G001") is not None
        assert GAP_ID_PATTERN.match("G123") is not None
        assert GAP_ID_PATTERN.match("G999") is not None

    def test_invalid_ids(self) -> None:
        """Invalid IDs do not match pattern."""
        assert GAP_ID_PATTERN.match("GAP-001") is None
        assert GAP_ID_PATTERN.match("G1") is None
        assert GAP_ID_PATTERN.match("G0001") is None
        assert GAP_ID_PATTERN.match("g001") is None
        assert GAP_ID_PATTERN.match("001") is None


class TestLegacyGapIdPattern:
    """Tests for legacy GAP-### pattern (backward compatibility)."""

    def test_valid_legacy_ids(self) -> None:
        """Valid legacy GAP-### IDs match pattern."""
        assert LEGACY_GAP_ID_PATTERN.match("GAP-001") is not None
        assert LEGACY_GAP_ID_PATTERN.match("GAP-42") is not None
        assert LEGACY_GAP_ID_PATTERN.match("GAP-999") is not None

    def test_invalid_legacy_ids(self) -> None:
        """Invalid legacy IDs do not match pattern."""
        assert LEGACY_GAP_ID_PATTERN.match("G001") is None
        assert LEGACY_GAP_ID_PATTERN.match("GAP001") is None
        assert LEGACY_GAP_ID_PATTERN.match("gap-001") is None


class TestNormalizeGapId:
    """Tests for gap ID normalization (backward compatibility)."""

    def test_normalize_new_format(self) -> None:
        """New G### format is unchanged."""
        assert normalize_gap_id("G001") == "G001"
        assert normalize_gap_id("G123") == "G123"
        assert normalize_gap_id("G999") == "G999"

    def test_normalize_legacy_format(self) -> None:
        """Legacy GAP-### format normalizes to G###."""
        assert normalize_gap_id("GAP-001") == "G001"
        assert normalize_gap_id("GAP-42") == "G042"
        assert normalize_gap_id("GAP-999") == "G999"
        assert normalize_gap_id("GAP-1") == "G001"

    def test_normalize_strips_whitespace(self) -> None:
        """Whitespace is stripped before normalization."""
        assert normalize_gap_id("  G001  ") == "G001"
        assert normalize_gap_id("  GAP-042  ") == "G042"

    def test_normalize_invalid_unchanged(self) -> None:
        """Invalid IDs are returned as-is (validation will catch)."""
        assert normalize_gap_id("INVALID") == "INVALID"
        assert normalize_gap_id("G0001") == "G0001"
        assert normalize_gap_id("GAP-1000") == "GAP-1000"  # Out of range


class TestBackwardCompatibilityParsing:
    """Tests for backward compatibility with legacy GAP-### IDs."""

    def test_parse_matrix_with_legacy_ids(self, tmp_path: Path) -> None:
        """Legacy GAP-### IDs are normalized to G### when parsing matrix."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            # Gap Matrix

            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | Legacy gap | Launch-risk | tests/test_legacy.py | repo | V2 | Tests pass |
            | G002 | New gap | Post-launch | tests/test_new.py | infra | V2+ | Done |
        """)
        )

        gaps = parse_gap_matrix(matrix)

        assert len(gaps) == 2
        assert gaps[0].id == "G001"  # Normalized from GAP-001
        assert gaps[1].id == "G002"  # Already in new format

    def test_parse_waivers_with_legacy_ids(self, tmp_path: Path) -> None:
        """Legacy GAP-### IDs are normalized to G### when parsing waivers."""
        waivers_file = tmp_path / "RISK_WAIVERS.md"
        waivers_file.write_text(
            dedent("""
            # Risk Waivers

            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | GAP-001 | Launch-risk | Business | Alice Smith | 2099-12-31 | 2099-12-01 |
        """)
        )

        waivers = parse_waivers(waivers_file)

        assert len(waivers) == 1
        assert waivers[0].gap_id == "G001"  # Normalized from GAP-001

    def test_audit_accepts_legacy_ids(self, tmp_path: Path) -> None:
        """Gap audit accepts legacy GAP-### IDs and normalizes them."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | Legacy gap | Launch-risk | tests/test_legacy.py | repo | V2 | Tests pass |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        result = run_gap_audit(matrix, waivers)

        # Should be parsed and normalized successfully
        assert len(result.launch_risk_gaps) == 1
        assert result.launch_risk_gaps[0].id == "G001"
        # No validation errors about ID format
        assert not any("Invalid ID format" in e for e in result.validation_errors)

    def test_duplicate_detection_with_mixed_ids(self, tmp_path: Path) -> None:
        """Duplicate IDs are detected even with mixed GAP-### and G### formats."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | First gap | Launch-risk | tests/test_first.py | repo | V2 | Fixed |
            | G001 | Duplicate | Launch-risk | tests/test_dup.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        result = run_gap_audit(matrix, waivers)

        # Should detect duplicate after normalization
        assert len(result.validation_errors) >= 1
        assert any("Duplicate gap ID" in e for e in result.validation_errors)

    def test_waiver_matches_legacy_gap(self, tmp_path: Path) -> None:
        """Waiver with legacy ID matches gap with new ID format."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | G001 | Gap in new format | Launch-risk | tests/test_gap.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text(
            dedent("""
            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | GAP-001 | Launch-risk | Business | Alice Smith | 2099-12-31 | 2099-12-01 |
        """)
        )

        result = run_gap_audit(matrix, waivers, today=datetime(2024, 1, 1))

        # Waiver should match despite different formats
        assert len(result.waived_gaps) == 1
        assert result.waived_gaps[0][0].id == "G001"


class TestScorecardDeterminism:
    """Tests for scorecard determinism (no timestamps, stable output)."""

    def test_scorecard_no_timestamps(self, tmp_path: Path) -> None:
        """Scorecard output contains NO timestamps."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | G001 | Test gap | Launch-risk | tests/test_gap.py | repo | V2 | Done |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        content = generate_scorecard(matrix, waivers)

        # Check for common timestamp patterns
        import re

        # ISO timestamps
        assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", content) is None
        # Unix timestamps
        assert re.search(r"\d{10,13}", content) is None
        # "Generated at" or similar phrases
        assert "generated at" not in content.lower()
        assert "timestamp" not in content.lower()

    def test_scorecard_stable_across_runs(self, tmp_path: Path) -> None:
        """Scorecard is stable across two consecutive runs."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | G001 | Test gap one | Launch-risk | tests/test_one.py | repo | V2 | Done |
            | G002 | Test gap two | Post-launch | tests/test_two.py | infra | V2+ | Done |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        run1 = generate_scorecard(matrix, waivers)
        run2 = generate_scorecard(matrix, waivers)

        assert run1 == run2, (
            "Scorecard output differs between runs - NOT deterministic!"
        )
