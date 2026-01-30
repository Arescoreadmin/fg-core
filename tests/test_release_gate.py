"""Tests for release_gate.py enforcement.

These tests verify:
- release-gate blocks when Production-blocking gaps exist
- release-gate blocks when Production Readiness < 100%
- release-gate passes when all blocking conditions cleared
- expired waivers block release
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path
from textwrap import dedent

import pytest

# Add scripts to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from release_gate import (
    calculate_readiness_score,
    run_release_gate,
)


class TestReadinessScore:
    """Tests for readiness score calculation."""

    def test_full_readiness_no_gaps(self) -> None:
        """No gaps = 100% readiness."""
        score = calculate_readiness_score(open_count=0, total_count=0)
        assert score == 100.0

    def test_full_readiness_all_closed(self) -> None:
        """All gaps closed = 100% readiness."""
        score = calculate_readiness_score(open_count=0, total_count=5)
        assert score == 100.0

    def test_partial_readiness(self) -> None:
        """Some open gaps = partial readiness."""
        score = calculate_readiness_score(open_count=2, total_count=5)
        assert score == 60.0

    def test_zero_readiness(self) -> None:
        """All gaps open = 0% readiness."""
        score = calculate_readiness_score(open_count=5, total_count=5)
        assert score == 0.0


class TestReleaseGate:
    """Integration tests for release gate."""

    def test_blocks_on_production_blocking_gap(self, tmp_path: Path) -> None:
        """Release blocked when Production-blocking gaps exist."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | Critical issue | Production-blocking | test.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        passed, summary = run_release_gate(matrix, waivers)

        assert passed is False
        assert "BLOCKED" in summary
        assert "Production-blocking gap" in summary

    def test_passes_with_no_blocking_gaps(self, tmp_path: Path) -> None:
        """Release passes when no Production-blocking gaps exist."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | Minor issue | Launch-risk | test.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        passed, summary = run_release_gate(matrix, waivers)

        assert passed is True
        assert "PASSED" in summary

    def test_blocks_on_expired_waiver(self, tmp_path: Path) -> None:
        """Release blocked when waivers are expired."""
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
            | GAP-001 | Launch-risk | Expired | Alice | 2020-01-01 | 2019-12-01 |
        """)
        )

        passed, summary = run_release_gate(matrix, waivers, today=datetime(2024, 1, 1))

        assert passed is False
        assert "expired waiver" in summary.lower()

    def test_blocks_on_invalid_waiver_attempt(self, tmp_path: Path) -> None:
        """Release blocked when Production-blocking waiver attempted."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | Critical | Production-blocking | test.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text(
            dedent("""
            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | GAP-001 | Production-blocking | Illegal | Bob | 2099-12-31 | 2099-12-01 |
        """)
        )

        passed, summary = run_release_gate(matrix, waivers, today=datetime(2024, 1, 1))

        assert passed is False
        assert "invalid waiver" in summary.lower()

    def test_shows_readiness_scores(self, tmp_path: Path) -> None:
        """Summary includes readiness scores."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | Minor | Launch-risk | test.py | repo | V2 | Fixed |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        passed, summary = run_release_gate(matrix, waivers)

        assert "Production Readiness: 100.0%" in summary
        assert "Launch Readiness:" in summary

    def test_warns_on_launch_risk_gaps(self, tmp_path: Path) -> None:
        """Summary lists Launch-risk gaps as warnings."""
        matrix = tmp_path / "GAP_MATRIX.md"
        matrix.write_text(
            dedent("""
            | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
            |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
            | GAP-001 | Risk A | Launch-risk | a.py | repo | V2 | Fixed |
            | GAP-002 | Risk B | Launch-risk | b.py | infra | V2 | Done |
        """)
        )
        waivers = tmp_path / "RISK_WAIVERS.md"
        waivers.write_text("# No waivers")

        passed, summary = run_release_gate(matrix, waivers)

        assert passed is True  # Launch-risk doesn't block
        assert "GAP-001" in summary
        assert "GAP-002" in summary

    def test_warns_on_expiring_waivers(self, tmp_path: Path) -> None:
        """Summary warns about waivers expiring soon."""
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

        passed, summary = run_release_gate(matrix, waivers, today=today)

        assert passed is True  # Still valid
        assert "EXPIRING" in summary.upper()


class TestReleaseGateCLI:
    """Tests for release_gate.py CLI behavior."""

    def test_cli_returns_nonzero_on_block(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CLI returns non-zero exit code when release blocked."""
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

        monkeypatch.chdir(tmp_path)

        from release_gate import main

        exit_code = main()

        assert exit_code == 1

    def test_cli_returns_zero_on_pass(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CLI returns zero exit code when release passes."""
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

        from release_gate import main

        exit_code = main()

        assert exit_code == 0

    def test_cli_fails_on_missing_matrix(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CLI returns non-zero when GAP_MATRIX.md is missing."""
        # Create empty docs dir (no matrix)
        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()

        monkeypatch.chdir(tmp_path)

        from release_gate import main

        exit_code = main()

        assert exit_code == 1
