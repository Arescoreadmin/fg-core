"""Tests for BP-C-001 gate: Exceptions workflow (time-boxed, approved).

All tests use tmp_path to create isolated repo-like structures.
FG_GATE_TODAY is always set so tests are deterministic and never time-dependent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from textwrap import dedent

import pytest

# Add scripts to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from verify_bp_c_001 import (
    normalize_gap_id,
    parse_gap_ids,
    parse_waivers,
    run_gate,
    validate_align_map,
    validate_gap_matrix_structure,
    validate_waivers,
    validate_waivers_structure,
)

FIXED_TODAY = "2026-02-01"

# A valid waiver row reusable across tests
_VALID_WAIVER_ROW = (
    "| G001 | Launch-risk | Business need | alice@corp.com | 2026-03-15 | 2026-03-01 |"
)
_VALID_GAP_ROW = (
    "| G001 | Auth fallback | Launch-risk | docker-compose.yml | repo | V2 | Fixed |"
)


def _write_gap_matrix(tmp_path: Path, rows: str = "") -> Path:
    """Write a minimal GAP_MATRIX.md with optional table rows."""
    content = dedent(f"""\
        # Gap Matrix

        | ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
        |----|-----|----------|----------------------------------|-------|-----------------|--------------------|
        {rows}
    """)
    p = tmp_path / "docs" / "GAP_MATRIX.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _write_waivers(tmp_path: Path, rows: str = "") -> Path:
    """Write a minimal RISK_WAIVERS.md with optional table rows."""
    content = dedent(f"""\
        # Risk Waivers

        | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
        |--------|----------|--------|-------------|------------|-------------|
        {rows}
    """)
    p = tmp_path / "docs" / "RISK_WAIVERS.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _write_waivers_raw(tmp_path: Path, content: str) -> Path:
    """Write raw content to RISK_WAIVERS.md (for malformed-file tests)."""
    p = tmp_path / "docs" / "RISK_WAIVERS.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _write_gap_matrix_raw(tmp_path: Path, content: str) -> Path:
    """Write raw content to GAP_MATRIX.md (for malformed-file tests)."""
    p = tmp_path / "docs" / "GAP_MATRIX.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _write_align_map(
    tmp_path: Path, bp_c_001_value: str = "make bp-c-001-gate"
) -> Path:
    """Write a minimal align_score_map.json."""
    data = {"BP-C-001": bp_c_001_value}
    p = tmp_path / "tools" / "align_score_map.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Unit tests: gap ID normalization
# ---------------------------------------------------------------------------


class TestNormalizeGapId:
    def test_g_format(self) -> None:
        assert normalize_gap_id("G001") == "GAP-001"
        assert normalize_gap_id("G042") == "GAP-042"
        assert normalize_gap_id("G999") == "GAP-999"

    def test_gap_format(self) -> None:
        assert normalize_gap_id("GAP-001") == "GAP-001"
        assert normalize_gap_id("GAP-42") == "GAP-042"

    def test_invalid(self) -> None:
        assert normalize_gap_id("invalid") is None
        assert normalize_gap_id("G1") is None
        assert normalize_gap_id("GAP-0") is None
        assert normalize_gap_id("GAP-1000") is None


# ---------------------------------------------------------------------------
# Unit tests: parsing
# ---------------------------------------------------------------------------


class TestParseGapIds:
    def test_extracts_gap_ids_normalized(self) -> None:
        text = dedent("""\
            | ID | Gap | Severity |
            |----|-----|----------|
            | G001 | First gap | Launch-risk |
            | G042 | Second gap | Post-launch |
        """)
        assert parse_gap_ids(text) == {"GAP-001", "GAP-042"}

    def test_accepts_legacy_format(self) -> None:
        text = dedent("""\
            | ID | Gap | Severity |
            |----|-----|----------|
            | GAP-001 | First gap | Launch-risk |
        """)
        assert parse_gap_ids(text) == {"GAP-001"}

    def test_ignores_non_gap_rows(self) -> None:
        text = dedent("""\
            | ID | Gap |
            |----|-----|
            | header | not a gap |
            | G001 | Real gap |
        """)
        assert parse_gap_ids(text) == {"GAP-001"}

    def test_empty_table(self) -> None:
        text = "# No table here\nJust text."
        assert parse_gap_ids(text) == set()


class TestParseWaivers:
    def test_parses_valid_waiver(self) -> None:
        text = dedent("""\
            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | G001 | Launch-risk | Business need | alice@corp.com | 2026-03-15 | 2026-03-01 |
        """)
        waivers = parse_waivers(text)
        assert len(waivers) == 1
        assert waivers[0]["gap_id"] == "G001"
        assert waivers[0]["approver"] == "alice@corp.com"

    def test_accepts_legacy_gap_format(self) -> None:
        text = dedent("""\
            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | GAP-001 | Launch-risk | Need | bob@corp.com | 2026-03-15 | 2026-03-01 |
        """)
        waivers = parse_waivers(text)
        assert len(waivers) == 1
        assert waivers[0]["gap_id"] == "GAP-001"

    def test_empty_waivers(self) -> None:
        text = "# No waivers"
        assert parse_waivers(text) == []


# ---------------------------------------------------------------------------
# Unit tests: structural validation (fail-closed)
# ---------------------------------------------------------------------------


class TestValidateWaiversStructure:
    def test_valid_structure_passes(self) -> None:
        text = dedent("""\
            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
            | G001 | Launch-risk | Need | alice@corp.com | 2026-03-15 | 2026-03-01 |
        """)
        assert validate_waivers_structure(text) == []

    def test_no_pipe_lines_fails(self) -> None:
        text = "# Risk Waivers\n\nJust some text, no table.\n"
        errors = validate_waivers_structure(text)
        assert len(errors) == 1
        assert "no waiver table found" in errors[0]

    def test_header_but_no_data_rows_fails(self) -> None:
        text = dedent("""\
            | Gap ID | Severity | Reason | Approved By | Expiration | Review Date |
            |--------|----------|--------|-------------|------------|-------------|
        """)
        errors = validate_waivers_structure(text)
        assert len(errors) == 1
        assert "no waiver rows found" in errors[0]

    def test_missing_columns_fails(self) -> None:
        text = dedent("""\
            | Gap ID | Severity |
            |--------|----------|
            | G001 | Launch-risk |
        """)
        errors = validate_waivers_structure(text)
        assert len(errors) == 1
        assert "missing required columns" in errors[0]


class TestValidateGapMatrixStructure:
    def test_valid_structure_passes(self) -> None:
        text = dedent("""\
            | ID | Gap | Severity |
            |----|-----|----------|
            | G001 | Auth | Launch-risk |
        """)
        errors = validate_gap_matrix_structure(text, {"GAP-001"})
        assert errors == []

    def test_no_pipe_lines_fails(self) -> None:
        text = "# Gap Matrix\n\nJust text.\n"
        errors = validate_gap_matrix_structure(text, set())
        assert len(errors) == 1
        assert "no gap table found" in errors[0]

    def test_table_but_no_ids_fails(self) -> None:
        text = dedent("""\
            | ID | Gap | Severity |
            |----|-----|----------|
            | header | not a gap | info |
        """)
        errors = validate_gap_matrix_structure(text, set())
        assert len(errors) == 1
        assert "no gap ids found" in errors[0]


# ---------------------------------------------------------------------------
# Unit tests: waiver validation
# ---------------------------------------------------------------------------


class TestValidateWaivers:
    def test_valid_waiver_passes(self) -> None:
        from datetime import datetime, timezone

        today = datetime(2026, 2, 1, tzinfo=timezone.utc)
        waivers = [
            {
                "gap_id": "G001",
                "severity": "Launch-risk",
                "reason": "Acceptable for MVP",
                "approver": "alice@corp.com",
                "expires_on": "2026-03-15",
                "review_date": "2026-03-01",
            }
        ]
        errors = validate_waivers(waivers, {"GAP-001"}, today)
        assert errors == []

    def test_missing_gap_id_fails(self) -> None:
        from datetime import datetime, timezone

        today = datetime(2026, 2, 1, tzinfo=timezone.utc)
        waivers = [
            {
                "gap_id": "G999",
                "severity": "Launch-risk",
                "reason": "Some reason",
                "approver": "bob@corp.com",
                "expires_on": "2026-03-15",
                "review_date": "2026-03-01",
            }
        ]
        errors = validate_waivers(waivers, {"GAP-001"}, today)
        assert any("G999" in e and "not found" in e for e in errors)
        # Error should include both original and normalized form
        assert any("GAP-999" in e for e in errors)

    def test_expired_waiver_fails(self) -> None:
        from datetime import datetime, timezone

        today = datetime(2026, 2, 1, tzinfo=timezone.utc)
        waivers = [
            {
                "gap_id": "G001",
                "severity": "Launch-risk",
                "reason": "Old waiver",
                "approver": "carol@corp.com",
                "expires_on": "2026-01-15",
                "review_date": "2026-01-01",
            }
        ]
        errors = validate_waivers(waivers, {"GAP-001"}, today)
        assert any("expired" in e.lower() or "expir" in e.lower() for e in errors)

    def test_bad_approver_fails(self) -> None:
        from datetime import datetime, timezone

        today = datetime(2026, 2, 1, tzinfo=timezone.utc)
        waivers = [
            {
                "gap_id": "G001",
                "severity": "Launch-risk",
                "reason": "Some reason",
                "approver": "just a name",
                "expires_on": "2026-03-15",
                "review_date": "2026-03-01",
            }
        ]
        errors = validate_waivers(waivers, {"GAP-001"}, today)
        assert any("approver" in e.lower() for e in errors)

    def test_normalizes_gap_ids_for_comparison(self) -> None:
        """Passing gap_ids as G001 still works (normalized internally)."""
        from datetime import datetime, timezone

        today = datetime(2026, 2, 1, tzinfo=timezone.utc)
        waivers = [
            {
                "gap_id": "G001",
                "severity": "Launch-risk",
                "reason": "Need",
                "approver": "alice@corp.com",
                "expires_on": "2026-03-15",
                "review_date": "2026-03-01",
            }
        ]
        # Pass un-normalized gap_ids — validate_waivers normalizes both sides
        errors = validate_waivers(waivers, {"G001"}, today)
        assert errors == []


class TestValidateAlignMap:
    def test_correct_mapping_passes(self, tmp_path: Path) -> None:
        p = _write_align_map(tmp_path, "make bp-c-001-gate")
        errors = validate_align_map(p)
        assert errors == []

    def test_wrong_mapping_fails(self, tmp_path: Path) -> None:
        p = _write_align_map(tmp_path, "MISSING")
        errors = validate_align_map(p)
        assert len(errors) == 1
        assert "BP-C-001" in errors[0]

    def test_missing_file_fails(self, tmp_path: Path) -> None:
        p = tmp_path / "tools" / "align_score_map.json"
        errors = validate_align_map(p)
        assert len(errors) == 1
        assert "not found" in errors[0]


# ---------------------------------------------------------------------------
# Integration tests: run_gate
# ---------------------------------------------------------------------------


class TestRunGate:
    """Integration tests calling run_gate() with isolated temp repo structures."""

    def test_valid_waiver_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Valid waiver + correct align map = PASS."""
        monkeypatch.setenv("FG_GATE_TODAY", FIXED_TODAY)
        _write_gap_matrix(tmp_path, _VALID_GAP_ROW)
        _write_waivers(tmp_path, _VALID_WAIVER_ROW)
        _write_align_map(tmp_path)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is True
        assert report["gate_id"] == "BP-C-001"
        assert report["waivers_checked"] == 1
        assert report["errors"] == []
        assert report["today"] == FIXED_TODAY

    def test_valid_waiver_expires_today_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Waiver with expires_on == today should PASS (not expired yet)."""
        monkeypatch.setenv("FG_GATE_TODAY", FIXED_TODAY)
        _write_gap_matrix(tmp_path, _VALID_GAP_ROW)
        _write_waivers(
            tmp_path,
            f"| G001 | Launch-risk | Business need | alice@corp.com | {FIXED_TODAY} | 2026-01-15 |",
        )
        _write_align_map(tmp_path)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is True
        assert report["waivers_checked"] == 1
        assert report["errors"] == []

    def test_expired_waiver_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Waiver with expires_on < today should FAIL with expiry error."""
        monkeypatch.setenv("FG_GATE_TODAY", FIXED_TODAY)
        _write_gap_matrix(tmp_path, _VALID_GAP_ROW)
        _write_waivers(
            tmp_path,
            "| G001 | Launch-risk | Old waiver | alice@corp.com | 2026-01-15 | 2026-01-01 |",
        )
        _write_align_map(tmp_path)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert report["waivers_checked"] == 1
        assert any("expir" in e.lower() for e in report["errors"])

    def test_missing_gap_id_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Waiver referencing non-existent gap ID should FAIL."""
        monkeypatch.setenv("FG_GATE_TODAY", FIXED_TODAY)
        _write_gap_matrix(tmp_path, _VALID_GAP_ROW)
        _write_waivers(
            tmp_path,
            "| G999 | Launch-risk | No such gap | alice@corp.com | 2026-03-15 | 2026-03-01 |",
        )
        _write_align_map(tmp_path)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any("G999" in e and "not found" in e for e in report["errors"])

    def test_align_map_mismatch_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Incorrect align_score_map.json mapping should FAIL."""
        monkeypatch.setenv("FG_GATE_TODAY", FIXED_TODAY)
        _write_gap_matrix(tmp_path, _VALID_GAP_ROW)
        _write_waivers(tmp_path, _VALID_WAIVER_ROW)
        _write_align_map(tmp_path, "MISSING")

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any("BP-C-001" in e for e in report["errors"])

    def test_name_email_approver_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Approver in 'Name <email>' format should pass."""
        monkeypatch.setenv("FG_GATE_TODAY", FIXED_TODAY)
        _write_gap_matrix(tmp_path, _VALID_GAP_ROW)
        _write_waivers(
            tmp_path,
            "| G001 | Launch-risk | Business need | Alice Smith <alice@corp.com> | 2026-03-15 | 2026-03-01 |",
        )
        _write_align_map(tmp_path)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is True

    def test_bad_approver_format_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Approver not matching either format should FAIL."""
        monkeypatch.setenv("FG_GATE_TODAY", FIXED_TODAY)
        _write_gap_matrix(tmp_path, _VALID_GAP_ROW)
        _write_waivers(
            tmp_path,
            "| G001 | Launch-risk | Business need | just a name | 2026-03-15 | 2026-03-01 |",
        )
        _write_align_map(tmp_path)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any("approver" in e.lower() for e in report["errors"])

    def test_report_structure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Report JSON has all required keys."""
        monkeypatch.setenv("FG_GATE_TODAY", FIXED_TODAY)
        _write_gap_matrix(tmp_path, _VALID_GAP_ROW)
        _write_waivers(tmp_path, _VALID_WAIVER_ROW)
        _write_align_map(tmp_path)

        passed, report = run_gate(repo_root=tmp_path)
        assert report["gate_id"] == "BP-C-001"
        assert "passed" in report
        assert "today" in report
        assert "generated_at" in report
        assert "checked_files" in report
        assert "waivers_checked" in report
        assert "errors" in report
        assert set(report["checked_files"].keys()) == {
            "gap_matrix",
            "risk_waivers",
            "align_map",
        }


# ---------------------------------------------------------------------------
# Integration tests: fail-closed behavior
# ---------------------------------------------------------------------------


class TestFailClosed:
    """Verify that malformed or empty docs cause explicit gate failures."""

    def test_fails_when_waivers_file_has_no_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RISK_WAIVERS.md with no pipe-delimited lines -> FAIL."""
        monkeypatch.setenv("FG_GATE_TODAY", FIXED_TODAY)
        _write_gap_matrix(tmp_path, _VALID_GAP_ROW)
        _write_waivers_raw(tmp_path, "# Risk Waivers\n\nNo table here, just prose.\n")
        _write_align_map(tmp_path)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert report["errors"]
        assert any("no waiver table found" in e for e in report["errors"])

    def test_fails_when_waivers_table_has_header_but_no_rows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RISK_WAIVERS.md with header + separator but no data rows -> FAIL."""
        monkeypatch.setenv("FG_GATE_TODAY", FIXED_TODAY)
        _write_gap_matrix(tmp_path, _VALID_GAP_ROW)
        # _write_waivers with no rows produces header + separator only
        _write_waivers(tmp_path)
        _write_align_map(tmp_path)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert report["waivers_checked"] == 0
        assert any("no waiver rows found" in e for e in report["errors"])

    def test_fails_when_gap_matrix_has_no_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GAP_MATRIX.md with no pipe-delimited lines -> FAIL."""
        monkeypatch.setenv("FG_GATE_TODAY", FIXED_TODAY)
        _write_gap_matrix_raw(tmp_path, "# Gap Matrix\n\nNo table here.\n")
        _write_waivers(tmp_path, _VALID_WAIVER_ROW)
        _write_align_map(tmp_path)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any("no gap table found" in e for e in report["errors"])

    def test_fails_when_gap_matrix_has_no_ids(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GAP_MATRIX.md with table but no valid gap IDs -> FAIL."""
        monkeypatch.setenv("FG_GATE_TODAY", FIXED_TODAY)
        # Write a gap matrix with header but no valid gap ID rows
        _write_gap_matrix(tmp_path)  # no rows = no gap IDs
        _write_waivers(tmp_path, _VALID_WAIVER_ROW)
        _write_align_map(tmp_path)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any("no gap ids found" in e for e in report["errors"])
