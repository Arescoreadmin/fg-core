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
    parse_gap_ids,
    parse_waivers,
    run_gate,
    validate_align_map,
    validate_waivers,
)

FIXED_TODAY = "2026-02-01"


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
# Unit tests: parsing
# ---------------------------------------------------------------------------


class TestParseGapIds:
    def test_extracts_gap_ids(self) -> None:
        text = dedent("""\
            | ID | Gap | Severity |
            |----|-----|----------|
            | G001 | First gap | Launch-risk |
            | G042 | Second gap | Post-launch |
        """)
        assert parse_gap_ids(text) == {"G001", "G042"}

    def test_ignores_non_gap_rows(self) -> None:
        text = dedent("""\
            | ID | Gap |
            |----|-----|
            | header | not a gap |
            | G001 | Real gap |
        """)
        assert parse_gap_ids(text) == {"G001"}

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

    def test_empty_waivers(self) -> None:
        text = "# No waivers"
        assert parse_waivers(text) == []


# ---------------------------------------------------------------------------
# Unit tests: validation
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
        errors = validate_waivers(waivers, {"G001"}, today)
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
        errors = validate_waivers(waivers, {"G001"}, today)
        assert any("G999" in e and "not found" in e for e in errors)

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
        errors = validate_waivers(waivers, {"G001"}, today)
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
        errors = validate_waivers(waivers, {"G001"}, today)
        assert any("approver" in e.lower() for e in errors)


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

    def test_no_waivers_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Empty waivers table + correct align map = PASS."""
        monkeypatch.setenv("FG_GATE_TODAY", FIXED_TODAY)
        _write_gap_matrix(
            tmp_path,
            "| G001 | Auth fallback | Launch-risk | docker-compose.yml | repo | V2 | Fixed |",
        )
        _write_waivers(tmp_path)
        _write_align_map(tmp_path)

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is True
        assert report["gate_id"] == "BP-C-001"
        assert report["waivers_checked"] == 0
        assert report["errors"] == []
        assert report["today"] == FIXED_TODAY

    def test_valid_waiver_expires_today_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Waiver with expires_on == today should PASS (not expired yet)."""
        monkeypatch.setenv("FG_GATE_TODAY", FIXED_TODAY)
        _write_gap_matrix(
            tmp_path,
            "| G001 | Auth fallback | Launch-risk | docker-compose.yml | repo | V2 | Fixed |",
        )
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
        _write_gap_matrix(
            tmp_path,
            "| G001 | Auth fallback | Launch-risk | docker-compose.yml | repo | V2 | Fixed |",
        )
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
        _write_gap_matrix(
            tmp_path,
            "| G001 | Auth fallback | Launch-risk | docker-compose.yml | repo | V2 | Fixed |",
        )
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
        _write_gap_matrix(
            tmp_path,
            "| G001 | Auth fallback | Launch-risk | docker-compose.yml | repo | V2 | Fixed |",
        )
        _write_waivers(tmp_path)
        _write_align_map(tmp_path, "MISSING")

        passed, report = run_gate(repo_root=tmp_path)
        assert passed is False
        assert any("BP-C-001" in e for e in report["errors"])

    def test_name_email_approver_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Approver in 'Name <email>' format should pass."""
        monkeypatch.setenv("FG_GATE_TODAY", FIXED_TODAY)
        _write_gap_matrix(
            tmp_path,
            "| G001 | Auth fallback | Launch-risk | docker-compose.yml | repo | V2 | Fixed |",
        )
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
        _write_gap_matrix(
            tmp_path,
            "| G001 | Auth fallback | Launch-risk | docker-compose.yml | repo | V2 | Fixed |",
        )
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
        _write_gap_matrix(tmp_path)
        _write_waivers(tmp_path)
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
