#!/usr/bin/env python3
"""BP-C-001 gate: Exceptions workflow (time-boxed, approved).

Validates docs/RISK_WAIVERS.md against docs/GAP_MATRIX.md:
- Every waiver must reference an existing gap ID in GAP_MATRIX.
- Every waiver must have required fields: gap_id, severity, approver, expires_on, reason.
- Approver must match strict format: "Name <email>" OR "handle@domain".
- Expiration must be YYYY-MM-DD and not expired relative to deterministic today.
- tools/align_score_map.json must map BP-C-001 to "make bp-c-001-gate".

Determinism: uses FG_GATE_TODAY env var (YYYY-MM-DD) if set, else UTC date.
Outputs: artifacts/gates/bp_c_001_report.json
Exit code: 0 if passed, 1 if failed.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Deterministic "today"
# ---------------------------------------------------------------------------


def get_today() -> datetime:
    """Return today as a date, using FG_GATE_TODAY env var if set."""
    env_today = os.environ.get("FG_GATE_TODAY", "").strip()
    if env_today:
        return datetime.strptime(env_today, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

_GAP_ID_RE = re.compile(r"^G\d{3}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_APPROVER_NAME_EMAIL_RE = re.compile(r"^.+ <[^@<>\s]+@[^@<>\s]+>$")
_APPROVER_HANDLE_RE = re.compile(r"^[^@\s]+@[^@\s]+$")

EXPECTED_ALIGN_VALUE = "make bp-c-001-gate"


def _parse_table_rows(text: str) -> list[list[str]]:
    """Parse markdown table rows, skipping header separator lines."""
    rows: list[list[str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        # Skip separator lines like |---|---|
        if re.match(r"^\|[\s\-|]+\|$", stripped):
            continue
        cells = [c.strip() for c in stripped.split("|")]
        # split("|") produces empty strings at start/end for "|a|b|"
        cells = [c for c in cells if c != "" or len(cells) <= 2]
        if cells and cells[0] == "":
            cells = cells[1:]
        if cells and cells[-1] == "":
            cells = cells[:-1]
        if cells:
            rows.append(cells)
    return rows


def parse_gap_ids(gap_matrix_text: str) -> set[str]:
    """Extract all gap IDs from GAP_MATRIX.md table."""
    ids: set[str] = set()
    rows = _parse_table_rows(gap_matrix_text)
    for row in rows:
        if not row:
            continue
        candidate = row[0].strip().strip("`")
        if _GAP_ID_RE.match(candidate):
            ids.add(candidate)
    return ids


def parse_waivers(waivers_text: str) -> list[dict[str, str]]:
    """Parse waivers from RISK_WAIVERS.md table.

    Expected columns: Gap ID | Severity | Reason | Approved By | Expiration | Review Date
    """
    rows = _parse_table_rows(waivers_text)
    waivers: list[dict[str, str]] = []
    for row in rows:
        if len(row) < 6:
            continue
        gap_id = row[0].strip().strip("`")
        if not _GAP_ID_RE.match(gap_id):
            continue
        waivers.append(
            {
                "gap_id": gap_id,
                "severity": row[1].strip(),
                "reason": row[2].strip(),
                "approver": row[3].strip(),
                "expires_on": row[4].strip(),
                "review_date": row[5].strip(),
            }
        )
    return waivers


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_waivers(
    waivers: list[dict[str, str]],
    gap_ids: set[str],
    today: datetime,
) -> list[str]:
    """Validate each waiver. Returns list of error strings (empty = all OK)."""
    errors: list[str] = []

    for i, w in enumerate(waivers, start=1):
        prefix = f"waiver #{i} (gap_id={w.get('gap_id', '?')})"

        # Required fields
        for field in ("gap_id", "severity", "approver", "expires_on", "reason"):
            val = w.get(field, "").strip()
            if not val:
                errors.append(f"{prefix}: missing required field '{field}'")

        gap_id = w.get("gap_id", "").strip()
        # gap_id must exist in GAP_MATRIX
        if gap_id and gap_id not in gap_ids:
            errors.append(f"{prefix}: gap_id '{gap_id}' not found in GAP_MATRIX.md")

        # expires_on must parse as YYYY-MM-DD and be >= today
        expires_on_str = w.get("expires_on", "").strip()
        if expires_on_str:
            if not _DATE_RE.match(expires_on_str):
                errors.append(
                    f"{prefix}: expires_on '{expires_on_str}' is not YYYY-MM-DD"
                )
            else:
                try:
                    exp_date = datetime.strptime(expires_on_str, "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    )
                    if exp_date < today:
                        errors.append(
                            f"{prefix}: expired on {expires_on_str} (today={today.strftime('%Y-%m-%d')})"
                        )
                except ValueError:
                    errors.append(
                        f"{prefix}: expires_on '{expires_on_str}' failed to parse"
                    )

        # approver must match strict regex
        approver = w.get("approver", "").strip()
        if approver:
            if not (
                _APPROVER_NAME_EMAIL_RE.match(approver)
                or _APPROVER_HANDLE_RE.match(approver)
            ):
                errors.append(
                    f"{prefix}: approver '{approver}' does not match "
                    f"'Name <email>' or 'handle@domain' format"
                )

    return errors


def validate_align_map(align_map_path: Path) -> list[str]:
    """Validate that align_score_map.json maps BP-C-001 correctly."""
    errors: list[str] = []
    if not align_map_path.exists():
        errors.append(f"align_score_map.json not found at {align_map_path}")
        return errors

    try:
        data = json.loads(align_map_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        errors.append(f"align_score_map.json parse error: {exc}")
        return errors

    actual = data.get("BP-C-001")
    if actual != EXPECTED_ALIGN_VALUE:
        errors.append(
            f"align_score_map.json BP-C-001 must be '{EXPECTED_ALIGN_VALUE}', "
            f"got '{actual}'"
        )
    return errors


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def generate_report(
    *,
    passed: bool,
    today: datetime,
    gap_matrix_path: str,
    waivers_path: str,
    align_map_path: str,
    waivers_checked: int,
    errors: list[str],
) -> dict:
    """Build the JSON report structure."""
    return {
        "gate_id": "BP-C-001",
        "passed": passed,
        "today": today.strftime("%Y-%m-%d"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "checked_files": {
            "gap_matrix": gap_matrix_path,
            "risk_waivers": waivers_path,
            "align_map": align_map_path,
        },
        "waivers_checked": waivers_checked,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def run_gate(
    *,
    repo_root: Path | None = None,
) -> tuple[bool, dict]:
    """Run BP-C-001 gate. Returns (passed, report_dict)."""
    if repo_root is None:
        repo_root = Path(__file__).resolve().parent.parent

    gap_matrix_path = repo_root / "docs" / "GAP_MATRIX.md"
    waivers_path = repo_root / "docs" / "RISK_WAIVERS.md"
    align_map_path = repo_root / "tools" / "align_score_map.json"

    today = get_today()
    all_errors: list[str] = []

    # --- Read gap matrix ---
    if not gap_matrix_path.exists():
        all_errors.append(f"GAP_MATRIX.md not found at {gap_matrix_path}")
        gap_ids: set[str] = set()
    else:
        gap_ids = parse_gap_ids(gap_matrix_path.read_text(encoding="utf-8"))

    # --- Read waivers ---
    if not waivers_path.exists():
        all_errors.append(f"RISK_WAIVERS.md not found at {waivers_path}")
        waivers: list[dict[str, str]] = []
    else:
        waivers = parse_waivers(waivers_path.read_text(encoding="utf-8"))

    # --- Validate waivers ---
    waiver_errors = validate_waivers(waivers, gap_ids, today)
    all_errors.extend(waiver_errors)

    # --- Validate align map ---
    align_errors = validate_align_map(align_map_path)
    all_errors.extend(align_errors)

    passed = len(all_errors) == 0
    report = generate_report(
        passed=passed,
        today=today,
        gap_matrix_path=str(gap_matrix_path),
        waivers_path=str(waivers_path),
        align_map_path=str(align_map_path),
        waivers_checked=len(waivers),
        errors=all_errors,
    )
    return passed, report


def main() -> int:
    """CLI entry point."""
    passed, report = run_gate()

    # Write artifact
    repo_root = Path(__file__).resolve().parent.parent
    gates_dir = repo_root / "artifacts" / "gates"
    gates_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = gates_dir / "bp_c_001_report.json"
    artifact_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    # Print summary
    if passed:
        print(f"BP-C-001 gate: PASS ({report['waivers_checked']} waivers checked)")
    else:
        print(f"BP-C-001 gate: FAIL ({len(report['errors'])} errors)")
        for err in report["errors"]:
            print(f"  - {err}")

    print(f"Report: {artifact_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
