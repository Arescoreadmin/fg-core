#!/usr/bin/env python3
"""Release gate enforcement for FrostGate production releases.

This script provides a hard block on releases:
- Runs gap_audit
- Fails release if ANY Production-blocking gaps exist
- Fails release if Production Readiness < 100%
- Outputs single-screen failure summary

FAIL-CLOSED: No release without explicit pass.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

from gap_audit import (
    parse_gap_matrix,
    run_gap_audit,
)


def calculate_readiness_score(
    open_count: int,
    total_count: int,
) -> float:
    """Calculate readiness percentage.

    Returns 100.0 if no gaps of this severity exist (vacuously true).
    """
    if total_count == 0:
        return 100.0
    return ((total_count - open_count) / total_count) * 100.0


def run_release_gate(
    matrix_path: Path,
    waivers_path: Path,
    today: datetime | None = None,
) -> tuple[bool, str]:
    """Run release gate checks.

    Returns:
        Tuple of (passed: bool, summary: str)
    """
    if today is None:
        today = datetime.now()

    lines: list[str] = []

    # Run gap audit
    result = run_gap_audit(matrix_path, waivers_path, today)

    # Parse full matrix to get totals (including closed gaps for scoring)
    # For now, treat all parsed gaps as open (adjust when we have closure tracking)
    all_gaps = parse_gap_matrix(matrix_path)

    # Count by severity (all gaps = total, result gaps = open)
    total_blocking = sum(1 for g in all_gaps if g.severity == "Production-blocking")
    total_launch = sum(1 for g in all_gaps if g.severity == "Launch-risk")

    open_blocking = len(result.blocking_gaps)
    open_launch = len(result.launch_risk_gaps)

    # Calculate scores
    prod_readiness = calculate_readiness_score(open_blocking, total_blocking)
    launch_readiness = calculate_readiness_score(open_launch, total_launch)

    # Build summary
    lines.append("=" * 60)
    lines.append("RELEASE GATE CHECK")
    lines.append("=" * 60)
    lines.append("")

    # Readiness scores
    lines.append("READINESS SCORES:")
    lines.append(f"  Production Readiness: {prod_readiness:.1f}%")
    lines.append(f"  Launch Readiness: {launch_readiness:.1f}%")
    lines.append("")

    # Blocking conditions
    blocking_reasons: list[str] = []

    if result.blocking_gaps:
        blocking_reasons.append(
            f"{len(result.blocking_gaps)} Production-blocking gap(s)"
        )
        lines.append("PRODUCTION-BLOCKING GAPS:")
        for gap in result.blocking_gaps:
            lines.append(f"  - {gap.id}: {gap.description}")
        lines.append("")

    if result.validation_errors:
        blocking_reasons.append(f"{len(result.validation_errors)} validation error(s)")
        lines.append("VALIDATION ERRORS:")
        for error in result.validation_errors:
            lines.append(f"  - {error}")
        lines.append("")

    if result.expired_waivers:
        blocking_reasons.append(f"{len(result.expired_waivers)} expired waiver(s)")
        lines.append("EXPIRED WAIVERS:")
        for waiver in result.expired_waivers:
            lines.append(f"  - {waiver.gap_id}: Expired {waiver.expiration}")
        lines.append("")

    if result.invalid_waiver_attempts:
        blocking_reasons.append(
            f"{len(result.invalid_waiver_attempts)} invalid waiver attempt(s)"
        )
        lines.append("INVALID WAIVER ATTEMPTS:")
        for waiver in result.invalid_waiver_attempts:
            lines.append(f"  - {waiver.gap_id}: Production-blocking cannot be waived")
        lines.append("")

    if prod_readiness < 100.0:
        blocking_reasons.append(f"Production Readiness {prod_readiness:.1f}% < 100%")

    # Warnings (non-blocking)
    if result.expiring_soon_waivers:
        lines.append("WAIVERS EXPIRING SOON:")
        for waiver in result.expiring_soon_waivers:
            lines.append(f"  - {waiver.gap_id}: Expires {waiver.expiration}")
        lines.append("")

    if result.launch_risk_gaps:
        lines.append("LAUNCH-RISK GAPS (not blocking release):")
        for gap in result.launch_risk_gaps:
            lines.append(f"  - {gap.id}: {gap.description}")
        lines.append("")

    # Final verdict
    lines.append("-" * 60)

    passed = len(blocking_reasons) == 0

    if passed:
        lines.append("RELEASE GATE: PASSED")
        lines.append("")
        lines.append("Release is authorized to proceed.")
    else:
        lines.append("RELEASE GATE: BLOCKED")
        lines.append("")
        lines.append("Release blocked for the following reasons:")
        for reason in blocking_reasons:
            lines.append(f"  - {reason}")
        lines.append("")
        lines.append("ACTION REQUIRED:")
        lines.append("  1. Remediate Production-blocking gaps, OR")
        lines.append("  2. Escalate to leadership with explicit risk acceptance")
        lines.append("")
        lines.append("No release without explicit approval.")

    lines.append("=" * 60)

    return passed, "\n".join(lines)


def main() -> int:
    """Run release gate and return exit code."""
    matrix_path = Path("docs/GAP_MATRIX.md")
    waivers_path = Path("docs/RISK_WAIVERS.md")

    # Check if matrix exists
    if not matrix_path.exists():
        print("=" * 60)
        print("RELEASE GATE: BLOCKED")
        print("=" * 60)
        print()
        print("ERROR: docs/GAP_MATRIX.md not found")
        print("Cannot release without production readiness matrix.")
        print()
        print("FAIL-CLOSED: Release blocked by default.")
        print("=" * 60)
        return 1

    passed, summary = run_release_gate(matrix_path, waivers_path)
    print(summary)

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
