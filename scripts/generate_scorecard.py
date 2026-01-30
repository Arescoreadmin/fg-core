#!/usr/bin/env python3
"""Generate deterministic GAP_SCORECARD.md from GAP_MATRIX.md.

This script produces a reproducible, CI-safe scorecard with:
- Production Readiness %
- Launch Readiness %
- Gap counts by severity and owner

NO timestamps. NO randomness. Deterministic output.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

from gap_audit import parse_gap_matrix, run_gap_audit


def calculate_readiness(open_count: int, total_count: int) -> float:
    """Calculate readiness percentage.

    Readiness = 1 - (open gaps / total gaps)
    Returns 100.0 if no gaps exist (vacuously true).
    """
    if total_count == 0:
        return 100.0
    return ((total_count - open_count) / total_count) * 100.0


def generate_scorecard(
    matrix_path: Path,
    waivers_path: Path,
    today: datetime | None = None,
) -> str:
    """Generate the scorecard markdown content."""
    if today is None:
        today = datetime.now()

    # Run audit to get current state
    result = run_gap_audit(matrix_path, waivers_path, today)

    # Parse all gaps for totals
    all_gaps = parse_gap_matrix(matrix_path)

    # Count by severity
    total_blocking = sum(1 for g in all_gaps if g.severity == "Production-blocking")
    total_launch = sum(1 for g in all_gaps if g.severity == "Launch-risk")
    total_post = sum(1 for g in all_gaps if g.severity == "Post-launch")

    open_blocking = len(result.blocking_gaps)
    open_launch = len(result.launch_risk_gaps)
    open_post = len(result.post_launch_gaps)

    # Count by owner
    owner_counts: dict[str, dict[str, int]] = {
        "repo": {"total": 0, "open": 0},
        "infra": {"total": 0, "open": 0},
        "docs": {"total": 0, "open": 0},
    }

    for gap in all_gaps:
        if gap.owner in owner_counts:
            owner_counts[gap.owner]["total"] += 1

    # Count open gaps by owner
    for gap in result.blocking_gaps + result.launch_risk_gaps + result.post_launch_gaps:
        if gap.owner in owner_counts:
            owner_counts[gap.owner]["open"] += 1

    # Calculate scores
    prod_readiness = calculate_readiness(open_blocking, total_blocking)
    launch_readiness = calculate_readiness(open_launch, total_launch)

    # Build markdown
    lines = [
        "# Gap Scorecard — FrostGate Production Readiness",
        "",
        "> **Deterministic scoring** generated from `docs/GAP_MATRIX.md`.",
        "> Regenerate with: `python scripts/generate_scorecard.py`",
        "",
        "---",
        "",
        "## Readiness Scores",
        "",
        "| Metric | Score | Status |",
        "|--------|-------|--------|",
    ]

    # Production readiness row
    prod_status = "READY" if prod_readiness == 100.0 else "BLOCKED"
    lines.append(f"| Production Readiness | {prod_readiness:.1f}% | {prod_status} |")

    # Launch readiness row
    launch_status = "READY" if launch_readiness == 100.0 else "AT RISK"
    lines.append(f"| Launch Readiness | {launch_readiness:.1f}% | {launch_status} |")

    lines.extend(
        [
            "",
            "### Scoring Rules",
            "",
            "```",
            "Production Readiness = 1 - (open Production-blocking gaps / total Production-blocking gaps)",
            "Launch Readiness = 1 - (open Launch-risk gaps / total Launch-risk gaps)",
            "```",
            "",
            "- **Production Readiness < 100%** → Release BLOCKED",
            "- **Launch Readiness < 100%** → Release proceeds with documented risk",
            "",
            "---",
            "",
            "## Gap Summary by Severity",
            "",
            "| Severity | Open | Waived | Total |",
            "|----------|------|--------|-------|",
        ]
    )

    waived_count = len(result.waived_gaps)
    lines.append(f"| Production-blocking | {open_blocking} | 0 | {total_blocking} |")
    lines.append(f"| Launch-risk | {open_launch} | {waived_count} | {total_launch} |")
    lines.append(f"| Post-launch | {open_post} | 0 | {total_post} |")

    lines.extend(
        [
            "",
            "---",
            "",
            "## Gap Summary by Owner",
            "",
            "| Owner | Open | Total |",
            "|-------|------|-------|",
        ]
    )

    for owner in ["repo", "infra", "docs"]:
        counts = owner_counts[owner]
        lines.append(f"| {owner} | {counts['open']} | {counts['total']} |")

    lines.extend(
        [
            "",
            "---",
            "",
            "## Release Gate Status",
            "",
        ]
    )

    # Determine gate status
    gate_blocked = (
        open_blocking > 0
        or len(result.validation_errors) > 0
        or len(result.expired_waivers) > 0
        or len(result.invalid_waiver_attempts) > 0
    )

    if gate_blocked:
        lines.extend(
            [
                "**Status: BLOCKED**",
                "",
                "Release cannot proceed due to:",
                "",
            ]
        )

        if open_blocking > 0:
            lines.append(f"- {open_blocking} Production-blocking gap(s)")
        if result.validation_errors:
            lines.append(f"- {len(result.validation_errors)} validation error(s)")
        if result.expired_waivers:
            lines.append(f"- {len(result.expired_waivers)} expired waiver(s)")
        if result.invalid_waiver_attempts:
            lines.append(
                f"- {len(result.invalid_waiver_attempts)} invalid waiver attempt(s)"
            )
    else:
        lines.extend(
            [
                "**Status: READY**",
                "",
                "All Production-blocking gaps resolved. Release may proceed.",
            ]
        )

    # Warnings section
    if result.expiring_soon_waivers or result.launch_risk_gaps:
        lines.extend(
            [
                "",
                "---",
                "",
                "## Warnings",
                "",
            ]
        )

        if result.expiring_soon_waivers:
            lines.append("### Waivers Expiring Soon")
            lines.append("")
            for waiver in result.expiring_soon_waivers:
                lines.append(f"- **{waiver.gap_id}**: Expires {waiver.expiration}")
            lines.append("")

        if result.launch_risk_gaps:
            lines.append("### Active Launch Risks")
            lines.append("")
            for gap in result.launch_risk_gaps:
                lines.append(f"- **{gap.id}**: {gap.description}")
            lines.append("")

    lines.extend(
        [
            "",
            "---",
            "",
            "## Detailed Gap List",
            "",
        ]
    )

    # List all gaps
    if result.blocking_gaps:
        lines.append("### Production-blocking")
        lines.append("")
        for gap in result.blocking_gaps:
            lines.append(f"- **{gap.id}**: {gap.description}")
            lines.append(f"  - Evidence: `{gap.evidence}`")
            lines.append(f"  - Owner: {gap.owner}")
        lines.append("")

    if result.launch_risk_gaps:
        lines.append("### Launch-risk")
        lines.append("")
        for gap in result.launch_risk_gaps:
            lines.append(f"- **{gap.id}**: {gap.description}")
            lines.append(f"  - Evidence: `{gap.evidence}`")
            lines.append(f"  - Owner: {gap.owner}")
        lines.append("")

    if result.post_launch_gaps:
        lines.append("### Post-launch")
        lines.append("")
        for gap in result.post_launch_gaps:
            lines.append(f"- **{gap.id}**: {gap.description}")
            lines.append(f"  - Evidence: `{gap.evidence}`")
            lines.append(f"  - Owner: {gap.owner}")
        lines.append("")

    if result.waived_gaps:
        lines.append("### Waived")
        lines.append("")
        for gap, waiver in result.waived_gaps:
            lines.append(f"- **{gap.id}**: {gap.description}")
            lines.append(f"  - Approved by: {waiver.approved_by}")
            lines.append(f"  - Expires: {waiver.expiration}")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    """Generate scorecard and write to file."""
    matrix_path = Path("docs/GAP_MATRIX.md")
    waivers_path = Path("docs/RISK_WAIVERS.md")
    output_path = Path("docs/GAP_SCORECARD.md")

    if not matrix_path.exists():
        print("ERROR: docs/GAP_MATRIX.md not found")
        return 1

    content = generate_scorecard(matrix_path, waivers_path)
    output_path.write_text(content)

    print(f"Generated: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
