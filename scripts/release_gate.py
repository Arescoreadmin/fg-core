#!/usr/bin/env python3
"""Release gate enforcement for FrostGate production releases.

This script provides a hard block on releases:
- Runs gap_audit
- Runs generate_scorecard
- Runs contracts-gen and verifies no diff
- Runs fg-contract
- Runs lint checks (ruff format --check)
- Fails release if ANY Production-blocking gaps exist
- Fails release if Production Readiness < 100%
- Outputs single-screen failure summary

FAIL-CLOSED: No release without explicit pass.
"""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime
from pathlib import Path

from gap_audit import (
    parse_gap_matrix,
    run_gap_audit,
)
from generate_scorecard import generate_scorecard as gen_scorecard_content


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


def run_command(cmd: list[str], description: str) -> tuple[bool, str]:
    """Run a shell command and return (success, output).

    Returns a tuple of (passed, message) where message contains
    stdout/stderr on failure.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            return True, ""
        # Include both stdout and stderr in error message
        output = (result.stdout + result.stderr).strip()
        if len(output) > 500:
            output = output[:500] + "... (truncated)"
        return False, f"{description} failed:\n{output}"
    except subprocess.TimeoutExpired:
        return False, f"{description} timed out after 120s"
    except FileNotFoundError as e:
        return False, f"{description} command not found: {e}"
    except Exception as e:
        return False, f"{description} error: {e}"


def run_readiness_checks(
    scorecard_path: Path | None = None,
) -> list[tuple[str, bool, str]]:
    """Run all readiness checks and return results.

    Returns list of (check_name, passed, error_message) tuples.

    Args:
        scorecard_path: Path to scorecard for drift check (optional)
    """
    results: list[tuple[str, bool, str]] = []

    # Check 1: contracts-gen (generate contracts)
    passed, msg = run_command(
        ["make", "contracts-gen"],
        "contracts-gen",
    )
    results.append(("contracts-gen", passed, msg))

    # Check 2: git diff --exit-code contracts/ (verify no uncommitted contract changes)
    if passed:  # Only check diff if generation succeeded
        passed, msg = run_command(
            ["git", "diff", "--exit-code", "contracts/"],
            "contracts diff check",
        )
        if not passed and not msg:
            msg = "contracts diff check failed: uncommitted contract changes detected"
        results.append(("contracts-diff", passed, msg))
    else:
        results.append(("contracts-diff", False, "Skipped (contracts-gen failed)"))

    # Check 3: fg-contract (contract validation)
    passed, msg = run_command(
        ["make", "fg-contract"],
        "fg-contract",
    )
    results.append(("fg-contract", passed, msg))

    # Check 4: lint check (ruff format --check)
    passed, msg = run_command(
        ["make", "fg-lint"],
        "fg-lint",
    )
    results.append(("fg-lint", passed, msg))

    # Check 5: Postgres verification lane
    passed, msg = run_command(
        ["make", "db-postgres-verify"],
        "db-postgres-verify",
    )
    results.append(("db-postgres-verify", passed, msg))

    # Check 6: scorecard drift check (generate and verify no changes)
    if scorecard_path is not None:
        passed, msg = run_command(
            ["make", "generate-scorecard"],
            "generate-scorecard",
        )
        results.append(("generate-scorecard", passed, msg))

        if passed:
            passed, msg = run_command(
                ["git", "diff", "--exit-code", str(scorecard_path)],
                "scorecard drift check",
            )
            if not passed and not msg:
                msg = (
                    "scorecard drift check failed: GAP_SCORECARD.md differs from committed version. "
                    "Run 'make generate-scorecard' and commit the updated scorecard."
                )
            results.append(("scorecard-drift", passed, msg))
        else:
            results.append(
                ("scorecard-drift", False, "Skipped (generate-scorecard failed)")
            )

    return results


def run_release_gate(
    matrix_path: Path,
    waivers_path: Path,
    today: datetime | None = None,
    skip_subprocess_checks: bool = False,
    scorecard_path: Path | None = None,
    skip_evidence_verification: bool = False,
    repo_root: Path | None = None,
) -> tuple[bool, str]:
    """Run release gate checks.

    Args:
        matrix_path: Path to GAP_MATRIX.md
        waivers_path: Path to RISK_WAIVERS.md
        today: Override for current date (for testing)
        skip_subprocess_checks: Skip subprocess-based checks (for unit tests)
        scorecard_path: Path to GAP_SCORECARD.md for drift check
        skip_evidence_verification: Skip deep evidence verification (for unit tests)
        repo_root: Repository root for evidence verification (defaults to cwd)

    Returns:
        Tuple of (passed: bool, summary: str)
    """
    if today is None:
        today = datetime.now()

    lines: list[str] = []

    # Run gap audit
    # Note: skip_evidence_verification is independent of skip_subprocess_checks
    # to allow testing evidence verification without running make commands
    result = run_gap_audit(
        matrix_path,
        waivers_path,
        today,
        repo_root=repo_root,
        skip_evidence_verification=skip_evidence_verification,
    )

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

    # Evidence verification errors (blocking)
    if result.evidence_verification_errors:
        blocking_reasons.append(
            f"{len(result.evidence_verification_errors)} evidence verification error(s)"
        )
        lines.append("EVIDENCE VERIFICATION ERRORS:")
        for error in result.evidence_verification_errors[:5]:  # Show first 5
            lines.append(f"  - {error}")
        if len(result.evidence_verification_errors) > 5:
            lines.append(
                f"  ... and {len(result.evidence_verification_errors) - 5} more"
            )
        lines.append("")

    # Owner/evidence mismatch errors (blocking)
    if result.owner_evidence_mismatches:
        blocking_reasons.append(
            f"{len(result.owner_evidence_mismatches)} owner/evidence mismatch(es)"
        )
        lines.append("OWNER/EVIDENCE MISMATCH ERRORS:")
        for error in result.owner_evidence_mismatches[:5]:  # Show first 5
            lines.append(f"  - {error}")
        if len(result.owner_evidence_mismatches) > 5:
            lines.append(f"  ... and {len(result.owner_evidence_mismatches) - 5} more")
        lines.append("")

    if prod_readiness < 100.0:
        blocking_reasons.append(f"Production Readiness {prod_readiness:.1f}% < 100%")

    # Run additional readiness checks (contracts, lint, scorecard drift)
    if not skip_subprocess_checks:
        lines.append("READINESS CHECKS:")
        check_results = run_readiness_checks(scorecard_path=scorecard_path)
        for check_name, check_passed, check_msg in check_results:
            status = "PASS" if check_passed else "FAIL"
            lines.append(f"  [{status}] {check_name}")
            if not check_passed:
                blocking_reasons.append(f"Readiness check '{check_name}' failed")
                if check_msg:
                    for msg_line in check_msg.split("\n")[:3]:
                        lines.append(f"        {msg_line}")
        lines.append("")

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
    scorecard_path = Path("docs/GAP_SCORECARD.md")

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

    # Generate scorecard (deterministic, no timestamps)
    try:
        scorecard_content = gen_scorecard_content(matrix_path, waivers_path)
        scorecard_path.write_text(scorecard_content)
        print(f"Generated: {scorecard_path}")
    except Exception as e:
        print(f"WARNING: Failed to generate scorecard: {e}")

    passed, summary = run_release_gate(
        matrix_path,
        waivers_path,
        scorecard_path=scorecard_path,
    )
    print(summary)

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
