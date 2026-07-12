#!/usr/bin/env python3
"""Runtime Intelligence CLI — record gate results and generate summaries."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.testing.runtime_intelligence.github_summary import (  # noqa: E402
    generate_summary,
    write_step_summary,
)
from tools.testing.runtime_intelligence.history import (  # noqa: E402
    append_result,
    baseline_collected_for_history,
    load_history,
    rolling_stats_for_history,
    save_history,
)
from tools.testing.runtime_intelligence.models import RuntimeResult  # noqa: E402
from tools.testing.runtime_intelligence.parser import (  # noqa: E402
    JUNIT_DIR,
    _FAST_DUR_PATH,
    merge_artifacts,
    parse_fg_fast_artifact,
)
from tools.testing.runtime_intelligence.recorder import record_gate_result  # noqa: E402
from tools.testing.runtime_intelligence.regression import detect_regressions  # noqa: E402
from tools.testing.runtime_intelligence.serializer import to_json  # noqa: E402, F401

# Per-gate default selector expressions (mirrors Makefile PYTEST_*_FILTER values)
_GATE_SELECTORS: dict[str, str] = {
    "fg-fast": '-m "smoke or contract or security"',
    "fg-security": 'tests/security -m "not slow"',
    "fg-full": "",
    "fg-contract": "",
}


def _auto_junit(gate: str, junit_dir: Path) -> Path | None:
    """Return path to the canonical JUnit file for this gate, or None."""
    path = junit_dir / f"{gate}.xml"
    return path if path.exists() else None


def _auto_duration(gate: str) -> Path | None:
    """Return path to duration artifact if it exists."""
    if gate == "fg-fast" and _FAST_DUR_PATH.exists():
        return _FAST_DUR_PATH
    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Record CI gate runtime and generate summaries"
    )
    ap.add_argument(
        "--gate",
        required=True,
        choices=["fg-fast", "fg-security", "fg-contract", "fg-full"],
    )
    ap.add_argument("--artifact-dir", default="artifacts/ci/runtime")
    ap.add_argument("--history-dir", default="artifacts/ci/runtime/history")
    ap.add_argument("--junit", help="Path to JUnit XML file (auto-detected if absent)")
    ap.add_argument(
        "--junit-dir",
        default=None,
        help="Directory containing gate JUnit files (default: artifacts/ci/junit)",
    )
    ap.add_argument(
        "--selector",
        default=None,
        help="Pytest selector expression for selector_fingerprint",
    )
    ap.add_argument(
        "--github-summary", action="store_true", help="Write GitHub step summary"
    )
    ap.add_argument(
        "--dry-run", action="store_true", help="Parse and print but don't write"
    )
    args = ap.parse_args()

    artifact_dir = REPO_ROOT / args.artifact_dir
    history_dir = REPO_ROOT / args.history_dir
    junit_dir = Path(args.junit_dir) if args.junit_dir else JUNIT_DIR

    # --- Resolve inputs ---
    junit_path: Path | None = None
    if args.junit:
        junit_path = REPO_ROOT / args.junit
    else:
        junit_path = _auto_junit(args.gate, junit_dir)

    duration_path = _auto_duration(args.gate)

    selector = (
        args.selector
        if args.selector is not None
        else _GATE_SELECTORS.get(args.gate, "")
    )

    # --- Merge all available sources into a complete RuntimeResult ---
    result: RuntimeResult | None = merge_artifacts(
        gate=args.gate,
        junit_path=junit_path,
        duration_json_path=duration_path,
        selector=selector,
    )

    # Final fallback: duration-only artifact (fg-fast only)
    if result is None and args.gate == "fg-fast":
        result = parse_fg_fast_artifact()

    if result is None:
        print(
            f"[runtime-intelligence] no artifact found for gate={args.gate}",
            file=sys.stderr,
        )
        return 0  # non-blocking — advisory only

    # --- Regression detection ---
    history_path = history_dir / f"{args.gate}-history.json"
    history = load_history(history_path)
    stats = rolling_stats_for_history(history, last_n=30)
    regressions = detect_regressions(
        gate=args.gate,
        current_duration=result.duration_seconds,
        current_collected=result.collected,
        baseline_stats=stats,
        baseline_collected=baseline_collected_for_history(history, last_n=30),
    )

    if not args.dry_run:
        # Write canonical RuntimeResult artifact
        out = record_gate_result(result, artifact_dir)
        print(f"[runtime-intelligence] wrote {out}")

        # Update rolling history with complete entry
        history_entry: dict[str, object] = {
            "duration_seconds": result.duration_seconds,
            "passed": result.passed,
            "failed": result.failed,
            "collected": result.collected,
            "skipped": result.skipped,
            "commit_sha": result.meta.commit_sha[:12],
            "gate": args.gate,
            "manifest_fingerprint": result.manifest_fingerprint,
            "selector_fingerprint": result.selector_fingerprint,
        }
        updated = append_result(history, history_entry)
        save_history(updated, history_path)
        print(f"[runtime-intelligence] history: {len(updated.runs)} runs recorded")

    # --- GitHub step summary ---
    if args.github_summary or args.dry_run or os.getenv("GITHUB_STEP_SUMMARY"):
        summary = generate_summary(
            result, stats if stats.count > 0 else None, regressions
        )
        if not args.dry_run:
            write_step_summary(summary)
        print(summary)

    # --- Advisory regression printout ---
    for reg in regressions:
        print(
            f"[runtime-intelligence] REGRESSION [{reg.severity.upper()}]: {reg.message}",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
