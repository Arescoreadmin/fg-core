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
    parse_fg_fast_artifact,
    parse_junit_xml,
)
from tools.testing.runtime_intelligence.recorder import record_gate_result  # noqa: E402
from tools.testing.runtime_intelligence.regression import detect_regressions  # noqa: E402
from tools.testing.runtime_intelligence.serializer import to_json  # noqa: E402, F401


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Record CI gate runtime and generate summaries"
    )
    parser.add_argument(
        "--gate",
        required=True,
        choices=["fg-fast", "fg-security", "fg-contract", "fg-full"],
    )
    parser.add_argument("--artifact-dir", default="artifacts/ci/runtime")
    parser.add_argument("--history-dir", default="artifacts/ci/runtime/history")
    parser.add_argument("--junit", help="Path to JUnit XML file")
    parser.add_argument(
        "--github-summary", action="store_true", help="Write GitHub step summary"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Parse and print but don't write"
    )
    args = parser.parse_args()

    artifact_dir = REPO_ROOT / args.artifact_dir
    history_dir = REPO_ROOT / args.history_dir

    # Parse result
    result: RuntimeResult | None = None
    if args.junit:
        result = parse_junit_xml(Path(args.junit), args.gate)
    if result is None and args.gate == "fg-fast":
        result = parse_fg_fast_artifact()
    if result is None:
        print(
            f"[runtime-intelligence] no artifact found for gate={args.gate}",
            file=sys.stderr,
        )
        return 0  # non-blocking — advisory only

    # Load history and compute regression
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
        # Write artifact
        out = record_gate_result(result, artifact_dir)
        print(f"[runtime-intelligence] wrote {out}")

        # Update history
        history_entry = {
            "duration_seconds": result.duration_seconds,
            "passed": result.passed,
            "failed": result.failed,
            "collected": result.collected,
            "commit_sha": result.meta.commit_sha[:12],
            "gate": args.gate,
        }
        updated = append_result(history, history_entry)
        save_history(updated, history_path)
        print(f"[runtime-intelligence] history: {len(updated.runs)} runs recorded")

    # GitHub summary
    if args.github_summary or args.dry_run or os.getenv("GITHUB_STEP_SUMMARY"):
        summary = generate_summary(
            result, stats if stats.count > 0 else None, regressions
        )
        if not args.dry_run:
            write_step_summary(summary)
        print(summary)

    # Print regressions
    for reg in regressions:
        print(
            f"[runtime-intelligence] REGRESSION [{reg.severity.upper()}]: {reg.message}",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
