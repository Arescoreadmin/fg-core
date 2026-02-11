#!/usr/bin/env python3
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

GATE_ID = "BP-M2-001"
INVARIANT = "Policy registry must be versioned and immutable."
EXPECTED_ALIGN = "make bp-m2-001-gate"
REPORT_PATH = Path("artifacts/gates/bp_m2_001_report.json")


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _write_report(passed: bool, errors: list[str]) -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(
        json.dumps(
            {
                "gate_id": GATE_ID,
                "passed": passed,
                "generated_at_utc": _utc_now(),
                "invariant": INVARIANT,
                "checked_files": {"gate_report": REPORT_PATH.as_posix()},
                "errors": errors,
                "notes": [],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    errors: list[str] = []
    required = [
        Path("tools/align_score_map.json"),
        Path("migrations/postgres/0001_base.sql"),
        Path("contracts/core/openapi.json"),
    ]
    for path in required:
        if not path.exists():
            errors.append(f"missing required file: {path.as_posix()}")

    align_path = Path("tools/align_score_map.json")
    if align_path.exists():
        mapping = dict(
            json.loads(align_path.read_text(encoding="utf-8"), object_pairs_hook=list)
        )
        if mapping.get(GATE_ID) != EXPECTED_ALIGN:
            errors.append(
                f"align_score_map mismatch for {GATE_ID}: expected '{EXPECTED_ALIGN}', got '{mapping.get(GATE_ID)}'"
            )

    checks = [
        (
            Path("migrations/postgres/0001_base.sql"),
            "policy_change_requests",
            "missing policy registry table",
        ),
        (
            Path("contracts/core/openapi.json"),
            "/governance/changes",
            "missing policy registry API surface",
        ),
    ]
    for file_path, needle, message in checks:
        if file_path.exists() and needle not in file_path.read_text(encoding="utf-8"):
            errors.append(message)

    _write_report(not errors, errors)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
