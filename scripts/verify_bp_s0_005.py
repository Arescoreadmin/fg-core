#!/usr/bin/env python3
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

GATE_ID = "BP-S0-005"
INVARIANT = "Centralized auditable logs must be persisted and queryable via contracted forensics APIs."
EXPECTED_ALIGN = "make bp-s0-005-gate"
REPORT_PATH = Path("artifacts/gates/bp_s0_005_report.json")


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _load_align_map(path: Path) -> dict[str, str]:
    return dict(json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=list))


def _write_report(passed: bool, errors: list[str], notes: list[str]) -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(
        json.dumps(
            {
                "gate_id": GATE_ID,
                "passed": passed,
                "generated_at_utc": _utc_now(),
                "invariant": INVARIANT,
                "checked_files": {
                    "align_score_map": "tools/align_score_map.json",
                    "openapi": "contracts/core/openapi.json",
                    "audit_migration": "migrations/postgres/0001_base.sql",
                    "gate_report": REPORT_PATH.as_posix(),
                },
                "errors": errors,
                "notes": notes,
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
        Path("contracts/core/openapi.json"),
        Path("migrations/postgres/0001_base.sql"),
    ]
    for p in required:
        if not p.exists():
            errors.append(f"missing required file: {p.as_posix()}")

    if not errors:
        align = _load_align_map(Path("tools/align_score_map.json"))
        if align.get(GATE_ID) != EXPECTED_ALIGN:
            errors.append(
                f"align_score_map mismatch for {GATE_ID}: expected '{EXPECTED_ALIGN}', got '{align.get(GATE_ID)}'"
            )

    if Path("contracts/core/openapi.json").exists():
        op = json.loads(Path("contracts/core/openapi.json").read_text(encoding="utf-8"))
        if "/forensics/audit_trail/{event_id}" not in op.get("paths", {}):
            errors.append("missing forensics audit trail API path")

    if Path("migrations/postgres/0001_base.sql").exists():
        sql = Path("migrations/postgres/0001_base.sql").read_text(encoding="utf-8")
        if "CREATE TABLE IF NOT EXISTS security_audit_log" not in sql:
            errors.append("missing centralized security_audit_log table")

    _write_report(not errors, errors, [])
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
