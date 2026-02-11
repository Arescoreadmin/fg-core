#!/usr/bin/env python3
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

GATE_ID = "BP-C-005"
INVARIANT = (
    "Tenant sharding primitives and performance SLO guardrails must be enforced."
)
EXPECTED_ALIGN = "make bp-c-005-gate"
REPORT_PATH = Path("artifacts/gates/bp_c_005_report.json")


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
                "checked_files": {
                    "align_score_map": "tools/align_score_map.json",
                    "tenant_migration": "migrations/postgres/0001_base.sql",
                    "tenant_tests": "tests/test_tenant_invariant.py",
                    "slo_tests": "tests/test_dos_guard.py",
                    "gate_report": REPORT_PATH.as_posix(),
                },
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
    align = Path("tools/align_score_map.json")
    mig = Path("migrations/postgres/0001_base.sql")
    ttest = Path("tests/test_tenant_invariant.py")
    slotest = Path("tests/test_dos_guard.py")
    for p in (align, mig, ttest, slotest):
        if not p.exists():
            errors.append(f"missing required file: {p.as_posix()}")

    if align.exists():
        mapping = dict(
            json.loads(align.read_text(encoding="utf-8"), object_pairs_hook=list)
        )
        if mapping.get(GATE_ID) != EXPECTED_ALIGN:
            errors.append(
                f"align_score_map mismatch for {GATE_ID}: expected '{EXPECTED_ALIGN}', got '{mapping.get(GATE_ID)}'"
            )

    if mig.exists():
        text = mig.read_text(encoding="utf-8")
        required_indexes = [
            "idx_decisions_tenant_id",
            "idx_decision_evidence_tenant_id",
            "idx_security_audit_log_tenant_id",
        ]
        for idx in required_indexes:
            if idx not in text:
                errors.append(f"missing tenant sharding index: {idx}")

    _write_report(not errors, errors)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
