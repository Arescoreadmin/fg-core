#!/usr/bin/env python3
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

GATE_ID = "BP-S0-001"
INVARIANT = "Startup and readiness probes must be deterministic and contract-declared."
EXPECTED_ALIGN = "make bp-s0-001-gate"
REPORT_PATH = Path("artifacts/gates/bp_s0_001_report.json")


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _load_align_map(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    pairs = json.loads(text, object_pairs_hook=list)
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("align_score_map.json contains duplicate keys")
    return dict(pairs)


def _write_report(passed: bool, errors: list[str], notes: list[str]) -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "gate_id": GATE_ID,
        "passed": passed,
        "generated_at_utc": _utc_now(),
        "invariant": INVARIANT,
        "checked_files": {
            "align_score_map": "tools/align_score_map.json",
            "openapi": "contracts/core/openapi.json",
            "ready_script": "scripts/wait_core_ready.sh",
            "gate_report": REPORT_PATH.as_posix(),
        },
        "errors": errors,
        "notes": notes,
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    errors: list[str] = []
    notes: list[str] = []

    required = [
        Path("tools/align_score_map.json"),
        Path("contracts/core/openapi.json"),
        Path("scripts/wait_core_ready.sh"),
    ]
    for path in required:
        if not path.exists():
            errors.append(f"missing required file: {path.as_posix()}")

    if not errors:
        try:
            align = _load_align_map(Path("tools/align_score_map.json"))
            if align.get(GATE_ID) != EXPECTED_ALIGN:
                errors.append(
                    f"align_score_map mismatch for {GATE_ID}: expected '{EXPECTED_ALIGN}', got '{align.get(GATE_ID)}'"
                )
        except Exception as exc:
            errors.append(f"failed to read align_score_map.json: {exc}")

    openapi_path = Path("contracts/core/openapi.json")
    if openapi_path.exists():
        try:
            openapi = json.loads(openapi_path.read_text(encoding="utf-8"))
            paths = openapi.get("paths", {})
            for probe in ("/health/live", "/health/ready"):
                if probe not in paths:
                    errors.append(f"missing probe path in contract: {probe}")
                elif "get" not in paths[probe]:
                    errors.append(f"missing GET operation for probe path: {probe}")
        except Exception as exc:
            errors.append(f"failed to parse openapi contract: {exc}")

    wait_script = Path("scripts/wait_core_ready.sh")
    if wait_script.exists():
        text = wait_script.read_text(encoding="utf-8")
        if "/health/ready" not in text:
            errors.append("wait_core_ready.sh must probe /health/ready")

    passed = not errors
    _write_report(passed, errors, notes)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
