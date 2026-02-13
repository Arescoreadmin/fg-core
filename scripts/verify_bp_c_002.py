#!/usr/bin/env python3
from __future__ import annotations

import difflib
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.openapi_canonical import parse_openapi_text, render_openapi  # noqa: E402

GATE_ID = "BP-C-002"
INVARIANT = "The committed OpenAPI contracts MUST be byte-for-byte identical to the contracts generated under a locked prod-spec environment."
EXPECTED_ALIGN = "make bp-c-002-gate"
REPORT_PATH = Path("artifacts/gates/bp_c_002_report.json")
REQUIRED_FILES = (
    Path("tools/align_score_map.json"),
    Path("contracts/core/openapi.json"),
    Path("schemas/api/openapi.json"),
    Path("Makefile"),
)
CONTRACT_FILES = (
    Path("contracts/core/openapi.json"),
    Path("schemas/api/openapi.json"),
)


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_text(path: Path) -> str:
    return render_openapi(parse_openapi_text(path.read_text(encoding="utf-8")))


def _load_align_map(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    pairs: list[tuple[str, Any]] = json.loads(text, object_pairs_hook=list)
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
            "makefile": "Makefile",
            "committed_core_openapi": "contracts/core/openapi.json",
            "committed_schema_openapi": "schemas/api/openapi.json",
            "gate_report": "artifacts/gates/bp_c_002_report.json",
        },
        "errors": errors,
        "notes": notes,
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    errors: list[str] = []
    notes: list[str] = []

    for path in REQUIRED_FILES:
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

    if errors:
        _write_report(False, errors, notes)
        return 1

    committed_canonical = {p.as_posix(): _canonical_text(p) for p in CONTRACT_FILES}
    committed_hashes = {
        p: _sha256_text(text) for p, text in committed_canonical.items()
    }

    env = os.environ.copy()
    env.update(
        {
            "FG_CONTRACT_SPEC": "prod",
            "FG_ENV": "prod",
            "FG_ADMIN_ENABLED": "0",
            "FG_AUTH_ENABLED": "1",
            "FG_UI_ENABLED": "0",
            "FG_DEV_EVENTS_ENABLED": "0",
        }
    )

    run = subprocess.run(
        ["make", "contracts-core-gen"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if run.returncode != 0:
        errors.append("canonical generation command failed: make contracts-core-gen")
        if run.stdout.strip():
            notes.append(f"make stdout: {run.stdout.strip()}")
        if run.stderr.strip():
            notes.append(f"make stderr: {run.stderr.strip()}")
        _write_report(False, errors, notes)
        return 1

    regenerated_canonical = {p.as_posix(): _canonical_text(p) for p in CONTRACT_FILES}
    regenerated_hashes = {
        p: _sha256_text(text) for p, text in regenerated_canonical.items()
    }
    notes.append(f"committed_hashes={committed_hashes}")
    notes.append(f"regenerated_hashes={regenerated_hashes}")

    for path in CONTRACT_FILES:
        key = path.as_posix()
        if committed_canonical[key] != regenerated_canonical[key]:
            errors.append("openapi drift detected after canonical regeneration")
            diff = "\n".join(
                difflib.unified_diff(
                    committed_canonical[key].splitlines(),
                    regenerated_canonical[key].splitlines(),
                    fromfile=f"committed:{key}",
                    tofile=f"regenerated:{key}",
                    lineterm="",
                )
            )
            if diff:
                notes.append(f"diff_summary_{key}={diff}")
            break

    passed = not errors
    _write_report(passed, errors, notes)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
