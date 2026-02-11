#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

GATE_ID = "BP-C-004"
INVARIANT = (
    "All authoritative artifacts MUST be cryptographically anchored and in sync."
)
EXPECTED_ALIGN = "make bp-c-004-gate"
REPORT_PATH = Path("artifacts/gates/bp_c_004_report.json")

REQUIRED_FILES = (
    Path("tools/align_score_map.json"),
    Path("contracts/core/openapi.json"),
    Path("CONTRACT.md"),
    Path("BLUEPRINT_STAGED.md"),
)
HASH_RE = re.compile(r"^Contract-Authority-SHA256:\s*([0-9a-f]{64})\s*$", re.MULTILINE)


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_align_map(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    pairs = json.loads(text, object_pairs_hook=list)
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("align_score_map.json contains duplicate keys")
    return dict(pairs)


def _extract_single_hash(path: Path) -> str:
    matches = HASH_RE.findall(path.read_text(encoding="utf-8"))
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one Contract-Authority-SHA256 in {path.as_posix()}, found {len(matches)}"
        )
    return matches[0]


def _write_report(passed: bool, errors: list[str], notes: list[str]) -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "gate_id": GATE_ID,
        "passed": passed,
        "generated_at_utc": _utc_now(),
        "invariant": INVARIANT,
        "checked_files": {
            "align_score_map": "tools/align_score_map.json",
            "authority_contract": "contracts/core/openapi.json",
            "contract_doc": "CONTRACT.md",
            "blueprint_doc": "BLUEPRINT_STAGED.md",
            "gate_report": "artifacts/gates/bp_c_004_report.json",
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

    authority_hash = _sha256(Path("contracts/core/openapi.json"))
    notes.append(f"authority_hash={authority_hash}")

    for doc in (Path("CONTRACT.md"), Path("BLUEPRINT_STAGED.md")):
        try:
            doc_hash = _extract_single_hash(doc)
            notes.append(f"{doc.as_posix()}_hash={doc_hash}")
            if doc_hash != authority_hash:
                errors.append(
                    f"hash mismatch: {doc.as_posix()} has {doc_hash}, contracts/core/openapi.json has {authority_hash}"
                )
        except Exception as exc:
            errors.append(str(exc))

    passed = not errors
    _write_report(passed, errors, notes)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
