#!/usr/bin/env python3
"""BP-C-004 gate: Authority & Provenance Gate.

Invariant:
All authoritative artifacts MUST be cryptographically anchored and in sync.

Mandatory conditions:
- Compute SHA256 of contracts/core/openapi.json.
- MUST exactly match: CONTRACT.md, BLUEPRINT_STAGED.md.
- Multiple hashes, missing hashes, or mismatch -> FAIL.

Evidence artifact: artifacts/gates/bp_c_004_report.json
Exit code: 0 if passed, 1 if failed.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

GATE_ID = "BP-C-004"
INVARIANT = (
    "All authoritative artifacts MUST be cryptographically anchored and in sync."
)
EXPECTED_ALIGN_VALUE = "make bp-c-004-gate"

CONTRACT_PATH = "contracts/core/openapi.json"
ANCHOR_DOCS = {
    "contract_md": "CONTRACT.md",
    "blueprint_staged_md": "BLUEPRINT_STAGED.md",
}

_SHA256_LINE_RE = re.compile(
    r"Contract-Authority-SHA256:\s*([0-9a-fA-F]{64})", re.MULTILINE
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_align_map(align_map_path: Path) -> list[str]:
    errors: list[str] = []
    if not align_map_path.exists():
        errors.append(f"align_score_map.json not found at {align_map_path}")
        return errors
    try:
        data = json.loads(align_map_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        errors.append(f"align_score_map.json parse error: {exc}")
        return errors
    actual = data.get(GATE_ID)
    if actual != EXPECTED_ALIGN_VALUE:
        errors.append(
            f"align_score_map.json {GATE_ID} must be '{EXPECTED_ALIGN_VALUE}', "
            f"got '{actual}'"
        )
    return errors


def extract_sha256_hashes(text: str) -> list[str]:
    """Extract all Contract-Authority-SHA256 values from a document."""
    return _SHA256_LINE_RE.findall(text)


def run_gate(
    *,
    repo_root: Path | None = None,
) -> tuple[bool, dict]:
    """Run BP-C-004 gate. Returns (passed, report_dict)."""
    if repo_root is None:
        repo_root = Path(__file__).resolve().parent.parent

    align_map_path = repo_root / "tools" / "align_score_map.json"
    contract_file = repo_root / CONTRACT_PATH
    errors: list[str] = []
    notes: list[str] = []
    checked_files: dict[str, str] = {
        "align_map": str(align_map_path),
        "contract_artifact": str(contract_file),
    }

    # Validate align map
    align_errors = validate_align_map(align_map_path)
    errors.extend(align_errors)

    # Compute SHA256 of the authoritative contract
    if not contract_file.exists():
        errors.append(f"Authoritative contract not found: {CONTRACT_PATH}")
        return False, _build_report(
            passed=False,
            checked_files=checked_files,
            errors=errors,
            notes=notes,
        )

    actual_hash = sha256_file(contract_file)
    notes.append(f"{CONTRACT_PATH}: SHA256={actual_hash}")

    # Check each anchor document
    for doc_key, doc_rel_path in ANCHOR_DOCS.items():
        doc_path = repo_root / doc_rel_path
        checked_files[doc_key] = str(doc_path)

        if not doc_path.exists():
            errors.append(f"Anchor document not found: {doc_rel_path}")
            continue

        text = doc_path.read_text(encoding="utf-8")
        hashes = extract_sha256_hashes(text)

        if len(hashes) == 0:
            errors.append(
                f"{doc_rel_path}: no Contract-Authority-SHA256 found"
            )
        elif len(hashes) > 1:
            errors.append(
                f"{doc_rel_path}: multiple Contract-Authority-SHA256 values found "
                f"({len(hashes)}); exactly one required"
            )
        else:
            doc_hash = hashes[0].lower()
            if doc_hash != actual_hash:
                errors.append(
                    f"{doc_rel_path}: Contract-Authority-SHA256 mismatch: "
                    f"document={doc_hash}, actual={actual_hash}"
                )
            else:
                notes.append(f"{doc_rel_path}: SHA256 match ({doc_hash})")

    passed = len(errors) == 0
    return passed, _build_report(
        passed=passed,
        checked_files=checked_files,
        errors=errors,
        notes=notes,
    )


def _build_report(
    *,
    passed: bool,
    checked_files: dict[str, str],
    errors: list[str],
    notes: list[str],
) -> dict:
    return {
        "gate_id": GATE_ID,
        "passed": passed,
        "generated_at_utc": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "invariant": INVARIANT,
        "checked_files": checked_files,
        "errors": errors,
        "notes": notes,
    }


def main() -> int:
    passed, report = run_gate()

    repo_root = Path(__file__).resolve().parent.parent
    gates_dir = repo_root / "artifacts" / "gates"
    gates_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = gates_dir / "bp_c_004_report.json"
    artifact_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if passed:
        print("BP-C-004 gate: PASS")
    else:
        print(f"BP-C-004 gate: FAIL ({len(report['errors'])} errors)")
        for err in report["errors"]:
            print(f"  - {err}")

    print(f"Report: {artifact_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
