#!/usr/bin/env python3
"""BP-C-002 gate: Contract Drift Gate.

Invariant:
The committed OpenAPI contracts MUST be byte-for-byte identical
to the contracts generated under a locked prod-spec environment.

Mandatory conditions:
- Force environment to prod-spec locked values.
- Regenerate OpenAPI.
- SHA256 compare against contracts/core/openapi.json and schemas/api/openapi.json.
- Any difference -> FAIL.

Evidence artifact: artifacts/gates/bp_c_002_report.json
Exit code: 0 if passed, 1 if failed.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

GATE_ID = "BP-C-002"
INVARIANT = (
    "The committed OpenAPI contracts MUST be byte-for-byte identical "
    "to the contracts generated under a locked prod-spec environment."
)
EXPECTED_ALIGN_VALUE = "make bp-c-002-gate"

CONTRACT_PATHS = {
    "core_openapi": "contracts/core/openapi.json",
    "schemas_api_openapi": "schemas/api/openapi.json",
}

PROD_ENV = {
    "FG_CONTRACT_SPEC": "prod",
    "FG_ENV": "prod",
    "FG_ADMIN_ENABLED": "0",
    "FG_AUTH_ENABLED": "1",
    "FG_UI_ENABLED": "0",
    "FG_DEV_EVENTS_ENABLED": "0",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def regenerate_openapi(repo_root: Path) -> bytes:
    """Regenerate OpenAPI under locked prod-spec environment. Returns raw bytes."""
    env = os.environ.copy()
    env.update(PROD_ENV)
    env["PYTHONPATH"] = str(repo_root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    script = (
        "import json, sys; "
        "sys.path.insert(0, '.'); "
        "from scripts.contracts_gen_core import generate_openapi; "
        "spec = generate_openapi(); "
        "sys.stdout.buffer.write("
        "(json.dumps(spec, indent=2, sort_keys=True) + chr(10)).encode('utf-8'))"
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        env=env,
        cwd=str(repo_root),
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"OpenAPI regeneration failed (exit {result.returncode}): "
            f"{result.stderr.decode('utf-8', errors='replace')}"
        )
    return result.stdout


def run_gate(
    *,
    repo_root: Path | None = None,
    generated_bytes: bytes | None = None,
) -> tuple[bool, dict]:
    """Run BP-C-002 gate. Returns (passed, report_dict).

    Args:
        repo_root: Repository root directory.
        generated_bytes: Pre-computed regenerated OpenAPI bytes (for testing).
            When None, the gate regenerates OpenAPI by importing the app.
    """
    if repo_root is None:
        repo_root = Path(__file__).resolve().parent.parent

    align_map_path = repo_root / "tools" / "align_score_map.json"
    errors: list[str] = []
    notes: list[str] = []
    checked_files: dict[str, str] = {"align_map": str(align_map_path)}

    # Validate align map
    align_errors = validate_align_map(align_map_path)
    errors.extend(align_errors)

    # Check committed contracts exist
    for name, rel_path in CONTRACT_PATHS.items():
        full_path = repo_root / rel_path
        checked_files[name] = str(full_path)
        if not full_path.exists():
            errors.append(f"Committed contract not found: {rel_path}")

    if errors:
        return False, _build_report(
            passed=False,
            checked_files=checked_files,
            errors=errors,
            notes=notes,
        )

    # Regenerate or use provided content
    if generated_bytes is None:
        try:
            generated_bytes = regenerate_openapi(repo_root)
        except RuntimeError as exc:
            errors.append(str(exc))
            return False, _build_report(
                passed=False,
                checked_files=checked_files,
                errors=errors,
                notes=notes,
            )

    generated_hash = sha256_bytes(generated_bytes)

    # SHA256 compare against each committed contract
    for name, rel_path in CONTRACT_PATHS.items():
        full_path = repo_root / rel_path
        committed_bytes = full_path.read_bytes()
        committed_hash = sha256_bytes(committed_bytes)
        if committed_hash != generated_hash:
            errors.append(
                f"Contract drift in {rel_path}: "
                f"committed={committed_hash}, generated={generated_hash}"
            )
        else:
            notes.append(f"{rel_path}: SHA256 match ({committed_hash})")

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
    artifact_path = gates_dir / "bp_c_002_report.json"
    artifact_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if passed:
        print("BP-C-002 gate: PASS")
    else:
        print(f"BP-C-002 gate: FAIL ({len(report['errors'])} errors)")
        for err in report["errors"]:
            print(f"  - {err}")

    print(f"Report: {artifact_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
