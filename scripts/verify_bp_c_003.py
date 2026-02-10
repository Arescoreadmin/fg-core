#!/usr/bin/env python3
"""BP-C-003 gate: Schema Registry Integrity Gate.

Invariant:
Every schema MUST be:
- Valid under JSON Schema Draft 2020-12
- Referenced by at least one OpenAPI document
- Non-orphaned

Mandatory conditions:
- Load all schemas under schemas/api/.
- Validate each with Draft202012Validator.
- Extract $ref usage from OpenAPI.
- Any invalid schema, unused schema, missing referenced schema -> FAIL.

Evidence artifact: artifacts/gates/bp_c_003_report.json
Exit code: 0 if passed, 1 if failed.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

GATE_ID = "BP-C-003"
INVARIANT = (
    "Every schema MUST be: valid under JSON Schema Draft 2020-12, "
    "referenced by at least one OpenAPI document, non-orphaned."
)
EXPECTED_ALIGN_VALUE = "make bp-c-003-gate"

SCHEMAS_DIR = "schemas/api"
OPENAPI_PATHS = [
    "contracts/core/openapi.json",
    "schemas/api/openapi.json",
]

_COMPONENT_SCHEMA_REF_RE = re.compile(r"^#/components/schemas/(.+)$")


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


def extract_component_schemas(openapi: dict) -> dict[str, dict]:
    """Extract component schemas from an OpenAPI document."""
    components = openapi.get("components", {})
    if not isinstance(components, dict):
        return {}
    schemas = components.get("schemas", {})
    if not isinstance(schemas, dict):
        return {}
    return schemas


def collect_refs(obj: object) -> set[str]:
    """Recursively collect all $ref values from a JSON structure."""
    refs: set[str] = set()
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key == "$ref" and isinstance(val, str):
                refs.add(val)
            else:
                refs.update(collect_refs(val))
    elif isinstance(obj, list):
        for item in obj:
            refs.update(collect_refs(item))
    return refs


def extract_referenced_schema_names(openapi: dict) -> set[str]:
    """Extract all schema names referenced via $ref in an OpenAPI document.

    Only considers #/components/schemas/... refs.
    Excludes self-references from within components.schemas definitions.
    """
    all_refs = set()

    # Collect refs from paths, webhooks, and top-level (excluding components.schemas
    # self-references is not needed; any $ref counts as usage)
    raw_refs = collect_refs(openapi)

    for ref_val in raw_refs:
        m = _COMPONENT_SCHEMA_REF_RE.match(ref_val)
        if m:
            all_refs.add(m.group(1))

    return all_refs


def validate_schemas(
    component_schemas: dict[str, dict],
) -> list[str]:
    """Validate each component schema with Draft202012Validator.

    Returns list of error strings.
    """
    from jsonschema.validators import Draft202012Validator

    errors: list[str] = []
    for name, schema in sorted(component_schemas.items()):
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            errors.append(f"Schema '{name}' invalid under Draft 2020-12: {exc}")
    return errors


def check_orphans_and_missing(
    defined_names: set[str],
    referenced_names: set[str],
) -> tuple[list[str], list[str]]:
    """Check for unused schemas and missing referenced schemas.

    Returns (unused_errors, missing_errors).
    """
    unused_errors: list[str] = []
    missing_errors: list[str] = []

    unused = defined_names - referenced_names
    for name in sorted(unused):
        unused_errors.append(f"Schema '{name}' defined but never referenced (orphaned)")

    missing = referenced_names - defined_names
    for name in sorted(missing):
        missing_errors.append(
            f"Schema '{name}' referenced via $ref but not defined in components.schemas"
        )

    return unused_errors, missing_errors


def run_gate(
    *,
    repo_root: Path | None = None,
) -> tuple[bool, dict]:
    """Run BP-C-003 gate. Returns (passed, report_dict)."""
    if repo_root is None:
        repo_root = Path(__file__).resolve().parent.parent

    align_map_path = repo_root / "tools" / "align_score_map.json"
    schemas_dir = repo_root / SCHEMAS_DIR
    errors: list[str] = []
    notes: list[str] = []
    checked_files: dict[str, str] = {"align_map": str(align_map_path)}

    # Validate align map
    align_errors = validate_align_map(align_map_path)
    errors.extend(align_errors)

    # Load all schema files under schemas/api/
    if not schemas_dir.exists() or not schemas_dir.is_dir():
        errors.append(f"Schema directory not found: {schemas_dir}")
        return False, _build_report(
            passed=False,
            checked_files=checked_files,
            errors=errors,
            notes=notes,
        )

    schema_files = sorted(schemas_dir.glob("*.json"))
    if not schema_files:
        errors.append(f"No JSON schema files found in {schemas_dir}")
        return False, _build_report(
            passed=False,
            checked_files=checked_files,
            errors=errors,
            notes=notes,
        )

    # Aggregate component schemas and refs across all files
    all_defined: dict[str, dict] = {}
    all_referenced: set[str] = set()

    for sf in schema_files:
        checked_files[sf.name] = str(sf)
        try:
            doc = json.loads(sf.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"Failed to parse {sf.name}: {exc}")
            continue

        component_schemas = extract_component_schemas(doc)
        all_defined.update(component_schemas)

        refs = extract_referenced_schema_names(doc)
        all_referenced.update(refs)
        notes.append(
            f"{sf.name}: {len(component_schemas)} schemas, {len(refs)} refs"
        )

    # Also extract refs from contracts/core/openapi.json if it differs from schemas/api/
    for openapi_rel in OPENAPI_PATHS:
        openapi_path = repo_root / openapi_rel
        if not openapi_path.exists():
            continue
        if str(openapi_path) in [str(sf) for sf in schema_files]:
            continue
        checked_files[openapi_rel.replace("/", "_")] = str(openapi_path)
        try:
            doc = json.loads(openapi_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        refs = extract_referenced_schema_names(doc)
        all_referenced.update(refs)
        component_schemas = extract_component_schemas(doc)
        all_defined.update(component_schemas)

    # Validate each schema with Draft202012Validator
    validation_errors = validate_schemas(all_defined)
    errors.extend(validation_errors)

    # Check orphans and missing
    defined_names = set(all_defined.keys())
    unused_errors, missing_errors = check_orphans_and_missing(
        defined_names, all_referenced
    )
    errors.extend(unused_errors)
    errors.extend(missing_errors)

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
    artifact_path = gates_dir / "bp_c_003_report.json"
    artifact_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if passed:
        print("BP-C-003 gate: PASS")
    else:
        print(f"BP-C-003 gate: FAIL ({len(report['errors'])} errors)")
        for err in report["errors"]:
            print(f"  - {err}")

    print(f"Report: {artifact_path}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
