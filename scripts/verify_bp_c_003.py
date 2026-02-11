#!/usr/bin/env python3
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GATE_ID = "BP-C-003"
INVARIANT = "Every schema MUST be: Valid under JSON Schema Draft 2020-12 Referenced by at least one OpenAPI document Non-orphaned"
EXPECTED_ALIGN = "make bp-c-003-gate"
REPORT_PATH = Path("artifacts/gates/bp_c_003_report.json")

REQUIRED_FILES = (
    Path("tools/align_score_map.json"),
    Path("contracts/core/openapi.json"),
    Path("schemas/api/openapi.json"),
    Path("schemas/api"),
)


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


def _collect_refs(node: Any, refs: set[str]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "$ref" and isinstance(v, str):
                refs.add(v)
            else:
                _collect_refs(v, refs)
    elif isinstance(node, list):
        for item in node:
            _collect_refs(item, refs)


def _normalize_ref(ref: str) -> str | None:
    base = ref.split("#", 1)[0]
    if not base:
        return None
    p = Path(base)
    try:
        return p.as_posix()
    except Exception:
        return None


def _write_report(passed: bool, errors: list[str], notes: list[str]) -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "gate_id": GATE_ID,
        "passed": passed,
        "generated_at_utc": _utc_now(),
        "invariant": INVARIANT,
        "checked_files": {
            "align_score_map": "tools/align_score_map.json",
            "core_openapi": "contracts/core/openapi.json",
            "schema_openapi": "schemas/api/openapi.json",
            "schema_registry_dir": "schemas/api",
            "gate_report": "artifacts/gates/bp_c_003_report.json",
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

    try:
        from jsonschema import Draft202012Validator  # type: ignore
    except ImportError as exc:
        errors.append(f"jsonschema import failed: {exc}")
        _write_report(False, errors, notes)
        return 1

    if errors:
        _write_report(False, errors, notes)
        return 1

    schema_files = sorted(
        p for p in Path("schemas/api").glob("*.json") if p.name != "openapi.json"
    )
    if not schema_files:
        notes.append(
            "schema_registry_mode=openapi-mirror (no standalone schema files under schemas/api)"
        )

    refs: set[str] = set()
    openapi_paths = [
        Path("contracts/core/openapi.json"),
        Path("schemas/api/openapi.json"),
    ]
    openapi_docs: list[dict[str, Any]] = []
    for op in openapi_paths:
        try:
            openapi_docs.append(json.loads(op.read_text(encoding="utf-8")))
        except Exception as exc:
            errors.append(f"failed to parse openapi document {op.as_posix()}: {exc}")
    for doc in openapi_docs:
        _collect_refs(doc, refs)

    normalized_refs = {r for ref in refs if (r := _normalize_ref(ref))}
    notes.append(f"openapi_refs={sorted(normalized_refs)}")

    existing_registry_paths = {p.as_posix() for p in schema_files}

    for ref in sorted(normalized_refs):
        if (
            ref.startswith("schemas/api/")
            and ref not in existing_registry_paths
            and ref != "schemas/api/openapi.json"
        ):
            errors.append(f"missing referenced schema: {ref}")

    for schema_path in schema_files:
        try:
            schema_doc = json.loads(schema_path.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"invalid schema json: {schema_path.as_posix()}: {exc}")
            continue

        try:
            Draft202012Validator.check_schema(schema_doc)
        except Exception as exc:
            errors.append(
                f"invalid schema for Draft 2020-12: {schema_path.as_posix()}: {exc}"
            )

        if schema_path.as_posix() not in normalized_refs:
            errors.append(f"unused schema: {schema_path.as_posix()}")

    passed = not errors
    _write_report(passed, errors, notes)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
