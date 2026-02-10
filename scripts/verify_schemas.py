#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REGISTRY_PATH = Path("schemas/registry.json")
SEMVER_RE = re.compile(r"^\d+\.\d+(\.\d+)?$")


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, indent=2) + "\n"


def _fail(msg: str) -> int:
    print(f"❌ Schema verification failed: {msg}", file=sys.stderr)
    return 1


def _extract_version(schema: dict, schema_type: str) -> str | None:
    if schema_type == "api":
        return str(schema.get("info", {}).get("version") or "").strip() or None
    if schema_type == "events":
        return schema.get("properties", {}).get("version", {}).get("enum", [None])[0]
    if schema_type == "artifacts":
        return (
            schema.get("properties", {})
            .get("schema_version", {})
            .get("enum", [None])[0]
        )
    return None


def main() -> int:
    if not REGISTRY_PATH.exists():
        return _fail(f"Missing registry: {REGISTRY_PATH}")

    registry = _load_json(REGISTRY_PATH)
    entries = registry.get("schemas", [])
    if not isinstance(entries, list) or not entries:
        return _fail("Registry has no schemas.")

    registry_paths = set()
    for entry in entries:
        path = Path(entry.get("path", ""))
        if not path:
            return _fail("Registry entry missing path.")
        if not path.exists():
            return _fail(f"Schema missing: {path}")
        registry_paths.add(path.resolve())

        schema = _load_json(path)
        schema_type = entry.get("type", "")
        version = _extract_version(schema, schema_type)
        if not version:
            return _fail(f"{path} missing version metadata for type={schema_type}")
        if not SEMVER_RE.fullmatch(str(version)):
            return _fail(f"{path} has invalid version: {version}")

        source_path = entry.get("source_path")
        if source_path:
            source = Path(source_path)
            if not source.exists():
                return _fail(f"Source schema missing: {source_path}")
            if _canonical_json(schema) != _canonical_json(_load_json(source)):
                return _fail(f"Schema mismatch: {path} != {source_path}")

    all_schema_paths = {
        p.resolve()
        for p in Path("schemas").rglob("*.json")
        if p.name != "registry.json"
    }
    extra = sorted(p for p in all_schema_paths if p not in registry_paths)
    if extra:
        return _fail(f"Unregistered schemas found: {', '.join(str(p) for p in extra)}")

    print("✅ Schema registry verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
