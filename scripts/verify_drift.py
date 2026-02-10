#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from scripts.contracts_diff_core import main as openapi_diff_main
from scripts.verify_schemas import _extract_version

REGISTRY_PATH = Path("schemas/registry.json")

VERSION_PATTERNS = {
    "api/ingest_bus.py": re.compile(r'MESSAGE_SCHEMA_VERSION\s*=\s*"([^"]+)"'),
    "api/evidence_artifacts.py": re.compile(
        r'DECISION_EVIDENCE_SCHEMA_VERSION\s*=\s*"([^"]+)"'
    ),
}


def _fail(msg: str) -> int:
    print(f"❌ Drift check failed: {msg}", file=sys.stderr)
    return 1


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _check_code_refs(registry: dict) -> int:
    for entry in registry.get("schemas", []):
        for ref in entry.get("code_refs", []):
            path = Path(ref.get("path", ""))
            pattern = ref.get("pattern", "")
            if not path.exists():
                return _fail(f"code_ref path missing: {path}")
            content = path.read_text(encoding="utf-8")
            if pattern not in content:
                return _fail(f"code_ref pattern missing: {pattern} in {path}")
    return 0


def _check_version_alignment(registry: dict) -> int:
    for entry in registry.get("schemas", []):
        schema_path = Path(entry.get("path", ""))
        schema = _load_json(schema_path)
        schema_version = _extract_version(schema, entry.get("type", ""))
        for ref in entry.get("code_refs", []):
            path = Path(ref.get("path", ""))
            pattern = VERSION_PATTERNS.get(str(path))
            if not pattern:
                continue
            content = path.read_text(encoding="utf-8")
            match = pattern.search(content)
            if not match:
                return _fail(f"missing version constant in {path}")
            code_version = match.group(1)
            if schema_version != code_version:
                return _fail(
                    f"schema version mismatch for {schema_path}: "
                    f"{schema_version} != {code_version} ({path})"
                )
    return 0


def main() -> int:
    if not REGISTRY_PATH.exists():
        return _fail(f"Missing registry: {REGISTRY_PATH}")

    registry = _load_json(REGISTRY_PATH)

    openapi_rc = openapi_diff_main()
    if openapi_rc != 0:
        return openapi_rc

    rc = _check_code_refs(registry)
    if rc != 0:
        return rc

    rc = _check_version_alignment(registry)
    if rc != 0:
        return rc

    print("✅ Drift verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
