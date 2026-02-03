#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterable

from jsonschema import Draft202012Validator

SCHEMA_DIR = Path("contracts/artifacts")
FIXTURE_DIR = SCHEMA_DIR / "fixtures"
DECISION_SCHEMA = SCHEMA_DIR / "decision.schema.json"
DECISION_FIXTURE = FIXTURE_DIR / "decision_fixture.v1.json"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _iter_schema_paths() -> Iterable[Path]:
    return sorted(SCHEMA_DIR.glob("*.schema.json"))


def _iter_fixtures_for(schema_path: Path) -> Iterable[Path]:
    stem = schema_path.stem.replace(".schema", "")
    pattern = f"{stem}_fixture*.json"
    return sorted(FIXTURE_DIR.glob(pattern))


def _fail(msg: str) -> int:
    print(f"❌ Artifact schema check failed: {msg}", file=sys.stderr)
    return 1


def _validate_schema(path: Path) -> None:
    schema = _load_json(path)
    Draft202012Validator.check_schema(schema)


def _validate_fixture(schema_path: Path, fixture_path: Path) -> None:
    schema = _load_json(schema_path)
    fixture = _load_json(fixture_path)
    Draft202012Validator(schema).validate(fixture)


def main() -> int:
    schema_paths = list(_iter_schema_paths())
    if not schema_paths:
        return _fail("No artifact schemas found in contracts/artifacts.")

    for path in schema_paths:
        try:
            _validate_schema(path)
        except Exception as exc:
            return _fail(f"Invalid JSON Schema ({path}): {exc}")

    if not DECISION_SCHEMA.exists():
        return _fail(f"Missing decision schema at {DECISION_SCHEMA}")
    if not DECISION_FIXTURE.exists():
        return _fail(f"Missing decision fixture at {DECISION_FIXTURE}")

    try:
        _validate_fixture(DECISION_SCHEMA, DECISION_FIXTURE)
    except Exception as exc:
        return _fail(f"Decision fixture does not validate: {exc}")

    for schema_path in schema_paths:
        for fixture_path in _iter_fixtures_for(schema_path):
            try:
                _validate_fixture(schema_path, fixture_path)
            except Exception as exc:
                return _fail(
                    f"Fixture {fixture_path} does not validate against {schema_path}: {exc}"
                )

    print("✅ Artifact schemas valid; fixture validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
