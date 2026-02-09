#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

CONTRACT_SPEC = Path("contracts/core/openapi.json")
BLUEPRINT = Path("BLUEPRINT_STAGED.md")
CONTRACT_MD = Path("CONTRACT.md")


def _die(msg: str) -> int:
    print(f"❌ CONTRACT AUTHORITY CHECK FAILED: {msg}", file=sys.stderr)
    return 1


def _hash_file(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest()


def _require_marker(path: Path, expected_hash: str) -> None:
    content = path.read_text(encoding="utf-8")
    marker = f"Contract-Authority-SHA256: {expected_hash}"
    if marker not in content:
        raise ValueError(f"{path} missing or outdated authority marker: {marker}")
    if "Contract Authority: contracts/core/openapi.json (prod)" not in content:
        raise ValueError(f"{path} missing Contract Authority declaration for prod spec")


def main() -> int:
    if not CONTRACT_SPEC.exists():
        return _die(f"Missing contract spec at {CONTRACT_SPEC}")
    if not BLUEPRINT.exists():
        return _die("Missing BLUEPRINT_STAGED.md")
    if not CONTRACT_MD.exists():
        return _die("Missing CONTRACT.md")

    spec_hash = _hash_file(CONTRACT_SPEC)

    try:
        _require_marker(BLUEPRINT, spec_hash)
        _require_marker(CONTRACT_MD, spec_hash)
    except ValueError as exc:
        return _die(str(exc))

    print("✅ Contract authority markers match prod OpenAPI spec")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
