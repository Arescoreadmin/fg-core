#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_SPEC = ROOT / "contracts/core/openapi.json"
SCHEMA_SPEC = ROOT / "schemas/api/openapi.json"
MARKER_RE = re.compile(r"^Contract-Authority-SHA256:\s*[0-9a-f]{64}\s*$", re.MULTILINE)
TARGETS = [ROOT / "BLUEPRINT_STAGED.md", ROOT / "CONTRACT.md"]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _replace_marker(path: Path, digest: str) -> None:
    content = path.read_text(encoding="utf-8")
    replacement = f"Contract-Authority-SHA256: {digest}"
    if not MARKER_RE.search(content):
        raise RuntimeError(
            f"missing Contract-Authority-SHA256 marker in {path.relative_to(ROOT)}"
        )
    updated = MARKER_RE.sub(replacement, content)
    path.write_text(updated, encoding="utf-8")


def main() -> int:
    if not CONTRACT_SPEC.exists() or not SCHEMA_SPEC.exists():
        raise RuntimeError(
            "openapi artifacts are missing; run contracts generation first"
        )

    contract_bytes = CONTRACT_SPEC.read_bytes()
    SCHEMA_SPEC.write_bytes(contract_bytes)
    digest = _sha256(CONTRACT_SPEC)

    for target in TARGETS:
        _replace_marker(target, digest)

    print(
        f"✅ refreshed contract authority markers and mirrored schema (sha256={digest})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
