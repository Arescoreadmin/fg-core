#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

BLUEPRINT_PATH = Path("BLUEPRINT_STAGED.md")
MAP_PATH = Path("tools/align_score_map.json")
REQ_RE = re.compile(r"\b(BP-[A-Z0-9-]{4,})\b")


def _fail(msg: str) -> int:
    print(f"❌ align_score failed: {msg}", file=sys.stderr)
    return 1


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    if not BLUEPRINT_PATH.exists():
        return _fail(f"Missing blueprint: {BLUEPRINT_PATH}")
    if not MAP_PATH.exists():
        return _fail(f"Missing align map: {MAP_PATH}")

    blueprint_text = BLUEPRINT_PATH.read_text(encoding="utf-8")
    req_ids = sorted(set(REQ_RE.findall(blueprint_text)))
    if not req_ids:
        return _fail("No requirement IDs found in blueprint.")

    mapping = _load_json(MAP_PATH)

    missing = [req for req in req_ids if req not in mapping]
    if missing:
        return _fail(f"Missing mappings for: {', '.join(missing)}")

    implemented = [req for req in req_ids if mapping.get(req) != "MISSING"]
    missing_checks = [req for req in req_ids if mapping.get(req) == "MISSING"]
    score = round((len(implemented) / max(len(req_ids), 1)) * 100, 2)

    print("Alignment score:", f"{score}%")
    print("Implemented checks:", len(implemented))
    if missing_checks:
        print("Missing checks:", ", ".join(missing_checks))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
