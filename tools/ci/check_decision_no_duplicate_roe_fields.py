#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

LEGACY_FIELDS = ("roe_applied", "disruption_limited", "ao_required")


def _iter_json_files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*.json") if p.is_file()]


def main() -> int:
    # Adjust this path if your emitted artifacts live elsewhere too.
    roots = [
        Path("contracts/artifacts"),
        Path("artifacts"),
    ]

    offenders: list[tuple[str, str]] = []

    for root in roots:
        if not root.exists():
            continue
        for p in _iter_json_files(root):
            try:
                obj = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue

            if not isinstance(obj, dict):
                continue

            # Only police decision-like shapes that have tie_d (avoid random JSON)
            tie_d = obj.get("tie_d")
            if not isinstance(tie_d, dict):
                continue

            for f in LEGACY_FIELDS:
                if f in obj:
                    offenders.append((str(p), f))

    if offenders:
        print(
            "ERROR: legacy ROE fields present at top-level; tie_d is the source of truth."
        )
        for path, field in offenders[:200]:
            print(f" - {path}: {field}")
        if len(offenders) > 200:
            print(f"... and {len(offenders) - 200} more")
        return 2

    print("OK: no legacy top-level ROE fields found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
