#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))


def main() -> int:
    from services.plane_registry import PLANE_REGISTRY

    failures: list[str] = []

    route_inventory = json.loads((REPO / "tools/ci/route_inventory.json").read_text(encoding="utf-8"))
    route_paths = {str(r.get("path", "")) for r in route_inventory}
    makefile = (REPO / "Makefile").read_text(encoding="utf-8")

    for plane in PLANE_REGISTRY:
        if not plane.route_prefixes:
            failures.append(f"plane {plane.plane_id} missing route prefixes")
        else:
            matched = False
            for prefix in plane.route_prefixes:
                if any(p.startswith(prefix) for p in route_paths):
                    matched = True
                    break
            if not matched:
                failures.append(f"plane {plane.plane_id} has no routes in inventory for prefixes {plane.route_prefixes}")

        if not plane.mount_flag.startswith("FG_"):
            failures.append(f"plane {plane.plane_id} mount_flag invalid: {plane.mount_flag}")

        for target in plane.required_make_targets:
            if f"{target}:" not in makefile:
                failures.append(f"plane {plane.plane_id} missing make target {target}")

        for e in plane.evidence:
            if not (REPO / e.schema_path).exists():
                failures.append(f"plane {plane.plane_id} missing evidence schema {e.schema_path}")
            if not (REPO / e.generator_script).exists():
                failures.append(f"plane {plane.plane_id} missing evidence generator {e.generator_script}")

    if failures:
        print("plane registry check: FAILED")
        for f in failures:
            print(f" - {f}")
        return 1

    print("plane registry check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
