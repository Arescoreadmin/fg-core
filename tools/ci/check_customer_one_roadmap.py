#!/usr/bin/env python3
"""Deterministic Customer-One roadmap authority checker.

Usage:
    python tools/ci/check_customer_one_roadmap.py --work-class NEXT
    python tools/ci/check_customer_one_roadmap.py --authority customer_one/roadmap_authority.yaml --work-class REPAIR

Exit codes:
    0 — work class is authorized (gate=OPEN)
    1 — work class is blocked, unknown, or authority file is missing/malformed
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed — pip install pyyaml", file=sys.stderr)
    sys.exit(1)

_DEFAULT_AUTHORITY = "customer_one/roadmap_authority.yaml"


def _load_authority(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        print(f"ERROR: authority file not found: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        data = yaml.safe_load(p.read_text())
    except yaml.YAMLError as exc:
        print(f"ERROR: malformed YAML in {path}: {exc}", file=sys.stderr)
        sys.exit(1)
    if not isinstance(data, dict):
        print(f"ERROR: authority file must be a YAML mapping, got {type(data).__name__}", file=sys.stderr)
        sys.exit(1)
    if "work_classes" not in data:
        print(f"ERROR: authority file missing required key 'work_classes'", file=sys.stderr)
        sys.exit(1)
    return data


def _check(authority: dict, work_class: str) -> bool:
    """Return True if work_class is authorized (gate=OPEN). Fail-closed on unknown class."""
    classes = authority.get("work_classes", {})
    entry = classes.get(work_class)
    if entry is None:
        print(
            f"BLOCKED: work class '{work_class}' is not declared in authority; "
            "fail-closed — add it explicitly with gate=OPEN to authorize",
            file=sys.stderr,
        )
        return False
    gate = entry.get("gate", "BLOCKED")
    if gate == "OPEN":
        print(f"AUTHORIZED: work class '{work_class}' — gate=OPEN")
        return True
    desc = entry.get("description", "")
    print(f"BLOCKED: work class '{work_class}' — gate={gate}. {desc}", file=sys.stderr)
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--authority",
        default=_DEFAULT_AUTHORITY,
        help=f"Path to roadmap authority YAML (default: {_DEFAULT_AUTHORITY})",
    )
    parser.add_argument(
        "--work-class",
        required=True,
        help="Work class of the proposed change (NEXT, REPAIR, DEFERRED, UNKNOWN)",
    )
    args = parser.parse_args()

    authority = _load_authority(args.authority)
    authorized = _check(authority, args.work_class)
    sys.exit(0 if authorized else 1)


if __name__ == "__main__":
    main()
