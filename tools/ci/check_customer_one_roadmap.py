#!/usr/bin/env python3
"""Deterministic Customer-One roadmap authority checker.

Derives authorization from the authority file — the caller cannot self-declare
a work class and bypass the Freeze Law.  Authorization is determined by looking
up the proposed work item in next_sequence (authorized) or deferred (blocked).
Items not listed in either are fail-closed (blocked).

Usage:
    # Specific work item — authorization derived from authority file:
    python tools/ci/check_customer_one_roadmap.py --work-item P1-01-PR2
    python tools/ci/check_customer_one_roadmap.py --work-item SAML

    # Defect repair — always authorized, no item ID required:
    python tools/ci/check_customer_one_roadmap.py --work-class REPAIR

    # Custom authority path:
    python tools/ci/check_customer_one_roadmap.py --authority customer_one/roadmap_authority.yaml --work-item P1-01-PR2

Exit codes:
    0 — work item is authorized (in next_sequence) or work-class is REPAIR
    1 — work item is deferred, unknown, or authority file is missing/malformed
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
        print(
            f"ERROR: authority file must be a YAML mapping, got {type(data).__name__}",
            file=sys.stderr,
        )
        sys.exit(1)
    if "next_sequence" not in data or "deferred" not in data or "completed" not in data:
        print(
            "ERROR: authority file missing required keys 'next_sequence', 'deferred', and/or 'completed'",
            file=sys.stderr,
        )
        sys.exit(1)
    return data


def _check_item(authority: dict, work_item: str) -> bool:
    """Derive authorization from item presence in next_sequence or deferred.

    Completed items are explicitly blocked — re-opening completed work requires
    a new Freeze Law justification filed as a PR against the authority file.
    Fail-closed: an item not listed in any known set is blocked.
    """
    next_ids = {
        entry["id"] for entry in authority.get("next_sequence", []) if "id" in entry
    }
    deferred_ids = {
        entry["id"] for entry in authority.get("deferred", []) if "id" in entry
    }
    completed_ids = {
        entry["id"] for entry in authority.get("completed", []) if "id" in entry
    }

    if work_item in completed_ids:
        prs: list[str] = next(
            (
                e.get("prs", [])
                for e in authority.get("completed", [])
                if e.get("id") == work_item
            ),
            [],
        )
        pr_str = f" ({', '.join(prs)})" if prs else ""
        print(
            f"BLOCKED: '{work_item}' is COMPLETED{pr_str} — already merged and closed; "
            "no further work authorized on this item",
            file=sys.stderr,
        )
        return False

    if work_item in next_ids:
        print(
            f"AUTHORIZED: '{work_item}' is in next_sequence — on Customer-One critical path"
        )
        return True

    if work_item in deferred_ids:
        # Find reason if available
        reason = next(
            (
                e.get("reason", "")
                for e in authority.get("deferred", [])
                if e.get("id") == work_item
            ),
            "",
        )
        msg = f"BLOCKED: '{work_item}' is explicitly DEFERRED under the Freeze Law"
        if reason:
            msg += f" — {reason}"
        print(msg, file=sys.stderr)
        return False

    print(
        f"BLOCKED: '{work_item}' is not in next_sequence or deferred — fail-closed; "
        "add it to next_sequence with Freeze Law justification to authorize",
        file=sys.stderr,
    )
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--authority",
        default=_DEFAULT_AUTHORITY,
        help=f"Path to roadmap authority YAML (default: {_DEFAULT_AUTHORITY})",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--work-item",
        help="ID of the proposed work item (looked up in next_sequence/deferred)",
    )
    group.add_argument(
        "--work-class",
        choices=["REPAIR"],
        help="Work class for class-level authorization (only REPAIR is accepted; use --work-item for all other work)",
    )
    args = parser.parse_args()

    if args.work_class == "REPAIR":
        print("AUTHORIZED: work-class REPAIR — defect repairs are always authorized")
        sys.exit(0)

    authority = _load_authority(args.authority)
    authorized = _check_item(authority, args.work_item)
    sys.exit(0 if authorized else 1)


if __name__ == "__main__":
    main()
