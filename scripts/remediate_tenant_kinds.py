#!/usr/bin/env python3
"""scripts/remediate_tenant_kinds.py — Reclassify non-commercial tenants whose
tenant_kind is incorrectly set to 'customer', preventing the backfill script
from running clean.

Background
----------
The backfill classifier treats tenant_kind='customer' + active credential as
either ASSIGN (if in KNOWN_COMMERCIAL_TENANTS) or MANUAL_REVIEW (otherwise).
Several test/demo tenants created before the tenant_kind discipline was enforced
are still stored as 'customer', causing them to land in MANUAL_REVIEW on every
dry-run.

This script reclassifies them so the next dry-run reports 0 MANUAL_REVIEW.

Reclassification map (founder-approved 2026-08-12)
----------------------------------------------------
  demo-bank           customer → demo        (demo/showcase fixture)
  demo-healthcare     customer → demo        (demo/showcase fixture)
  lace-money-group    customer → validation  (T5 load-test tenant; never a paying client)
  fg-gold-path-*      customer → validation  (T4/T5 gold-path test fixtures)
  fg-t6-rehearsal-*   customer → validation  (T6 operational rehearsal artifacts)
  fg-t13-purge-test-* customer → validation  (T13 purge-test fixture)

Safety
------
- dry-run by default; pass --commit to write
- only touches tenant_kind; no credential mutations
- logs every row it would (or does) update
- idempotent: skips rows already at target kind

Exit codes
----------
  0  all updates applied (or already correct)
  1  error
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Tuple

RECLASSIFY: list[Tuple[str, str, str]] = [
    # (tenant_id_or_prefix, match_mode, target_kind)
    # match_mode: "exact" or "prefix"
    ("demo-bank", "exact", "demo"),
    ("demo-healthcare", "exact", "demo"),
    ("lace-money-group", "exact", "validation"),
    ("fg-gold-path-", "prefix", "validation"),
    ("fg-t6-rehearsal-", "prefix", "validation"),
    ("fg-t13-purge-test-", "prefix", "validation"),
]


def _get_engine():
    try:
        from sqlalchemy import create_engine as _ce
    except ImportError:
        print("ERROR: sqlalchemy not installed", file=sys.stderr)
        sys.exit(1)

    for var in ("FG_DB_OPERATOR_URL", "FG_DB_URL"):
        url = os.environ.get(var, "").strip()
        if url:
            if var == "FG_DB_URL":
                print(
                    f"WARNING: using {var} — prefer FG_DB_OPERATOR_URL (superuser) "
                    "to bypass RLS; tenant_kind updates may be blocked by row-level policies",
                    file=sys.stderr,
                )
            return _ce(url, future=True)

    sqlite_path = os.environ.get("FG_SQLITE_PATH", "").strip()
    if sqlite_path:
        return _ce(f"sqlite:///{sqlite_path}", future=True)

    print(
        "ERROR: no DB URL configured. Set FG_DB_OPERATOR_URL, FG_DB_URL, or FG_SQLITE_PATH.",
        file=sys.stderr,
    )
    sys.exit(1)


def _fetch_candidates(conn, pattern: str, match_mode: str) -> list[str]:
    from sqlalchemy import text

    if match_mode == "exact":
        rows = conn.execute(
            text(
                "SELECT tenant_id FROM tenants WHERE tenant_id = :tid AND tenant_kind = 'customer'"
            ),
            {"tid": pattern},
        ).fetchall()
    else:
        rows = conn.execute(
            text(
                "SELECT tenant_id FROM tenants WHERE tenant_id LIKE :pat AND tenant_kind = 'customer'"
            ),
            {"pat": f"{pattern}%"},
        ).fetchall()
    return [r[0] for r in rows]


def run(dry_run: bool) -> None:
    from sqlalchemy import text

    engine = _get_engine()
    updates: list[tuple[str, str]] = []

    with engine.connect() as conn:
        for pattern, match_mode, target_kind in RECLASSIFY:
            candidates = _fetch_candidates(conn, pattern, match_mode)
            for tid in candidates:
                updates.append((tid, target_kind))
                verb = "WOULD UPDATE" if dry_run else "UPDATING"
                print(f"[remediate] {verb}: {tid!r}  customer → {target_kind}")

    if not updates:
        print("[remediate] no rows to update — already correct or tenants not found")
        return

    if dry_run:
        print(
            f"\n[remediate] DRY-RUN: {len(updates)} row(s) would be updated. Pass --commit to write."
        )
        return

    with engine.begin() as conn:
        for tid, target_kind in updates:
            conn.execute(
                text("UPDATE tenants SET tenant_kind = :kind WHERE tenant_id = :tid"),
                {"kind": target_kind, "tid": tid},
            )

    print(
        f"\n[remediate] committed {len(updates)} update(s). Re-run backfill dry-run to confirm 0 MANUAL_REVIEW."
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reclassify test/demo tenants whose tenant_kind is incorrectly 'customer'."
    )
    parser.add_argument(
        "--commit",
        action="store_true",
        help="Apply updates (default is dry-run).",
    )
    args = parser.parse_args()
    run(dry_run=not args.commit)


if __name__ == "__main__":
    main()
