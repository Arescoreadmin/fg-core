#!/usr/bin/env python3
"""scripts/backfill_credential_roles.py — Backfill tenant_credential_roles for existing credentials.

Context:
  The R4 Credential Authority work moved all credential storage to tenant_credentials +
  tenant_credential_roles, but the provisioning pipeline was never updated to write the
  initial role at issuance time.  All credentials issued before this fix have a valid
  entry in tenant_credentials but zero rows in tenant_credential_roles.

Classification logic:
  - tenant_kind = 'customer' AND credential status = 'active'  → tenant_admin
  - All other tenant_kind values (internal_platform, validation, demo)            → SKIP
    Rationale: internal/test credentials do not need portal access; over-privileging
    them with tenant_admin would violate least-privilege.  If a demo tenant genuinely
    needs RBAC access, it should be assigned manually after review.
  - Credentials with status != 'active' (rotated, revoked, expired)               → SKIP

Usage:
  python scripts/backfill_credential_roles.py [--dry-run]

  --dry-run   Print what would be written without actually writing anything.

Environment:
  Set FG_DB_URL (or FG_SQLITE_PATH for local dev) before running.
  The script reads from the same database used by the API.

  FG_DB_URL=postgresql://... python scripts/backfill_credential_roles.py
  FG_SQLITE_PATH=/path/to/fg.db python scripts/backfill_credential_roles.py --dry-run

This script is idempotent: INSERT ... ON CONFLICT DO NOTHING means running it
twice produces no duplicate active rows.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GRANTED_BY = "operator:backfill-20260811"
ROLE_FOR_CUSTOMER = "tenant_admin"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# DB connectivity
# ---------------------------------------------------------------------------


def _get_engine():
    """Build a SQLAlchemy engine from environment variables."""
    try:
        from sqlalchemy import create_engine
    except ImportError:
        print("ERROR: sqlalchemy is not installed.  Run: pip install sqlalchemy", file=sys.stderr)
        sys.exit(1)

    db_url = (os.getenv("FG_DB_URL") or "").strip()
    if db_url:
        return create_engine(db_url, future=True)

    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if sqlite_path:
        return create_engine(f"sqlite:///{sqlite_path}", future=True)

    # Last resort: try the api.db path resolution (works when run inside the repo).
    try:
        from api.db import get_engine as _api_get_engine
        return _api_get_engine()
    except Exception:
        pass

    print(
        "ERROR: Could not determine database URL.\n"
        "Set FG_DB_URL (Postgres) or FG_SQLITE_PATH (SQLite) before running.",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def _fetch_all_credentials(conn) -> list[dict]:
    """Return all credentials with tenant kind and existing active role (if any).

    This is the full inspection query used for dry-run display. It shows every
    credential so the operator can verify classification before any writes occur.
    """
    from sqlalchemy import text

    rows = conn.execute(
        text(
            """
            SELECT
                tc.credential_id,
                tc.tenant_id,
                tc.credential_type,
                tc.credential_slot,
                tc.status                   AS credential_status,
                t.tenant_kind,
                tcr.role_name               AS existing_active_role
            FROM tenant_credentials tc
            JOIN tenants t ON t.tenant_id = tc.tenant_id
            LEFT JOIN tenant_credential_roles tcr
                ON  tcr.credential_id = tc.credential_id
                AND tcr.tenant_id     = tc.tenant_id
                AND tcr.revoked_at IS NULL
            ORDER BY tc.tenant_id, tc.issued_at
            """
        )
    ).mappings().fetchall()
    return [dict(r) for r in rows]


def _fetch_candidates(conn) -> list[dict]:
    """Return credentials with no active role — the backfill targets."""
    from sqlalchemy import text

    rows = conn.execute(
        text(
            """
            SELECT
                tc.credential_id,
                tc.tenant_id,
                tc.credential_type,
                tc.credential_slot,
                tc.status          AS credential_status,
                t.tenant_kind
            FROM tenant_credentials tc
            JOIN tenants t ON t.tenant_id = tc.tenant_id
            LEFT JOIN tenant_credential_roles tcr
                ON  tcr.credential_id = tc.credential_id
                AND tcr.tenant_id     = tc.tenant_id
                AND tcr.revoked_at IS NULL
            WHERE tcr.id IS NULL
            ORDER BY tc.tenant_id, tc.issued_at
            """
        )
    ).mappings().fetchall()
    # Alias cred_status for backward compatibility with _classify().
    return [{**dict(r), "cred_status": r["credential_status"]} for r in rows]


def _classify(row: dict) -> tuple[str | None, str]:
    """Return (role_or_None, reason_string) for a candidate row."""
    cred_status = (row.get("cred_status") or row.get("credential_status") or "").strip()
    tenant_kind = (row.get("tenant_kind") or "").strip()

    if cred_status != "active":
        return None, f"credential_status={cred_status!r} is not active"

    if tenant_kind == "customer":
        return ROLE_FOR_CUSTOMER, f"tenant_kind={tenant_kind!r} → assign {ROLE_FOR_CUSTOMER}"

    # internal_platform, validation, demo, disposable — do not over-privilege.
    return None, f"tenant_kind={tenant_kind!r} is not customer (least-privilege skip)"


def _print_candidate_table(all_rows: list[dict]) -> None:
    """Print the full per-candidate classification table to stdout.

    Columns (no secrets, hashes, or plaintext credentials):
      tenant_id | tenant_kind | credential_id | credential_type | credential_slot
      | credential_status | existing_active_role | proposed_role | action | reason
    """
    col_w = {
        "tenant_id": max(9, max((len(r["tenant_id"]) for r in all_rows), default=9)),
        "tenant_kind": max(11, max((len(r.get("tenant_kind") or "") for r in all_rows), default=11)),
        "credential_id": max(13, max((len(r["credential_id"]) for r in all_rows), default=13)),
        "credential_type": max(15, max((len(r.get("credential_type") or "") for r in all_rows), default=15)),
        "credential_slot": max(15, max((len(r.get("credential_slot") or "") for r in all_rows), default=15)),
        "credential_status": 18,
        "existing_active_role": 20,
        "proposed_role": 13,
        "action": 6,
    }

    header = (
        f"{'tenant_id':<{col_w['tenant_id']}}  "
        f"{'tenant_kind':<{col_w['tenant_kind']}}  "
        f"{'credential_id':<{col_w['credential_id']}}  "
        f"{'credential_type':<{col_w['credential_type']}}  "
        f"{'credential_slot':<{col_w['credential_slot']}}  "
        f"{'credential_status':<{col_w['credential_status']}}  "
        f"{'existing_active_role':<{col_w['existing_active_role']}}  "
        f"{'proposed_role':<{col_w['proposed_role']}}  "
        f"{'action':<{col_w['action']}}  reason"
    )
    sep = "-" * len(header)
    print(header)
    print(sep)

    for row in all_rows:
        existing = row.get("existing_active_role") or "(none)"
        cred_status = (row.get("credential_status") or row.get("cred_status") or "").strip()
        tenant_kind = (row.get("tenant_kind") or "").strip()

        if existing != "(none)":
            proposed = existing
            action = "KEEP"
            reason = "already has active role"
        else:
            # Use _classify logic.
            if cred_status != "active":
                proposed = "(none)"
                action = "SKIP"
                reason = f"credential_status={cred_status!r} is not active"
            elif tenant_kind == "customer":
                proposed = ROLE_FOR_CUSTOMER
                action = "ASSIGN"
                reason = f"tenant_kind={tenant_kind!r} → assign {ROLE_FOR_CUSTOMER}"
            else:
                proposed = "(none)"
                action = "SKIP"
                reason = f"tenant_kind={tenant_kind!r} is not customer (least-privilege skip)"

        print(
            f"{row['tenant_id']:<{col_w['tenant_id']}}  "
            f"{tenant_kind:<{col_w['tenant_kind']}}  "
            f"{row['credential_id']:<{col_w['credential_id']}}  "
            f"{(row.get('credential_type') or ''):<{col_w['credential_type']}}  "
            f"{(row.get('credential_slot') or ''):<{col_w['credential_slot']}}  "
            f"{cred_status:<{col_w['credential_status']}}  "
            f"{existing:<{col_w['existing_active_role']}}  "
            f"{proposed:<{col_w['proposed_role']}}  "
            f"{action:<{col_w['action']}}  {reason}"
        )


def run(dry_run: bool) -> None:
    """Main entry point."""
    from sqlalchemy import text

    engine = _get_engine()
    now = _utc_now_iso()

    print(f"[backfill] {'DRY-RUN — ' if dry_run else ''}started at {now}")
    print(f"[backfill] database: {engine.url!r}")
    print(f"[backfill] granted_by: {GRANTED_BY}")
    print()

    with engine.begin() as conn:
        all_rows = _fetch_all_credentials(conn)
        candidates = [
            {**r, "cred_status": r["credential_status"]}
            for r in all_rows
            if r.get("existing_active_role") is None
        ]

    print(f"[backfill] total credentials inspected: {len(all_rows)}")
    print(f"[backfill] credentials with no active role: {len(candidates)}")
    print()
    _print_candidate_table(all_rows)
    print()

    stats = {
        "total": len(candidates),
        "backfilled": 0,
        "skipped": 0,
        "already_had_role": len(all_rows) - len(candidates),
    }
    skip_reasons: dict[str, int] = {}

    rows_to_insert: list[dict] = []
    for row in candidates:
        role, reason = _classify(row)
        if role is None:
            stats["skipped"] += 1
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
        else:
            rows_to_insert.append(
                {
                    "tenant_id": row["tenant_id"],
                    "credential_id": row["credential_id"],
                    "role_name": role,
                }
            )
            stats["backfilled"] += 1

    print(f"[backfill] plan: {stats['backfilled']} to assign, {stats['skipped']} to skip, "
          f"{stats['already_had_role']} already correct")

    if dry_run:
        print("[backfill] DRY-RUN: no writes performed.")
        _print_summary(stats, skip_reasons)
        return

    if not rows_to_insert:
        print("[backfill] nothing to insert — all candidates classified as skip.")
        _print_summary(stats, skip_reasons)
        return

    with engine.begin() as conn:
        # Detect SQL dialect for the upsert statement.
        dialect = engine.dialect.name  # 'postgresql' or 'sqlite'

        for r in rows_to_insert:
            if dialect == "postgresql":
                # PostgreSQL: use ON CONFLICT DO NOTHING with the partial unique index.
                # The partial index uidx_tcr_active_role covers (tenant_id, credential_id)
                # WHERE revoked_at IS NULL, so a plain ON CONFLICT (tenant_id, credential_id)
                # won't match it.  We use a DO NOTHING on the role_name + combination instead
                # by doing a guard SELECT first (idempotency).
                existing = conn.execute(
                    text(
                        "SELECT 1 FROM tenant_credential_roles "
                        "WHERE tenant_id = :tid AND credential_id = :cid AND revoked_at IS NULL"
                    ),
                    {"tid": r["tenant_id"], "cid": r["credential_id"]},
                ).fetchone()
                if existing:
                    stats["already_had_role"] += 1
                    stats["backfilled"] -= 1
                    continue
                conn.execute(
                    text(
                        "INSERT INTO tenant_credential_roles "
                        "(tenant_id, credential_id, role_name, granted_at, granted_by) "
                        "VALUES (:tid, :cid, :role, :now, :actor)"
                    ),
                    {
                        "tid": r["tenant_id"],
                        "cid": r["credential_id"],
                        "role": r["role_name"],
                        "now": now,
                        "actor": GRANTED_BY,
                    },
                )
            else:
                # SQLite: INSERT OR IGNORE (no partial-index ON CONFLICT support in older SQLite).
                existing = conn.execute(
                    text(
                        "SELECT 1 FROM tenant_credential_roles "
                        "WHERE tenant_id = :tid AND credential_id = :cid AND revoked_at IS NULL"
                    ),
                    {"tid": r["tenant_id"], "cid": r["credential_id"]},
                ).fetchone()
                if existing:
                    stats["already_had_role"] += 1
                    stats["backfilled"] -= 1
                    continue
                conn.execute(
                    text(
                        "INSERT OR IGNORE INTO tenant_credential_roles "
                        "(tenant_id, credential_id, role_name, granted_at, granted_by) "
                        "VALUES (:tid, :cid, :role, :now, :actor)"
                    ),
                    {
                        "tid": r["tenant_id"],
                        "cid": r["credential_id"],
                        "role": r["role_name"],
                        "now": now,
                        "actor": GRANTED_BY,
                    },
                )
            print(
                f"  [inserted] {r['tenant_id']} credential={r['credential_id']} role={r['role_name']}"
            )

    print()
    _print_summary(stats, skip_reasons)


def _print_summary(stats: dict, skip_reasons: dict) -> None:
    print("=" * 60)
    print("SUMMARY")
    print(f"  Total candidates (no active role): {stats['total']}")
    print(f"  Backfilled (inserted):             {stats['backfilled']}")
    print(f"  Skipped:                           {stats['skipped']}")
    if stats.get("already_had_role"):
        print(f"  Already had role (race/rerun):     {stats['already_had_role']}")
    if skip_reasons:
        print("  Skip breakdown:")
        for reason, count in sorted(skip_reasons.items()):
            print(f"    {reason}: {count}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Backfill tenant_credential_roles for credentials with no active role.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be written without actually writing anything.",
    )
    args = parser.parse_args()
    run(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
