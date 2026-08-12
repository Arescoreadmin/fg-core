#!/usr/bin/env python3
"""scripts/attest_historical_role_assignments.py — Write attestation records to
tenant_role_audit for the three role assignments that predate the corrected audit
path (PR #632).

Background
----------
The initial live backfill ran before PR #632 added the audit write to assign_role().
The three resulting assignments (odin-financial-group × 1, the-wick-network × 2)
are correct and active, but tenant_role_audit has zero rows for them.

This script appends one immutable attestation event per assignment using
action="historical_assignment_attested".  It does NOT touch tenant_credential_roles;
the authorization state is unchanged.

Prefer this over calling assign_role() (revoke-then-reinsert) because:
  - The existing bindings are correct; there is no need to revoke them.
  - Revoke-then-reinsert changes granted_at, disrupting any audit chain that
    references the original grant timestamp.
  - Attestation records are honest: they record WHEN the evidence was reconstructed,
    not fabricate a historical event timestamp.

The attested facts match the actual grant rows in tenant_credential_roles:
  odin-financial-group / b50ea02a... / tenant_admin / granted_at 2026-08-12T10:38:17Z
  the-wick-network     / 4921106c... / tenant_admin / granted_at 2026-08-12T10:38:17Z
  the-wick-network     / c672771d... / tenant_admin / granted_at 2026-08-12T10:38:17Z

The actual credential IDs must be supplied via --credentials-json (see usage below)
so this script can be audited against the live DB before execution.

Usage
-----
  FG_DB_OPERATOR_URL=<superuser> python scripts/attest_historical_role_assignments.py \\
      --credentials-json '[
          {"tenant_id": "odin-financial-group", "credential_id": "b50ea02a-...", "original_granted_at": "2026-08-12T10:38:17Z"},
          {"tenant_id": "the-wick-network",     "credential_id": "4921106c-...", "original_granted_at": "2026-08-12T10:38:17Z"},
          {"tenant_id": "the-wick-network",     "credential_id": "c672771d-...", "original_granted_at": "2026-08-12T10:38:17Z"}
      ]'

  Add --commit to write.  Default is dry-run.

Exit codes
----------
  0  success
  1  error
  2  one or more credentials already have an attestation record (idempotency guard)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone


ATTESTATION_ACTOR = "operator:audit-remediation-20260812"
ATTESTATION_ACTION = "historical_assignment_attested"


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
                    f"WARNING: using {var} — prefer FG_DB_OPERATOR_URL (superuser)",
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


def _check_existing(conn, tenant_id: str, credential_id: str) -> bool:
    from sqlalchemy import text

    row = conn.execute(
        text(
            "SELECT event_id FROM tenant_role_audit "
            "WHERE tenant_id = :tid AND target_credential_id = :cid "
            "AND action = :action LIMIT 1"
        ),
        {"tid": tenant_id, "cid": credential_id, "action": ATTESTATION_ACTION},
    ).fetchone()
    return row is not None


def _get_active_role(conn, tenant_id: str, credential_id: str) -> str:
    """Return the active role_name, or '<no active role>' if none exists."""
    from sqlalchemy import text

    row = conn.execute(
        text(
            "SELECT role_name FROM tenant_credential_roles "
            "WHERE tenant_id = :tid AND credential_id = :cid AND revoked_at IS NULL LIMIT 1"
        ),
        {"tid": tenant_id, "cid": credential_id},
    ).fetchone()
    return str(row[0]) if row else "<no active role>"


def run(credentials: list[dict], dry_run: bool) -> int:
    from sqlalchemy import text

    engine = _get_engine()
    now = datetime.now(timezone.utc).isoformat()
    already_attested: list[str] = []

    with engine.connect() as conn:
        for entry in credentials:
            tid = entry["tenant_id"]
            cid = entry["credential_id"]
            original_granted_at = entry.get("original_granted_at", "unknown")

            actual = _get_active_role(conn, tid, cid)
            if actual != "tenant_admin":
                print(
                    f"ERROR: {tid}/{cid[:8]}... — active role is {actual!r}, "
                    "expected 'tenant_admin'. Refusing to attest a mismatched assignment.",
                    file=sys.stderr,
                )
                sys.exit(1)

            if _check_existing(conn, tid, cid):
                print(f"[attest] SKIP (already attested): {tid}/{cid[:8]}...")
                already_attested.append(cid)
                continue

            verb = "WOULD INSERT" if dry_run else "INSERTING"
            print(
                f"[attest] {verb}: {tid}/{cid[:8]}...  "
                f"original_granted_at={original_granted_at}"
            )

    if dry_run:
        print(
            f"\n[attest] DRY-RUN: {len(credentials) - len(already_attested)} record(s) to write. Pass --commit to write."
        )
        return 2 if already_attested else 0

    with engine.begin() as conn:
        for entry in credentials:
            tid = entry["tenant_id"]
            cid = entry["credential_id"]
            original_granted_at = entry.get("original_granted_at", "unknown")

            if _check_existing(conn, tid, cid):
                continue

            event_id = str(uuid.uuid4())
            conn.execute(
                text(
                    "INSERT INTO tenant_role_audit "
                    "(event_id, tenant_id, actor_key_prefix, action, target_key_prefix, "
                    "target_credential_id, role_name, timestamp, success) "
                    "VALUES (:eid, :tid, :actor, :action, NULL, :cid, :role, :ts, 1)"
                ),
                {
                    "eid": event_id,
                    "tid": tid,
                    "actor": ATTESTATION_ACTOR,
                    "action": ATTESTATION_ACTION,
                    "cid": cid,
                    "role": "tenant_admin",
                    "ts": now,
                },
            )
            print(f"[attest] wrote attestation event {event_id} for {tid}/{cid[:8]}...")

    print(
        f"\n[attest] done. Verify: SELECT * FROM tenant_role_audit WHERE action = '{ATTESTATION_ACTION}';"
    )
    return 2 if already_attested else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Append attestation records to tenant_role_audit for pre-audit-fix assignments."
    )
    parser.add_argument(
        "--credentials-json",
        required=True,
        help="JSON array of {tenant_id, credential_id, original_granted_at} objects.",
    )
    parser.add_argument(
        "--commit",
        action="store_true",
        help="Write records (default is dry-run).",
    )
    args = parser.parse_args()

    try:
        credentials = json.loads(args.credentials_json)
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(credentials, list) or not credentials:
        print(
            "ERROR: --credentials-json must be a non-empty JSON array", file=sys.stderr
        )
        sys.exit(1)

    rc = run(credentials, dry_run=not args.commit)
    sys.exit(rc)


if __name__ == "__main__":
    main()
