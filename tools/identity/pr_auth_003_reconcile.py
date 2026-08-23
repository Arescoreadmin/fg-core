#!/usr/bin/env python3
"""PR-AUTH-003C — Operator tool for running the identity-backfill reconciliation.

Wraps `api.identity_backfill_reconciliation.run_reconciliation` in a CLI:

    python tools/identity/pr_auth_003_reconcile.py [--json-out PATH]

Prints a summary to stdout. Exits 0 iff migration_closed is True, else 1.

Connection: constructed from environment variables (never a CLI argument, so
credentials never leak into shell history / process listings):

    FG_DB_MIGRATION_URL (preferred) — postgres URL for a BYPASSRLS / superuser
      role. Same requirement as run_preflight / run_backfill.
    FG_SQLITE_PATH — SQLite file for local dev / smoke tests.

Zero writes. Wrapped in a REPEATABLE READ transaction on PostgreSQL so all
reads see the same snapshot.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, is_dataclass
from typing import Any

from sqlalchemy import create_engine


def _get_engine() -> Any:
    """Build an engine from environment. Fails closed if nothing is configured."""
    migration_url = (os.getenv("FG_DB_MIGRATION_URL") or "").strip()
    if migration_url:
        # Normalize scheme for psycopg3 (matches api/db.py _db_migration_url).
        if migration_url.startswith("postgres://"):
            migration_url = (
                "postgresql+psycopg://" + migration_url[len("postgres://") :]
            )
        elif migration_url.startswith("postgresql://"):
            migration_url = (
                "postgresql+psycopg://" + migration_url[len("postgresql://") :]
            )
        return create_engine(migration_url, future=True)

    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if sqlite_path:
        return create_engine(f"sqlite:///{sqlite_path}", future=True)

    print(
        "ERROR: no database configured. Set FG_DB_MIGRATION_URL (postgres,"
        " BYPASSRLS/superuser) or FG_SQLITE_PATH (local sqlite).",
        file=sys.stderr,
    )
    sys.exit(2)


def _serialize(report: Any) -> dict[str, Any]:
    """Serialize the reconciliation report to a JSON-safe dict."""
    # is_dataclass returns True for both instances and classes; the caller only
    # ever passes instances, but narrow explicitly for mypy.
    if is_dataclass(report) and not isinstance(report, type):
        data: dict[str, Any] = asdict(report)
    else:
        data = dict(report.__dict__)
    # Convert findings (tuple of frozen dataclasses) to a plain list of dicts.
    findings_raw = data.get("findings") or []
    serialized: list[dict[str, Any]] = []
    for f in findings_raw:
        if is_dataclass(f) and not isinstance(f, type):
            serialized.append(asdict(f))
        else:
            serialized.append(dict(f.__dict__))
    data["findings"] = serialized
    return data


def _print_summary(report: Any) -> None:
    print(f"source_memberships:          {report.source_membership_count}")
    print(f"migrated_consistent:         {report.migrated_consistent_count}")
    print(f"legitimate_unbound:          {report.unbound_legitimate_count}")
    print(f"principal_groups:            {report.principal_group_count}")
    print(f"blocking_findings:           {report.blocking_count}")
    print(f"  missing_principal_link:    {report.missing_principal_link_count}")
    print(f"  missing_external_identity: {report.missing_external_identity_count}")
    print(f"  external_identity_mismatch:{report.external_identity_mismatch_count}")
    print(f"  duplicate_canonical:       {report.duplicate_canonical_binding_count}")
    print(f"  cross_tenant_split:        {report.cross_tenant_split_count}")
    print(f"  orphan_external_identity:  {report.orphan_external_identity_count}")
    print(f"  orphan_principal:          {report.orphan_principal_count}")
    print(f"  already_linked_conflict:   {report.already_linked_conflict_count}")
    print(f"  legacy_mutation:           {report.legacy_mutation_count}")
    print(f"  invalid_lifecycle:         {report.invalid_lifecycle_count}")
    print(f"  primary_email_mismatch:    {report.primary_email_mismatch_count}")
    print(f"backfill_writes_required:    {report.backfill_dry_run_writes_required}")
    print(f"migration_closed:            {report.migration_closed}")
    print(f"fingerprint:                 {report.fingerprint}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "PR-AUTH-003C: reconcile identity backfill. Prints a summary and"
            " exits 0 iff migration_closed is True."
        )
    )
    parser.add_argument(
        "--json-out",
        metavar="PATH",
        help="Write the full report (counts + findings) as JSON to PATH.",
    )
    args = parser.parse_args()

    # Deferred import so `--help` works without the api package on PYTHONPATH.
    from api.identity_backfill_reconciliation import run_reconciliation

    engine = _get_engine()

    # REPEATABLE READ on postgres for a stable snapshot; SQLite ignores.
    dialect = engine.dialect.name
    if dialect == "postgresql":
        with engine.connect().execution_options(
            isolation_level="REPEATABLE READ"
        ) as conn:
            report = run_reconciliation(conn)
    else:
        with engine.connect() as conn:
            report = run_reconciliation(conn)

    _print_summary(report)

    if args.json_out:
        payload = _serialize(report)
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, sort_keys=True, indent=2)
        print(f"wrote JSON evidence to: {args.json_out}")

    return 0 if report.migration_closed else 1


if __name__ == "__main__":
    sys.exit(main())
