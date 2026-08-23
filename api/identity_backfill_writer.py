"""PR-AUTH-003B: Deterministic principal + ExternalIdentity backfill writer.

Consumes the preflight analysis from AUTH-003A and writes canonical identity
records for every READY row. Gated on PreflightReport.ready_for_backfill —
refuses to write if any blocking classification exists.

For each PrincipalGroup in the preflight:
  1. Create one fg_principals row (principal_type='human', lifecycle_state='active').
  2. Create one fg_external_identities row binding the canonical triple.
  3. UPDATE tenant_users SET principal_id = <new> for each member in the group.

The caller owns the transaction. Wrap in engine.begin() for atomicity — a partial
failure leaves the database in a state where re-running preflight surfaces the
partial writes as CONFLICT_GLOBAL_BINDING rows, which are blocking, preventing
a silent half-migration.

Requires the same global (BYPASSRLS or superuser) connection as run_preflight.
tenant_users has RLS (migration 0099); an app-role connection would silently
restrict the population scan and the UPDATE.

Idempotency: previously migrated rows are classified ALREADY_LINKED by
run_preflight and excluded from principal_groups, so a re-run on a fully
migrated population writes nothing and returns success with all counts at zero.

DOES NOT:
  - Run if ready_for_backfill is False
  - Add NOT NULL constraints
  - Remove legacy identity_* columns
  - Change session claims or RBAC
  - Delete or deactivate tenant_users rows
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.engine import Connection

from api.identity_backfill_preflight import PreflightReport, run_preflight

log = logging.getLogger("frostgate.identity_backfill_writer")


# ---------------------------------------------------------------------------
# Report type
# ---------------------------------------------------------------------------


@dataclass
class BackfillReport:
    preflight: PreflightReport
    principals_created: int
    external_identities_created: int
    tenant_users_linked: int
    dry_run: bool

    @property
    def groups_processed(self) -> int:
        return self.principals_created

    @property
    def success(self) -> bool:
        """True iff counts match the preflight plan exactly."""
        expected_groups = len(self.preflight.principal_groups)
        expected_members = self.preflight.ready
        return (
            self.principals_created == expected_groups
            and self.external_identities_created == expected_groups
            and self.tenant_users_linked == expected_members
        )


# ---------------------------------------------------------------------------
# Backfill writer
# ---------------------------------------------------------------------------


def run_backfill(conn: Connection, *, dry_run: bool = False) -> BackfillReport:
    """Write canonical principals and external identities for all READY rows.

    Calls run_preflight internally. Raises RuntimeError if the preflight
    reports any blocking row — never writes partial state.

    dry_run=True: counts what would be written without executing any DML.
    Use this to verify the plan before committing.

    Source attribution: for each principal group, display_name and primary_email
    are sourced from the first (alphabetically sorted) member row.
    identity_email is preferred over email; both are nullable.
    """
    preflight = run_preflight(conn)

    if not preflight.ready_for_backfill:
        raise RuntimeError(
            f"Backfill blocked: {preflight.blocking_count} blocking row(s). "
            "Resolve all blocking classifications before retrying. "
            "Run run_preflight() for the full classification breakdown."
        )

    if not preflight.principal_groups:
        return BackfillReport(
            preflight=preflight,
            principals_created=0,
            external_identities_created=0,
            tenant_users_linked=0,
            dry_run=dry_run,
        )

    principals_created = 0
    external_identities_created = 0
    tenant_users_linked = 0
    now = datetime.now(UTC).isoformat()

    for group in preflight.principal_groups:
        provider, issuer, subject = group.canonical_key

        if dry_run:
            principals_created += 1
            external_identities_created += 1
            tenant_users_linked += len(group.member_ids)
            continue

        # Source attribution from first (sorted) member.
        first_member_id = group.member_ids[0]
        src = conn.execute(
            text(
                "SELECT display_name, identity_email, email"
                "  FROM tenant_users"
                " WHERE id = :id"
            ),
            {"id": first_member_id},
        ).fetchone()
        display_name: str | None = src.display_name if src else None
        # Prefer IdP-provided email; fall back to membership email.
        primary_email: str | None = (src.identity_email or src.email) if src else None

        principal_id = str(uuid.uuid4())

        conn.execute(
            text(
                "INSERT INTO fg_principals"
                "    (id, display_name, primary_email, principal_type,"
                "     lifecycle_state, mfa_verified, authority_version,"
                "     created_at, updated_at)"
                " VALUES"
                "    (:id, :display_name, :primary_email, 'human',"
                "     'active', :mfa_verified, 1, :now, :now)"
            ),
            {
                "id": principal_id,
                "display_name": display_name,
                "primary_email": primary_email,
                "mfa_verified": False,
                "now": now,
            },
        )
        principals_created += 1

        conn.execute(
            text(
                "INSERT INTO fg_external_identities"
                "    (id, principal_id, provider, provider_issuer,"
                "     provider_subject, provider_email, created_at)"
                " VALUES"
                "    (:id, :principal_id, :provider, :provider_issuer,"
                "     :provider_subject, :provider_email, :now)"
            ),
            {
                "id": str(uuid.uuid4()),
                "principal_id": principal_id,
                "provider": provider,
                "provider_issuer": issuer,
                "provider_subject": subject,
                "provider_email": primary_email,
                "now": now,
            },
        )
        external_identities_created += 1

        for member_id in group.member_ids:
            conn.execute(
                text("UPDATE tenant_users   SET principal_id = :pid WHERE id = :id"),
                {"pid": principal_id, "id": member_id},
            )
            tenant_users_linked += 1

    return BackfillReport(
        preflight=preflight,
        principals_created=principals_created,
        external_identities_created=external_identities_created,
        tenant_users_linked=tenant_users_linked,
        dry_run=dry_run,
    )
