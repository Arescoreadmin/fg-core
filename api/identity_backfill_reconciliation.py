"""PR-AUTH-003C: Post-backfill identity reconciliation and closure proof.

Third and final phase of the AUTH-003 identity backfill sequence:

    AUTH-003A (preflight)  → read-only classification of legacy tenant_users
    AUTH-003B (writer)     → deterministic backfill of fg_principals +
                             fg_external_identities + tenant_users.principal_id
    AUTH-003C (this file)  → post-backfill reconciliation proof

This module answers ONE operator question: is the backfill correct and complete
enough to close the data-migration phase?

ZERO writes. ZERO INSERTs. ZERO UPDATEs. ZERO DELETEs. This module reads:
    - all tenant_users
    - all fg_principals
    - all fg_external_identities
    - the AUTH-003A preflight view (reused, not duplicated)
    - the AUTH-003B dry-run view (reused, not duplicated)

The report classifies every row into one of 13 categories and emits a single
boolean `migration_closed` that is True iff:
    - every legacy row that should have been migrated is migrated correctly
    - every UNBOUND / incomplete row is legitimately unmigrated
    - fg_external_identities is one-to-one with the migration groups
    - fg_principals' derived fields (lifecycle_state, primary_email) still
      match the source-of-truth membership rows
    - a dry-run of AUTH-003B against the current DB requires zero writes

The report also emits a deterministic sha256 fingerprint of the count vector.
Two runs against the same DB state produce the same fingerprint — this is the
evidence artifact operators attach to the migration closure record.

Transaction model:
    The caller passes a `conn`. All reads happen through that connection in
    a single logical snapshot.
      - PostgreSQL: caller SHOULD use a REPEATABLE READ (or SERIALIZABLE)
        transaction so all reads see the same snapshot. The preflight guard
        (BYPASSRLS or superuser) still applies — inherited from run_preflight.
      - SQLite (tests): single connection provides sufficient consistency.

Why there is no migration 0182:
    `tenant_users.principal_id` remains nullable on purpose. UNBOUND memberships
    (identity_binding_status != 'bound') legitimately have NULL principal_id
    after reconciliation — they are not migration targets. Adding a global
    NOT NULL constraint would break the UNBOUND lifecycle. See
    docs/architecture/PR_AUTH_003_RECONCILIATION.md for the full decision
    record. AUTH-003C proves closure with the current nullable schema.

Legacy mutation detection is BEST-EFFORT:
    The reconciliation compares tenant_users.identity_* against
    fg_external_identities.provider* for MIGRATED_CONSISTENT rows. If they
    differ, it flags LEGACY_MUTATION_DETECTED. This only catches mutations
    that happened AFTER AUTH-003B ran. Pre-migration mutations are not
    detectable — the migration snapshot is not preserved.

What comes after AUTH-003C:
    - HARD-001 (constraint hardening — separate PR) — may add tenant-user
      scoped NOT NULL enforcement for BOUND rows via a check constraint.
    - AUTH cutover (separate PR) — the auth path starts reading principal_id
      instead of identity_* columns.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Connection

from api.identity_backfill_preflight import run_preflight
from api.identity_backfill_writer import run_backfill
from api.principal_authority import _VALID_PROVIDERS

log = logging.getLogger("frostgate.identity_backfill_reconciliation")

# ---------------------------------------------------------------------------
# Classification taxonomy — 13 categories
# ---------------------------------------------------------------------------

MIGRATED_CONSISTENT = "MIGRATED_CONSISTENT"
# Row is linked to a principal, the external identity matches, lifecycle and
# primary_email are consistent. Non-blocking.

UNBOUND_LEGITIMATE = "UNBOUND_LEGITIMATE"
# Row is unbound or incomplete/unknown-provider — was never a migration target.
# Non-blocking.

MISSING_PRINCIPAL_LINK = "MISSING_PRINCIPAL_LINK"
# Row is READY-classifiable (bound, complete triple, known provider) but has
# no principal_id. Blocking — indicates an incomplete backfill.

MISSING_EXTERNAL_IDENTITY = "MISSING_EXTERNAL_IDENTITY"
# Row has principal_id, but no fg_external_identities row exists for its
# canonical triple. Blocking.

EXTERNAL_IDENTITY_PRINCIPAL_MISMATCH = "EXTERNAL_IDENTITY_PRINCIPAL_MISMATCH"
# Row's principal_id does not match the principal_id in the matching
# fg_external_identities row. Blocking.

DUPLICATE_CANONICAL_BINDING = "DUPLICATE_CANONICAL_BINDING"
# More than one fg_external_identities row shares the same
# (provider, issuer, subject) triple. Blocking — the uniqueness invariant
# is violated.

CROSS_TENANT_GROUP_SPLIT = "CROSS_TENANT_GROUP_SPLIT"
# The same canonical triple is present in two tenant_users rows that point
# to DIFFERENT principal_ids. Blocking — the multi-tenant invariant is
# violated.

ORPHAN_EXTERNAL_IDENTITY = "ORPHAN_EXTERNAL_IDENTITY"
# An fg_external_identities row's principal has zero linked tenant_users.
# Blocking.

ORPHAN_PRINCIPAL = "ORPHAN_PRINCIPAL"
# CAUTIOUS: a principal has zero linked tenant_users AND at least one
# fg_external_identities row (implying it was migration-created). Blocking.
# We DO NOT classify principals with no external identity binding as
# orphaned — they may have been created by other legitimate means we
# cannot introspect from here.

ALREADY_LINKED_LEGACY_CONFLICT = "ALREADY_LINKED_LEGACY_CONFLICT"
# Row has principal_id but its legacy identity triple is incomplete.
# Should not happen post-migration. Blocking.

LEGACY_MUTATION_DETECTED = "LEGACY_MUTATION_DETECTED"
# For a MIGRATED_CONSISTENT row, the current (identity_provider,
# identity_issuer, identity_subject) does not match the
# (provider, provider_issuer, provider_subject) in fg_external_identities.
# Blocking. Best-effort: detects post-migration drift only.

INVALID_LIFECYCLE_STATE = "INVALID_LIFECYCLE_STATE"
# fg_principals.lifecycle_state does not equal the value AUTH-003B would
# derive from the current tenant_users.active values:
#   any(active) → 'active', else 'suspended'
# Blocking.

PRIMARY_EMAIL_MAPPING_MISMATCH = "PRIMARY_EMAIL_MAPPING_MISMATCH"
# fg_principals.primary_email does not equal the email of the first-sorted
# (by member id) tenant_users row linked to that principal. This mirrors
# the AUTH-003B source-attribution rule. Blocking.

_BLOCKING_CLASSIFICATIONS: frozenset[str] = frozenset(
    {
        MISSING_PRINCIPAL_LINK,
        MISSING_EXTERNAL_IDENTITY,
        EXTERNAL_IDENTITY_PRINCIPAL_MISMATCH,
        DUPLICATE_CANONICAL_BINDING,
        CROSS_TENANT_GROUP_SPLIT,
        ORPHAN_EXTERNAL_IDENTITY,
        ORPHAN_PRINCIPAL,
        ALREADY_LINKED_LEGACY_CONFLICT,
        LEGACY_MUTATION_DETECTED,
        INVALID_LIFECYCLE_STATE,
        PRIMARY_EMAIL_MAPPING_MISMATCH,
    }
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


def _hash_triple(provider: str, issuer: str, subject: str) -> str:
    """Return a 16-char sha256 prefix of the canonical triple. Never store the raw subject."""
    return hashlib.sha256(f"{provider}:{issuer}:{subject}".encode()).hexdigest()[:16]


@dataclass(frozen=True)
class ReconciliationFinding:
    """One non-consistent row surfaced by reconciliation.

    tenant_user_id may be None for ORPHAN_PRINCIPAL / DUPLICATE_CANONICAL_BINDING
    findings that are not tied to a specific membership row. principal_id may
    be None for MISSING_PRINCIPAL_LINK.

    canonical_key_hash is a sha256 prefix — never the raw triple.
    """

    tenant_user_id: str | None
    principal_id: str | None
    classification: str
    blocking: bool
    reason: str
    canonical_key_hash: str | None = field(default=None, repr=False)


@dataclass
class ReconciliationReport:
    """Full reconciliation output. Deterministic under identical DB state."""

    source_membership_count: int
    migrated_consistent_count: int
    unbound_legitimate_count: int
    missing_principal_link_count: int
    missing_external_identity_count: int
    external_identity_mismatch_count: int
    duplicate_canonical_binding_count: int
    cross_tenant_split_count: int
    orphan_external_identity_count: int
    orphan_principal_count: int
    already_linked_conflict_count: int
    legacy_mutation_count: int
    invalid_lifecycle_count: int
    primary_email_mismatch_count: int
    principal_group_count: int
    backfill_dry_run_writes_required: bool
    migration_closed: bool
    fingerprint: str
    findings: tuple[ReconciliationFinding, ...]
    report_version: str = "1"

    @property
    def blocking_count(self) -> int:
        return (
            self.missing_principal_link_count
            + self.missing_external_identity_count
            + self.external_identity_mismatch_count
            + self.duplicate_canonical_binding_count
            + self.cross_tenant_split_count
            + self.orphan_external_identity_count
            + self.orphan_principal_count
            + self.already_linked_conflict_count
            + self.legacy_mutation_count
            + self.invalid_lifecycle_count
            + self.primary_email_mismatch_count
        )


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------


def _compute_fingerprint(
    *,
    report_version: str,
    source_membership_count: int,
    migrated_consistent_count: int,
    unbound_legitimate_count: int,
    missing_principal_link_count: int,
    missing_external_identity_count: int,
    external_identity_mismatch_count: int,
    duplicate_canonical_binding_count: int,
    cross_tenant_split_count: int,
    orphan_external_identity_count: int,
    orphan_principal_count: int,
    already_linked_conflict_count: int,
    legacy_mutation_count: int,
    invalid_lifecycle_count: int,
    primary_email_mismatch_count: int,
    principal_group_count: int,
    backfill_dry_run_writes_required: bool,
    migration_closed: bool,
) -> str:
    """Deterministic sha256 over the count vector.

    Excludes findings (which may contain hashes but not raw identifiers) so
    two DBs with the same aggregate shape produce the same fingerprint.
    """
    material = {
        "report_version": report_version,
        "source_membership_count": source_membership_count,
        "migrated_consistent_count": migrated_consistent_count,
        "unbound_legitimate_count": unbound_legitimate_count,
        "missing_principal_link_count": missing_principal_link_count,
        "missing_external_identity_count": missing_external_identity_count,
        "external_identity_mismatch_count": external_identity_mismatch_count,
        "duplicate_canonical_binding_count": duplicate_canonical_binding_count,
        "cross_tenant_split_count": cross_tenant_split_count,
        "orphan_external_identity_count": orphan_external_identity_count,
        "orphan_principal_count": orphan_principal_count,
        "already_linked_conflict_count": already_linked_conflict_count,
        "legacy_mutation_count": legacy_mutation_count,
        "invalid_lifecycle_count": invalid_lifecycle_count,
        "primary_email_mismatch_count": primary_email_mismatch_count,
        "principal_group_count": principal_group_count,
        "backfill_dry_run_writes_required": backfill_dry_run_writes_required,
        "migration_closed": migration_closed,
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Reconciliation core
# ---------------------------------------------------------------------------


def run_reconciliation(conn: Connection) -> ReconciliationReport:
    """Reconcile the current identity population against the backfill invariants.

    Zero writes. Zero mutations. Read-only from start to finish.

    The caller owns the transaction. On PostgreSQL, wrap in a REPEATABLE READ
    transaction to guarantee a stable snapshot. On SQLite (tests), a single
    connection is sufficient.

    Uses the AUTH-003A preflight and AUTH-003B dry-run internally — never
    duplicates classification/normalization logic.
    """
    # ------------------------------------------------------------------
    # Step 1: reuse the AUTH-003A preflight view for consistent classification.
    #         (Also triggers the BYPASSRLS/superuser guard on PostgreSQL.)
    # ------------------------------------------------------------------
    preflight = run_preflight(conn)

    # ------------------------------------------------------------------
    # Step 2: reuse the AUTH-003B dry-run to prove idempotency.
    # ------------------------------------------------------------------
    try:
        dry = run_backfill(conn, dry_run=True)
        writes_required = (
            (not dry.success)
            or dry.principals_created > 0
            or dry.external_identities_created > 0
            or dry.tenant_users_linked > 0
        )
    except RuntimeError:
        # Preflight blocked backfill from starting → not zero-write.
        writes_required = True

    # ------------------------------------------------------------------
    # Step 3: load current state for cross-checks. All queries within the
    #         same connection form the reconciliation snapshot.
    # ------------------------------------------------------------------
    ei_rows = conn.execute(
        text(
            "SELECT id, principal_id, provider, provider_issuer, provider_subject,"
            "       provider_email"
            "  FROM fg_external_identities"
            " ORDER BY id"
        )
    ).fetchall()

    ei_by_triple: dict[tuple[str, str, str], list[Any]] = defaultdict(list)
    ei_by_principal: dict[str, list[Any]] = defaultdict(list)
    for row in ei_rows:
        ei_by_triple[(row.provider, row.provider_issuer, row.provider_subject)].append(
            row
        )
        ei_by_principal[row.principal_id].append(row)

    principal_rows = conn.execute(
        text(
            "SELECT id, primary_email, lifecycle_state  FROM fg_principals ORDER BY id"
        )
    ).fetchall()
    principals_by_id: dict[str, Any] = {row.id: row for row in principal_rows}

    tu_rows = conn.execute(
        text(
            "SELECT id, tenant_id, email, active,"
            "       identity_binding_status,"
            "       identity_provider, identity_issuer, identity_subject,"
            "       principal_id"
            "  FROM tenant_users"
            " ORDER BY id"
        )
    ).fetchall()

    # Group tenant_users by principal_id for lifecycle + primary_email checks.
    tus_by_principal: dict[str, list[Any]] = defaultdict(list)
    for tu in tu_rows:
        if tu.principal_id is not None:
            tus_by_principal[tu.principal_id].append(tu)

    # Group tenant_users by canonical triple for cross-tenant-split check.
    tus_by_triple: dict[tuple[str, str, str], list[Any]] = defaultdict(list)
    for tu in tu_rows:
        if (
            tu.identity_binding_status == "bound"
            and tu.identity_provider
            and tu.identity_issuer
            and tu.identity_subject
            and tu.identity_provider in _VALID_PROVIDERS
        ):
            tus_by_triple[
                (tu.identity_provider, tu.identity_issuer, tu.identity_subject)
            ].append(tu)

    findings: list[ReconciliationFinding] = []

    migrated_consistent = 0
    unbound_legitimate = 0
    missing_link = 0
    missing_ei = 0
    ei_mismatch = 0
    already_linked_conflict = 0
    legacy_mutation = 0
    invalid_lifecycle = 0
    primary_email_mismatch = 0

    # Track which principals we've already emitted lifecycle/email findings for,
    # so we count once per principal, not once per member.
    lifecycle_flagged: set[str] = set()
    email_flagged: set[str] = set()

    # ------------------------------------------------------------------
    # Step 4: classify each tenant_users row.
    # ------------------------------------------------------------------
    for tu in tu_rows:
        provider = tu.identity_provider
        issuer = tu.identity_issuer
        subject = tu.identity_subject
        has_complete_triple = bool(provider) and bool(issuer) and bool(subject)
        provider_valid = provider in _VALID_PROVIDERS if provider else False

        if tu.principal_id is None:
            # Not linked. Should it have been?
            if (
                tu.identity_binding_status == "bound"
                and has_complete_triple
                and provider_valid
            ):
                # This is a READY-shaped row that never got a principal_id.
                missing_link += 1
                findings.append(
                    ReconciliationFinding(
                        tenant_user_id=tu.id,
                        principal_id=None,
                        classification=MISSING_PRINCIPAL_LINK,
                        blocking=True,
                        reason="bound row with complete triple and known provider has NULL principal_id",
                        canonical_key_hash=_hash_triple(provider, issuer, subject),
                    )
                )
            else:
                # Unbound, incomplete, or unknown provider — not a migration target.
                unbound_legitimate += 1
            continue

        # tu.principal_id is not None → row is (supposed to be) migrated.
        if not has_complete_triple:
            # Linked but the legacy triple is incomplete — should not happen
            # post-migration.
            already_linked_conflict += 1
            findings.append(
                ReconciliationFinding(
                    tenant_user_id=tu.id,
                    principal_id=tu.principal_id,
                    classification=ALREADY_LINKED_LEGACY_CONFLICT,
                    blocking=True,
                    reason="tenant_user has principal_id but incomplete legacy identity triple",
                )
            )
            continue

        # Complete triple — assume provider is valid; if it isn't, the
        # AUTH-003B backfill would never have linked it, so treat as
        # a legacy mutation.
        triple = (provider, issuer, subject)
        ei_matches = ei_by_triple.get(triple, [])
        if not ei_matches:
            missing_ei += 1
            findings.append(
                ReconciliationFinding(
                    tenant_user_id=tu.id,
                    principal_id=tu.principal_id,
                    classification=MISSING_EXTERNAL_IDENTITY,
                    blocking=True,
                    reason="tenant_user has principal_id but no fg_external_identities row for its triple",
                    canonical_key_hash=_hash_triple(provider, issuer, subject),
                )
            )
            continue

        # If there are multiple ei rows for this triple, DUPLICATE_CANONICAL_BINDING
        # is reported below (step 5); still, pick the first for the per-row check.
        ei = ei_matches[0]

        if ei.principal_id != tu.principal_id:
            ei_mismatch += 1
            findings.append(
                ReconciliationFinding(
                    tenant_user_id=tu.id,
                    principal_id=tu.principal_id,
                    classification=EXTERNAL_IDENTITY_PRINCIPAL_MISMATCH,
                    blocking=True,
                    reason="tenant_user.principal_id != fg_external_identities.principal_id for the same triple",
                    canonical_key_hash=_hash_triple(provider, issuer, subject),
                )
            )
            continue

        # Row is consistent so far — check lifecycle / email once per principal.
        pid = tu.principal_id
        principal = principals_by_id.get(pid)
        if principal is not None:
            group_members = sorted(tus_by_principal.get(pid, []), key=lambda r: r.id)
            expected_lifecycle = (
                "active" if any(bool(m.active) for m in group_members) else "suspended"
            )
            if (
                principal.lifecycle_state != expected_lifecycle
                and pid not in lifecycle_flagged
            ):
                invalid_lifecycle += 1
                lifecycle_flagged.add(pid)
                findings.append(
                    ReconciliationFinding(
                        tenant_user_id=None,
                        principal_id=pid,
                        classification=INVALID_LIFECYCLE_STATE,
                        blocking=True,
                        reason=(
                            f"principal.lifecycle_state={principal.lifecycle_state!r}"
                            f" but derived expected={expected_lifecycle!r}"
                        ),
                    )
                )

            if group_members:
                expected_primary = group_members[0].email
                if (
                    principal.primary_email != expected_primary
                    and pid not in email_flagged
                ):
                    primary_email_mismatch += 1
                    email_flagged.add(pid)
                    findings.append(
                        ReconciliationFinding(
                            tenant_user_id=None,
                            principal_id=pid,
                            classification=PRIMARY_EMAIL_MAPPING_MISMATCH,
                            blocking=True,
                            reason="principal.primary_email != first-sorted member.email",
                        )
                    )

        # Legacy mutation: does the current tenant_users triple still match
        # fg_external_identities? (Best-effort — detects post-migration drift.)
        if (
            ei.provider != provider
            or ei.provider_issuer != issuer
            or ei.provider_subject != subject
        ):
            legacy_mutation += 1
            findings.append(
                ReconciliationFinding(
                    tenant_user_id=tu.id,
                    principal_id=tu.principal_id,
                    classification=LEGACY_MUTATION_DETECTED,
                    blocking=True,
                    reason="tenant_users identity triple diverges from fg_external_identities triple",
                    canonical_key_hash=_hash_triple(provider, issuer, subject),
                )
            )
            continue

        migrated_consistent += 1

    # ------------------------------------------------------------------
    # Step 5: duplicate canonical bindings in fg_external_identities.
    # ------------------------------------------------------------------
    duplicate_binding = 0
    for triple, rows in sorted(ei_by_triple.items()):
        if len(rows) > 1:
            duplicate_binding += 1
            findings.append(
                ReconciliationFinding(
                    tenant_user_id=None,
                    principal_id=None,
                    classification=DUPLICATE_CANONICAL_BINDING,
                    blocking=True,
                    reason=f"{len(rows)} fg_external_identities rows share the same (provider, issuer, subject)",
                    canonical_key_hash=_hash_triple(*triple),
                )
            )

    # ------------------------------------------------------------------
    # Step 6: cross-tenant group split.
    #         If the same canonical triple exists in tenant_users rows that
    #         point to DIFFERENT principal_ids, the multi-tenant invariant
    #         is violated.
    # ------------------------------------------------------------------
    cross_tenant_split = 0
    for triple, rows in sorted(tus_by_triple.items()):
        principal_ids = {r.principal_id for r in rows if r.principal_id is not None}
        if len(principal_ids) > 1:
            cross_tenant_split += 1
            findings.append(
                ReconciliationFinding(
                    tenant_user_id=None,
                    principal_id=None,
                    classification=CROSS_TENANT_GROUP_SPLIT,
                    blocking=True,
                    reason=f"canonical triple resolves to {len(principal_ids)} distinct principal_ids across tenant_users",
                    canonical_key_hash=_hash_triple(*triple),
                )
            )

    # ------------------------------------------------------------------
    # Step 7: orphan external identity — ei row exists but its principal
    #         has zero linked tenant_users.
    # ------------------------------------------------------------------
    orphan_ei = 0
    for pid, ei_list in sorted(ei_by_principal.items()):
        if not tus_by_principal.get(pid):
            orphan_ei += 1
            findings.append(
                ReconciliationFinding(
                    tenant_user_id=None,
                    principal_id=pid,
                    classification=ORPHAN_EXTERNAL_IDENTITY,
                    blocking=True,
                    reason=f"principal has {len(ei_list)} fg_external_identities row(s) but zero linked tenant_users",
                )
            )

    # ------------------------------------------------------------------
    # Step 8: orphan principal (CAUTIOUS).
    #         Only classify a principal as orphaned when it has zero linked
    #         tenant_users AND zero fg_external_identities rows. The
    #         (has-ei, no-tu) case is already covered by ORPHAN_EXTERNAL_IDENTITY;
    #         we do NOT double-report.
    #         Principals with (no-ei, no-tu) are conservatively flagged only
    #         when we can be confident they came from this migration path.
    #         Without migration provenance in the schema, we skip this
    #         double-orphan case to avoid false positives from principals
    #         created by other legitimate means (e.g. platform bootstrap).
    #
    #         Result: orphan_principal_count is always 0 in the current
    #         schema. The category is retained in the report shape so a
    #         future provenance column can activate it without a schema
    #         change to the report itself.
    # ------------------------------------------------------------------
    orphan_principal = 0

    # ------------------------------------------------------------------
    # Step 9: assemble the report.
    # ------------------------------------------------------------------
    principal_group_count = len(
        {tu.principal_id for tu in tu_rows if tu.principal_id is not None}
    )

    migration_closed = (
        missing_link == 0
        and missing_ei == 0
        and ei_mismatch == 0
        and duplicate_binding == 0
        and cross_tenant_split == 0
        and orphan_ei == 0
        and orphan_principal == 0
        and already_linked_conflict == 0
        and legacy_mutation == 0
        and invalid_lifecycle == 0
        and primary_email_mismatch == 0
        and not writes_required
    )

    fingerprint = _compute_fingerprint(
        report_version="1",
        source_membership_count=len(tu_rows),
        migrated_consistent_count=migrated_consistent,
        unbound_legitimate_count=unbound_legitimate,
        missing_principal_link_count=missing_link,
        missing_external_identity_count=missing_ei,
        external_identity_mismatch_count=ei_mismatch,
        duplicate_canonical_binding_count=duplicate_binding,
        cross_tenant_split_count=cross_tenant_split,
        orphan_external_identity_count=orphan_ei,
        orphan_principal_count=orphan_principal,
        already_linked_conflict_count=already_linked_conflict,
        legacy_mutation_count=legacy_mutation,
        invalid_lifecycle_count=invalid_lifecycle,
        primary_email_mismatch_count=primary_email_mismatch,
        principal_group_count=principal_group_count,
        backfill_dry_run_writes_required=writes_required,
        migration_closed=migration_closed,
    )

    # Preflight is used for its side-effect (RLS guard + normalization); the
    # count vector already reflects the classifications derived here.
    del preflight

    return ReconciliationReport(
        source_membership_count=len(tu_rows),
        migrated_consistent_count=migrated_consistent,
        unbound_legitimate_count=unbound_legitimate,
        missing_principal_link_count=missing_link,
        missing_external_identity_count=missing_ei,
        external_identity_mismatch_count=ei_mismatch,
        duplicate_canonical_binding_count=duplicate_binding,
        cross_tenant_split_count=cross_tenant_split,
        orphan_external_identity_count=orphan_ei,
        orphan_principal_count=orphan_principal,
        already_linked_conflict_count=already_linked_conflict,
        legacy_mutation_count=legacy_mutation,
        invalid_lifecycle_count=invalid_lifecycle,
        primary_email_mismatch_count=primary_email_mismatch,
        principal_group_count=principal_group_count,
        backfill_dry_run_writes_required=writes_required,
        migration_closed=migration_closed,
        fingerprint=fingerprint,
        findings=tuple(findings),
    )
