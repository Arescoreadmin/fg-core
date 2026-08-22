"""PR-AUTH-003A: Identity backfill preflight analysis.

Read-only classification of the legacy tenant_users identity population.
Determines for every row:
  - what migration state it is in
  - whether it can migrate safely
  - which canonical principal group it belongs to
  - whether it conflicts with existing canonical identity state
  - why migration is blocked if unsafe

ZERO writes. ZERO identity mutations. ZERO modifications to principal_id.

Called before AUTH-003B to produce a deterministic migration plan.
AUTH-003B may begin only when PreflightReport.ready_for_backfill is True.

Callers should use engine.connect() (not engine.begin()) to make the
non-mutating intent explicit.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field

from sqlalchemy import text
from sqlalchemy.engine import Connection

from api.principal_authority import _VALID_PROVIDERS

log = logging.getLogger("frostgate.identity_backfill_preflight")

# ---------------------------------------------------------------------------
# Classification codes
# ---------------------------------------------------------------------------

ALREADY_LINKED = "ALREADY_LINKED"
# principal_id already set — row is already migrated, skip.

UNBOUND = "UNBOUND"
# identity_binding_status != 'bound' — not a migration target.

INCOMPLETE_TRIPLE = "INCOMPLETE_TRIPLE"
# Bound but missing provider, issuer, or subject — blocking.

UNKNOWN_PROVIDER = "UNKNOWN_PROVIDER"
# Provider not in the canonical set (_VALID_PROVIDERS) — blocking.

CONFLICT_GLOBAL_BINDING = "CONFLICT_GLOBAL_BINDING"
# (provider, issuer, subject) triple already present in fg_external_identities
# — blocking; manual resolution required before AUTH-003B.

READY = "READY"
# Passes all preflight checks — safe to migrate in AUTH-003B.

_BLOCKING_CODES: frozenset[str] = frozenset(
    {INCOMPLETE_TRIPLE, UNKNOWN_PROVIDER, CONFLICT_GLOBAL_BINDING}
)

_CanonicalKey = tuple[str, str, str]  # (provider, issuer, subject)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClassifiedRow:
    tenant_user_id: str
    tenant_id: str
    classification: str
    blocking: bool
    reason: str
    canonical_key: _CanonicalKey | None = field(default=None, repr=False)


@dataclass(frozen=True)
class PrincipalGroup:
    """One canonical principal AUTH-003B will create from this group.

    canonical_key holds the raw (provider, issuer, subject) triple.
    Do not log it — treat as credential-adjacent.
    """

    group_index: int
    member_ids: tuple[str, ...]  # tenant_user_ids, sorted for determinism
    distinct_tenant_ids: tuple[str, ...]  # tenants this principal spans
    canonical_key: _CanonicalKey = field(repr=False)  # never log raw


@dataclass
class PreflightReport:
    total_rows: int
    already_linked: int
    unbound: int
    ready: int
    blocking_incomplete_triple: int
    blocking_unknown_provider: int
    blocking_conflict_global: int
    principal_groups: tuple[PrincipalGroup, ...]
    classified: tuple[ClassifiedRow, ...]

    @property
    def blocking_count(self) -> int:
        return (
            self.blocking_incomplete_triple
            + self.blocking_unknown_provider
            + self.blocking_conflict_global
        )

    @property
    def ready_for_backfill(self) -> bool:
        """True iff zero blocking rows exist. This is the AUTH-003B gate."""
        return self.blocking_count == 0

    @property
    def migration_target_count(self) -> int:
        """Number of rows AUTH-003B will process (READY only)."""
        return self.ready


# ---------------------------------------------------------------------------
# Connection guard
# ---------------------------------------------------------------------------


def _assert_global_scan_connection(conn: Connection) -> None:
    """Require a connection that bypasses RLS for the full tenant_users scan.

    tenant_users has RLS enforced (migration 0099). An app-role connection
    scoped to a single app.tenant_id will silently return a partial population,
    potentially making ready_for_backfill=True while blocking rows in other
    tenants go undetected.

    Requires: superuser OR rolbypassrls.
    Use FG_DB_MIGRATION_URL or an equivalent elevated credential.

    SQLite (tests): skipped — no RLS.
    """
    if conn.dialect.name != "postgresql":
        return
    row = conn.execute(
        text(
            "SELECT rolsuper, rolbypassrls  FROM pg_roles WHERE rolname = current_user"
        )
    ).fetchone()
    if row is None or (not row.rolsuper and not row.rolbypassrls):
        raise RuntimeError(
            "run_preflight requires a global (superuser or BYPASSRLS) connection. "
            "The standard app role is RLS-restricted to a single tenant and will "
            "silently omit blocking rows from other tenants, producing a false "
            "ready_for_backfill=True. Use FG_DB_MIGRATION_URL or an equivalent "
            "elevated credential."
        )


# ---------------------------------------------------------------------------
# Preflight analysis
# ---------------------------------------------------------------------------


def run_preflight(conn: Connection) -> PreflightReport:
    """Classify the full legacy tenant_users identity population. Zero writes.

    Requires a global (BYPASSRLS or superuser) connection — see
    _assert_global_scan_connection. Fails closed on PostgreSQL app roles.

    Principal grouping algorithm: all READY rows sharing the same
    (provider, issuer, subject) triple belong to the same canonical principal.
    This is the multi-tenant invariant — one person in N tenants produces
    one fg_principals row and one fg_external_identities row.

    Groups are assigned stable indices by sorted canonical key order,
    making the output deterministic across repeated runs.
    """
    _assert_global_scan_connection(conn)
    # Load existing canonical bindings to detect CONFLICT_GLOBAL_BINDING.
    existing_bindings: set[_CanonicalKey] = {
        (row.provider, row.provider_issuer, row.provider_subject)
        for row in conn.execute(
            text(
                "SELECT provider, provider_issuer, provider_subject"
                "  FROM fg_external_identities"
            )
        ).fetchall()
    }

    source_rows = conn.execute(
        text(
            "SELECT id, tenant_id,"
            "       identity_provider, identity_issuer, identity_subject,"
            "       identity_binding_status, principal_id"
            "  FROM tenant_users"
            " ORDER BY id"  # stable ordering for deterministic output
        )
    ).fetchall()

    classified: list[ClassifiedRow] = []
    counts: dict[str, int] = defaultdict(int)
    # groups accumulates READY rows only; key → [(tenant_user_id, tenant_id)]
    groups: dict[_CanonicalKey, list[tuple[str, str]]] = defaultdict(list)

    for row in source_rows:
        tu_id: str = row.id
        tenant_id: str = row.tenant_id

        # 1. Already linked — skip, non-blocking.
        if row.principal_id is not None:
            classified.append(
                ClassifiedRow(
                    tenant_user_id=tu_id,
                    tenant_id=tenant_id,
                    classification=ALREADY_LINKED,
                    blocking=False,
                    reason="principal_id already set",
                )
            )
            counts[ALREADY_LINKED] += 1
            continue

        # 2. Not identity-bound — not a migration target, non-blocking.
        if row.identity_binding_status != "bound":
            classified.append(
                ClassifiedRow(
                    tenant_user_id=tu_id,
                    tenant_id=tenant_id,
                    classification=UNBOUND,
                    blocking=False,
                    reason=f"identity_binding_status={row.identity_binding_status!r}",
                )
            )
            counts[UNBOUND] += 1
            continue

        provider: str | None = row.identity_provider
        issuer: str | None = row.identity_issuer
        subject: str | None = row.identity_subject

        # 3. Bound but incomplete identity triple — blocking.
        if not provider or not issuer or not subject:
            missing = [
                col
                for col, val in [
                    ("identity_provider", provider),
                    ("identity_issuer", issuer),
                    ("identity_subject", subject),
                ]
                if not val
            ]
            classified.append(
                ClassifiedRow(
                    tenant_user_id=tu_id,
                    tenant_id=tenant_id,
                    classification=INCOMPLETE_TRIPLE,
                    blocking=True,
                    reason=f"bound but missing: {', '.join(missing)}",
                )
            )
            counts[INCOMPLETE_TRIPLE] += 1
            continue

        # 4. Provider not in canonical set — blocking.
        if provider not in _VALID_PROVIDERS:
            classified.append(
                ClassifiedRow(
                    tenant_user_id=tu_id,
                    tenant_id=tenant_id,
                    classification=UNKNOWN_PROVIDER,
                    blocking=True,
                    reason=f"provider {provider!r} not in canonical set",
                )
            )
            counts[UNKNOWN_PROVIDER] += 1
            continue

        key: _CanonicalKey = (provider, issuer, subject)

        # 5. Triple already present in fg_external_identities — blocking.
        if key in existing_bindings:
            classified.append(
                ClassifiedRow(
                    tenant_user_id=tu_id,
                    tenant_id=tenant_id,
                    classification=CONFLICT_GLOBAL_BINDING,
                    blocking=True,
                    reason="triple already present in fg_external_identities",
                    canonical_key=key,
                )
            )
            counts[CONFLICT_GLOBAL_BINDING] += 1
            continue

        # 6. Passes all checks — ready for AUTH-003B.
        classified.append(
            ClassifiedRow(
                tenant_user_id=tu_id,
                tenant_id=tenant_id,
                classification=READY,
                blocking=False,
                reason="passes all preflight checks",
                canonical_key=key,
            )
        )
        counts[READY] += 1
        groups[key].append((tu_id, tenant_id))

    # Build principal groups sorted by canonical key for stable group_index.
    principal_groups = [
        PrincipalGroup(
            group_index=idx,
            member_ids=tuple(sorted(m[0] for m in members)),
            distinct_tenant_ids=tuple(sorted({m[1] for m in members})),
            canonical_key=key,
        )
        for idx, (key, members) in enumerate(sorted(groups.items()))
    ]

    return PreflightReport(
        total_rows=len(source_rows),
        already_linked=counts[ALREADY_LINKED],
        unbound=counts[UNBOUND],
        ready=counts[READY],
        blocking_incomplete_triple=counts[INCOMPLETE_TRIPLE],
        blocking_unknown_provider=counts[UNKNOWN_PROVIDER],
        blocking_conflict_global=counts[CONFLICT_GLOBAL_BINDING],
        principal_groups=tuple(principal_groups),
        classified=tuple(classified),
    )
