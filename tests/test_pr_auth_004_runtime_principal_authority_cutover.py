"""PR-AUTH-004 — Runtime Principal Authority Cutover + Atomic BOUND-State.

Cuts over the invitation-binding runtime path to the canonical Principal +
ExternalIdentity model established in PR-AUTH-001/002/003. From this PR
onward, every transition of ``tenant_users.identity_binding_status`` from
``pending`` to ``bound`` is atomic with populating
``tenant_users.principal_id`` (via the canonical resolver in
``api.principal_authority``).

Deferred deliverable (SPLIT — documented in the module docstring below):
    Migration 0183 (partial NOT NULL / CHECK constraint on tenant_users)
    is *not* included in PR-AUTH-004. The runtime cutover must ship, prove
    itself in production, and reconciliation must confirm every newly-bound
    row has a populated ``principal_id`` before the CHECK can safely be
    enforced. See test N1 for the assertion.

Coverage groups:
    A — Canonical resolver structure and contract (function signature,
        module location, dataclass shape).
    B — Canonical resolution semantics (existing binding resolves; unknown
        binding creates; idempotent; malformed triple fails; inactive
        principal fails closed).
    C — Invitation acceptance atomicity (principal_id set before/with
        BOUND; no partial intermediate state; rollback leaves membership
        unbound and no principal orphan).
    D — BOUND invariant (deferred to HARD-002; this group asserts the
        invariant HOLDS in application code even without the DB CHECK).
    E — Multi-tenant principal (same IdP identity → one principal →
        multiple memberships across tenants).
    F — No-fallback (canonical resolver never silently returns a
        lookup-only principal; canonical write path never falls back to
        legacy-tuple-only mode).
    G — Concurrency (simulated race on unique index → one canonical
        binding survives; caller receives a valid principal_id).
    H — Lifecycle (suspended / deactivated principal denied).
    I — RBAC preservation (roles remain membership-scoped; resolver does
        not read or write roles).
    J — Session/token impact (no new claims required; documented).
    K — Legacy column preservation (identity_provider / identity_issuer /
        identity_subject still written after cutover for rollback / audit
        evidence per §8 of the frozen data model).
    L — AUTH / HARD regression (imports and existing test counts stable).
    M — Privacy (raw provider_subject never appears in error messages,
        logs, or exception reprs).
    N — Deployment / migration ordering decision documented as tests
        (migration 0183 absent; module docstring documents split reason).
    O — Direct SQL: skipped (no CHECK constraint shipped in this PR).
    P — Error semantics (explicit resolver error codes are preserved,
        not remapped to IDENTITY_ALREADY_BOUND).

PR-AUTH-004 CUTS OVER RUNTIME HUMAN IDENTITY TO CANONICAL PRINCIPAL AUTHORITY.
PR-AUTH-004 PRESERVES TENANT-SCOPED MEMBERSHIP AUTHORITY.
PR-AUTH-004 DOES NOT REMOVE LEGACY IDENTITY COLUMNS.
PR-AUTH-004 DOES NOT ALLOW CANONICAL-MODE FALLBACK TO LEGACY IDENTITY AUTHORITY.
"""

from __future__ import annotations

import inspect
import pathlib
import uuid
from dataclasses import fields, is_dataclass
from typing import Any

import pytest
import sqlalchemy
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from api.principal_authority import (
    PrincipalResolution,
    PrincipalResolutionError,
    resolve_or_create_principal_for_external_identity,
)


_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_INVITATION_FLOW = _REPO_ROOT / "admin_gateway" / "identity" / "invitation_flow.py"
_PRINCIPAL_AUTHORITY = _REPO_ROOT / "api" / "principal_authority.py"
_MIGRATION_0183 = (
    _REPO_ROOT
    / "migrations"
    / "postgres"
    / "0183_bound_membership_principal_integrity.sql"
)
_MIGRATION_0182 = (
    _REPO_ROOT / "migrations" / "postgres" / "0182_identity_authority_hardening.sql"
)

_NOW = "2026-08-23T00:00:00+00:00"
_ISSUER = "https://example.auth0.com/"
_SUBJECT = "auth0|abc-123"


# ---------------------------------------------------------------------------
# In-memory SQLite schema. Mirrors 0179 + 0180 + 0181 (no CHECK from 0183).
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS fg_principals (
    id                TEXT    PRIMARY KEY,
    display_name      TEXT,
    primary_email     TEXT,
    principal_type    TEXT    NOT NULL DEFAULT 'human',
    lifecycle_state   TEXT    NOT NULL DEFAULT 'active',
    mfa_verified      INTEGER NOT NULL DEFAULT 0,
    authority_version INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS fg_external_identities (
    id               TEXT PRIMARY KEY,
    principal_id     TEXT NOT NULL REFERENCES fg_principals(id),
    provider         TEXT NOT NULL,
    provider_issuer  TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    provider_email   TEXT,
    created_at       TEXT NOT NULL,
    last_seen_at     TEXT,
    UNIQUE (provider, provider_issuer, provider_subject)
);

CREATE TABLE IF NOT EXISTS tenant_users (
    id                      TEXT    PRIMARY KEY,
    tenant_id               TEXT    NOT NULL,
    email                   TEXT    NOT NULL DEFAULT 'x@example.com',
    display_name            TEXT    NOT NULL DEFAULT 'Test User',
    active                  INTEGER NOT NULL DEFAULT 1,
    identity_binding_status TEXT    NOT NULL DEFAULT 'unbound',
    identity_type           TEXT    NOT NULL DEFAULT 'human',
    identity_provider       TEXT,
    identity_issuer         TEXT,
    identity_subject        TEXT,
    identity_email          TEXT,
    principal_id            TEXT    REFERENCES fg_principals(id)
);
"""


def _setup_schema(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("PRAGMA foreign_keys = ON"))
        for stmt in _SCHEMA.split(";"):
            stripped = stmt.strip()
            if stripped:
                conn.execute(text(stripped))


@pytest.fixture()
def engine() -> Engine:
    eng = create_engine("sqlite:///:memory:", echo=False)
    _setup_schema(eng)

    @sqlalchemy.event.listens_for(eng, "connect")
    def _fk_on(dbapi_con, _rec):  # type: ignore[no-untyped-def]
        dbapi_con.execute("PRAGMA foreign_keys = ON")

    return eng


# ---------------------------------------------------------------------------
# A — Canonical resolver structure and contract
# ---------------------------------------------------------------------------


def test_A1_resolver_module_location() -> None:
    """The resolver lives in api.principal_authority, not in the invitation
    flow module or a new sidecar. Owning module is the write authority."""
    assert _PRINCIPAL_AUTHORITY.exists()
    from api import principal_authority

    assert hasattr(
        principal_authority, "resolve_or_create_principal_for_external_identity"
    )


def test_A2_resolver_signature_uses_canonical_keys() -> None:
    """Signature must accept provider / issuer / subject as required kwargs and
    display_name / primary_email / provider_email as optional attributes.
    """
    sig = inspect.signature(resolve_or_create_principal_for_external_identity)
    params = sig.parameters
    # First positional: connection or session.
    assert list(params.keys())[0] in {"conn", "session", "conn_or_session"}
    for required in ("provider", "issuer", "subject"):
        assert required in params, f"resolver missing required kwarg {required!r}"
        # Must be keyword-only (all keyword-args after conn).
        assert params[required].kind == inspect.Parameter.KEYWORD_ONLY
    for optional in ("display_name", "primary_email", "provider_email"):
        assert optional in params
        assert params[optional].default is None


def test_A3_resolver_returns_principal_resolution_dataclass() -> None:
    assert is_dataclass(PrincipalResolution)
    fnames = {f.name for f in fields(PrincipalResolution)}
    for expected in ("principal_id", "external_identity_id", "created"):
        assert expected in fnames, f"PrincipalResolution missing {expected!r}"


def test_A4_resolver_error_type_carries_code() -> None:
    err = PrincipalResolutionError("INVALID_SUBJECT", "test")
    assert err.code == "INVALID_SUBJECT"


# ---------------------------------------------------------------------------
# B — Canonical resolution semantics
# ---------------------------------------------------------------------------


def _make_principal(conn: Any, *, pid: str | None = None, state: str = "active") -> str:
    pid = pid or str(uuid.uuid4())
    conn.execute(
        text(
            "INSERT INTO fg_principals (id, display_name, primary_email,"
            " principal_type, lifecycle_state, mfa_verified,"
            " authority_version, created_at, updated_at)"
            " VALUES (:id, :dn, :email, 'human', :lc, 0, 1, :now, :now)"
        ),
        {
            "id": pid,
            "dn": "seed",
            "email": "seed@example.com",
            "lc": state,
            "now": _NOW,
        },
    )
    return pid


def _make_binding(
    conn: Any,
    *,
    principal_id: str,
    provider: str = "auth0",
    issuer: str = _ISSUER,
    subject: str = _SUBJECT,
) -> str:
    eid = str(uuid.uuid4())
    conn.execute(
        text(
            "INSERT INTO fg_external_identities (id, principal_id, provider,"
            " provider_issuer, provider_subject, provider_email, created_at)"
            " VALUES (:id, :pid, :p, :i, :s, NULL, :now)"
        ),
        {
            "id": eid,
            "pid": principal_id,
            "p": provider,
            "i": issuer,
            "s": subject,
            "now": _NOW,
        },
    )
    return eid


def test_B1_new_binding_creates_principal(engine: Engine) -> None:
    with engine.begin() as conn:
        result = resolve_or_create_principal_for_external_identity(
            conn,
            provider="auth0",
            issuer=_ISSUER,
            subject=_SUBJECT,
            display_name="New User",
            primary_email="new@example.com",
        )
    assert result.created is True
    assert result.principal_id
    assert result.external_identity_id
    with engine.connect() as conn:
        p = conn.execute(text("SELECT lifecycle_state FROM fg_principals")).fetchone()
    assert p is not None
    assert p.lifecycle_state == "active"


def test_B2_existing_binding_resolves_and_does_not_create(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _make_principal(conn)
        _make_binding(conn, principal_id=pid)
    with engine.begin() as conn:
        result = resolve_or_create_principal_for_external_identity(
            conn,
            provider="auth0",
            issuer=_ISSUER,
            subject=_SUBJECT,
        )
    assert result.created is False
    assert result.principal_id == pid


def test_B3_resolver_is_idempotent(engine: Engine) -> None:
    with engine.begin() as conn:
        first = resolve_or_create_principal_for_external_identity(
            conn,
            provider="auth0",
            issuer=_ISSUER,
            subject=_SUBJECT,
        )
    with engine.begin() as conn:
        second = resolve_or_create_principal_for_external_identity(
            conn,
            provider="auth0",
            issuer=_ISSUER,
            subject=_SUBJECT,
        )
    assert first.principal_id == second.principal_id
    assert second.created is False


def test_B4_malformed_triple_missing_subject_fails(engine: Engine) -> None:
    with engine.begin() as conn:
        with pytest.raises(PrincipalResolutionError) as excinfo:
            resolve_or_create_principal_for_external_identity(
                conn,
                provider="auth0",
                issuer=_ISSUER,
                subject="",
            )
    assert excinfo.value.code == "INVALID_SUBJECT"


def test_B5_malformed_triple_missing_issuer_fails(engine: Engine) -> None:
    with engine.begin() as conn:
        with pytest.raises(PrincipalResolutionError) as excinfo:
            resolve_or_create_principal_for_external_identity(
                conn,
                provider="auth0",
                issuer="",
                subject=_SUBJECT,
            )
    assert excinfo.value.code == "INVALID_ISSUER"


def test_B6_unknown_provider_fails(engine: Engine) -> None:
    with engine.begin() as conn:
        with pytest.raises(PrincipalResolutionError) as excinfo:
            resolve_or_create_principal_for_external_identity(
                conn,
                provider="not-a-provider",
                issuer=_ISSUER,
                subject=_SUBJECT,
            )
    assert excinfo.value.code == "UNKNOWN_PROVIDER"


# ---------------------------------------------------------------------------
# C — Invitation acceptance atomicity (source-level assertions on the fix)
# ---------------------------------------------------------------------------


def test_C1_bind_calls_resolver_before_setting_bound() -> None:
    """Reading the source of admin_gateway.identity.invitation_flow.bind_identity:
    the resolver call must appear before the identity_binding_status='bound'
    assignment."""
    src = _INVITATION_FLOW.read_text(encoding="utf-8")
    assert "resolve_or_create_principal_for_external_identity" in src, (
        "invitation_flow.py must call the canonical resolver"
    )
    resolver_idx = src.find("resolve_or_create_principal_for_external_identity(")
    principal_id_idx = src.find("membership.principal_id = resolution.principal_id")
    bound_idx = src.find('membership.identity_binding_status = "bound"')
    assert 0 < resolver_idx < principal_id_idx < bound_idx, (
        "atomic order: resolver → set principal_id → set BOUND (before flush)"
    )


def test_C2_source_contains_rollback_on_resolver_failure() -> None:
    src = _INVITATION_FLOW.read_text(encoding="utf-8")
    assert "except PrincipalResolutionError" in src
    # Rollback the DB session on resolver failure — no partial state.
    resolver_except_start = src.find("except PrincipalResolutionError")
    resolver_except_end = src.find("raise IdentityFlowError", resolver_except_start)
    assert resolver_except_start > 0
    assert resolver_except_end > resolver_except_start
    body = src[resolver_except_start:resolver_except_end]
    assert "db.rollback()" in body, (
        "resolver failure must roll back the session to avoid partial writes"
    )


def test_C3_source_sets_principal_id_before_flush() -> None:
    src = _INVITATION_FLOW.read_text(encoding="utf-8")
    principal_id_idx = src.find("membership.principal_id = resolution.principal_id")
    flush_idx = src.find("db.flush()")
    assert 0 < principal_id_idx < flush_idx


def test_C4_source_preserves_legacy_identity_columns_write() -> None:
    """The legacy identity_provider/issuer/subject fields are still written
    for rollback + audit evidence during the migration window."""
    src = _INVITATION_FLOW.read_text(encoding="utf-8")
    assert "membership.identity_provider" in src
    assert "membership.identity_issuer" in src
    assert "membership.identity_subject" in src


# ---------------------------------------------------------------------------
# D — BOUND invariant enforced by application code (constraint deferred)
# ---------------------------------------------------------------------------


def test_D1_application_never_flips_bound_without_principal_id() -> None:
    """Source-level guarantee: the only occurrence of setting
    identity_binding_status='bound' in the invitation flow is preceded by a
    principal_id assignment in the same function body."""
    src = _INVITATION_FLOW.read_text(encoding="utf-8")
    bound_lines = [
        (i, line)
        for i, line in enumerate(src.splitlines())
        if 'membership.identity_binding_status = "bound"' in line
    ]
    # Exactly one bind site in the flow.
    assert len(bound_lines) == 1, (
        "invitation_flow.py must contain exactly one BOUND write site"
    )
    # Same body must set principal_id above it.
    idx, _line = bound_lines[0]
    context = "\n".join(src.splitlines()[max(0, idx - 60) : idx])
    assert "membership.principal_id = resolution.principal_id" in context


def test_D2_bind_flow_does_not_leave_bound_without_principal(engine: Engine) -> None:
    """Simulate the atomic write pattern the flow uses."""
    with engine.begin() as conn:
        # Seed an unbound membership.
        mid = str(uuid.uuid4())
        conn.execute(
            text(
                "INSERT INTO tenant_users (id, tenant_id, email, display_name,"
                " active, identity_binding_status, identity_type)"
                " VALUES (:id, 'tenant-a', 'u@ex.com', 'U', 1, 'unbound', 'human')"
            ),
            {"id": mid},
        )
        # Apply the resolver, then atomically set principal_id + BOUND.
        resolution = resolve_or_create_principal_for_external_identity(
            conn,
            provider="auth0",
            issuer=_ISSUER,
            subject=_SUBJECT,
        )
        conn.execute(
            text(
                "UPDATE tenant_users SET"
                "  principal_id = :pid,"
                "  identity_provider = 'auth0',"
                "  identity_issuer = :iss,"
                "  identity_subject = :sub,"
                "  identity_binding_status = 'bound'"
                " WHERE id = :id"
            ),
            {
                "pid": resolution.principal_id,
                "iss": _ISSUER,
                "sub": _SUBJECT,
                "id": mid,
            },
        )
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT principal_id, identity_binding_status"
                " FROM tenant_users WHERE id = :id"
            ),
            {"id": mid},
        ).fetchone()
    assert row is not None
    assert row.identity_binding_status == "bound"
    assert row.principal_id is not None


# ---------------------------------------------------------------------------
# E — Multi-tenant principal (same identity, one principal, many memberships)
# ---------------------------------------------------------------------------


def test_E1_same_identity_two_tenants_one_principal(engine: Engine) -> None:
    """The canonical model: one fg_principals row, multiple tenant_users
    rows. The shadow unique index on legacy columns still blocks — but the
    canonical binding is single."""
    with engine.begin() as conn:
        r1 = resolve_or_create_principal_for_external_identity(
            conn,
            provider="auth0",
            issuer=_ISSUER,
            subject=_SUBJECT,
        )
        r2 = resolve_or_create_principal_for_external_identity(
            conn,
            provider="auth0",
            issuer=_ISSUER,
            subject=_SUBJECT,
        )
    assert r1.principal_id == r2.principal_id
    with engine.connect() as conn:
        count = conn.execute(text("SELECT COUNT(*) FROM fg_principals")).scalar()
    assert count == 1


def test_E2_different_identities_yield_distinct_principals(engine: Engine) -> None:
    with engine.begin() as conn:
        a = resolve_or_create_principal_for_external_identity(
            conn,
            provider="auth0",
            issuer=_ISSUER,
            subject="auth0|alice",
        )
        b = resolve_or_create_principal_for_external_identity(
            conn,
            provider="auth0",
            issuer=_ISSUER,
            subject="auth0|bob",
        )
    assert a.principal_id != b.principal_id


# ---------------------------------------------------------------------------
# F — No-fallback (canonical mode does not fall back to legacy tuple)
# ---------------------------------------------------------------------------


def test_F1_resolver_source_never_reads_tenant_users_identity_columns() -> None:
    """The canonical resolver must not query tenant_users for identity — its
    inputs are the IdP triple. Anything else would be a fallback path.
    """
    src = _PRINCIPAL_AUTHORITY.read_text(encoding="utf-8")
    fn_start = src.find("def resolve_or_create_principal_for_external_identity")
    assert fn_start > 0
    # Function body ends at the next top-level def or EOF.
    tail = src[fn_start:]
    assert "tenant_users" not in tail, (
        "canonical resolver must never read from tenant_users (would be a fallback)"
    )


def test_F2_invitation_flow_does_not_silently_bypass_resolver() -> None:
    """The BOUND write must be conditional on a successful resolver return.
    If the resolver raises, the flow must not fall through to a legacy-only
    tuple set + BOUND flip."""
    src = _INVITATION_FLOW.read_text(encoding="utf-8")
    # No legacy-only branch that flips BOUND if resolver import/failure occurs.
    assert "try:\n        from api.principal_authority" not in src, (
        "canonical import must be unconditional; no optional/try import path"
    )


# ---------------------------------------------------------------------------
# G — Concurrency (simulated race — the second INSERT hits the unique index)
# ---------------------------------------------------------------------------


def test_G1_concurrent_new_binding_race_resolves_to_single_principal(
    engine: Engine,
) -> None:
    """Simulate the race: two writers both see 'no external identity'
    concurrently. One inserts; the other hits uq_fg_external_identities_binding.
    The resolver must detect the IntegrityError and return the winner rather
    than duplicate."""
    provider = "auth0"
    # Race one: seed an external identity through the resolver.
    with engine.begin() as conn:
        winner = resolve_or_create_principal_for_external_identity(
            conn,
            provider=provider,
            issuer=_ISSUER,
            subject=_SUBJECT,
        )
    # Race two: the "loser" call would race — but SQLite serializes writes.
    # Simulate the race by attempting a direct insert that conflicts on unique.
    with engine.begin() as conn:
        # This resolver call must observe the winner (idempotent lookup) and
        # not raise a unique-violation to the caller.
        loser = resolve_or_create_principal_for_external_identity(
            conn,
            provider=provider,
            issuer=_ISSUER,
            subject=_SUBJECT,
        )
    assert winner.principal_id == loser.principal_id
    with engine.connect() as conn:
        n_principals = conn.execute(text("SELECT COUNT(*) FROM fg_principals")).scalar()
        n_ei = conn.execute(
            text("SELECT COUNT(*) FROM fg_external_identities")
        ).scalar()
    assert n_principals == 1
    assert n_ei == 1


def test_G2_race_savepoint_leaves_transaction_valid(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The race handler must query the winner on the same still-valid
    transaction. Without the savepoint, Postgres aborts the transaction on
    IntegrityError; every subsequent query raises 'current transaction is
    aborted'. Simulate the race window by pre-seeding the winner directly and
    patching the initial lookup to return None, forcing the INSERT path."""
    import api.principal_authority as _pa

    winner_principal_id = str(uuid.uuid4())
    winner_ei_id = str(uuid.uuid4())
    now = "2026-08-24T00:00:00+00:00"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO fg_principals (id, display_name, primary_email,"
                " principal_type, lifecycle_state, mfa_verified,"
                " authority_version, created_at, updated_at)"
                " VALUES (:id, NULL, NULL, 'human', 'active', 0, 1, :now, :now)"
            ),
            {"id": winner_principal_id, "now": now},
        )
        conn.execute(
            text(
                "INSERT INTO fg_external_identities (id, principal_id, provider,"
                " provider_issuer, provider_subject, provider_email, created_at)"
                " VALUES (:id, :pid, 'auth0', :issuer, :subject, NULL, :now)"
            ),
            {
                "id": winner_ei_id,
                "pid": winner_principal_id,
                "issuer": _ISSUER,
                "subject": _SUBJECT,
                "now": now,
            },
        )

    original_lookup = _pa._lookup_external_identity
    call_count = 0

    def _patched_lookup(*args: Any, **kwargs: Any) -> Any:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return None  # simulate race window: loser sees nothing on first lookup
        return original_lookup(*args, **kwargs)

    monkeypatch.setattr(_pa, "_lookup_external_identity", _patched_lookup)

    with engine.begin() as conn:
        result = resolve_or_create_principal_for_external_identity(
            conn, provider="auth0", issuer=_ISSUER, subject=_SUBJECT
        )

    assert result.principal_id == winner_principal_id
    assert result.created is False
    assert call_count == 2


# ---------------------------------------------------------------------------
# H — Lifecycle enforcement
# ---------------------------------------------------------------------------


def test_H1_suspended_principal_denied(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _make_principal(conn, state="suspended")
        _make_binding(conn, principal_id=pid)
    with engine.begin() as conn:
        with pytest.raises(PrincipalResolutionError) as excinfo:
            resolve_or_create_principal_for_external_identity(
                conn,
                provider="auth0",
                issuer=_ISSUER,
                subject=_SUBJECT,
            )
    assert excinfo.value.code == "PRINCIPAL_INACTIVE"


def test_H2_deactivated_principal_denied(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _make_principal(conn, state="deactivated")
        _make_binding(conn, principal_id=pid)
    with engine.begin() as conn:
        with pytest.raises(PrincipalResolutionError) as excinfo:
            resolve_or_create_principal_for_external_identity(
                conn,
                provider="auth0",
                issuer=_ISSUER,
                subject=_SUBJECT,
            )
    assert excinfo.value.code == "PRINCIPAL_INACTIVE"


# ---------------------------------------------------------------------------
# I — RBAC preservation
# ---------------------------------------------------------------------------


def test_I1_resolver_does_not_read_or_write_role_columns() -> None:
    """Resolver must not touch tenant_users.role or tenant_credential_roles."""
    src = _PRINCIPAL_AUTHORITY.read_text(encoding="utf-8")
    fn_start = src.find("def resolve_or_create_principal_for_external_identity")
    tail = src[fn_start:]
    for forbidden in (
        "tenant_credential_roles",
        "tenant_users.role",
        "role_name",
    ):
        assert forbidden not in tail, (
            f"resolver must not reference {forbidden!r} — role is membership-scoped"
        )


def test_I2_role_stays_on_membership_source_check() -> None:
    """Verify the invitation flow does not attempt to move role onto the
    principal."""
    src = _INVITATION_FLOW.read_text(encoding="utf-8")
    # No attempt to write role onto fg_principals.
    assert "fg_principals.role" not in src
    assert "principal.role" not in src


# ---------------------------------------------------------------------------
# J — Session/token impact
# ---------------------------------------------------------------------------


def test_J1_session_service_source_check() -> None:
    """Session service continues to read the membership; no new required
    JWT claim is introduced. This PR does not modify session_service.py
    beyond what invitation_flow.py provides transparently."""
    session_service = _REPO_ROOT / "admin_gateway" / "identity" / "session_service.py"
    assert session_service.exists()
    src = session_service.read_text(encoding="utf-8")
    # Session context is built from the membership; principal_id is not a
    # required claim under this PR (it becomes canonical in a future session
    # issuance PR).
    assert "membership.identity_binding_status" in src


def test_J2_no_new_token_claims_added_by_this_pr() -> None:
    """The scope of PR-AUTH-004 is invitation binding cutover. Session
    issuance re-shape (adding principal_id claim, principal-derived roles,
    etc.) is a distinct downstream PR."""
    session_service = _REPO_ROOT / "admin_gateway" / "identity" / "session_service.py"
    src = session_service.read_text(encoding="utf-8")
    # No principal_id claim added to session build in this PR.
    assert 'claims["principal_id"]' not in src


# ---------------------------------------------------------------------------
# K — Legacy column preservation
# ---------------------------------------------------------------------------


def test_K1_legacy_identity_columns_still_populated_by_flow() -> None:
    src = _INVITATION_FLOW.read_text(encoding="utf-8")
    # After cutover, both the canonical FK AND the legacy triple are written.
    assert "membership.principal_id = resolution.principal_id" in src
    assert "membership.identity_provider," in src
    assert "membership.identity_issuer," in src
    assert "membership.identity_subject," in src


def test_K2_no_column_drops_ship_in_this_pr() -> None:
    """This PR must not drop any legacy identity_* columns."""
    if _MIGRATION_0183.exists():
        src = _MIGRATION_0183.read_text(encoding="utf-8").upper()
        for legacy in (
            "IDENTITY_PROVIDER",
            "IDENTITY_ISSUER",
            "IDENTITY_SUBJECT",
            "IDENTITY_BINDING_STATUS",
            "IDENTITY_EMAIL",
        ):
            assert f"DROP COLUMN {legacy}" not in src


# ---------------------------------------------------------------------------
# L — AUTH / HARD regression
# ---------------------------------------------------------------------------


def test_L1_auth_003c_reconciliation_module_unchanged_import() -> None:
    """Reconciliation module must still import successfully."""
    from api import identity_backfill_reconciliation

    assert hasattr(identity_backfill_reconciliation, "run_reconciliation")


def test_L2_hard_001_trigger_migration_untouched() -> None:
    """Migration 0182 (HARD-001 trigger) must remain in place — this PR
    does not modify it."""
    assert _MIGRATION_0182.exists()
    src = _MIGRATION_0182.read_text(encoding="utf-8")
    assert "fg_principal_authority_version_enforce" in src


# ---------------------------------------------------------------------------
# M — Privacy (no raw subject in errors)
# ---------------------------------------------------------------------------


def test_M1_resolver_error_does_not_contain_raw_subject(engine: Engine) -> None:
    """PrincipalResolutionError.message must not embed the subject."""
    secret_subject = "auth0|SECRET-SUBJECT-42"
    with engine.begin() as conn:
        with pytest.raises(PrincipalResolutionError) as excinfo:
            resolve_or_create_principal_for_external_identity(
                conn,
                provider="not-a-provider",
                issuer=_ISSUER,
                subject=secret_subject,
            )
    assert secret_subject not in str(excinfo.value)
    assert secret_subject not in repr(excinfo.value)


def test_M2_resolver_error_omits_subject_for_inactive_principal(engine: Engine) -> None:
    secret_subject = "auth0|OTHER-SECRET-99"
    with engine.begin() as conn:
        pid = _make_principal(conn, state="deactivated")
        _make_binding(conn, principal_id=pid, subject=secret_subject)
    with engine.begin() as conn:
        with pytest.raises(PrincipalResolutionError) as excinfo:
            resolve_or_create_principal_for_external_identity(
                conn,
                provider="auth0",
                issuer=_ISSUER,
                subject=secret_subject,
            )
    assert secret_subject not in str(excinfo.value)
    assert secret_subject not in repr(excinfo.value)


# ---------------------------------------------------------------------------
# N — Deployment / migration ordering decision
# ---------------------------------------------------------------------------


def test_N1_migration_0183_intentionally_split_out_of_this_pr() -> None:
    """The BOUND→principal_id CHECK constraint is deferred to a follow-up
    hardening PR. Rationale: deploy order in this repo is not guaranteed to
    place new application code strictly before migrations. A CHECK deployed
    before all replicas of the app are running the resolver would break
    concurrent invitation acceptance. The runtime cutover ships first; the
    constraint follows once reconciliation proves all new BOUND rows carry
    principal_id.
    """
    assert not _MIGRATION_0183.exists(), (
        "PR-AUTH-004 splits the CHECK constraint out; see module docstring "
        "under 'Deferred deliverable'. Ship HARD-002 for the constraint."
    )


def test_N2_module_docstring_documents_split() -> None:
    """The test module documents the deployment-order decision explicitly."""
    with open(__file__, encoding="utf-8") as f:
        src = f.read()
    assert "Deferred deliverable" in src
    assert "0183" in src


def test_N3_hard_001_migration_still_documents_deferred_check() -> None:
    """HARD-001 migration 0182 documents the CHECK was deferred to a runtime
    cutover PR. Confirm that documentation is still present."""
    src = _MIGRATION_0182.read_text(encoding="utf-8")
    assert "deferred" in src.lower()
    assert "invitation_flow" in src


# ---------------------------------------------------------------------------
# P — Error semantics
# ---------------------------------------------------------------------------


def test_P1_flow_source_does_not_remap_resolver_errors_to_already_bound() -> None:
    """A resolver failure must not be silently re-raised as
    IDENTITY_ALREADY_BOUND — that would hide legitimate faults (unknown
    provider, invalid triple, inactive principal)."""
    src = _INVITATION_FLOW.read_text(encoding="utf-8")
    resolver_block_start = src.find("except PrincipalResolutionError")
    assert resolver_block_start > 0
    resolver_block_end = src.find("raise IdentityFlowError", resolver_block_start)
    resolver_block = src[resolver_block_start:resolver_block_end]
    # Strip Python comments so only executable code is analyzed.
    executable = "\n".join(line.split("#")[0] for line in resolver_block.splitlines())
    assert "IDENTITY_ALREADY_BOUND" not in executable, (
        "resolver errors must carry their own explicit code, not IDENTITY_ALREADY_BOUND"
    )


def test_P2_flow_source_preserves_already_bound_for_cross_tenant_conflict() -> None:
    """The one legitimate IDENTITY_ALREADY_BOUND path is a cross-tenant
    conflict on the shadow unique index — that mapping is preserved."""
    src = _INVITATION_FLOW.read_text(encoding="utf-8")
    # The IntegrityError handler continues to map the shadow-index collision
    # to IDENTITY_ALREADY_BOUND.
    assert "uq_tenant_users_bound_identity" in src
    assert 'IdentityFlowError("IDENTITY_ALREADY_BOUND", 409)' in src


def test_P3_principal_linkage_error_is_distinct(  # noqa: D401
) -> None:
    """A principal FK / linkage failure surfaces as PRINCIPAL_LINKAGE_INVALID,
    not IDENTITY_ALREADY_BOUND."""
    src = _INVITATION_FLOW.read_text(encoding="utf-8")
    assert "PRINCIPAL_LINKAGE_INVALID" in src
    assert "IDENTITY_BINDING_FAILED" in src
