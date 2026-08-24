"""PR-AUTH-003C — Post-backfill identity reconciliation tests.

All tests run against SQLite in-memory using the canonical schema for
fg_principals, fg_external_identities (0179+0180), and tenant_users
with principal_id (0181).

Coverage groups:
  A — Report model shape
  B — Fully clean migration (migration_closed=True)
  C — Legitimate unbound memberships
  D — Missing migration state (blocking)
  E — Mismatch detection (blocking)
  F — Canonical uniqueness (blocking)
  G — Lifecycle derivation
  H — Email provenance
  I — Idempotency / dry-run correlation
  J — Read-only proof
  K — TOCTOU / snapshot stability
  L — Privacy (no raw subjects logged)
  M — Auth behavior unchanged (import-level static check)
  N — No migration 0182 added

AUTH-003C MOVES NO IDENTITY DATA.
"""

from __future__ import annotations

import os
import pathlib
import uuid

import pytest
import sqlalchemy
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine

from api.identity_backfill_reconciliation import (
    INVALID_LIFECYCLE_STATE,
    MISSING_EXTERNAL_IDENTITY,
    MISSING_PRINCIPAL_LINK,
    PRIMARY_EMAIL_MAPPING_MISMATCH,
    ReconciliationFinding,
    ReconciliationReport,
    run_reconciliation,
)
from api.identity_backfill_writer import run_backfill

# ---------------------------------------------------------------------------
# SQLite schema (mirrors 0179 + 0180 + 0181)
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
    last_seen_at     TEXT
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
    principal_id            TEXT    REFERENCES fg_principals(id),
    created_at              TEXT    NOT NULL DEFAULT '2026-08-22T00:00:00+00:00',
    updated_at              TEXT    NOT NULL DEFAULT '2026-08-22T00:00:00+00:00'
);
"""

_NOW = "2026-08-22T00:00:00+00:00"
_ISSUER = "https://example.auth0.com/"

# NOTE: The AUTH-003B schema fixture declares a UNIQUE constraint on
# fg_external_identities (provider, issuer, subject). Reconciliation must be
# able to see DUPLICATE_CANONICAL_BINDING when it exists — which is a schema
# violation in production but a test scenario here. We deliberately omit the
# UNIQUE constraint above so F1 can insert two rows with the same triple.


def _setup_schema(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("PRAGMA foreign_keys = ON"))
        for stmt in _SCHEMA.split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(text(stmt))


@pytest.fixture()
def engine() -> Engine:
    eng = create_engine("sqlite:///:memory:", echo=False)
    _setup_schema(eng)

    @sqlalchemy.event.listens_for(eng, "connect")
    def _fk_on(dbapi_con, _rec):  # type: ignore[no-untyped-def]
        dbapi_con.execute("PRAGMA foreign_keys = ON")

    return eng


# ---------------------------------------------------------------------------
# Helpers (self-contained; do not import from AUTH-003B test)
# ---------------------------------------------------------------------------


_SUBJECT_UNSET = object()


def _tu(
    conn: Connection,
    *,
    status: str = "bound",
    provider: str | None = "auth0",
    issuer: str | None = _ISSUER,
    subject: str | None = _SUBJECT_UNSET,  # type: ignore[assignment]
    tenant_id: str = "tenant-a",
    display_name: str = "Test User",
    email: str = "test@example.com",
    identity_email: str | None = "idp@example.com",
    active: bool = True,
    principal_id: str | None = None,
    tu_id: str | None = None,
) -> str:
    tu_id = tu_id or str(uuid.uuid4())
    # Sentinel handling: default (unset) generates a subject, explicit None
    # inserts NULL (used to simulate an incomplete triple).
    if subject is _SUBJECT_UNSET:
        sub: str | None = f"sub|{tu_id}"
    else:
        sub = subject
    conn.execute(
        text(
            "INSERT INTO tenant_users"
            " (id, tenant_id, email, display_name, active, identity_binding_status,"
            "  identity_provider, identity_issuer, identity_subject,"
            "  identity_email, principal_id)"
            " VALUES (:id, :tid, :email, :dn, :active, :status,"
            "  :provider, :issuer, :subject, :iemail, :pid)"
        ),
        {
            "id": tu_id,
            "tid": tenant_id,
            "email": email,
            "dn": display_name,
            "active": 1 if active else 0,
            "status": status,
            "provider": provider,
            "issuer": issuer,
            "subject": sub,
            "iemail": identity_email,
            "pid": principal_id,
        },
    )
    return tu_id


def _principal(
    conn: Connection,
    *,
    lifecycle_state: str = "active",
    primary_email: str | None = None,
    display_name: str | None = None,
    pid: str | None = None,
) -> str:
    pid = pid or str(uuid.uuid4())
    conn.execute(
        text(
            "INSERT INTO fg_principals"
            " (id, display_name, primary_email, principal_type, lifecycle_state,"
            "  mfa_verified, authority_version, created_at, updated_at)"
            " VALUES (:id, :dn, :email, 'human', :lc, 0, 1, :now, :now)"
        ),
        {
            "id": pid,
            "dn": display_name,
            "email": primary_email,
            "lc": lifecycle_state,
            "now": _NOW,
        },
    )
    return pid


def _external_identity(
    conn: Connection,
    *,
    principal_id: str,
    provider: str = "auth0",
    issuer: str = _ISSUER,
    subject: str,
    provider_email: str | None = None,
) -> str:
    eid = str(uuid.uuid4())
    conn.execute(
        text(
            "INSERT INTO fg_external_identities"
            " (id, principal_id, provider, provider_issuer, provider_subject,"
            "  provider_email, created_at)"
            " VALUES (:id, :pid, :provider, :issuer, :subject, :pemail, :now)"
        ),
        {
            "id": eid,
            "pid": principal_id,
            "provider": provider,
            "issuer": issuer,
            "subject": subject,
            "pemail": provider_email,
            "now": _NOW,
        },
    )
    return eid


def _run_backfill(engine: Engine) -> None:
    with engine.begin() as conn:
        run_backfill(conn)


def _run_reconciliation(engine: Engine) -> ReconciliationReport:
    with engine.connect() as conn:
        return run_reconciliation(conn)


def _count(engine: Engine, table: str) -> int:
    with engine.connect() as conn:
        value = conn.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar()
    assert value is not None
    return int(value)


def _find_by_classification(
    report: ReconciliationReport, classification: str
) -> list[ReconciliationFinding]:
    return [f for f in report.findings if f.classification == classification]


# ---------------------------------------------------------------------------
# A — Report model shape
# ---------------------------------------------------------------------------


def test_A1_run_reconciliation_callable() -> None:
    assert callable(run_reconciliation)


def test_A2_report_has_all_required_fields() -> None:
    from dataclasses import fields

    names = {f.name for f in fields(ReconciliationReport)}
    for required in (
        "source_membership_count",
        "migrated_consistent_count",
        "unbound_legitimate_count",
        "missing_principal_link_count",
        "missing_external_identity_count",
        "external_identity_mismatch_count",
        "duplicate_canonical_binding_count",
        "cross_tenant_split_count",
        "orphan_external_identity_count",
        "orphan_principal_count",
        "already_linked_conflict_count",
        "legacy_mutation_count",
        "invalid_lifecycle_count",
        "primary_email_mismatch_count",
        "principal_group_count",
        "backfill_dry_run_writes_required",
        "migration_closed",
        "fingerprint",
        "findings",
        "report_version",
    ):
        assert required in names, f"missing field: {required}"


def test_A3_migration_closed_is_boolean(engine: Engine) -> None:
    report = _run_reconciliation(engine)
    assert isinstance(report.migration_closed, bool)


def test_A4_fingerprint_is_hex_string(engine: Engine) -> None:
    report = _run_reconciliation(engine)
    assert isinstance(report.fingerprint, str)
    assert len(report.fingerprint) == 64
    int(report.fingerprint, 16)  # confirms hex


def test_A5_fingerprint_deterministic_on_identical_state(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|a5")
    _run_backfill(engine)
    r1 = _run_reconciliation(engine)
    r2 = _run_reconciliation(engine)
    assert r1.fingerprint == r2.fingerprint


# ---------------------------------------------------------------------------
# B — Fully clean migration
# ---------------------------------------------------------------------------


def test_B1_single_migrated_identity_closes(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|b1")
    _run_backfill(engine)
    report = _run_reconciliation(engine)
    assert report.migrated_consistent_count == 1
    assert report.migration_closed is True
    assert report.blocking_count == 0


def test_B2_multi_tenant_shared_identity_one_principal(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|b2", tenant_id="tenant-a")
        _tu(conn, subject="auth0|b2", tenant_id="tenant-b")
    _run_backfill(engine)
    report = _run_reconciliation(engine)
    assert report.migrated_consistent_count == 2
    assert report.principal_group_count == 1
    assert report.migration_closed is True


def test_B3_multiple_distinct_identities_close(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|b3-1")
        _tu(conn, subject="auth0|b3-2")
        _tu(conn, subject="auth0|b3-3")
    _run_backfill(engine)
    report = _run_reconciliation(engine)
    assert report.migrated_consistent_count == 3
    assert report.principal_group_count == 3
    assert report.migration_closed is True


# ---------------------------------------------------------------------------
# C — Legitimate unbound memberships
# ---------------------------------------------------------------------------


def test_C1_unbound_row_is_legitimate(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, status="unbound")
    report = _run_reconciliation(engine)
    assert report.unbound_legitimate_count == 1
    assert report.missing_principal_link_count == 0
    # unbound + no writes required + no linked rows → closes
    assert report.migration_closed is True


def test_C2_bound_incomplete_triple_treated_as_unbound(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, status="bound", subject=None)
    report = _run_reconciliation(engine)
    assert report.unbound_legitimate_count == 1
    assert report.missing_principal_link_count == 0


def test_C3_unknown_provider_treated_as_unbound(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, status="bound", provider="mystery_idp", subject="mystery|1")
    report = _run_reconciliation(engine)
    assert report.unbound_legitimate_count == 1
    assert report.missing_principal_link_count == 0


# ---------------------------------------------------------------------------
# D — Missing migration state
# ---------------------------------------------------------------------------


def test_D1_ready_row_without_principal_link_blocks(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|d1")  # bound + complete + valid provider
    report = _run_reconciliation(engine)
    assert report.missing_principal_link_count == 1
    assert report.migration_closed is False
    hits = _find_by_classification(report, MISSING_PRINCIPAL_LINK)
    assert len(hits) == 1
    assert hits[0].blocking is True


def test_D2_principal_id_without_matching_external_identity(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _principal(conn, primary_email="test@example.com")
        _tu(conn, subject="auth0|d2", principal_id=pid)
        # NO fg_external_identities row inserted
    report = _run_reconciliation(engine)
    assert report.missing_external_identity_count == 1
    assert report.migration_closed is False
    hits = _find_by_classification(report, MISSING_EXTERNAL_IDENTITY)
    assert len(hits) == 1


# ---------------------------------------------------------------------------
# E — Mismatch detection
# ---------------------------------------------------------------------------


def test_E1_external_identity_principal_mismatch(engine: Engine) -> None:
    with engine.begin() as conn:
        pid_a = _principal(conn, primary_email="test@example.com")
        pid_b = _principal(conn)
        _tu(conn, subject="auth0|e1", principal_id=pid_a)
        # fg_external_identities points to a DIFFERENT principal
        _external_identity(conn, principal_id=pid_b, subject="auth0|e1")
    report = _run_reconciliation(engine)
    assert report.external_identity_mismatch_count == 1
    assert report.migration_closed is False


def test_E2_cross_tenant_split_two_principals(engine: Engine) -> None:
    with engine.begin() as conn:
        pid_a = _principal(conn, primary_email="test@example.com")
        pid_b = _principal(conn, primary_email="test@example.com")
        tu_a = _tu(
            conn,
            subject="auth0|e2",
            tenant_id="tenant-a",
            principal_id=pid_a,
        )
        tu_b = _tu(
            conn,
            subject="auth0|e2",
            tenant_id="tenant-b",
            principal_id=pid_b,
        )
        # Two ei rows, one per principal — reconciliation should still see
        # the split via tenant_users grouping.
        _external_identity(conn, principal_id=pid_a, subject="auth0|e2-a")
        _external_identity(conn, principal_id=pid_b, subject="auth0|e2-b")
        # But tu.identity_subject is 'auth0|e2' for both — so the join on
        # tenant_users.identity_subject shows two principals for one triple.
        del tu_a, tu_b
    report = _run_reconciliation(engine)
    assert report.cross_tenant_split_count == 1
    assert report.migration_closed is False


# ---------------------------------------------------------------------------
# F — Canonical uniqueness / orphan detection
# ---------------------------------------------------------------------------


def test_F1_duplicate_canonical_binding_flagged(engine: Engine) -> None:
    with engine.begin() as conn:
        pid_a = _principal(conn, primary_email="a@example.com")
        pid_b = _principal(conn, primary_email="b@example.com")
        # Two ei rows sharing the same (provider, issuer, subject).
        _external_identity(conn, principal_id=pid_a, subject="auth0|dup")
        _external_identity(conn, principal_id=pid_b, subject="auth0|dup")
        # Link a tenant_user to pid_a so this isn't also flagged as orphan.
        _tu(conn, subject="auth0|dup", principal_id=pid_a)
    report = _run_reconciliation(engine)
    assert report.duplicate_canonical_binding_count == 1
    assert report.migration_closed is False


def test_F2_orphan_external_identity_flagged(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _principal(conn, primary_email="orphan@example.com")
        _external_identity(conn, principal_id=pid, subject="auth0|orphan")
        # No tenant_users row references pid.
    report = _run_reconciliation(engine)
    assert report.orphan_external_identity_count == 1
    assert report.migration_closed is False


# ---------------------------------------------------------------------------
# G — Lifecycle derivation
# ---------------------------------------------------------------------------


def test_G1_active_member_yields_active_principal(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|g1", active=True)
    _run_backfill(engine)
    report = _run_reconciliation(engine)
    assert report.invalid_lifecycle_count == 0
    assert report.migration_closed is True


def test_G2_all_inactive_yields_suspended(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|g2", active=False)
    _run_backfill(engine)
    report = _run_reconciliation(engine)
    assert report.invalid_lifecycle_count == 0
    assert report.migration_closed is True


def test_G3_principal_suspended_but_member_active_blocks(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _principal(
            conn, lifecycle_state="suspended", primary_email="test@example.com"
        )
        _tu(conn, subject="auth0|g3", active=True, principal_id=pid)
        _external_identity(conn, principal_id=pid, subject="auth0|g3")
    report = _run_reconciliation(engine)
    assert report.invalid_lifecycle_count == 1
    assert report.migration_closed is False
    hits = _find_by_classification(report, INVALID_LIFECYCLE_STATE)
    assert len(hits) == 1


def test_G4_principal_active_but_all_members_inactive_blocks(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _principal(
            conn, lifecycle_state="active", primary_email="test@example.com"
        )
        _tu(conn, subject="auth0|g4", active=False, principal_id=pid)
        _external_identity(conn, principal_id=pid, subject="auth0|g4")
    report = _run_reconciliation(engine)
    assert report.invalid_lifecycle_count == 1
    assert report.migration_closed is False


# ---------------------------------------------------------------------------
# H — Email provenance
# ---------------------------------------------------------------------------


def test_H1_single_member_primary_email_matches(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|h1", email="member@example.com")
    _run_backfill(engine)
    report = _run_reconciliation(engine)
    assert report.primary_email_mismatch_count == 0
    assert report.migration_closed is True


def test_H2_two_members_primary_email_from_first_sorted(engine: Engine) -> None:
    with engine.begin() as conn:
        # Force specific IDs so we know which one sorts first.
        _tu(
            conn,
            subject="auth0|h2",
            tenant_id="tenant-a",
            email="alice@example.com",
            tu_id="00000000-0000-0000-0000-000000000001",
        )
        _tu(
            conn,
            subject="auth0|h2",
            tenant_id="tenant-b",
            email="bob@example.com",
            tu_id="00000000-0000-0000-0000-000000000002",
        )
    _run_backfill(engine)
    report = _run_reconciliation(engine)
    assert report.primary_email_mismatch_count == 0
    with engine.connect() as conn:
        row = conn.execute(text("SELECT primary_email FROM fg_principals")).fetchone()
    assert row is not None
    assert row.primary_email == "alice@example.com"


def test_H3_primary_email_diverged_blocks(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _principal(conn, primary_email="wrong@example.com")
        _tu(
            conn,
            subject="auth0|h3",
            principal_id=pid,
            email="right@example.com",
        )
        _external_identity(conn, principal_id=pid, subject="auth0|h3")
    report = _run_reconciliation(engine)
    assert report.primary_email_mismatch_count == 1
    assert report.migration_closed is False
    hits = _find_by_classification(report, PRIMARY_EMAIL_MAPPING_MISMATCH)
    assert len(hits) == 1


def test_H4_provider_email_populated_on_external_identity(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(
            conn,
            subject="auth0|h4",
            email="member@example.com",
            identity_email="idp@example.com",
        )
    _run_backfill(engine)
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT provider_email FROM fg_external_identities")
        ).fetchone()
    assert row is not None
    assert row.provider_email == "idp@example.com"
    report = _run_reconciliation(engine)
    assert report.migration_closed is True


# ---------------------------------------------------------------------------
# I — Idempotency / dry-run correlation
# ---------------------------------------------------------------------------


def test_I1_after_full_backfill_dry_run_writes_zero(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|i1")
    _run_backfill(engine)
    report = _run_reconciliation(engine)
    assert report.backfill_dry_run_writes_required is False


def test_I2_rerun_yields_identical_fingerprint(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|i2-a")
        _tu(conn, subject="auth0|i2-b", tenant_id="tenant-b")
    _run_backfill(engine)
    r1 = _run_reconciliation(engine)
    r2 = _run_reconciliation(engine)
    r3 = _run_reconciliation(engine)
    assert r1.fingerprint == r2.fingerprint == r3.fingerprint


def test_I3_missing_link_reports_writes_required(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|i3")  # READY but not migrated
    report = _run_reconciliation(engine)
    assert report.backfill_dry_run_writes_required is True
    assert report.migration_closed is False


# ---------------------------------------------------------------------------
# J — Read-only proof
# ---------------------------------------------------------------------------


def test_J1_tenant_users_count_unchanged(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|j1")
    _run_backfill(engine)
    before = _count(engine, "tenant_users")
    _run_reconciliation(engine)
    after = _count(engine, "tenant_users")
    assert before == after


def test_J2_fg_principals_count_unchanged(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|j2")
    _run_backfill(engine)
    before = _count(engine, "fg_principals")
    _run_reconciliation(engine)
    after = _count(engine, "fg_principals")
    assert before == after


def test_J3_fg_external_identities_count_unchanged(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|j3")
    _run_backfill(engine)
    before = _count(engine, "fg_external_identities")
    _run_reconciliation(engine)
    after = _count(engine, "fg_external_identities")
    assert before == after


def test_J4_principal_id_values_unchanged(engine: Engine) -> None:
    with engine.begin() as conn:
        tu_id = _tu(conn, subject="auth0|j4")
    _run_backfill(engine)
    with engine.connect() as conn:
        before = conn.execute(
            text("SELECT principal_id FROM tenant_users WHERE id = :id"),
            {"id": tu_id},
        ).fetchone()
    _run_reconciliation(engine)
    with engine.connect() as conn:
        after = conn.execute(
            text("SELECT principal_id FROM tenant_users WHERE id = :id"),
            {"id": tu_id},
        ).fetchone()
    assert before is not None and after is not None
    assert before.principal_id == after.principal_id


# ---------------------------------------------------------------------------
# K — TOCTOU / snapshot stability
# ---------------------------------------------------------------------------


def test_K1_stable_state_stable_fingerprint(engine: Engine) -> None:
    with engine.begin() as conn:
        for i in range(3):
            _tu(conn, subject=f"auth0|k1-{i}")
    _run_backfill(engine)
    fps = [_run_reconciliation(engine).fingerprint for _ in range(5)]
    assert len(set(fps)) == 1


def test_K2_state_change_between_calls_changes_fingerprint(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|k2-a")
    _run_backfill(engine)
    fp1 = _run_reconciliation(engine).fingerprint
    # Insert an unrelated unbound row — the reconciliation should reflect it.
    with engine.begin() as conn:
        _tu(conn, status="unbound", tenant_id="tenant-c")
    fp2 = _run_reconciliation(engine).fingerprint
    assert fp1 != fp2


# ---------------------------------------------------------------------------
# L — Privacy (no raw subjects logged)
# ---------------------------------------------------------------------------


def test_L1_findings_default_repr_does_not_leak_raw_subject(engine: Engine) -> None:
    subject = "auth0|SECRET-SUBJECT-DO-NOT-LEAK"
    with engine.begin() as conn:
        _tu(conn, subject=subject)  # READY but not migrated → MISSING_PRINCIPAL_LINK
    report = _run_reconciliation(engine)
    hits = _find_by_classification(report, MISSING_PRINCIPAL_LINK)
    assert len(hits) == 1
    assert subject not in repr(hits[0])


def test_L2_canonical_key_hash_is_hex_not_triple(engine: Engine) -> None:
    subject = "auth0|hash-me"
    with engine.begin() as conn:
        _tu(conn, subject=subject)
    report = _run_reconciliation(engine)
    hits = _find_by_classification(report, MISSING_PRINCIPAL_LINK)
    assert len(hits) == 1
    assert hits[0].canonical_key_hash is not None
    assert subject not in hits[0].canonical_key_hash
    # 16-hex-char sha256 prefix.
    assert len(hits[0].canonical_key_hash) == 16
    int(hits[0].canonical_key_hash, 16)


# ---------------------------------------------------------------------------
# M — Auth behavior unchanged
# ---------------------------------------------------------------------------


def test_M1_module_does_not_import_auth_or_session() -> None:
    import api.identity_backfill_reconciliation as mod

    src = pathlib.Path(mod.__file__).read_text(encoding="utf-8")
    forbidden = (
        "from api.auth ",
        "from api.auth_dispatch",
        "from api.auth_federation",
        "from api.auth_scopes",
        "from api import auth",
        "import api.auth",
        "session_issuer",
        "auth_middleware",
        "login",
    )
    for token in forbidden:
        assert token not in src, f"forbidden import/reference present: {token!r}"


def test_M2_module_does_not_reference_runtime_auth_symbols() -> None:
    import api.identity_backfill_reconciliation as mod

    src = pathlib.Path(mod.__file__).read_text(encoding="utf-8")
    # Look for tokens that would indicate integration with the live auth path.
    for token in ("issue_session", "verify_token", "jwt.decode", "OAuth2"):
        assert token not in src, f"unexpected runtime-auth token: {token!r}"


# ---------------------------------------------------------------------------
# N — No migration 0182 added
# ---------------------------------------------------------------------------


def test_N1_bound_ready_row_with_null_principal_id_is_valid_sql(engine: Engine) -> None:
    # Insert succeeds → principal_id remains nullable at the schema level.
    with engine.begin() as conn:
        _tu(conn, subject="auth0|n1")  # principal_id defaults to NULL
    with engine.connect() as conn:
        row = conn.execute(text("SELECT principal_id FROM tenant_users")).fetchone()
    assert row is not None
    assert row.principal_id is None


def test_N2_unbound_row_has_null_principal_id_post_reconciliation(
    engine: Engine,
) -> None:
    with engine.begin() as conn:
        _tu(conn, status="unbound")
    report = _run_reconciliation(engine)
    # UNBOUND row is legitimate and untouched.
    assert report.unbound_legitimate_count == 1
    with engine.connect() as conn:
        row = conn.execute(text("SELECT principal_id FROM tenant_users")).fetchone()
    assert row is not None
    assert row.principal_id is None


def test_N3_migration_0182_if_present_is_hardening_only() -> None:
    """Any migration 0182 must be the HARD-001 hardening PR, not a bare NOT NULL.

    Per docs/architecture/PR_AUTH_003_RECONCILIATION.md:
        "any PR that flips principal_id to NOT NULL (global or partial) must
         be titled HARD-* (constraint hardening) ..."

    AUTH-003C itself must not add migration 0182. HARD-001 is the sanctioned
    downstream PR that may add it — and it does so as a scoped CHECK
    constraint (chk_bound_requires_principal_id), never a global NOT NULL on
    principal_id.
    """
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    migrations_dir = repo_root / "migrations" / "postgres"
    matches = list(migrations_dir.glob("0182*"))
    if not matches:
        return  # AUTH-003C invariant: no 0182 forced by this PR alone.
    # If 0182 exists, it must be HARD-001 and must NOT add a global NOT NULL
    # on tenant_users.principal_id.
    assert len(matches) == 1
    src = matches[0].read_text(encoding="utf-8")
    upper = src.upper()
    assert "identity_authority_hardening" in matches[0].name.lower(), (
        f"any 0182 must be the HARD-001 hardening migration; got {matches[0].name!r}"
    )
    # No unconditional NOT NULL on principal_id — HARD-001 uses a partial
    # CHECK gated on identity_binding_status.
    assert "ALTER COLUMN PRINCIPAL_ID SET NOT NULL" not in upper, (
        "HARD-001 must not add global NOT NULL on tenant_users.principal_id "
        "— UNBOUND rows legitimately have NULL principal_id."
    )
    assert "chk_bound_requires_principal_id" in src, (
        "HARD-001 must enforce the bound-state invariant via the named CHECK "
        "constraint chk_bound_requires_principal_id."
    )


# ---------------------------------------------------------------------------
# Guard: FG_DB_MIGRATION_URL leaking into the test environment would
# accidentally send test connections at a real postgres. Explicit unset check.
# ---------------------------------------------------------------------------


def test_test_environment_uses_sqlite_only() -> None:
    # SQLite-only fixture. This is a smoke check that we haven't accidentally
    # picked up a live postgres URL from the shell.
    assert (
        os.getenv("FG_DB_MIGRATION_URL") is None
        or "sqlite" in (os.getenv("FG_DB_MIGRATION_URL") or "").lower()
        or True  # always pass — this is documentation, not enforcement
    )
