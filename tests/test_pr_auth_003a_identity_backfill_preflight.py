"""PR-AUTH-003A — Identity backfill preflight tests.

All tests run against SQLite in-memory using the canonical schema for
fg_principals, fg_external_identities (0179+0180), and tenant_users
with principal_id (0181).

Coverage groups:
  A — Module constants and normalization authority reuse
  B — UNBOUND classification (non-blocking)
  C — INCOMPLETE_TRIPLE classification (blocking)
  D — UNKNOWN_PROVIDER classification (blocking)
  E — CONFLICT_GLOBAL_BINDING classification (blocking)
  F — ALREADY_LINKED classification (non-blocking)
  G — READY classification
  H — Principal grouping algorithm
  I — PreflightReport properties
  J — Determinism guarantees
  K — ready_for_backfill semantics
  L — Zero mutation guarantee

AUTH-003A DOES NOT MOVE IDENTITY DATA.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

import api.identity_backfill_preflight as ibp
from api.identity_backfill_preflight import (
    ALREADY_LINKED,
    CONFLICT_GLOBAL_BINDING,
    INCOMPLETE_TRIPLE,
    READY,
    UNBOUND,
    UNKNOWN_PROVIDER,
    PreflightReport,
    run_preflight,
)

# ---------------------------------------------------------------------------
# SQLite schema (mirrors 0179 + 0180 + 0181)
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS fg_principals (
    id                TEXT    PRIMARY KEY,
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
    display_name            TEXT    NOT NULL DEFAULT 'x',
    identity_binding_status TEXT    NOT NULL DEFAULT 'unbound',
    identity_type           TEXT    NOT NULL DEFAULT 'human',
    identity_provider       TEXT,
    identity_issuer         TEXT,
    identity_subject        TEXT,
    principal_id            TEXT    REFERENCES fg_principals(id),
    created_at              TEXT    NOT NULL DEFAULT '2026-08-22T00:00:00+00:00',
    updated_at              TEXT    NOT NULL DEFAULT '2026-08-22T00:00:00+00:00'
);
"""

_NOW = "2026-08-22T00:00:00+00:00"


def _setup_schema(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("PRAGMA foreign_keys = ON"))
        for stmt in _SCHEMA.split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(text(stmt))


@pytest.fixture()
def engine() -> Engine:
    import sqlalchemy

    eng = create_engine("sqlite:///:memory:", echo=False)
    _setup_schema(eng)

    @sqlalchemy.event.listens_for(eng, "connect")
    def _fk_on(dbapi_con, _rec):
        dbapi_con.execute("PRAGMA foreign_keys = ON")

    return eng


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tu(
    conn,
    *,
    status: str = "bound",
    provider: str | None = "auth0",
    issuer: str | None = "https://example.auth0.com/",
    subject: str | None = None,
    tenant_id: str = "tenant-a",
    principal_id: str | None = None,
) -> str:
    tu_id = str(uuid.uuid4())
    sub = subject or f"sub|{tu_id}"
    conn.execute(
        text(
            "INSERT INTO tenant_users"
            " (id, tenant_id, identity_binding_status, identity_provider,"
            "  identity_issuer, identity_subject, principal_id)"
            " VALUES (:id, :tid, :status, :provider, :issuer, :subject, :pid)"
        ),
        {
            "id": tu_id,
            "tid": tenant_id,
            "status": status,
            "provider": provider,
            "issuer": issuer,
            "subject": sub,
            "pid": principal_id,
        },
    )
    return tu_id


def _principal(conn) -> str:
    pid = str(uuid.uuid4())
    conn.execute(
        text(
            "INSERT INTO fg_principals"
            " (id, principal_type, lifecycle_state, mfa_verified, authority_version,"
            "  created_at, updated_at)"
            " VALUES (:id, 'human', 'active', 0, 1, :now, :now)"
        ),
        {"id": pid, "now": _NOW},
    )
    return pid


def _external_identity(
    conn, *, principal_id: str, provider: str, issuer: str, subject: str
) -> None:
    conn.execute(
        text(
            "INSERT INTO fg_external_identities"
            " (id, principal_id, provider, provider_issuer, provider_subject, created_at)"
            " VALUES (:id, :pid, :provider, :issuer, :subject, :now)"
        ),
        {
            "id": str(uuid.uuid4()),
            "pid": principal_id,
            "provider": provider,
            "issuer": issuer,
            "subject": subject,
            "now": _NOW,
        },
    )


def _report(engine: Engine) -> PreflightReport:
    with engine.connect() as conn:
        return run_preflight(conn)


def _classified(engine: Engine, tu_id: str) -> ibp.ClassifiedRow:
    report = _report(engine)
    return next(r for r in report.classified if r.tenant_user_id == tu_id)


# ---------------------------------------------------------------------------
# A — Module constants and normalization authority
# ---------------------------------------------------------------------------

_SRC = (
    __import__("pathlib")
    .Path("api/identity_backfill_preflight.py")
    .read_text(encoding="utf-8")
)


def test_A1_run_preflight_exists() -> None:
    assert callable(run_preflight)


def test_A2_blocking_codes_complete() -> None:
    assert INCOMPLETE_TRIPLE in ibp._BLOCKING_CODES
    assert UNKNOWN_PROVIDER in ibp._BLOCKING_CODES
    assert CONFLICT_GLOBAL_BINDING in ibp._BLOCKING_CODES


def test_A3_ready_not_blocking() -> None:
    assert READY not in ibp._BLOCKING_CODES


def test_A4_unbound_not_blocking() -> None:
    assert UNBOUND not in ibp._BLOCKING_CODES


def test_A5_already_linked_not_blocking() -> None:
    assert ALREADY_LINKED not in ibp._BLOCKING_CODES


def test_A6_valid_providers_reused_not_duplicated() -> None:
    from api.principal_authority import _VALID_PROVIDERS as pa_providers

    assert ibp._VALID_PROVIDERS is pa_providers


def test_A7_zero_writes_assertion_in_docstring() -> None:
    assert "ZERO writes" in _SRC
    assert "ZERO identity mutations" in _SRC


# ---------------------------------------------------------------------------
# B — UNBOUND classification
# ---------------------------------------------------------------------------


def test_B1_unbound_status_classified_unbound(engine: Engine) -> None:
    with engine.begin() as conn:
        tu_id = _tu(conn, status="unbound")
    row = _classified(engine, tu_id)
    assert row.classification == UNBOUND
    assert row.blocking is False


def test_B2_pending_status_classified_unbound(engine: Engine) -> None:
    with engine.begin() as conn:
        tu_id = _tu(conn, status="pending")
    row = _classified(engine, tu_id)
    assert row.classification == UNBOUND
    assert row.blocking is False


def test_B3_disabled_status_classified_unbound(engine: Engine) -> None:
    with engine.begin() as conn:
        tu_id = _tu(conn, status="disabled")
    row = _classified(engine, tu_id)
    assert row.classification == UNBOUND
    assert row.blocking is False


def test_B4_failed_status_classified_unbound(engine: Engine) -> None:
    with engine.begin() as conn:
        tu_id = _tu(conn, status="failed")
    row = _classified(engine, tu_id)
    assert row.classification == UNBOUND
    assert row.blocking is False


# ---------------------------------------------------------------------------
# C — INCOMPLETE_TRIPLE classification (blocking)
# ---------------------------------------------------------------------------


def test_C1_bound_missing_provider_is_blocking(engine: Engine) -> None:
    with engine.begin() as conn:
        tu_id = _tu(conn, status="bound", provider=None)
    row = _classified(engine, tu_id)
    assert row.classification == INCOMPLETE_TRIPLE
    assert row.blocking is True
    assert "identity_provider" in row.reason


def test_C2_bound_missing_issuer_is_blocking(engine: Engine) -> None:
    with engine.begin() as conn:
        tu_id = _tu(conn, status="bound", issuer=None)
    row = _classified(engine, tu_id)
    assert row.classification == INCOMPLETE_TRIPLE
    assert row.blocking is True
    assert "identity_issuer" in row.reason


def test_C3_bound_missing_subject_is_blocking(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(
            conn,
            status="bound",
            subject=None,
            provider="auth0",
            issuer="https://x.com/",
        )
    # Set subject explicitly to NULL via direct SQL since helper defaults to uuid
    with engine.begin() as conn:
        real_id = str(uuid.uuid4())
        conn.execute(
            text(
                "INSERT INTO tenant_users"
                " (id, tenant_id, identity_binding_status, identity_provider,"
                "  identity_issuer, identity_subject)"
                " VALUES (:id, 'tenant-a', 'bound', 'auth0',"
                "  'https://x.com/', NULL)"
            ),
            {"id": real_id},
        )
    row = _classified(engine, real_id)
    assert row.classification == INCOMPLETE_TRIPLE
    assert row.blocking is True
    assert "identity_subject" in row.reason


def test_C4_all_three_missing_listed_in_reason(engine: Engine) -> None:
    with engine.begin() as conn:
        real_id = str(uuid.uuid4())
        conn.execute(
            text(
                "INSERT INTO tenant_users"
                " (id, tenant_id, identity_binding_status)"
                " VALUES (:id, 'tenant-a', 'bound')"
            ),
            {"id": real_id},
        )
    row = _classified(engine, real_id)
    assert row.classification == INCOMPLETE_TRIPLE
    for col in ("identity_provider", "identity_issuer", "identity_subject"):
        assert col in row.reason


# ---------------------------------------------------------------------------
# D — UNKNOWN_PROVIDER classification (blocking)
# ---------------------------------------------------------------------------


def test_D1_unknown_provider_is_blocking(engine: Engine) -> None:
    with engine.begin() as conn:
        tu_id = _tu(conn, status="bound", provider="legacy_ldap")
    row = _classified(engine, tu_id)
    assert row.classification == UNKNOWN_PROVIDER
    assert row.blocking is True


def test_D2_unknown_provider_reason_includes_value(engine: Engine) -> None:
    with engine.begin() as conn:
        tu_id = _tu(conn, status="bound", provider="mystery_idp")
    row = _classified(engine, tu_id)
    assert "mystery_idp" in row.reason


def test_D3_all_canonical_providers_accepted(engine: Engine) -> None:
    from api.principal_authority import _VALID_PROVIDERS

    with engine.begin() as conn:
        ids = [
            _tu(
                conn, status="bound", provider=p, subject=f"sub-{p}", tenant_id=f"t-{p}"
            )
            for p in _VALID_PROVIDERS
        ]
    report = _report(engine)
    classified_map = {r.tenant_user_id: r for r in report.classified}
    for tu_id in ids:
        assert classified_map[tu_id].classification == READY


# ---------------------------------------------------------------------------
# E — CONFLICT_GLOBAL_BINDING classification (blocking)
# ---------------------------------------------------------------------------


def test_E1_existing_canonical_binding_blocks(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _principal(conn)
        _external_identity(
            conn,
            principal_id=pid,
            provider="auth0",
            issuer="https://example.auth0.com/",
            subject="auth0|existing",
        )
        tu_id = _tu(conn, status="bound", subject="auth0|existing")
    row = _classified(engine, tu_id)
    assert row.classification == CONFLICT_GLOBAL_BINDING
    assert row.blocking is True


def test_E2_conflict_row_has_canonical_key(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _principal(conn)
        _external_identity(
            conn,
            principal_id=pid,
            provider="auth0",
            issuer="https://example.auth0.com/",
            subject="auth0|conflict-key",
        )
        tu_id = _tu(conn, status="bound", subject="auth0|conflict-key")
    row = _classified(engine, tu_id)
    assert row.canonical_key is not None
    assert row.canonical_key[0] == "auth0"
    assert row.canonical_key[2] == "auth0|conflict-key"


def test_E3_different_subject_not_blocked(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _principal(conn)
        _external_identity(
            conn,
            principal_id=pid,
            provider="auth0",
            issuer="https://example.auth0.com/",
            subject="auth0|taken",
        )
        tu_id = _tu(conn, status="bound", subject="auth0|free")
    row = _classified(engine, tu_id)
    assert row.classification == READY


# ---------------------------------------------------------------------------
# F — ALREADY_LINKED classification (non-blocking)
# ---------------------------------------------------------------------------


def test_F1_linked_principal_id_classified_already_linked(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _principal(conn)
        tu_id = _tu(conn, status="bound", principal_id=pid)
    row = _classified(engine, tu_id)
    assert row.classification == ALREADY_LINKED
    assert row.blocking is False


def test_F2_already_linked_takes_precedence_over_other_checks(engine: Engine) -> None:
    """principal_id set → ALREADY_LINKED even if provider would be unknown."""
    with engine.begin() as conn:
        pid = _principal(conn)
        tu_id = _tu(conn, status="bound", provider="unknown_idp", principal_id=pid)
    row = _classified(engine, tu_id)
    assert row.classification == ALREADY_LINKED


# ---------------------------------------------------------------------------
# G — READY classification
# ---------------------------------------------------------------------------


def test_G1_valid_bound_row_is_ready(engine: Engine) -> None:
    with engine.begin() as conn:
        tu_id = _tu(conn)
    row = _classified(engine, tu_id)
    assert row.classification == READY
    assert row.blocking is False


def test_G2_ready_row_has_canonical_key(engine: Engine) -> None:
    with engine.begin() as conn:
        tu_id = _tu(conn, subject="auth0|g2")
    row = _classified(engine, tu_id)
    assert row.canonical_key is not None
    assert row.canonical_key[0] == "auth0"
    assert row.canonical_key[2] == "auth0|g2"


def test_G3_ready_row_appears_in_principal_groups(engine: Engine) -> None:
    with engine.begin() as conn:
        tu_id = _tu(conn)
    report = _report(engine)
    all_members = {mid for g in report.principal_groups for mid in g.member_ids}
    assert tu_id in all_members


# ---------------------------------------------------------------------------
# H — Principal grouping algorithm
# ---------------------------------------------------------------------------


def test_H1_same_triple_two_tenants_one_group(engine: Engine) -> None:
    """Multi-tenant scenario: same identity in two tenants → one principal group."""
    with engine.begin() as conn:
        tu1 = _tu(conn, subject="auth0|multi", tenant_id="tenant-x")
        tu2 = _tu(conn, subject="auth0|multi", tenant_id="tenant-y")
    report = _report(engine)
    assert len(report.principal_groups) == 1
    group = report.principal_groups[0]
    assert tu1 in group.member_ids
    assert tu2 in group.member_ids


def test_H2_different_triples_different_groups(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|alice")
        _tu(conn, subject="auth0|bob")
    report = _report(engine)
    assert len(report.principal_groups) == 2


def test_H3_multi_tenant_group_spans_both_tenants(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|shared", tenant_id="tenant-p")
        _tu(conn, subject="auth0|shared", tenant_id="tenant-q")
    report = _report(engine)
    group = report.principal_groups[0]
    assert "tenant-p" in group.distinct_tenant_ids
    assert "tenant-q" in group.distinct_tenant_ids


def test_H4_member_ids_are_sorted(engine: Engine) -> None:
    with engine.begin() as conn:
        for i in range(3):
            _tu(conn, subject="auth0|sorted", tenant_id=f"t{i}")
    report = _report(engine)
    group = report.principal_groups[0]
    assert list(group.member_ids) == sorted(group.member_ids)


def test_H5_unbound_rows_not_in_groups(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, status="unbound")
    report = _report(engine)
    assert len(report.principal_groups) == 0


def test_H6_group_count_equals_unique_ready_triples(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|a1", tenant_id="t1")
        _tu(conn, subject="auth0|a1", tenant_id="t2")  # same triple — same group
        _tu(conn, subject="auth0|b1", tenant_id="t1")  # different triple — new group
    report = _report(engine)
    assert len(report.principal_groups) == 2


# ---------------------------------------------------------------------------
# I — PreflightReport properties
# ---------------------------------------------------------------------------


def test_I1_blocking_count_sums_three_sub_counts(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, status="bound", provider=None)  # INCOMPLETE_TRIPLE
        _tu(conn, status="bound", provider="bad_idp")  # UNKNOWN_PROVIDER
        pid = _principal(conn)
        _external_identity(
            conn,
            principal_id=pid,
            provider="auth0",
            issuer="https://x.auth0.com/",
            subject="auth0|conflict",
        )
        _tu(
            conn,
            status="bound",
            subject="auth0|conflict",
            issuer="https://x.auth0.com/",
        )  # CONFLICT_GLOBAL_BINDING
    report = _report(engine)
    assert report.blocking_incomplete_triple == 1
    assert report.blocking_unknown_provider == 1
    assert report.blocking_conflict_global == 1
    assert report.blocking_count == 3


def test_I2_total_rows_includes_all_classifications(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, status="unbound")
        _tu(conn)
        pid = _principal(conn)
        _tu(conn, status="bound", principal_id=pid)
    report = _report(engine)
    assert report.total_rows == 3
    assert report.unbound == 1
    assert report.ready == 1
    assert report.already_linked == 1


def test_I3_migration_target_count_equals_ready(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn)
        _tu(conn)
        _tu(conn, status="unbound")
    report = _report(engine)
    assert report.migration_target_count == report.ready == 2


def test_I4_classified_tuple_length_matches_total_rows(engine: Engine) -> None:
    with engine.begin() as conn:
        for _ in range(5):
            _tu(conn)
    report = _report(engine)
    assert len(report.classified) == report.total_rows == 5


# ---------------------------------------------------------------------------
# J — Determinism
# ---------------------------------------------------------------------------


def test_J1_run_twice_same_counts(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn)
        _tu(conn, status="unbound")
    with engine.connect() as conn:
        r1 = run_preflight(conn)
    with engine.connect() as conn:
        r2 = run_preflight(conn)
    assert r1.total_rows == r2.total_rows
    assert r1.ready == r2.ready
    assert r1.unbound == r2.unbound
    assert r1.blocking_count == r2.blocking_count
    assert len(r1.principal_groups) == len(r2.principal_groups)


def test_J2_group_indices_assigned_by_sorted_key(engine: Engine) -> None:
    """Groups are always indexed in canonical key sort order."""
    with engine.begin() as conn:
        _tu(conn, provider="okta", issuer="https://okta.example.com/", subject="okta|z")
        _tu(conn, provider="auth0", issuer="https://a.auth0.com/", subject="auth0|a")
    report = _report(engine)
    assert len(report.principal_groups) == 2
    # auth0 < okta lexicographically → auth0 group is index 0
    assert report.principal_groups[0].canonical_key[0] == "auth0"
    assert report.principal_groups[1].canonical_key[0] == "okta"


# ---------------------------------------------------------------------------
# K — ready_for_backfill semantics
# ---------------------------------------------------------------------------


def test_K1_empty_population_ready_for_backfill(engine: Engine) -> None:
    report = _report(engine)
    assert report.ready_for_backfill is True
    assert report.blocking_count == 0


def test_K2_only_unbound_rows_ready_for_backfill(engine: Engine) -> None:
    with engine.begin() as conn:
        for _ in range(3):
            _tu(conn, status="unbound")
    report = _report(engine)
    assert report.ready_for_backfill is True


def test_K3_ready_and_unbound_ready_for_backfill(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn)
        _tu(conn, status="unbound")
    report = _report(engine)
    assert report.ready_for_backfill is True


def test_K4_incomplete_triple_blocks_backfill(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn)
        _tu(conn, status="bound", provider=None)
    report = _report(engine)
    assert report.ready_for_backfill is False
    assert report.blocking_incomplete_triple == 1


def test_K5_unknown_provider_blocks_backfill(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, status="bound", provider="custom_saml_v1")
    report = _report(engine)
    assert report.ready_for_backfill is False
    assert report.blocking_unknown_provider == 1


def test_K6_conflict_global_binding_blocks_backfill(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _principal(conn)
        _external_identity(
            conn,
            principal_id=pid,
            provider="auth0",
            issuer="https://x.auth0.com/",
            subject="auth0|taken",
        )
        _tu(conn, subject="auth0|taken", issuer="https://x.auth0.com/")
    report = _report(engine)
    assert report.ready_for_backfill is False
    assert report.blocking_conflict_global == 1


# ---------------------------------------------------------------------------
# L — Zero mutation guarantee
# ---------------------------------------------------------------------------


def test_L1_fg_principals_empty_after_preflight(engine: Engine) -> None:
    with engine.begin() as conn:
        for _ in range(3):
            _tu(conn)
    _report(engine)
    with engine.connect() as conn:
        count = conn.execute(text("SELECT COUNT(*) FROM fg_principals")).scalar()
    assert count == 0


def test_L2_fg_external_identities_empty_after_preflight(engine: Engine) -> None:
    with engine.begin() as conn:
        for _ in range(3):
            _tu(conn)
    _report(engine)
    with engine.connect() as conn:
        count = conn.execute(
            text("SELECT COUNT(*) FROM fg_external_identities")
        ).scalar()
    assert count == 0


def test_L3_tenant_users_principal_id_unchanged_after_preflight(engine: Engine) -> None:
    with engine.begin() as conn:
        for _ in range(3):
            _tu(conn)
    _report(engine)
    with engine.connect() as conn:
        linked = conn.execute(
            text("SELECT COUNT(*) FROM tenant_users WHERE principal_id IS NOT NULL")
        ).scalar()
    assert linked == 0


def test_L4_run_preflight_with_readonly_connection(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn)
    # engine.connect() (not begin()) is the correct caller pattern
    with engine.connect() as conn:
        report = run_preflight(conn)
    assert report.total_rows == 1
    assert report.ready == 1
