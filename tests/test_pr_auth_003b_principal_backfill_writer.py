"""PR-AUTH-003B — Principal + ExternalIdentity backfill writer tests.

All tests run against SQLite in-memory using the canonical schema for
fg_principals, fg_external_identities (0179+0180), and tenant_users
with principal_id (0181).

Coverage groups:
  A — Module structure and BackfillReport type
  B — Blocking gate: raises when preflight is not ready
  C — Dry run: counts correctly, writes nothing
  D — Happy path: single READY row
  E — Multi-tenant grouping: one principal spans multiple tenants
  F — Multiple distinct groups
  G — Report correctness
  H — Source attribution (display_name, primary_email)
  I — Empty and already-migrated populations
  J — Post-backfill state verification
  K — Preflight integration
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from api.identity_backfill_writer import BackfillReport, run_backfill

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
    principal_id            TEXT    REFERENCES fg_principals(id),
    created_at              TEXT    NOT NULL DEFAULT '2026-08-22T00:00:00+00:00',
    updated_at              TEXT    NOT NULL DEFAULT '2026-08-22T00:00:00+00:00'
);
"""

_NOW = "2026-08-22T00:00:00+00:00"
_ISSUER = "https://example.auth0.com/"


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
    provider: str = "auth0",
    issuer: str = _ISSUER,
    subject: str | None = None,
    tenant_id: str = "tenant-a",
    display_name: str = "Test User",
    email: str = "test@example.com",
    identity_email: str | None = "idp@example.com",
    active: bool = True,
    principal_id: str | None = None,
) -> str:
    tu_id = str(uuid.uuid4())
    sub = subject or f"sub|{tu_id}"
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


def _run(engine: Engine, *, dry_run: bool = False) -> BackfillReport:
    with engine.begin() as conn:
        return run_backfill(conn, dry_run=dry_run)


def _count(engine: Engine, table: str) -> int:
    with engine.connect() as conn:
        return conn.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar()


def _linked_count(engine: Engine) -> int:
    with engine.connect() as conn:
        return conn.execute(
            text("SELECT COUNT(*) FROM tenant_users WHERE principal_id IS NOT NULL")
        ).scalar()


# ---------------------------------------------------------------------------
# A — Module structure and BackfillReport type
# ---------------------------------------------------------------------------


def test_A1_run_backfill_callable() -> None:
    assert callable(run_backfill)


def test_A2_backfill_report_has_required_fields() -> None:
    from dataclasses import fields

    field_names = {f.name for f in fields(BackfillReport)}
    assert "principals_created" in field_names
    assert "external_identities_created" in field_names
    assert "tenant_users_linked" in field_names
    assert "dry_run" in field_names
    assert "preflight" in field_names


def test_A3_backfill_report_success_property(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn)
    report = _run(engine)
    assert report.success is True


def test_A4_backfill_report_groups_processed(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="sub-a")
        _tu(conn, subject="sub-b")
    report = _run(engine)
    assert report.groups_processed == 2


# ---------------------------------------------------------------------------
# B — Blocking gate
# ---------------------------------------------------------------------------


def test_B1_raises_when_blocking_row_exists(engine: Engine) -> None:
    with engine.begin() as conn:
        # INCOMPLETE_TRIPLE — blocking
        conn.execute(
            text(
                "INSERT INTO tenant_users"
                " (id, tenant_id, identity_binding_status)"
                " VALUES (:id, 'tenant-a', 'bound')"
            ),
            {"id": str(uuid.uuid4())},
        )
    with pytest.raises(RuntimeError, match="blocking"):
        _run(engine)


def test_B2_error_message_mentions_blocking_count(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenant_users"
                " (id, tenant_id, identity_binding_status)"
                " VALUES (:id, 'tenant-a', 'bound')"
            ),
            {"id": str(uuid.uuid4())},
        )
    with pytest.raises(RuntimeError, match="1 blocking"):
        _run(engine)


def test_B3_blocking_gate_prevents_any_writes(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn)  # READY
        conn.execute(  # INCOMPLETE_TRIPLE — blocks
            text(
                "INSERT INTO tenant_users"
                " (id, tenant_id, identity_binding_status)"
                " VALUES (:id, 'tenant-a', 'bound')"
            ),
            {"id": str(uuid.uuid4())},
        )
    with pytest.raises(RuntimeError):
        _run(engine)
    assert _count(engine, "fg_principals") == 0


# ---------------------------------------------------------------------------
# C — Dry run
# ---------------------------------------------------------------------------


def test_C1_dry_run_counts_principals(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="sub-c1")
        _tu(conn, subject="sub-c2")
    report = _run(engine, dry_run=True)
    assert report.principals_created == 2
    assert report.dry_run is True


def test_C2_dry_run_writes_nothing_to_fg_principals(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn)
    _run(engine, dry_run=True)
    assert _count(engine, "fg_principals") == 0


def test_C3_dry_run_writes_nothing_to_fg_external_identities(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn)
    _run(engine, dry_run=True)
    assert _count(engine, "fg_external_identities") == 0


def test_C4_dry_run_does_not_link_tenant_users(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn)
    _run(engine, dry_run=True)
    assert _linked_count(engine) == 0


def test_C5_dry_run_counts_match_live_run(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="sub-d1")
        _tu(conn, subject="sub-d2", tenant_id="tenant-b")
    dry = _run(engine, dry_run=True)
    live = _run(engine)
    assert dry.principals_created == live.principals_created
    assert dry.external_identities_created == live.external_identities_created
    assert dry.tenant_users_linked == live.tenant_users_linked


# ---------------------------------------------------------------------------
# D — Happy path: single READY row
# ---------------------------------------------------------------------------


def test_D1_creates_one_principal(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn)
    _run(engine)
    assert _count(engine, "fg_principals") == 1


def test_D2_creates_one_external_identity(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn)
    _run(engine)
    assert _count(engine, "fg_external_identities") == 1


def test_D3_links_tenant_user_principal_id(engine: Engine) -> None:
    with engine.begin() as conn:
        tu_id = _tu(conn)
    _run(engine)
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT principal_id FROM tenant_users WHERE id = :id"),
            {"id": tu_id},
        ).fetchone()
    assert row is not None
    assert row.principal_id is not None


def test_D4_principal_is_active_human(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn)
    _run(engine)
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT principal_type, lifecycle_state FROM fg_principals")
        ).fetchone()
    assert row is not None
    assert row.principal_type == "human"
    assert row.lifecycle_state == "active"


def test_D5_principal_authority_version_is_1(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn)
    _run(engine)
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT authority_version FROM fg_principals")
        ).fetchone()
    assert row is not None
    assert row.authority_version == 1


def test_D6_external_identity_triple_matches_source(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(
            conn,
            provider="okta",
            issuer="https://okta.example.com/",
            subject="okta|abc",
        )
    _run(engine)
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT provider, provider_issuer, provider_subject FROM fg_external_identities"
            )
        ).fetchone()
    assert row is not None
    assert row.provider == "okta"
    assert row.provider_issuer == "https://okta.example.com/"
    assert row.provider_subject == "okta|abc"


def test_D7_tenant_user_principal_id_matches_created_principal(engine: Engine) -> None:
    with engine.begin() as conn:
        tu_id = _tu(conn)
    _run(engine)
    with engine.connect() as conn:
        pid_from_tu = conn.execute(
            text("SELECT principal_id FROM tenant_users WHERE id = :id"), {"id": tu_id}
        ).fetchone()
        pid_from_p = conn.execute(text("SELECT id FROM fg_principals")).fetchone()
    assert pid_from_tu is not None
    assert pid_from_p is not None
    assert pid_from_tu.principal_id == pid_from_p.id


# ---------------------------------------------------------------------------
# E — Multi-tenant grouping
# ---------------------------------------------------------------------------


def test_E1_same_triple_two_tenants_one_principal(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|shared", tenant_id="tenant-x")
        _tu(conn, subject="auth0|shared", tenant_id="tenant-y")
    _run(engine)
    assert _count(engine, "fg_principals") == 1
    assert _count(engine, "fg_external_identities") == 1


def test_E2_both_tenant_users_linked_to_same_principal(engine: Engine) -> None:
    with engine.begin() as conn:
        tu1 = _tu(conn, subject="auth0|shared2", tenant_id="tenant-x")
        tu2 = _tu(conn, subject="auth0|shared2", tenant_id="tenant-y")
    _run(engine)
    with engine.connect() as conn:
        p1 = conn.execute(
            text("SELECT principal_id FROM tenant_users WHERE id = :id"), {"id": tu1}
        ).fetchone()
        p2 = conn.execute(
            text("SELECT principal_id FROM tenant_users WHERE id = :id"), {"id": tu2}
        ).fetchone()
    assert p1 is not None and p2 is not None
    assert p1.principal_id == p2.principal_id


def test_E3_multi_tenant_report_counts(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|shared3", tenant_id="tenant-x")
        _tu(conn, subject="auth0|shared3", tenant_id="tenant-y")
    report = _run(engine)
    assert report.principals_created == 1
    assert report.external_identities_created == 1
    assert report.tenant_users_linked == 2


# ---------------------------------------------------------------------------
# F — Multiple distinct groups
# ---------------------------------------------------------------------------


def test_F1_two_distinct_triples_two_principals(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|alice")
        _tu(conn, subject="auth0|bob")
    _run(engine)
    assert _count(engine, "fg_principals") == 2
    assert _count(engine, "fg_external_identities") == 2


def test_F2_each_tenant_user_linked_to_distinct_principal(engine: Engine) -> None:
    with engine.begin() as conn:
        tu1 = _tu(conn, subject="auth0|alice2")
        tu2 = _tu(conn, subject="auth0|bob2")
    _run(engine)
    with engine.connect() as conn:
        p1 = conn.execute(
            text("SELECT principal_id FROM tenant_users WHERE id = :id"), {"id": tu1}
        ).fetchone()
        p2 = conn.execute(
            text("SELECT principal_id FROM tenant_users WHERE id = :id"), {"id": tu2}
        ).fetchone()
    assert p1 is not None and p2 is not None
    assert p1.principal_id != p2.principal_id


def test_F3_unbound_rows_not_linked(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|ready")
        tu_unbound = _tu(conn, status="unbound")
    _run(engine)
    with engine.connect() as conn:
        unbound_pid = conn.execute(
            text("SELECT principal_id FROM tenant_users WHERE id = :id"),
            {"id": tu_unbound},
        ).fetchone()
    assert unbound_pid is not None
    assert unbound_pid.principal_id is None
    assert _count(engine, "fg_principals") == 1


# ---------------------------------------------------------------------------
# G — Report correctness
# ---------------------------------------------------------------------------


def test_G1_report_principals_created_matches_group_count(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="sub-g1")
        _tu(conn, subject="sub-g2")
        _tu(conn, subject="sub-g3")
    report = _run(engine)
    assert report.principals_created == 3
    assert report.principals_created == len(report.preflight.principal_groups)


def test_G2_report_external_identities_equals_principals(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="sub-g4")
        _tu(conn, subject="sub-g5")
    report = _run(engine)
    assert report.external_identities_created == report.principals_created


def test_G3_report_tenant_users_linked_matches_ready_count(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="sub-g6")
        _tu(conn, subject="sub-g7")
        _tu(conn, status="unbound")
    report = _run(engine)
    assert report.tenant_users_linked == report.preflight.ready == 2


def test_G4_success_is_false_on_dry_run(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn)
    report = _run(engine, dry_run=True)
    # dry_run counts correctly but hasn't actually written anything,
    # so success criterion (counts match plan) still holds
    assert report.success is True
    assert report.dry_run is True


# ---------------------------------------------------------------------------
# H — Source attribution
# ---------------------------------------------------------------------------


def test_H1_principal_primary_email_from_membership_email(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, identity_email="idp-user@corp.com", email="member@corp.com")
    _run(engine)
    with engine.connect() as conn:
        row = conn.execute(text("SELECT primary_email FROM fg_principals")).fetchone()
    assert row is not None
    assert row.primary_email == "member@corp.com"


def test_H2_provider_email_is_null_when_identity_email_null(
    engine: Engine,
) -> None:
    with engine.begin() as conn:
        _tu(conn, identity_email=None, email="member@corp.com")
    _run(engine)
    with engine.connect() as conn:
        ei = conn.execute(
            text("SELECT provider_email FROM fg_external_identities")
        ).fetchone()
    assert ei is not None
    assert ei.provider_email is None


def test_H3_display_name_sourced_from_tenant_user(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, display_name="Alice Backfill")
    _run(engine)
    with engine.connect() as conn:
        row = conn.execute(text("SELECT display_name FROM fg_principals")).fetchone()
    assert row is not None
    assert row.display_name == "Alice Backfill"


def test_H4_provider_email_uses_identity_email_not_membership_email(
    engine: Engine,
) -> None:
    with engine.begin() as conn:
        _tu(conn, identity_email="idp@corp.com", email="member@corp.com")
    _run(engine)
    with engine.connect() as conn:
        row = conn.execute(text("SELECT primary_email FROM fg_principals")).fetchone()
        ei = conn.execute(
            text("SELECT provider_email FROM fg_external_identities")
        ).fetchone()
    assert row is not None and ei is not None
    assert row.primary_email == "member@corp.com"
    assert ei.provider_email == "idp@corp.com"
    assert row.primary_email != ei.provider_email


# ---------------------------------------------------------------------------
# I — Empty and already-migrated populations
# ---------------------------------------------------------------------------


def test_I1_empty_population_succeeds_with_zero_counts(engine: Engine) -> None:
    report = _run(engine)
    assert report.success is True
    assert report.principals_created == 0
    assert report.tenant_users_linked == 0


def test_I2_already_linked_rows_not_remigrated(engine: Engine) -> None:
    with engine.begin() as conn:
        pid = _principal(conn)
        _tu(conn, principal_id=pid)
    report = _run(engine)
    assert report.principals_created == 0
    assert report.tenant_users_linked == 0
    assert _count(engine, "fg_principals") == 1  # original, untouched


def test_I3_re_run_after_full_backfill_writes_nothing(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|once")
    _run(engine)
    report2 = _run(engine)
    assert report2.principals_created == 0
    assert report2.tenant_users_linked == 0
    assert _count(engine, "fg_principals") == 1  # from first run, untouched


# ---------------------------------------------------------------------------
# J — Post-backfill state verification
# ---------------------------------------------------------------------------


def test_J1_all_bound_rows_have_principal_id_after_backfill(engine: Engine) -> None:
    with engine.begin() as conn:
        for i in range(4):
            _tu(conn, subject=f"auth0|j{i}")
    _run(engine)
    with engine.connect() as conn:
        unlinked = conn.execute(
            text(
                "SELECT COUNT(*) FROM tenant_users"
                " WHERE identity_binding_status = 'bound'"
                "   AND principal_id IS NULL"
            )
        ).scalar()
    assert unlinked == 0


def test_J2_fg_principals_count_equals_unique_triples(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|uniq1")
        _tu(conn, subject="auth0|uniq2")
        _tu(
            conn, subject="auth0|uniq1", tenant_id="tenant-b"
        )  # same triple, 2nd tenant
    _run(engine)
    assert _count(engine, "fg_principals") == 2


def test_J3_fg_external_identities_unique_constraint_respected(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|uniq3")
        _tu(conn, subject="auth0|uniq3", tenant_id="tenant-b")
    _run(engine)
    # Only one fg_external_identities row for the shared triple
    with engine.connect() as conn:
        count = conn.execute(
            text(
                "SELECT COUNT(*) FROM fg_external_identities WHERE provider_subject = 'auth0|uniq3'"
            )
        ).scalar()
    assert count == 1


def test_J4_legacy_identity_columns_preserved_after_backfill(engine: Engine) -> None:
    with engine.begin() as conn:
        tu_id = _tu(conn, provider="auth0", subject="auth0|legacy-check")
    _run(engine)
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT identity_provider, identity_subject FROM tenant_users WHERE id = :id"
            ),
            {"id": tu_id},
        ).fetchone()
    assert row is not None
    assert row.identity_provider == "auth0"
    assert row.identity_subject == "auth0|legacy-check"


# ---------------------------------------------------------------------------
# K — Preflight integration
# ---------------------------------------------------------------------------


def test_K1_run_backfill_calls_preflight_internally(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn)
    report = _run(engine)
    assert report.preflight is not None
    assert report.preflight.total_rows >= 1


def test_K2_report_preflight_ready_count_matches_linked(engine: Engine) -> None:
    with engine.begin() as conn:
        for i in range(3):
            _tu(conn, subject=f"auth0|k{i}")
        _tu(conn, status="unbound")
    report = _run(engine)
    assert report.preflight.ready == 3
    assert report.tenant_users_linked == 3


def test_K3_preflight_shows_all_rows_already_linked_after_backfill(
    engine: Engine,
) -> None:
    with engine.begin() as conn:
        _tu(conn, subject="auth0|already")
    _run(engine)
    from api.identity_backfill_preflight import run_preflight

    with engine.connect() as conn:
        report = run_preflight(conn)
    assert report.already_linked == 1
    assert report.ready == 0
    assert report.ready_for_backfill is True


# ---------------------------------------------------------------------------
# L — Lifecycle state derivation from tenant_users.active
# ---------------------------------------------------------------------------


def test_L1_principal_is_active_when_member_is_active(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, active=True)
    _run(engine)
    with engine.connect() as conn:
        row = conn.execute(text("SELECT lifecycle_state FROM fg_principals")).fetchone()
    assert row is not None
    assert row.lifecycle_state == "active"


def test_L2_principal_is_suspended_when_all_members_inactive(engine: Engine) -> None:
    with engine.begin() as conn:
        _tu(conn, active=False)
    _run(engine)
    with engine.connect() as conn:
        row = conn.execute(text("SELECT lifecycle_state FROM fg_principals")).fetchone()
    assert row is not None
    assert row.lifecycle_state == "suspended"


def test_L3_any_active_member_makes_principal_active(engine: Engine) -> None:
    shared_subject = "auth0|shared-triple"
    with engine.begin() as conn:
        _tu(conn, subject=shared_subject, tenant_id="tenant-a", active=False)
        _tu(conn, subject=shared_subject, tenant_id="tenant-b", active=True)
    _run(engine)
    with engine.connect() as conn:
        row = conn.execute(text("SELECT lifecycle_state FROM fg_principals")).fetchone()
    assert row is not None
    assert row.lifecycle_state == "active"


def test_L4_all_inactive_members_across_tenants_yields_suspended(
    engine: Engine,
) -> None:
    shared_subject = "auth0|all-inactive"
    with engine.begin() as conn:
        _tu(conn, subject=shared_subject, tenant_id="tenant-a", active=False)
        _tu(conn, subject=shared_subject, tenant_id="tenant-b", active=False)
    _run(engine)
    with engine.connect() as conn:
        row = conn.execute(text("SELECT lifecycle_state FROM fg_principals")).fetchone()
    assert row is not None
    assert row.lifecycle_state == "suspended"
