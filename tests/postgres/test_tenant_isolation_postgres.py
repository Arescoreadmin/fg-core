from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

from api.db import set_tenant_context


def _insert_decision(session: Session, tenant_id: str, event_id: str) -> None:
    set_tenant_context(session, tenant_id)
    session.execute(
        text(
            """
            INSERT INTO decisions (
                tenant_id,
                source,
                event_id,
                event_type,
                request_json,
                response_json
            )
            VALUES (
                :tenant_id,
                'unit-test',
                :event_id,
                'test',
                '{}'::jsonb,
                '{}'::jsonb
            )
            """
        ),
        {"tenant_id": tenant_id, "event_id": event_id},
    )


def _rls_diagnostics(session: Session) -> dict[str, object]:
    """
    Diagnostic SQL queries (kept inline for auditability):
    1) RLS flags:
       SELECT relname, relrowsecurity, relforcerowsecurity
       FROM pg_class
       WHERE relname IN ('decisions','decision_evidence_artifacts','api_keys','security_audit_log');
    2) Policies:
       SELECT tablename, policyname, qual, with_check
       FROM pg_policies
       WHERE tablename IN ('decisions','decision_evidence_artifacts','api_keys','security_audit_log');
    3) Tenant setting after set_tenant_context:
       SELECT NULLIF(current_setting('app.tenant_id', true), '');
    4) Role bypass:
       SELECT rolname, rolsuper, rolbypassrls
       FROM pg_roles
       WHERE rolname = current_user;
    5) Row security setting:
       SHOW row_security;
    """
    rls_rows = session.execute(
        text(
            """
            SELECT relname, relrowsecurity, relforcerowsecurity
            FROM pg_class
            WHERE relname IN (
                'decisions',
                'decision_evidence_artifacts',
                'api_keys',
                'security_audit_log'
            )
            """
        )
    ).fetchall()
    policies = session.execute(
        text(
            """
            SELECT tablename, policyname, qual, with_check
            FROM pg_policies
            WHERE tablename IN (
                'decisions',
                'decision_evidence_artifacts',
                'api_keys',
                'security_audit_log'
            )
            """
        )
    ).fetchall()
    role_row = session.execute(
        text(
            """
            SELECT rolname, rolsuper, rolbypassrls
            FROM pg_roles
            WHERE rolname = current_user
            """
        )
    ).one()
    row_security = session.execute(text("SHOW row_security")).scalar_one()
    return {
        "rls": {(row[0], row[1], row[2]) for row in rls_rows},
        "policies": {(row[0], row[1]) for row in policies},
        "role": role_row,
        "row_security": row_security,
    }


def test_tenant_rls_diagnostics(pg_engine) -> None:
    with Session(pg_engine) as session:
        diagnostics = _rls_diagnostics(session)

    expected_tables = {
        "decisions",
        "decision_evidence_artifacts",
        "api_keys",
        "security_audit_log",
    }
    rls_tables = {row[0] for row in diagnostics["rls"]}
    assert rls_tables == expected_tables
    for row in diagnostics["rls"]:
        assert row[1] is True and row[2] is True

    policies = diagnostics["policies"]
    for table in expected_tables:
        assert (table, f"{table}_tenant_isolation") in policies

    role = diagnostics["role"]
    assert role[1] is False, f"role {role[0]} is superuser"
    assert role[2] is False, f"role {role[0]} bypasses RLS"
    assert str(diagnostics["row_security"]).lower() == "on"


def test_tenant_rls_enforces_isolation(pg_engine) -> None:
    with Session(pg_engine) as session:
        _insert_decision(session, "tenant-a", "evt-tenant-a")
        _insert_decision(session, "tenant-b", "evt-tenant-b")
        session.commit()

    with Session(pg_engine) as session:
        set_tenant_context(session, "tenant-a")
        current_tenant = session.execute(
            text("SELECT NULLIF(current_setting('app.tenant_id', true), '')")
        ).scalar_one()
        assert current_tenant == "tenant-a"
        rows = session.execute(text("SELECT event_id FROM decisions")).fetchall()
        assert {row[0] for row in rows} == {"evt-tenant-a"}

    with Session(pg_engine) as session:
        set_tenant_context(session, "tenant-b")
        current_tenant = session.execute(
            text("SELECT NULLIF(current_setting('app.tenant_id', true), '')")
        ).scalar_one()
        assert current_tenant == "tenant-b"
        rows = session.execute(text("SELECT event_id FROM decisions")).fetchall()
        assert {row[0] for row in rows} == {"evt-tenant-b"}

    with Session(pg_engine) as session:
        current_tenant = session.execute(
            text("SELECT NULLIF(current_setting('app.tenant_id', true), '')")
        ).scalar_one()
        assert current_tenant is None
        rows = session.execute(text("SELECT event_id FROM decisions")).fetchall()
        assert rows == []
