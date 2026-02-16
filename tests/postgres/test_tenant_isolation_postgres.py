from __future__ import annotations

import hashlib
import json

from sqlalchemy import text
from sqlalchemy.orm import Session

from api.db import set_tenant_context


def _canonical_json_str(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _ensure_config_version(session: Session, tenant_id: str) -> str:
    set_tenant_context(session, tenant_id)

    config_obj = {"tenant": tenant_id, "purpose": "postgres-test"}
    canonical = _canonical_json_str(config_obj)
    config_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    session.execute(
        text(
            """
            INSERT INTO config_versions (
                tenant_id,
                config_hash,
                config_json_canonical,
                config_json
            )
            VALUES (
                :tenant_id,
                :config_hash,
                CAST(:config_json_canonical AS jsonb),
                CAST(:config_json AS jsonb)
            )
            ON CONFLICT (tenant_id, config_hash) DO NOTHING
            """
        ),
        {
            "tenant_id": tenant_id,
            "config_hash": config_hash,
            "config_json_canonical": canonical,
            "config_json": canonical,
        },
    )
    return config_hash


def _insert_decision(session: Session, tenant_id: str, event_id: str) -> None:
    set_tenant_context(session, tenant_id)
    config_hash = _ensure_config_version(session, tenant_id)
    session.execute(
        text(
            """
            INSERT INTO decisions (
                tenant_id,
                source,
                event_id,
                event_type,
                config_hash,
                request_json,
                response_json
            )
            VALUES (
                :tenant_id,
                'unit-test',
                :event_id,
                'test',
                :config_hash,
                '{}'::jsonb,
                '{}'::jsonb
            )
            """
        ),
        {"tenant_id": tenant_id, "event_id": event_id, "config_hash": config_hash},
    )


def _rls_diagnostics(session: Session) -> dict[str, object]:
    rls_rows = session.execute(
        text(
            """
            SELECT relname, relrowsecurity, relforcerowsecurity
            FROM pg_class
            WHERE relname IN (
                'decisions',
                'decision_evidence_artifacts',
                'api_keys',
                'security_audit_log',
                'policy_change_requests'
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
                'security_audit_log',
                'policy_change_requests'
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
        "policy_change_requests",
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
