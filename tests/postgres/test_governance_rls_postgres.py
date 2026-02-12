from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

from api.db import set_tenant_context


def test_governance_rls_blocks_cross_tenant_even_if_query_is_modified(
    pg_engine,
) -> None:
    with Session(pg_engine) as session:
        set_tenant_context(session, "tenant-a")
        session.execute(
            text(
                """
                INSERT INTO policy_change_requests (
                    tenant_id,
                    change_id,
                    change_type,
                    proposed_by,
                    justification,
                    simulation_results_json,
                    requires_approval_from_json,
                    approvals_json,
                    status
                ) VALUES (
                    'tenant-a',
                    'pcr-tenant-a',
                    'add_rule',
                    'seed',
                    'a',
                    '{}'::jsonb,
                    '[]'::jsonb,
                    '[]'::jsonb,
                    'pending'
                )
                """
            )
        )

        set_tenant_context(session, "tenant-b")
        session.execute(
            text(
                """
                INSERT INTO policy_change_requests (
                    tenant_id,
                    change_id,
                    change_type,
                    proposed_by,
                    justification,
                    simulation_results_json,
                    requires_approval_from_json,
                    approvals_json,
                    status
                ) VALUES (
                    'tenant-b',
                    'pcr-tenant-b',
                    'add_rule',
                    'seed',
                    'b',
                    '{}'::jsonb,
                    '[]'::jsonb,
                    '[]'::jsonb,
                    'pending'
                )
                """
            )
        )
        session.commit()

    with Session(pg_engine) as session:
        set_tenant_context(session, "tenant-a")
        rows = session.execute(
            text("SELECT tenant_id, change_id FROM policy_change_requests")
        ).fetchall()
        assert {(row[0], row[1]) for row in rows} == {("tenant-a", "pcr-tenant-a")}

    with Session(pg_engine) as session:
        set_tenant_context(session, "tenant-b")
        rows = session.execute(
            text("SELECT tenant_id, change_id FROM policy_change_requests")
        ).fetchall()
        assert {(row[0], row[1]) for row in rows} == {("tenant-b", "pcr-tenant-b")}
