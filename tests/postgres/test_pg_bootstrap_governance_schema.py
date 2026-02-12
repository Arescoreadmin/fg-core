from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

from api.db import set_tenant_context
from tests.postgres.pg_bootstrap import bootstrap_pg_for_tests


def test_pg_bootstrap_policy_change_requests_supports_governance_columns(
    pg_engine,
) -> None:
    bootstrap_pg_for_tests(pg_engine)

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
                    proposed_at,
                    justification,
                    rule_definition_json,
                    roe_update_json,
                    simulation_results_json,
                    requires_approval_from_json,
                    approvals_json,
                    status,
                    deployed_at
                ) VALUES (
                    :tenant_id,
                    :change_id,
                    :change_type,
                    :proposed_by,
                    now(),
                    :justification,
                    CAST(:rule_definition AS jsonb),
                    CAST(:roe_update AS jsonb),
                    CAST(:simulation_results AS jsonb),
                    CAST(:requires_approval_from AS jsonb),
                    CAST(:approvals AS jsonb),
                    :status,
                    NULL
                )
                """
            ),
            {
                "tenant_id": "tenant-a",
                "change_id": "pcr-bootstrap-a",
                "change_type": "add_rule",
                "proposed_by": "seed",
                "justification": "bootstrap-check",
                "rule_definition": '{"rule":"a"}',
                "roe_update": '{"roe":"a"}',
                "simulation_results": '{"ok": true}',
                "requires_approval_from": '["security-lead"]',
                "approvals": "[]",
                "status": "pending",
            },
        )
        session.commit()

    with Session(pg_engine) as session:
        set_tenant_context(session, "tenant-a")
        row = session.execute(
            text(
                """
                SELECT change_type, proposed_by, justification
                FROM policy_change_requests
                WHERE change_id = :change_id
                """
            ),
            {"change_id": "pcr-bootstrap-a"},
        ).one()

        assert row[0] == "add_rule"
        assert row[1] == "seed"
        assert row[2] == "bootstrap-check"
