"""PostgreSQL enforcement tests for tenant identity governance evidence."""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from api.identity.store import emit_identity_audit_event, verify_identity_audit_chain


pytestmark = pytest.mark.skipif(
    not os.getenv("FG_DB_URL"), reason="FG_DB_URL not configured"
)


def _role_name() -> str:
    return f"fg_identity_rls_{uuid.uuid4().hex[:12]}"


def test_identity_tables_enforce_wrong_tenant_rls() -> None:
    engine = create_engine(os.environ["FG_DB_URL"], future=True)
    role = _role_name()
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql(f'CREATE ROLE "{role}" NOSUPERUSER NOBYPASSRLS')
            conn.exec_driver_sql(
                f"GRANT SELECT ON tenant_identity_configs, tenant_identity_providers, "
                f"tenant_identity_domains, tenant_identity_role_assignments, "
                f"tenant_invitations, tenant_identity_audit_events, "
                f'tenant_identity_auth_states, tenant_users TO "{role}"'
            )
        with engine.connect() as conn:
            conn.exec_driver_sql(f'SET ROLE "{role}"')
            conn.execute(text("SELECT set_config('app.tenant_id', 'demo-bank', false)"))
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM tenant_identity_configs WHERE tenant_id='demo-bank'"
                    )
                ).scalar_one()
                == 1
            )
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM tenant_identity_configs WHERE tenant_id='demo-healthcare'"
                    )
                ).scalar_one()
                == 0
            )
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM tenant_identity_audit_events WHERE tenant_id='demo-healthcare'"
                    )
                ).scalar_one()
                == 0
            )
    finally:
        with engine.begin() as conn:
            conn.exec_driver_sql(f'DROP OWNED BY "{role}"')
            conn.exec_driver_sql(f'DROP ROLE IF EXISTS "{role}"')


def test_identity_audit_events_reject_update_delete_and_timestamp_mutation() -> None:
    engine = create_engine(os.environ["FG_DB_URL"], future=True)
    event_id = "migration-0099-config-demo-bank"
    for statement in (
        "UPDATE tenant_identity_audit_events SET created_at=NOW() WHERE id=:event_id",
        "DELETE FROM tenant_identity_audit_events WHERE id=:event_id",
    ):
        with pytest.raises(DBAPIError):
            with engine.begin() as conn:
                conn.execute(text(statement), {"event_id": event_id})


def test_migrated_identity_audit_events_verify_end_to_end() -> None:
    engine = create_engine(os.environ["FG_DB_URL"], future=True)
    with Session(engine) as db:
        assert verify_identity_audit_chain(db, "demo-bank")
        assert verify_identity_audit_chain(db, "demo-healthcare")
        emit_identity_audit_event(
            db,
            tenant_id="demo-bank",
            event_type="tenant.identity_config.updated",
            actor_user_id="system:test",
            identity_mode="managed",
            provider="auth0",
            reason_code="MIGRATION_CHAIN_VERIFICATION",
        )
        db.commit()
        assert verify_identity_audit_chain(db, "demo-bank")


def test_identity_auth_state_forced_rls_constraints_and_expiry_index() -> None:
    engine = create_engine(os.environ["FG_DB_URL"], future=True)
    role = _role_name()
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenant_identity_auth_states(id,tenant_id,invitation_id,state_digest,correlation_id,expires_at) VALUES ('rls-state-bank','demo-bank','invite-bank',repeat('a',64),'corr-bank',NOW()+INTERVAL '5 minutes'),('rls-state-health','demo-healthcare','invite-health',repeat('b',64),'corr-health',NOW()+INTERVAL '5 minutes') ON CONFLICT DO NOTHING"
                )
            )
            flags = conn.execute(
                text(
                    "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname='tenant_identity_auth_states'"
                )
            ).one()
            assert flags == (True, True)
            constraints = {
                row[0]
                for row in conn.execute(
                    text(
                        "SELECT conname FROM pg_constraint WHERE conrelid='tenant_identity_auth_states'::regclass"
                    )
                )
            }
            assert {
                "uq_tenant_identity_auth_state_digest",
                "uq_tenant_identity_auth_state_correlation",
            }.issubset(constraints)
            indexes = {
                row[0]
                for row in conn.execute(
                    text(
                        "SELECT indexname FROM pg_indexes WHERE tablename='tenant_identity_auth_states'"
                    )
                )
            }
            assert "ix_tenant_identity_auth_state_tenant_expiry" in indexes
            conn.exec_driver_sql(f'CREATE ROLE "{role}" NOSUPERUSER NOBYPASSRLS')
            conn.exec_driver_sql(
                f'GRANT SELECT ON tenant_identity_auth_states TO "{role}"'
            )
        with engine.connect() as conn:
            conn.exec_driver_sql(f'SET ROLE "{role}"')
            conn.execute(text("SELECT set_config('app.tenant_id', 'demo-bank', false)"))
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM tenant_identity_auth_states WHERE tenant_id='demo-bank'"
                    )
                ).scalar_one()
                == 1
            )
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM tenant_identity_auth_states WHERE tenant_id='demo-healthcare'"
                    )
                ).scalar_one()
                == 0
            )
    finally:
        with engine.begin() as conn:
            conn.exec_driver_sql(f'DROP OWNED BY "{role}"')
            conn.exec_driver_sql(f'DROP ROLE IF EXISTS "{role}"')
