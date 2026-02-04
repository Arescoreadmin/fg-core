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


def test_tenant_rls_enforces_isolation(pg_engine) -> None:
    with Session(pg_engine) as session:
        _insert_decision(session, "tenant-a", "evt-tenant-a")
        _insert_decision(session, "tenant-b", "evt-tenant-b")
        session.commit()

    with Session(pg_engine) as session:
        set_tenant_context(session, "tenant-a")
        rows = session.execute(text("SELECT event_id FROM decisions")).fetchall()
        assert {row[0] for row in rows} == {"evt-tenant-a"}

    with Session(pg_engine) as session:
        set_tenant_context(session, "tenant-b")
        rows = session.execute(text("SELECT event_id FROM decisions")).fetchall()
        assert {row[0] for row in rows} == {"evt-tenant-b"}

    with Session(pg_engine) as session:
        rows = session.execute(text("SELECT event_id FROM decisions")).fetchall()
        assert rows == []
