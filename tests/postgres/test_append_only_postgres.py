from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.db import set_tenant_context


def test_append_only_blocks_update_delete(pg_engine) -> None:
    with Session(pg_engine) as session:
        set_tenant_context(session, "tenant-a")
        decision_id = session.execute(
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
                    'evt-append-only',
                    'test',
                    '{}'::jsonb,
                    '{}'::jsonb
                )
                RETURNING id
                """
            ),
            {"tenant_id": "tenant-a"},
        ).scalar_one()
        session.execute(
            text(
                """
                INSERT INTO decision_evidence_artifacts (
                    tenant_id,
                    decision_id,
                    evidence_sha256,
                    storage_path,
                    payload_json
                )
                VALUES (
                    :tenant_id,
                    :decision_id,
                    'sha256',
                    '/tmp/evidence',
                    '{}'::jsonb
                )
                """
            ),
            {"tenant_id": "tenant-a", "decision_id": decision_id},
        )
        session.commit()

    with Session(pg_engine) as session:
        set_tenant_context(session, "tenant-a")
        with pytest.raises(SQLAlchemyError):
            session.execute(
                text(
                    "UPDATE decisions SET source = 'mutated' WHERE event_id = :event_id"
                ),
                {"event_id": "evt-append-only"},
            )
            session.commit()

    with Session(pg_engine) as session:
        set_tenant_context(session, "tenant-a")
        with pytest.raises(SQLAlchemyError):
            session.execute(
                text("DELETE FROM decisions WHERE event_id = :event_id"),
                {"event_id": "evt-append-only"},
            )
            session.commit()

    with Session(pg_engine) as session:
        set_tenant_context(session, "tenant-a")
        with pytest.raises(SQLAlchemyError):
            session.execute(
                text("UPDATE decision_evidence_artifacts SET storage_path = '/tmp/alt'")
            )
            session.commit()

    with Session(pg_engine) as session:
        set_tenant_context(session, "tenant-a")
        with pytest.raises(SQLAlchemyError):
            session.execute(text("DELETE FROM decision_evidence_artifacts"))
            session.commit()
