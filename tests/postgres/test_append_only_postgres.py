from __future__ import annotations

import hashlib
import json

import pytest
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.db import set_tenant_context

TEST_EVIDENCE_SHA256 = "1" * 64


def _canonical_json_str(obj: object) -> str:
    # Deterministic canonicalization: sorted keys, compact separators.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _ensure_config_version(session: Session, tenant_id: str) -> str:
    """
    Create a tenant-scoped config_versions row and return its config_hash.
    Satisfies decisions.config_hash NOT NULL + FK (fk_decisions_config_version)
    and config_versions.config_json_canonical NOT NULL.
    """
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
            "config_json": canonical,  # same payload; canonical is already compact+sorted
        },
    )
    return config_hash


def test_append_only_blocks_update_delete(pg_engine) -> None:
    with Session(pg_engine) as session:
        tenant_id = "tenant-a"
        set_tenant_context(session, tenant_id)
        config_hash = _ensure_config_version(session, tenant_id)

        decision_id = session.execute(
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
                    'evt-append-only',
                    'test',
                    :config_hash,
                    '{}'::jsonb,
                    '{}'::jsonb
                )
                RETURNING id
                """
            ),
            {"tenant_id": tenant_id, "config_hash": config_hash},
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
                    :evidence_sha256,
                    '/tmp/evidence',
                    '{}'::jsonb
                )
                """
            ),
            {
                "tenant_id": tenant_id,
                "decision_id": decision_id,
                "evidence_sha256": TEST_EVIDENCE_SHA256,
            },
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
