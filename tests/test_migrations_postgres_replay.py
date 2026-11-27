from __future__ import annotations

import contextlib
import hashlib
import os
import pathlib
import sys
import uuid

import pytest
from typing import Any
from sqlalchemy import create_engine, text

from api.db_migrations import (
    apply_migrations,
    assert_migrations_applied,
    migration_status,
)
from api.db_models import Base
import api.db_models_field_assessment  # noqa: F401 — registers FA ORM tables on Base

_MIGRATIONS_DIR = pathlib.Path(__file__).parent.parent / "migrations" / "postgres"


def test_postgres_migrations_replay_safe() -> None:
    db_url = os.getenv("FG_DB_URL")
    if not db_url:
        print(
            "SKIP tests/test_migrations_postgres_replay.py: FG_DB_URL not configured",
            file=sys.stderr,
        )
        pytest.skip("FG_DB_URL not configured")

    engine = create_engine(db_url, future=True)

    # FA tables are ORM-managed (not created by SQL migrations) — must exist before
    # SQL patches like ALTER TABLE fa_engagements run.
    Base.metadata.create_all(engine)

    schema_hash_before = _schema_signature(engine)
    print(f"schema_hash_before={schema_hash_before}")

    applied_first = apply_migrations(engine)
    assert applied_first, (
        "Expected first migration apply to mutate a clean CI DB. "
        f"Current status: {migration_status(engine)}"
    )

    schema_hash_first = _schema_signature(engine)
    print(f"schema_hash_after_first_apply={schema_hash_first}")

    applied_second = apply_migrations(engine)
    assert applied_second == []
    assert_migrations_applied(engine)

    schema_hash_second = _schema_signature(engine)
    print(f"schema_hash_after_replay={schema_hash_second}")
    assert schema_hash_second == schema_hash_first


# ─────────────────────────────────────────────────────────────────────────────
# Migration 0161 orphan-filtering regression tests (A–H)
#
# These tests verify that the canonical-tenant JOIN predicate in
# 0161_portal_access_migration.sql correctly filters orphaned portal_grants
# (those whose tenant_id has no row in the tenants table) without failing the
# migration, deleting source rows, or creating synthetic tenants.
#
# Each test runs inside a rolled-back transaction so it leaves the DB pristine.
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def _mig_engine():
    db_url = os.getenv("FG_DB_URL")
    if not db_url:
        pytest.skip("FG_DB_URL not configured")
    engine = create_engine(db_url, future=True)
    # ORM tables must precede SQL migration patches (mirrors the full replay test).
    Base.metadata.create_all(engine)
    apply_migrations(engine)  # idempotent — no-op if already applied
    yield engine
    engine.dispose()


@pytest.fixture
def _tx(_mig_engine):
    """Per-test rolled-back transaction — leaves no persistent test data."""
    with _mig_engine.connect() as conn:
        trans = conn.begin()
        try:
            yield conn
        finally:
            trans.rollback()


def _run_migration_body(conn, filename: str) -> None:
    """Execute every SQL statement in a migration file, skipping BEGIN/COMMIT.

    Single-line comments are stripped before splitting on semicolons to avoid
    false splits on semicolons embedded in comment text.
    """
    sql = (_MIGRATIONS_DIR / filename).read_text()
    # Strip single-line comments first — they may contain semicolons that
    # would falsely split a statement (e.g. "-- valid UUID; gen_random_uuid()").
    sql = "\n".join(ln for ln in sql.splitlines() if not ln.strip().startswith("--"))
    for raw in sql.split(";"):
        stmt = raw.strip()
        if not stmt or stmt.upper() in ("BEGIN", "COMMIT"):
            continue
        conn.execute(text(stmt))


def _uid(prefix: str = "t") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


def _insert_tenant(conn, tenant_id: str) -> None:
    conn.execute(
        text(
            "INSERT INTO tenants (tenant_id, display_name, lifecycle_state)"
            " VALUES (:tid, :dn, 'active') ON CONFLICT DO NOTHING"
        ),
        {"tid": tenant_id, "dn": f"Test {tenant_id}"},
    )


def _insert_portal_grant(
    conn,
    *,
    grant_id: str,
    tenant_id: str,
    client_id: str = "test-client",
    engagement_id: str = "test-eng",
) -> None:
    conn.execute(
        text(
            """
            INSERT INTO portal_grants
                (id, tenant_id, client_id, engagement_id, grant_type,
                 grant_hash, created_by, created_at, expires_at,
                 status, rotation_counter)
            VALUES
                (:id, :tid, :cid, :eid, 'client_portal',
                 'sentinel-not-for-auth', 'test-actor',
                 now()::text, (now() + interval '14 days')::text,
                 'active', 0)
            """
        ),
        {"id": grant_id, "tid": tenant_id, "cid": client_id, "eid": engagement_id},
    )


def _credential_row_exists(conn, grant_id: str) -> bool:
    row = conn.execute(
        text("SELECT 1 FROM tenant_credentials WHERE idempotency_key = :k"),
        {"k": f"legacy-migration:{grant_id}"},
    ).fetchone()
    return row is not None


def _slot_row_exists(
    conn, tenant_id: str, client_id: str, engagement_id: str, grant_id: str
) -> bool:
    slot = f"legacy:{client_id}:{engagement_id}:{grant_id}"
    row = conn.execute(
        text(
            "SELECT 1 FROM credential_slots"
            " WHERE tenant_id = :tid AND credential_slot = :slot"
        ),
        {"tid": tenant_id, "slot": slot},
    ).fetchone()
    return row is not None


def _portal_grant_exists(conn, grant_id: str) -> bool:
    row = conn.execute(
        text("SELECT 1 FROM portal_grants WHERE id = :id"),
        {"id": grant_id},
    ).fetchone()
    return row is not None


# A — canonical grant (tenant exists in tenants) migrates to tenant_credentials
def test_0161_a_canonical_grant_migrates(_tx) -> None:
    tid = _uid("tenant")
    gid = _uid("grant")
    _insert_tenant(_tx, tid)
    _insert_portal_grant(_tx, grant_id=gid, tenant_id=tid)
    _run_migration_body(_tx, "0161_portal_access_migration.sql")
    assert _credential_row_exists(_tx, gid), (
        "Canonical grant must appear in tenant_credentials"
    )
    assert _slot_row_exists(_tx, tid, "test-client", "test-eng", gid), (
        "Canonical grant must appear in credential_slots"
    )


# B — orphaned grant (tenant absent from tenants) is silently excluded
def test_0161_b_orphan_grant_excluded(_tx) -> None:
    gid = _uid("orphan")
    _insert_portal_grant(_tx, grant_id=gid, tenant_id="test-absent-tenant-b")
    _run_migration_body(_tx, "0161_portal_access_migration.sql")
    assert not _credential_row_exists(_tx, gid), (
        "Orphaned grant must not appear in tenant_credentials"
    )


# C — orphan does not abort or error the migration
def test_0161_c_orphan_does_not_abort(_tx) -> None:
    gid = _uid("orphan")
    _insert_portal_grant(_tx, grant_id=gid, tenant_id="test-absent-tenant-c")
    _run_migration_body(_tx, "0161_portal_access_migration.sql")  # must not raise


# D — source portal_grant row is NOT deleted or modified by the migration
def test_0161_d_source_row_survives(_tx) -> None:
    tid = _uid("tenant")
    gid = _uid("grant")
    _insert_tenant(_tx, tid)
    _insert_portal_grant(_tx, grant_id=gid, tenant_id=tid)
    _run_migration_body(_tx, "0161_portal_access_migration.sql")
    assert _portal_grant_exists(_tx, gid), (
        "Source portal_grant row must survive the migration"
    )


# E — mixed dataset: canonical migrates, orphan is skipped
def test_0161_e_mixed_dataset(_tx) -> None:
    tid = _uid("tenant")
    canonical_gid = _uid("canon")
    orphan_gid = _uid("orphan")
    _insert_tenant(_tx, tid)
    _insert_portal_grant(_tx, grant_id=canonical_gid, tenant_id=tid, client_id="c1")
    _insert_portal_grant(_tx, grant_id=orphan_gid, tenant_id="test-absent-tenant-e")
    _run_migration_body(_tx, "0161_portal_access_migration.sql")
    assert _credential_row_exists(_tx, canonical_gid), "Canonical grant must migrate"
    assert not _credential_row_exists(_tx, orphan_gid), "Orphan grant must not migrate"


# F — replay is idempotent: re-running 0161 produces exactly one row per grant
def test_0161_f_idempotent_replay(_tx) -> None:
    tid = _uid("tenant")
    gid = _uid("grant")
    _insert_tenant(_tx, tid)
    _insert_portal_grant(_tx, grant_id=gid, tenant_id=tid)
    _run_migration_body(_tx, "0161_portal_access_migration.sql")
    _run_migration_body(_tx, "0161_portal_access_migration.sql")  # second pass
    count = _tx.execute(
        text("SELECT COUNT(*) FROM tenant_credentials WHERE idempotency_key = :k"),
        {"k": f"legacy-migration:{gid}"},
    ).scalar()
    assert count == 1, (
        f"Expected exactly 1 tenant_credentials row after replay, got {count}"
    )


# G — foreign-key constraint on credential_slots.tenant_id is still enforced
def test_0161_g_fk_integrity_enforced(_tx) -> None:
    sp = _tx.begin_nested()
    caught: Exception | None = None
    try:
        _tx.execute(
            text(
                "INSERT INTO credential_slots"
                " (tenant_id, credential_type, credential_slot, current_generation, rotation_policy)"
                " VALUES ('nonexistent-fk-test-g', 'portal_access', 'legacy:fk:fk:fk', 1, 'immediate')"
            )
        )
        sp.commit()
    except Exception as exc:
        sp.rollback()
        caught = exc
    assert caught is not None, "Expected FK violation but no exception was raised"
    msg = str(caught).lower()
    assert "foreign key" in msg or "violates" in msg, f"Unexpected exception: {caught}"


# H — migration does not insert synthetic tenants as a side-effect
def test_0161_h_no_synthetic_tenants(_tx) -> None:
    count_before = _tx.execute(text("SELECT COUNT(*) FROM tenants")).scalar()
    gid = _uid("orphan")
    _insert_portal_grant(_tx, grant_id=gid, tenant_id="test-absent-tenant-h")
    _run_migration_body(_tx, "0161_portal_access_migration.sql")
    count_after = _tx.execute(text("SELECT COUNT(*) FROM tenants")).scalar()
    assert count_after == count_before, (
        f"Migration must not create synthetic tenants; tenants count changed"
        f" from {count_before} to {count_after}"
    )


def _schema_signature(engine) -> str:
    with engine.begin() as conn:
        tables = conn.execute(
            text(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                ORDER BY table_name
                """
            )
        ).fetchall()
        columns = conn.execute(
            text(
                """
                SELECT table_name, column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_schema = 'public'
                ORDER BY table_name, ordinal_position
                """
            )
        ).fetchall()
        indexes = conn.execute(
            text(
                """
                SELECT schemaname, tablename, indexname, indexdef
                FROM pg_indexes
                WHERE schemaname = 'public'
                ORDER BY tablename, indexname
                """
            )
        ).fetchall()
        policies = conn.execute(
            text(
                """
                SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
                FROM pg_policies
                WHERE schemaname = 'public'
                ORDER BY tablename, policyname
                """
            )
        ).fetchall()

    payload = repr((tables, columns, indexes, policies)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def test_postgres_runtime_evidence_round_trip(_tx) -> None:
    """L14-SCAN-RUNNER-INTEGRITY-001: runtime evidence capture on real Postgres.

    Schema built exactly like production init_db(): ORM create_all() then the
    numbered migrations (the ``_mig_engine`` fixture).  Exercises the ORM/psycopg
    binding of the schema-tolerant UUID / TIMESTAMPTZ / collection-status columns
    (job + finding inserts, envelope insert, finding updates), the raw custody
    insert, stored-evidence verification, the evidence manifest and the 0204
    immutability trigger.  Runs in the per-test rolled-back transaction.
    """
    from sqlalchemy.orm import Session

    from api.db_models_field_assessment import (
        FaEngagement,
        FaNormalizedFinding,
        FaScanEvidenceEnvelope,
        FaScanJob,
    )
    from services.field_assessment import runtime_evidence as rte
    from services.field_assessment.connectors.web_headers_bridge import (
        import_web_headers_scan,
    )
    from services.field_assessment.evidence_integrity import ProvenanceStatus

    db = Session(bind=_tx, join_transaction_mode="create_savepoint")
    try:
        tenant = _uid("pg-rte")
        eid = uuid.uuid4().hex
        now = "2026-11-08T00:00:00+00:00"
        db.add(
            FaEngagement(
                id=eid,
                tenant_id=tenant,
                client_name="Synthetic PG",
                assessor_id="a",
                assessment_type="ai_governance",
                created_at=now,
                updated_at=now,
            )
        )
        db.flush()
        auth_id = _tx.execute(
            text(
                "INSERT INTO fa_scan_authorizations (tenant_id, engagement_id, "
                "authorization_ref, approved_targets, status, expires_at) VALUES "
                "(:t, :e, 'ROE-SYNTH', '[]'::jsonb, 'active', NOW() + interval '1 day') "
                "RETURNING id"
            ),
            {"t": tenant, "e": eid},
        ).scalar_one()
        job_id = str(uuid.uuid4())
        # collection_status left unset: must not bind NULL::VARCHAR into an enum.
        db.add(
            FaScanJob(
                id=job_id,
                tenant_id=tenant,
                engagement_id=eid,
                verified_target_ids="[]",
                scanner_type="web_headers",
                status="running",
                attempt_count=1,
                max_retries=3,
                actor="a",
                created_at=now,
            )
        )
        db.flush()
        payload = {
            "targets": [
                {
                    "url": "https://app.example.com",
                    "collection_status": "COMPLETE",
                    "error": None,
                }
            ],
            "findings": [
                {
                    "type": "missing_hsts",
                    "severity": "high",
                    "title": "t",
                    "description": "d",
                    "target": "app.example.com",
                }
            ],
            "collection_status": "COMPLETE",
            "authorization_context": {
                "tenant_id": tenant,
                "engagement_id": eid,
                "scan_job_id": job_id,
                "scanner_type": "web_headers",
                "authorization_id": str(auth_id),
                "authorization_version": 1,
                "customer_receipt_id": None,
                "proof_level": "LEGACY_OPERATOR_ASSERTED",
            },
        }
        sr = import_web_headers_scan(
            db=db, tenant_id=tenant, engagement_id=eid, scan_result=payload, actor="a"
        ).scan_result_id
        res = rte.capture_with_retry(
            db,
            tenant_id=tenant,
            engagement_id=eid,
            scan_result_id=sr,
            scanner_id="web_headers",
            scan_job_id=job_id,
        )
        assert res.created == 2 and res.findings_linked == 1
        db.flush()
        envs = db.query(FaScanEvidenceEnvelope).filter_by(tenant_id=tenant).all()
        assert {e.scan_job_id for e in envs} == {job_id}
        assert {e.authorization_ref for e in envs} == {str(auth_id)}
        (finding,) = db.query(FaNormalizedFinding).filter_by(tenant_id=tenant).all()
        assert finding.collection_status == "COMPLETE"
        assert finding.confidence_level == "CONFIRMED"
        status = rte.verify_stored_evidence(
            db, tenant_id=tenant, evidence_id=res.scan_envelope_id, record_custody=True
        )
        assert status == ProvenanceStatus.VERIFIED_INTEGRITY_ONLY
        manifest = rte.build_evidence_manifest(db, tenant_id=tenant, engagement_id=eid)
        assert (
            manifest["findings"][0]["evidence_integrity_status"] == "INTEGRITY_VERIFIED"
        )
        db.flush()
        # 0204 trigger: the captured digest is immutable at the database level.
        with pytest.raises(Exception, match="immutable"):
            with _tx.begin_nested():
                _tx.execute(
                    text(
                        "UPDATE fa_scan_evidence_envelopes SET payload_digest = 'sha256:x' "
                        "WHERE id = :i"
                    ),
                    {"i": res.scan_envelope_id},
                )
    finally:
        db.close()


class _TxEngine:
    """Engine-shaped adapter bound to the per-test transaction.

    TenantRepository and the lifecycle authority open ``engine.begin()`` /
    ``engine.connect()``; here those become SAVEPOINTs on the rolled-back test
    connection, so the canonical code runs unmodified and leaves no data.
    """

    def __init__(self, conn) -> None:
        self._conn = conn
        self.dialect = conn.dialect

    @contextlib.contextmanager
    def begin(self):
        with self._conn.begin_nested():
            yield self._conn

    @contextlib.contextmanager
    def connect(self):
        yield self._conn


def test_customer_zero_postgres_provisioning_and_authorization(_tx) -> None:
    """L14-CUSTOMER-ZERO-E2E-001: the Postgres-only steps of the customer journey.

    The SQLite acceptance harness (tests/test_customer_zero_e2e/) cannot run
    these canonical authorities, so they are exercised here on real Postgres:

    1. Tenant provisioning through the R7 tenant repository.
    2. Lifecycle enforcement (R3): suspend → credential validation not
       permitted → activate; transitions recorded.
    3. Customer scan authorization (#812): receipt request; approval refused
       for an API-key customer admin, the requester, and a platform operator;
       approval by a SIMULATED interactive customer identity (no real OIDC
       token — the ActorContext is constructed); double approval refused;
       revocation.
    4. Execution-time check fails closed with no approved scope.
    """
    from datetime import datetime, timedelta, timezone

    from sqlalchemy.orm import Session

    from api.actor_context import ActorContext, roles_to_permissions
    from api.credential_authority import _LIFECYCLE_POLICY
    from api.tenant_lifecycle import execute_transition, get_transition_history
    from api.tenant_repository import TenantRepository
    from services.field_assessment import customer_authorization as ca
    from services.field_assessment.scan_authorization import (
        ScanAuthorizationError,
        check_scan_authorized,
    )

    eng: Any = _TxEngine(_tx)  # Engine-shaped; see _TxEngine
    tenant = _uid("synthetic-northstar-pg")

    # 1 + 2 — provisioning and lifecycle through the canonical authorities.
    repo = TenantRepository(eng)
    created = repo.create(
        tenant_id=tenant,
        display_name="SYNTHETIC — Northstar Manufacturing Group",
        created_by="customer-zero-e2e",
        migration_source="api",
    )
    assert created.tenant_id == tenant
    assert repo.get_lifecycle_state_on_conn(_tx, tenant) == "active"
    execute_transition(
        eng,
        tenant_id=tenant,
        to_state="suspended",
        reason="cz-e2e",
        actor_id="platform",
    )
    state = repo.get_lifecycle_state_on_conn(_tx, tenant)
    assert state == "suspended"
    assert _LIFECYCLE_POLICY[state]["validate"] is False  # credentials stop validating
    execute_transition(
        eng, tenant_id=tenant, to_state="active", reason="cz-e2e", actor_id="platform"
    )
    assert repo.get_lifecycle_state_on_conn(_tx, tenant) == "active"
    history = get_transition_history(eng, tenant)
    assert [h.to_state for h in history][:2] == ["active", "suspended"]

    # 3 — customer scan authorization receipt.
    db = Session(bind=_tx, join_transaction_mode="create_savepoint")
    try:
        from api.db_models_field_assessment import FaEngagement

        engagement_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc)
        db.add(
            FaEngagement(
                id=engagement_id,
                tenant_id=tenant,
                client_name="SYNTHETIC — Northstar Manufacturing Group",
                assessor_id="assessor-subject",
                assessment_type="comprehensive",
                created_at=now.isoformat(),
                updated_at=now.isoformat(),
            )
        )
        db.flush()
        receipt = ca.create_request(
            db,
            tenant_id=tenant,
            engagement_id=engagement_id,
            requested_by_subject="assessor-subject",
            customer_org_name="SYNTHETIC — Northstar Manufacturing Group",
            assessment_purpose="External attack surface assessment (synthetic)",
            rules_of_engagement_ref="ROE-NSM-2026-001",
            approved_targets=[
                {
                    "target": "www.northstar-mfg.example",
                    "type": "fqdn",
                    "operations": ["web_headers"],
                }
            ],
            authorized_operations=["web_headers"],
            window_start=now - timedelta(hours=1),
            window_end=now + timedelta(days=7),
        )
        assert receipt["status"] == "pending_approval"

        def actor(
            subject: str, roles: list[str], auth_source: str, *, verified: bool = True
        ) -> ActorContext:
            return ActorContext(
                subject=subject,
                email=f"{subject}@northstar-mfg.example",
                name=subject,
                permissions=roles_to_permissions(roles),
                roles=roles,
                auth_source=auth_source,
                tenant_id=tenant,
                email_verified=verified,
            )

        refused = {
            "api_key_customer_admin": actor("csa-key", ["tenant_admin"], "api_key"),
            "requester": actor("assessor-subject", ["tenant_admin"], "oidc_auth0"),
            "platform_operator": actor(
                "ops", ["platform_admin", "tenant_admin"], "oidc_auth0"
            ),
            "unverified_email": actor(
                "csa-unverified",
                ["client_security_owner"],
                "oidc_auth0",
                verified=False,
            ),
        }
        for label, who in refused.items():
            with pytest.raises(ca.CustomerAuthorizationError):
                ca.approve(
                    db,
                    receipt_id=str(receipt["id"]),
                    tenant_id=tenant,
                    engagement_id=engagement_id,
                    actor_ctx=who,
                )
            current = ca.load_receipt(
                db,
                receipt_id=str(receipt["id"]),
                tenant_id=tenant,
                engagement_id=engagement_id,
            )
            assert current is not None and current["status"] == "pending_approval", (
                label
            )

        approver = actor(
            "csa-northstar", ["client_security_owner"], "oidc_auth0"
        )  # simulated IdP identity
        approved = ca.approve(
            db,
            receipt_id=str(receipt["id"]),
            tenant_id=tenant,
            engagement_id=engagement_id,
            actor_ctx=approver,
        )
        assert approved["status"] == "approved"
        assert approved["approver_subject"] == "csa-northstar"
        assert approved["payload_digest"] and approved["proof_level"]
        with pytest.raises(ca.CustomerAuthorizationError):
            ca.approve(
                db,
                receipt_id=str(receipt["id"]),
                tenant_id=tenant,
                engagement_id=engagement_id,
                actor_ctx=approver,
            )

        # 4 — no approved scope record exists: execution check fails closed.
        with pytest.raises(ScanAuthorizationError):
            check_scan_authorized(
                db,
                tenant_id=tenant,
                engagement_id=engagement_id,
                target="www.northstar-mfg.example",
                target_type="fqdn",
                operation="web_headers",
            )

        revoked = ca.revoke(
            db,
            receipt_id=str(receipt["id"]),
            tenant_id=tenant,
            engagement_id=engagement_id,
            revoked_by_subject="csa-northstar",
            reason="customer-zero acceptance complete",
        )
        assert revoked["status"] == "revoked"
    finally:
        db.close()


def test_assessment_assurance_postgres_qa_and_provenance(_tx) -> None:
    """L14-ASSESSMENT-ASSURANCE-001 on real Postgres.

    1. Migration 0205: one governance-stage QA decision per (tenant, report,
       stage) — a second decision (approve after reject) is refused by the DB.
    2. Reviewer identity resolution binds string subjects / principal ids
       against the real tenant_users / fg_principals column types.
    3. Material-contribution lookup and QA standing queries bind correctly.
    4. The canonical provenance evaluator runs (empty engagement → absent,
       never trusted).
    """
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import Session

    from api.actor_context import ActorContext, roles_to_permissions
    from api.db_models import TenantUser
    from api.db_models_field_assessment import FaEngagement, FaReportQaDecision
    from api.db_models_principal import FgPrincipal
    from services.field_assessment import assessment_assurance as aa
    from services.field_assessment.audit import emit_engagement_audit_event

    idx = _tx.execute(
        text(
            "SELECT indexdef FROM pg_indexes "
            "WHERE indexname = 'uq_fa_report_qa_decisions_governance_stage'"
        )
    ).scalar_one()
    assert "UNIQUE" in idx and "report_version_id IS NULL" in idx

    tenant = _uid("assurance-pg")
    _insert_tenant(_tx, tenant)
    db = Session(bind=_tx, join_transaction_mode="create_savepoint")
    eid = uuid.uuid4().hex
    now = "2026-11-09T00:00:00Z"
    db.add(
        FaEngagement(
            id=eid,
            tenant_id=tenant,
            client_name="SYNTHETIC — assurance",
            assessor_id="a",
            assessment_type="comprehensive",
            status="in_progress",
            engagement_metadata={},
            created_at=now,
            updated_at=now,
        )
    )
    db.flush()

    def _decision(decision: str) -> None:
        db.add(
            FaReportQaDecision(
                id=uuid.uuid4().hex,
                tenant_id=tenant,
                engagement_id=eid,
                report_id="report-1",
                report_version_id=None,
                report_version=1,
                qa_stage="governance",
                decision=decision,
                reviewer_id="auth0|qa",
                actor_type="human",
                created_at=now,
            )
        )
        db.flush()

    _decision("rejected")
    with db.begin_nested():
        try:
            _decision("approved")
        except IntegrityError:
            pass
        else:  # pragma: no cover
            raise AssertionError("0205 did not refuse a second governance decision")
    assert aa.governance_qa_status(
        db, tenant_id=tenant, engagement_id=eid, report_id="report-1"
    ) == {"rejected": True, "independent_approval": False}

    principal = FgPrincipal(display_name="Pat Example")
    db.add(principal)
    db.flush()
    for i, sub in enumerate(("auth0|pat", "entra|pat")):
        db.add(
            TenantUser(
                tenant_id=tenant,
                email=f"pat{i}@example.test",
                display_name="Pat",
                role="assessor",
                identity_subject=sub,
                identity_binding_status="bound",
                principal_id=principal.id,
            )
        )
    db.flush()
    ids = aa.reviewer_identity_set(db, tenant_id=tenant, subject="entra|pat")
    assert {"auth0|pat", "entra|pat", f"principal:{principal.id}"} <= ids

    emit_engagement_audit_event(
        db,
        tenant_id=tenant,
        engagement_id=eid,
        event_type="engagement_report_created",
        actor="auth0|pat",
        reason_code="ENGAGEMENT_REPORT_CREATED",
        payload={},
    )
    actor = ActorContext(
        subject="entra|pat",
        email="pat@example.test",
        name="Pat",
        permissions=roles_to_permissions(["qa_reviewer"]),
        roles=["qa_reviewer"],
        auth_source="oidc_entra",
        tenant_id=tenant,
    )
    try:
        aa.enforce_independent_reviewer(
            db, actor_ctx=actor, tenant_id=tenant, engagement_id=eid
        )
    except aa.AssuranceDenied as exc:
        assert exc.code == "REPORT_QA_SELF_REVIEW"
    else:  # pragma: no cover
        raise AssertionError("same principal via second provider was accepted")

    d = aa.evaluate_engagement_provenance(db, tenant_id=tenant, engagement_id=eid)
    assert d.evidence_absent and d.to_trust_inputs().chain_valid is False
    db.close()


# ─────────────────────────────────────────────────────────────────────────────
# L14-ASSURANCE-P1-REPAIR-001 — RLS tenant context across report-access commits
#
# The CI service user is a superuser and bypasses RLS, so these tests create
# a NOSUPERUSER / NOBYPASSRLS login role (as production's restricted runtime
# role) and use REAL commits: a savepoint-wrapped "commit" would keep the
# transaction-local app.tenant_id alive and give a false green.  A control
# assertion proves RLS is actually enforced for the probe role.
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def _rls_probe(_mig_engine):
    """Restricted runtime role + synthetic report rows; dropped afterwards."""
    from sqlalchemy.engine import make_url
    from sqlalchemy.orm import sessionmaker

    role = f"fg_rls_probe_{uuid.uuid4().hex[:10]}"
    password = uuid.uuid4().hex
    tenant, other = _uid("rls-a"), _uid("rls-b")
    ids: dict[str, str] = {}
    with _mig_engine.begin() as su:
        su.execute(
            text(
                f"CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS"
            )
        )
        su.execute(text(f"GRANT USAGE ON SCHEMA public TO {role}"))
        su.execute(
            text(
                f"GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO {role}"
            )
        )
        su.execute(
            text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}")
        )
        for t in (tenant, other):
            _insert_tenant(su, t)
            eid, rid = uuid.uuid4().hex, uuid.uuid4().hex[:32]
            ids[t] = rid
            ids[f"{t}:eng"] = eid
            su.execute(
                text(
                    "INSERT INTO fa_engagements (id, tenant_id, client_name, assessor_id,"
                    " assessment_type, status, engagement_metadata, schema_version,"
                    " created_at, updated_at) VALUES (:e, :t, 'SYNTHETIC', 'a',"
                    " 'comprehensive', 'in_progress', '{}', '1.0',"
                    " '2026-11-10T00:00:00Z', '2026-11-10T00:00:00Z')"
                ),
                {"e": eid, "t": t},
            )
            su.execute(
                text(
                    "INSERT INTO governance_reports (id, assessment_id, tenant_id,"
                    " engagement_id, version, schema_version, manifest_hash,"
                    " report_json, generated_at, is_finalized) VALUES (:r, :e, :t, :e,"
                    " 1, '1.0', :h, '{}', '2026-11-10T00:00:00Z', true)"
                ),
                {"r": rid, "e": eid, "t": t, "h": f"hash-{t}"},
            )
    url = make_url(str(_mig_engine.url)).set(username=role, password=password)
    engine = create_engine(url, future=True)
    # Same settings as api.db.get_sessionmaker (expire_on_commit defaults True).
    sm = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
    try:
        yield sm, tenant, other, ids
    finally:
        engine.dispose()
        with _mig_engine.begin() as su:
            su.execute(text(f"DROP OWNED BY {role}"))
            su.execute(text(f"DROP ROLE {role}"))


def _bind(db, tenant: str) -> None:
    from api.db import set_tenant_context

    set_tenant_context(db, tenant)  # exactly what auth_ctx_db_session does


def test_rls_probe_role_really_enforces_forced_rls(_rls_probe) -> None:
    """Control: without the repair, a post-commit reload is hidden by RLS."""
    from sqlalchemy.orm.exc import ObjectDeletedError

    from api.db_models_governance_report import GovernanceReportRecord

    sm, tenant, other, ids = _rls_probe
    db = sm()
    try:
        _bind(db, tenant)
        rec = db.get(GovernanceReportRecord, ids[tenant])
        assert rec is not None
        assert db.get(GovernanceReportRecord, ids[other]) is None  # isolation
        db.commit()  # context cleared, rec expired
        with pytest.raises(ObjectDeletedError):
            _ = rec.manifest_hash
    finally:
        db.rollback()
        db.close()


@pytest.mark.parametrize("allowed", [True, False])
def test_report_access_audit_commit_preserves_tenant_context(
    _rls_probe, allowed: bool
) -> None:
    """Codex P1: the access-audit commit must not break the rest of the request."""
    from types import SimpleNamespace

    from fastapi import HTTPException
    from sqlalchemy import select

    import api.field_assessment as fa
    from api.actor_context import ActorContext, roles_to_permissions
    from api.db_models_field_assessment import FaEngagement, FaEngagementAuditEvent
    from api.db_models_governance_report import GovernanceReportRecord

    sm, tenant, other, ids = _rls_probe
    db = sm()
    try:
        _bind(db, tenant)
        rec = db.get(GovernanceReportRecord, ids[tenant])
        eng = db.get(FaEngagement, ids[f"{tenant}:eng"])
        role = "assessor" if allowed else "client_executive"
        actor = ActorContext(
            subject=f"auth0|{role}",
            email="",
            name="",
            permissions=roles_to_permissions([role]),
            roles=[role],
            auth_source="oidc_auth0",
            tenant_id=tenant,
        )
        req: Any = SimpleNamespace(headers={}, state=SimpleNamespace(request_id="rls"))
        if allowed:
            fa._enforce_report_content_access(
                db,
                request=req,
                actor_ctx=actor,
                engagement=eng,
                record=rec,
                report_state={"state": "DRAFT"},
                channel="export:json",
            )
            # The caller's subsequent reads succeed under the same tenant.
            assert rec.manifest_hash == f"hash-{tenant}"
            assert eng.client_name == "SYNTHETIC"
        else:
            with pytest.raises(HTTPException) as exc:
                fa._enforce_report_content_access(
                    db,
                    request=req,
                    actor_ctx=actor,
                    engagement=eng,
                    record=rec,
                    report_state={"state": "DRAFT"},
                    channel="export:json",
                )
            assert exc.value.status_code == 403
        bound = db.execute(
            text("SELECT current_setting('app.tenant_id', true)")
        ).scalar()
        assert bound == tenant  # re-bound to the server-resolved tenant only
        # Isolation intact after the re-bind: the other tenant stays invisible.
        assert db.get(GovernanceReportRecord, ids[other]) is None
        db.rollback()
    finally:
        db.close()
    # The access decision was durably committed (and only for this tenant).
    check = sm()
    try:
        _bind(check, tenant)
        events = (
            check.execute(
                select(FaEngagementAuditEvent.event_type).where(
                    FaEngagementAuditEvent.entity_id == ids[tenant]
                )
            )
            .scalars()
            .all()
        )
        assert (
            "report.content_accessed" if allowed else "report.access_denied"
        ) in events
        _bind(check, other)
        assert not check.execute(
            select(FaEngagementAuditEvent.id).where(
                FaEngagementAuditEvent.entity_id == ids[tenant]
            )
        ).first()
    finally:
        check.rollback()
        check.close()


def test_qa_reject_response_survives_commit_under_rls(_rls_probe) -> None:
    """Same defect class in the governance-stage reject route (#816)."""
    from types import SimpleNamespace

    import api.field_assessment as fa
    from api.actor_context import ActorContext, roles_to_permissions

    sm, tenant, _other, ids = _rls_probe
    db = sm()
    try:
        _bind(db, tenant)
        actor = ActorContext(
            subject="auth0|independent-qa",
            email="qa@example.test",
            name="QA",
            permissions=roles_to_permissions(["qa_reviewer"]),
            roles=["qa_reviewer"],
            auth_source="oidc_auth0",
            tenant_id=tenant,
        )
        req: Any = SimpleNamespace(
            headers={}, state=SimpleNamespace(request_id="rls", tenant_id=tenant)
        )
        resp = fa.qa_reject_report_route(
            engagement_id=ids[f"{tenant}:eng"],
            report_id=ids[tenant],
            body=fa.ReportQaRejectBody(
                reason_code="OTHER", explanation="Rejected under real RLS."
            ),
            request=req,
            actor_ctx=actor,
            db=db,
        )
        assert resp.status == "rejected" and resp.report_version == 1
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
# MSP-001 — migration 0206 forced RLS, exercised through the real authority and
# audit code with a NOBYPASSRLS runtime role. All tenants are synthetic.
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def _msp_rls_probe(_mig_engine):
    from datetime import datetime, timedelta, timezone

    from sqlalchemy.engine import make_url
    from sqlalchemy.orm import sessionmaker

    import api.db_models_msp  # noqa: F401 — registers MSP tables on Base

    role = f"fg_msp_probe_{uuid.uuid4().hex[:10]}"
    password = uuid.uuid4().hex
    msp, cust, third = _uid("msp"), _uid("cust"), _uid("third")
    rid = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    with _mig_engine.begin() as su:
        su.execute(
            text(
                f"CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS"
            )
        )
        su.execute(text(f"GRANT USAGE ON SCHEMA public TO {role}"))
        su.execute(
            text(
                f"GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO {role}"
            )
        )
        for t in (msp, cust, third):
            _insert_tenant(su, t)
        su.execute(
            text(
                "INSERT INTO msp_organizations (tenant_id, status,"
                " designated_by_subject, designated_at, status_changed_by_subject,"
                " status_changed_at) VALUES (:m, 'active', 'synthetic', :n,"
                " 'synthetic', :n)"
            ),
            {"m": msp, "n": now},
        )
        su.execute(
            text(
                "INSERT INTO msp_service_relationships (id, msp_tenant_id, tenant_id,"
                " status, requested_capabilities, authorized_capabilities,"
                " proposed_by_subject, proposed_at, approved_by_subject, approved_at,"
                " effective_at, expires_at, version, created_at, updated_at) VALUES"
                " (:id, :m, :c, 'approved', '[\"governance.read\"]',"
                " '[\"governance.read\"]', 'synthetic-msp', :n, 'synthetic-cust', :n,"
                " :e, :x, 2, :n, :n)"
            ),
            {
                "id": rid,
                "m": msp,
                "c": cust,
                "n": now,
                "e": now - timedelta(minutes=1),
                "x": now + timedelta(days=1),
            },
        )
    url = make_url(str(_mig_engine.url)).set(username=role, password=password)
    engine = create_engine(url, future=True)
    sm = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
    try:
        yield sm, msp, cust, third, rid
    finally:
        engine.dispose()
        with _mig_engine.begin() as su:
            # tenant_identity_audit_events is append-only (append_only_guard
            # rejects DELETE even for the superuser); the probe's audit rows
            # stay, keyed to these unique synthetic tenant ids.
            su.execute(
                text("DELETE FROM msp_service_relationships WHERE id = :id"),
                {"id": rid},
            )
            su.execute(
                text("DELETE FROM msp_organizations WHERE tenant_id = :m"), {"m": msp}
            )
            su.execute(text(f"DROP OWNED BY {role}"))
            su.execute(text(f"DROP ROLE {role}"))


def test_0206_relationship_rows_visible_only_to_the_two_parties(_msp_rls_probe) -> None:
    from api.db_models_msp import MspOrganization, MspServiceRelationship

    sm, msp, cust, third, rid = _msp_rls_probe
    for tenant, visible in ((cust, True), (msp, True), (third, False)):
        db = sm()
        try:
            _bind(db, tenant)
            assert (db.get(MspServiceRelationship, rid) is not None) is visible, tenant
            assert (db.get(MspOrganization, msp) is not None) is (tenant == msp)
        finally:
            db.rollback()
            db.close()
    db = sm()  # no tenant context at all: nothing, no empty-context bypass
    try:
        assert db.get(MspServiceRelationship, rid) is None
    finally:
        db.close()


def test_0206_third_tenant_cannot_write_a_relationship_for_others(
    _msp_rls_probe,
) -> None:
    from sqlalchemy.exc import ProgrammingError

    sm, msp, cust, third, _ = _msp_rls_probe
    db = sm()
    try:
        _bind(db, third)
        with pytest.raises(ProgrammingError):  # WITH CHECK violation
            db.execute(
                text(
                    "INSERT INTO msp_service_relationships (id, msp_tenant_id,"
                    " tenant_id, status, requested_capabilities, proposed_by_subject,"
                    " proposed_at, created_at, updated_at) VALUES (:id, :m, :c,"
                    " 'proposed', '[]', 'x', now(), now(), now())"
                ),
                {"id": str(uuid.uuid4()), "m": msp, "c": cust},
            )
    finally:
        db.rollback()
        db.close()


def test_0206_authority_and_cross_chain_audit_work_under_forced_rls(
    _msp_rls_probe,
) -> None:
    from fastapi import HTTPException

    from api.identity.store import verify_identity_audit_chain
    from api.msp_authority import emit_msp_audit, resolve_credential_access

    sm, msp, cust, third, rid = _msp_rls_probe
    db = sm()
    try:
        _bind(db, msp)  # the MSP credential's own context, as in production
        access = resolve_credential_access(
            db, msp_tenant_id=msp, customer_tenant_id=cust, required="governance.read"
        )
        assert access.relationship_id == rid
        emit_msp_audit(
            db,
            chains=(cust, msp),
            restore_tenant=msp,
            event_type="tenant.msp.context_resolved",
            actor_subject="synthetic-msp-staff",
            membership_id=None,
            reason_code="MSP_CONTEXT_RESOLVED",
            msp_tenant_id=msp,
            customer_tenant_id=cust,
            relationship_id=rid,
            operation="context.resolve",
            capabilities=access.effective_permissions,
        )
        db.commit()
        for tenant in (cust, msp):
            _bind(db, tenant)
            assert verify_identity_audit_chain(db, tenant)
            db.rollback()
        _bind(db, third)
        with pytest.raises(HTTPException):
            resolve_credential_access(
                db,
                msp_tenant_id=third,
                customer_tenant_id=cust,
                required="governance.read",
            )
    finally:
        db.rollback()
        db.close()


def test_0206_relationship_view_must_be_built_before_commit(_msp_rls_probe) -> None:
    """Codex P1 (#872): commit clears app.tenant_id and expires the row, so a
    post-commit relationship_view() reload is hidden by forced RLS. The MSP
    mutation routes therefore serialize the response before committing."""
    from sqlalchemy.orm.exc import ObjectDeletedError

    from api.db_models_msp import MspServiceRelationship
    from api.msp_authority import relationship_view

    sm, msp, cust, third, rid = _msp_rls_probe
    db = sm()
    try:
        _bind(db, cust)
        row = db.get(MspServiceRelationship, rid)
        assert row is not None
        row.updated_at = row.updated_at  # a write in the customer's context
        view = relationship_view(row)  # built while the context is bound
        db.commit()
        assert view["relationship_id"] == rid
        with pytest.raises(ObjectDeletedError):
            relationship_view(row)  # what the routes did before the fix
    finally:
        db.rollback()
        db.close()


def test_0206_msp_002_portfolio_reads_only_under_the_customer_context(
    _msp_rls_probe, _mig_engine
) -> None:
    """MSP-002: forced RLS on the field-assessment tables hides a customer's
    rows from the MSP's own context; the portfolio reader sees them only by
    switching to the customer's context, and restores the MSP's context."""
    from api.msp_portfolio import PortfolioEntry, build_portfolio_items
    from services.field_assessment import store as fa_store

    sm, msp, cust, third, rid = _msp_rls_probe
    eid = f"eng-{uuid.uuid4().hex[:12]}"
    with _mig_engine.begin() as su:
        su.execute(
            text(
                "INSERT INTO fa_engagements (id, tenant_id, client_name, assessor_id,"
                " assessment_type, status, engagement_metadata, schema_version,"
                " created_at, updated_at) VALUES (:id, :t, 'Synthetic', 'assessor-x',"
                " 'ai_governance', 'delivered', '{}', '1.0', :u, :u)"
            ),
            {"id": eid, "t": cust, "u": "2026-11-10T10:00:00Z"},
        )
        su.execute(
            text(
                "INSERT INTO fa_normalized_findings (id, tenant_id, engagement_id,"
                " finding_type, findings_hash, severity, status, title, description,"
                " source_attribution, confidence_score, framework_mappings,"
                " nist_ai_rmf_mappings, evidence_ref_ids, schema_version, created_at,"
                " updated_at) VALUES (:id, :t, :e, 'policy_gap', :h, 'high', 'open',"
                " 'Synthetic', 'Synthetic', 'synthetic', 80, '[]', '[]', '[]', '1.0',"
                " :u, :u)"
            ),
            {
                "id": f"fnd-{uuid.uuid4().hex[:12]}",
                "t": cust,
                "e": eid,
                "h": uuid.uuid4().hex,
                "u": "2026-11-11T10:00:00Z",
            },
        )
    # Synthetic FA rows stay (unique tenant ids); FA tables may be append-only.
    db = sm()
    try:
        _bind(db, msp)
        hidden = fa_store.list_engagements(
            db, tenant_id=cust, status_filter=None, limit=100, cursor=None
        )
        assert hidden == []  # the MSP's own context cannot see customer rows
        entry = PortfolioEntry(
            customer_tenant_id=cust,
            display_name="Synthetic",
            relationship_id=rid,
            expires_at=None,
            effective_permissions=frozenset({"assessment.read", "finding.read"}),
        )
        items, reads = build_portfolio_items(db, entries=[entry], restore_tenant=msp)
        assert items[0]["assessment"]["engagements_by_status"] == {"delivered": 1}
        assert items[0]["findings"]["outstanding_by_severity"] == {"high": 1}
        assert reads == [(entry, ["assessment.read", "finding.read"])]
        current = db.execute(
            text("SELECT current_setting('app.tenant_id', true)")
        ).scalar()
        assert current == msp
        _bind(db, third)  # an unrelated tenant's context sees nothing either
        assert (
            fa_store.list_engagements(
                db, tenant_id=cust, status_filter=None, limit=100, cursor=None
            )
            == []
        )
    finally:
        db.rollback()
        db.close()


def test_0206_msp_002_history_filters_by_relationship_in_postgres(
    _msp_rls_probe,
) -> None:
    """MSP-002: the history route's relationship predicate on the JSONB
    details runs in Postgres under the chain owner's RLS context, and returns
    only that relationship's events."""
    from api.msp import relationship_events_query
    from api.msp_authority import emit_msp_audit

    sm, msp, cust, third, rid = _msp_rls_probe
    other = f"rel-other-{uuid.uuid4().hex[:12]}"
    db = sm()
    try:
        _bind(db, cust)
        for relationship_id in (other, rid, other):
            emit_msp_audit(
                db,
                chains=(cust,),
                restore_tenant=cust,
                event_type="tenant.msp.portfolio_summary_accessed",
                actor_subject="synthetic-probe",
                membership_id=None,
                reason_code="MSP_PORTFOLIO_SUMMARY_ACCESSED",
                msp_tenant_id=msp,
                customer_tenant_id=cust,
                relationship_id=relationship_id,
                operation="portfolio.summary",
            )
        db.commit()
        _bind(db, cust)
        mine = relationship_events_query(db, cust, rid).all()
        assert mine and all(e.details_json["relationship_id"] == rid for e in mine)
        assert relationship_events_query(db, cust, other).count() == 2
        _bind(db, third)  # another tenant's context sees none of these rows
        assert relationship_events_query(db, cust, rid).count() == 0
    finally:
        db.close()


def test_0207_msp_006_billing_rows_are_isolated_by_forced_rls(
    _msp_rls_probe, _mig_engine
) -> None:
    """MSP-006: a payer assignment is visible only to the customer and the
    payer (never to the MSP in customer-paid mode, never to a third tenant,
    never with no context); a usage event only to its own payer tenant. The
    billing_v2 metering path still records usage once the context is bound."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy.exc import DBAPIError

    from api.db_models_billing import UsageEvent
    from api.db_models_msp import MspPayerAssignment
    from services.billing.metering import record_usage_event

    sm, msp, cust, third, rid = _msp_rls_probe
    now = datetime.now(timezone.utc)
    meter = f"probe.meter.{uuid.uuid4().hex[:8]}"
    ids = [str(uuid.uuid4()), str(uuid.uuid4())]
    with _mig_engine.begin() as su:
        su.execute(
            text(
                "INSERT INTO usage_meters (id, meter_code, display_name, unit,"
                " aggregation_mode, billing_category, active, metadata_json,"
                " created_at, updated_at) VALUES (:i, :m, 'probe', 'count', 'sum',"
                " 'probe', '1', '{}', :n, :n)"
            ),
            {"i": str(uuid.uuid4()), "m": meter, "n": now},
        )

    def _assignment(aid: str, mode: str, product: str) -> MspPayerAssignment:
        return MspPayerAssignment(
            id=aid,
            tenant_id=cust,
            msp_tenant_id=msp,
            relationship_id=rid,
            payer_tenant_id=msp if mode == "msp_paid" else cust,
            billing_mode=mode,
            product_code=product,
            subscription_contract_id="sc-probe",
            currency="USD",
            status="active",
            effective_at=now,
            expires_at=now + timedelta(days=30),
            approved_by_subject="synthetic-platform",
            approved_at=now,
            version=1,
            created_at=now,
            updated_at=now,
        )

    db = sm()
    try:
        _bind(db, cust)
        db.add(_assignment(ids[0], "msp_paid", "assessment.delivered"))
        db.add(_assignment(ids[1], "customer_paid", "probe.other"))
        db.commit()

        def visible(tenant: str | None) -> set[str]:
            s = sm()
            try:
                if tenant:
                    _bind(s, tenant)
                return {r.id for r in s.query(MspPayerAssignment).all()}
            finally:
                s.close()

        assert visible(cust) == set(ids)
        assert visible(msp) == {ids[0]}  # the MSP never sees customer-paid rows
        assert visible(third) == set()
        assert visible(None) == set()  # no empty-context bypass

        # usage_events: the payer records and reads its own usage only.
        _bind(db, msp)
        evt = record_usage_event(db, msp, meter, "1", f"probe-{uuid.uuid4().hex}")
        # Capture before commit: the commit ends the transaction-local tenant
        # context, so a post-commit reload is (correctly) hidden by forced RLS.
        evt_id = evt.id
        db.commit()
        for tenant, expected in ((msp, {evt_id}), (cust, set()), (third, set())):
            s = sm()
            try:
                _bind(s, tenant)
                assert {r.id for r in s.query(UsageEvent).all()} == expected, tenant
            finally:
                s.close()
        s = sm()
        try:
            assert s.query(UsageEvent).count() == 0  # no context, no rows
            _bind(s, msp)
            s.add(
                UsageEvent(
                    id=str(uuid.uuid4()),
                    tenant_id=cust,  # spoofed: another tenant's usage
                    meter_code=meter,
                    quantity="1",
                    idempotency_key=f"spoof-{uuid.uuid4().hex}",
                )
            )
            with pytest.raises(DBAPIError):
                s.flush()
            s.rollback()
        finally:
            s.close()
    finally:
        db.close()
        with _mig_engine.begin() as su:
            su.execute(
                text("DELETE FROM msp_payer_assignments WHERE relationship_id = :r"),
                {"r": rid},
            )
            su.execute(
                text("DELETE FROM usage_events WHERE meter_code = :m"), {"m": meter}
            )
            su.execute(
                text("DELETE FROM usage_meters WHERE meter_code = :m"), {"m": meter}
            )


def test_0208_msp_003_orchestration_rows_are_isolated_by_forced_rls(
    _msp_rls_probe, _mig_engine
) -> None:
    """MSP-003: an assessment grant is visible and writable only by the
    customer and the MSP; an onboarding request only by its MSP. A third
    tenant and an empty context see nothing; spoofed writes are refused by
    WITH CHECK; the compare-and-set that initiates a grant lets exactly one
    concurrent writer win, and one engagement id can back only one grant."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy.exc import DBAPIError, IntegrityError

    from api.db_models_msp import MspAssessmentGrant, MspOnboardingRequest

    sm, msp, cust, third, rid = _msp_rls_probe
    now = datetime.now(timezone.utc)
    gid, oid = str(uuid.uuid4()), str(uuid.uuid4())

    def _grant(grant_id: str, customer: str, key: str) -> MspAssessmentGrant:
        return MspAssessmentGrant(
            id=grant_id,
            tenant_id=customer,
            msp_tenant_id=msp,
            relationship_id=rid,
            request_key=key,
            capabilities='["assessment.create"]',
            assessment_type="ai_governance",
            assessor_id="assessor-probe",
            status="approved",
            requested_by_subject="synthetic-msp",
            requested_at=now,
            expires_at=now + timedelta(days=5),
            decided_by_subject="synthetic-cust",
            decided_at=now,
            version=2,
            created_at=now,
            updated_at=now,
        )

    db = sm()
    try:
        _bind(db, msp)
        db.add(_grant(gid, cust, "probe-1"))
        db.add(
            MspOnboardingRequest(
                id=oid,
                tenant_id=msp,
                request_key="probe-onb",
                organization_name="Probe Co",
                contact_email="it@probe.invalid",
                requested_capabilities='["governance.read"]',
                status="requested",
                requested_by_subject="synthetic-msp",
                requested_at=now,
                expires_at=now + timedelta(days=30),
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()

        def visible(model, tenant: str | None) -> set[str]:
            s = sm()
            try:
                if tenant:
                    _bind(s, tenant)
                return {r.id for r in s.query(model).all()}
            finally:
                s.close()

        assert visible(MspAssessmentGrant, cust) == {gid}
        assert visible(MspAssessmentGrant, msp) == {gid}
        assert visible(MspAssessmentGrant, third) == set()
        assert visible(MspAssessmentGrant, None) == set()
        assert visible(MspOnboardingRequest, msp) == {oid}
        assert visible(MspOnboardingRequest, cust) == set()
        assert visible(MspOnboardingRequest, third) == set()
        assert visible(MspOnboardingRequest, None) == set()

        # Spoofed writes: a third tenant cannot create a grant between others,
        # nor an onboarding request owned by another MSP.
        for model_row in (
            _grant(str(uuid.uuid4()), cust, "spoof-1"),
            MspOnboardingRequest(
                id=str(uuid.uuid4()),
                tenant_id=msp,
                request_key="spoof-onb",
                organization_name="Spoof",
                contact_email="x@spoof.invalid",
                requested_capabilities="[]",
                status="requested",
                requested_by_subject="third",
                requested_at=now,
                expires_at=now + timedelta(days=1),
                version=1,
                created_at=now,
                updated_at=now,
            ),
        ):
            s = sm()
            try:
                _bind(s, third)
                s.add(model_row)
                with pytest.raises(DBAPIError):
                    s.flush()
                s.rollback()
            finally:
                s.close()

        # A third tenant's UPDATE matches no row (USING hides it).
        s = sm()
        try:
            _bind(s, third)
            n = (
                s.query(MspAssessmentGrant)
                .filter(MspAssessmentGrant.id == gid)
                .update({"status": "revoked"}, synchronize_session=False)
            )
            assert n == 0
            s.rollback()
        finally:
            s.close()

        # Concurrent initiation: two writers compare-and-set the same version.
        def _cas(session, engagement_id: str) -> int:
            return (
                session.query(MspAssessmentGrant)
                .filter(
                    MspAssessmentGrant.id == gid,
                    MspAssessmentGrant.status == "approved",
                    MspAssessmentGrant.version == 2,
                    MspAssessmentGrant.engagement_id.is_(None),
                )
                .update(
                    {
                        "status": "initiated",
                        "engagement_id": engagement_id,
                        "initiated_by_subject": "synthetic-msp",
                        "initiated_at": now,
                        "version": 3,
                    },
                    synchronize_session=False,
                )
            )

        first, second = sm(), sm()
        try:
            _bind(first, msp)
            _bind(second, cust)
            assert _cas(first, "eng-probe-a") == 1
            first.commit()
            assert _cas(second, "eng-probe-b") == 0
            second.rollback()
        finally:
            first.close()
            second.close()
        s = sm()
        try:
            _bind(s, cust)
            row = s.get(MspAssessmentGrant, gid)
            assert (row.status, row.engagement_id) == ("initiated", "eng-probe-a")
        finally:
            s.close()

        # One engagement id can back only one grant.
        s = sm()
        try:
            _bind(s, msp)
            dup = _grant(str(uuid.uuid4()), cust, "probe-2")
            dup.status = "initiated"
            dup.engagement_id = "eng-probe-a"
            dup.initiated_by_subject = "synthetic-msp"
            dup.initiated_at = now
            s.add(dup)
            with pytest.raises(IntegrityError):
                s.flush()
            s.rollback()
        finally:
            s.close()
    finally:
        db.close()
        with _mig_engine.begin() as su:
            su.execute(
                text("DELETE FROM msp_assessment_grants WHERE relationship_id = :r"),
                {"r": rid},
            )
            su.execute(
                text("DELETE FROM msp_onboarding_requests WHERE tenant_id = :m"),
                {"m": msp},
            )


def test_0209_msp_007_report_shares_are_isolated_by_forced_rls(
    _msp_rls_probe, _mig_engine
) -> None:
    """MSP-007: a report share is visible and writable only by its customer
    and its MSP. A third tenant and an empty context see nothing; spoofed
    writes are refused by WITH CHECK; a third tenant's revoke matches no row;
    two concurrent approvals of one request let exactly one win; and at most
    one active share per (customer, MSP, report) exists."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy.exc import DBAPIError, IntegrityError

    from api.db_models_msp import MspReportShare

    sm, msp, cust, third, rid = _msp_rls_probe
    now = datetime.now(timezone.utc)
    sid, req_id = str(uuid.uuid4()), str(uuid.uuid4())
    fingerprint = "a" * 64

    def _active(share_id: str, customer: str, key: str) -> MspReportShare:
        return MspReportShare(
            id=share_id,
            tenant_id=customer,
            msp_tenant_id=msp,
            relationship_id=rid,
            origin="customer",
            request_key=key,
            engagement_id="eng-probe",
            report_id="report-probe",
            report_version=1,
            manifest_hash=fingerprint,
            status="active",
            requested_by_subject="synthetic-cust",
            requested_at=now,
            decided_by_subject="synthetic-cust",
            decided_at=now,
            expires_at=now + timedelta(days=5),
            version=1,
            created_at=now,
            updated_at=now,
        )

    db = sm()
    try:
        _bind(db, cust)
        db.add(_active(sid, cust, "probe-share"))
        db.add(
            MspReportShare(
                id=req_id,
                tenant_id=cust,
                msp_tenant_id=msp,
                relationship_id=rid,
                origin="msp",
                request_key="probe-request",
                engagement_id="eng-probe-2",
                source_grant_id=str(uuid.uuid4()),
                status="requested",
                requested_by_subject="synthetic-msp",
                requested_at=now,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()

        def visible(tenant: str | None) -> set[str]:
            s = sm()
            try:
                if tenant:
                    _bind(s, tenant)
                return {r.id for r in s.query(MspReportShare).all()}
            finally:
                s.close()

        assert visible(cust) == {sid, req_id}
        assert visible(msp) == {sid, req_id}
        assert visible(third) == set()
        assert visible(None) == set()

        # Spoofed write: a third tenant cannot create a share between others.
        s = sm()
        try:
            _bind(s, third)
            s.add(_active(str(uuid.uuid4()), cust, "spoof-share"))
            with pytest.raises(DBAPIError):
                s.flush()
            s.rollback()
        finally:
            s.close()

        # A third tenant's revoke matches no row (USING hides it).
        s = sm()
        try:
            _bind(s, third)
            n = (
                s.query(MspReportShare)
                .filter(MspReportShare.id == sid)
                .update(
                    {
                        "status": "revoked",
                        "revoked_by_subject": "third",
                        "revoked_at": now,
                    },
                    synchronize_session=False,
                )
            )
            assert n == 0
            s.rollback()
        finally:
            s.close()

        # Concurrent approval of one request: compare-and-set on the version.
        def _approve(session, report_id: str) -> int:
            return (
                session.query(MspReportShare)
                .filter(
                    MspReportShare.id == req_id,
                    MspReportShare.status == "requested",
                    MspReportShare.version == 1,
                )
                .update(
                    {
                        "status": "active",
                        "report_id": report_id,
                        "report_version": 1,
                        "manifest_hash": fingerprint,
                        "decided_by_subject": "synthetic-cust",
                        "decided_at": now,
                        "expires_at": now + timedelta(days=1),
                        "version": 2,
                    },
                    synchronize_session=False,
                )
            )

        first, second = sm(), sm()
        try:
            _bind(first, cust)
            _bind(second, cust)
            assert _approve(first, "report-probe-2") == 1
            first.commit()
            assert _approve(second, "report-probe-3") == 0
            second.rollback()
        finally:
            first.close()
            second.close()

        # At most one active share of one report for one MSP.
        s = sm()
        try:
            _bind(s, cust)
            s.add(_active(str(uuid.uuid4()), cust, "probe-share-dup"))
            with pytest.raises(IntegrityError):
                s.flush()
            s.rollback()
        finally:
            s.close()

        # Retiring an expired share to 'expired' frees the active slot, and the
        # retired row stays bound to its report version.
        s = sm()
        try:
            _bind(s, cust)
            n = (
                s.query(MspReportShare)
                .filter(MspReportShare.id == sid, MspReportShare.status == "active")
                .update({"status": "expired", "version": 2}, synchronize_session=False)
            )
            assert n == 1
            s.add(_active(str(uuid.uuid4()), cust, "probe-share-renewed"))
            s.flush()
            s.commit()
        finally:
            s.close()

        # An active share must be bound to an exact report version.
        s = sm()
        try:
            _bind(s, cust)
            unbound = _active(str(uuid.uuid4()), cust, "probe-unbound")
            unbound.report_id = "report-probe-4"
            unbound.manifest_hash = None
            s.add(unbound)
            with pytest.raises(IntegrityError):
                s.flush()
            s.rollback()
        finally:
            s.close()
    finally:
        db.close()
        with _mig_engine.begin() as su:
            su.execute(
                text("DELETE FROM msp_report_shares WHERE relationship_id = :r"),
                {"r": rid},
            )


# ─────────────────────────────────────────────────────────────────────────────
# FG-ASSESSMENT-CONNECTOR-RLS-001 — synchronous connector routes under
# enforced RLS.
#
# Real PostgreSQL, real commits (a savepoint "commit" would keep the
# transaction-local app.tenant_id alive and give a false green), and a login
# role that is NOT a superuser, NOT BYPASSRLS and NOT the owner of any touched
# table — asserted, not assumed. All tenants and data are synthetic.
# ─────────────────────────────────────────────────────────────────────────────

_CONNECTOR_TABLES = (
    "fa_scan_jobs",
    "fa_scan_audit_events",
    "fa_scan_results",
    "fa_normalized_findings",
    "fa_evidence_links",
    "fa_external_ai_risk_records",
    "fa_ai_vendor_governance_records",
    "fa_ai_vendor_governance_decisions",
    "fa_scan_evidence_envelopes",
    "fa_engagements",
)

_CONNECTOR_ROUTES = (
    ("run_ai_data_access_mapping", "AiDataAccessMappingRunRequest", "assessor"),
    ("run_external_ai_risk_register", "ExternalAiRiskRegisterRunRequest", "assessor"),
    ("run_ai_vendor_governance", "AiVendorGovernanceRunRequest", "tenant_admin"),
)


def _connector_seed_tool(tenant: str) -> dict[str, Any]:
    return {
        "tool_name": "Shadow Writer AI",
        "vendor": "Unverified Co",
        "permissions": ["Files.ReadWrite.All", "Mail.Read"],
        "delegated_permissions": ["Files.ReadWrite.All", "Mail.Read"],
        "application_permissions": [],
        "admin_consent": True,
        "consent_type": "AllPrincipals",
        "verified_publisher": False,
        "publisher": "Unverified Co",
        "confidence": "confirmed",
        "service_principal_id": "sp-rls-1",
        "application_id": "app-rls-1",
        "app_id": "app-rls-1",
        "evidence_refs": ["servicePrincipal:sp-rls-1"],
        "risk_indicators": ["unverified_publisher", "sensitive_permissions"],
        "graph_node_id": f"ai_tool:{tenant}:app-rls-1",
    }


class _ConnectorRls:
    """Restricted-role harness: sessions bound exactly like auth_ctx_db_session."""

    def __init__(self, su, sm, role: str, tenants: dict[str, str]) -> None:
        self.su, self.sm, self.role, self.eng = su, sm, role, tenants

    def session(self, tenant: str | None):
        db = self.sm()
        if tenant is not None:
            _bind(db, tenant)
        return db

    def run(self, route: str, tenant: str, *, engagement_id: str | None = None):
        """Call a connector route as the tenant's named human; return (status, body)."""
        from types import SimpleNamespace

        from fastapi import HTTPException

        import api.field_assessment as fa
        from api.actor_context import ActorContext, roles_to_permissions

        name, body_cls, role = next(r for r in _CONNECTOR_ROUTES if r[0] == route)
        actor = ActorContext(
            subject=f"auth0|rls-{role}",
            email="",
            name="",
            permissions=roles_to_permissions([role]),
            roles=[role],
            auth_source="oidc_auth0",
            tenant_id=tenant,
        )
        req: Any = SimpleNamespace(
            headers={},
            state=SimpleNamespace(request_id="rls", tenant_id=tenant, auth=None),
        )
        db = self.session(tenant)
        try:
            out = getattr(fa, name)(
                engagement_id=engagement_id or self.eng[tenant],
                request=req,
                body=getattr(fa, body_cls)(),
                actor_ctx=actor,
                db=db,
            )
            return 200, out.model_dump()
        except HTTPException as exc:
            return exc.status_code, exc.detail
        finally:
            db.close()

    def rows(self, sql: str, **params: Any) -> list[Any]:
        """Read as the superuser (RLS bypassed) to observe committed state."""
        with self.su.connect() as conn:
            return list(conn.execute(text(sql), params))

    def jobs(self, tenant: str) -> list[Any]:
        return self.rows(
            "SELECT id, scanner_type, status, scan_result_id, attempt_count"
            " FROM fa_scan_jobs WHERE tenant_id = :t ORDER BY created_at, id",
            t=tenant,
        )

    def audit(self, tenant: str) -> list[tuple[str, str, str]]:
        return [
            (r.scanner_type, r.event_type, r.scan_job_id)
            for r in self.rows(
                "SELECT scanner_type, event_type, scan_job_id"
                " FROM fa_scan_audit_events WHERE tenant_id = :t",
                t=tenant,
            )
        ]


@pytest.fixture
def _connector_rls(_mig_engine):
    from sqlalchemy.engine import make_url
    from sqlalchemy.orm import sessionmaker

    from services.field_assessment.connectors.ai_tool_discovery_bridge import (
        import_ai_tool_discovery_scan,
    )

    role = f"fg_conn_rls_{uuid.uuid4().hex[:10]}"
    password = uuid.uuid4().hex
    tenants = {_uid("conn-a"): uuid.uuid4().hex, _uid("conn-b"): uuid.uuid4().hex}
    with _mig_engine.begin() as su:
        su.execute(
            text(
                f"CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS"
            )
        )
        su.execute(text(f"GRANT USAGE ON SCHEMA public TO {role}"))
        su.execute(
            text(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public"
                f" TO {role}"
            )
        )
        su.execute(
            text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}")
        )
        for t, eid in tenants.items():
            _insert_tenant(su, t)
            su.execute(
                text(
                    "INSERT INTO fa_engagements (id, tenant_id, client_name, assessor_id,"
                    " assessment_type, status, engagement_metadata, schema_version,"
                    " created_at, updated_at) VALUES (:e, :t, 'SYNTHETIC', 'a',"
                    " 'ai_governance', 'in_progress', '{}', '1.0',"
                    " '2026-11-27T00:00:00Z', '2026-11-27T00:00:00Z')"
                ),
                {"e": eid, "t": t},
            )
    url = make_url(str(_mig_engine.url)).set(username=role, password=password)
    engine = create_engine(url, future=True)
    # Same settings as api.db.get_sessionmaker (expire_on_commit defaults True).
    sm = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
    harness = _ConnectorRls(_mig_engine, sm, role, tenants)
    for t, eid in tenants.items():
        db = harness.session(t)  # seeding itself runs under enforced RLS
        try:
            import_ai_tool_discovery_scan(
                db=db,
                tenant_id=t,
                engagement_id=eid,
                actor="seed",
                scan_result={
                    "scan_completed_at": "2026-11-27T00:00:00Z",
                    "tools": [_connector_seed_tool(t)],
                    "summary": {"discovered": 1},
                    "findings": [],
                },
            )
            db.commit()
        finally:
            db.close()
    try:
        yield harness
    finally:
        engine.dispose()
        with _mig_engine.begin() as su:
            su.execute(text(f"DROP OWNED BY {role}"))
            su.execute(text(f"DROP ROLE {role}"))


def _tenant_pair(h: _ConnectorRls) -> tuple[str, str]:
    a, b = list(h.eng)
    return a, b


def test_connector_rls_role_is_restricted_and_rls_is_enforced(_connector_rls) -> None:
    """Control: the role cannot bypass RLS, and RLS is enabled and forced."""
    h = _connector_rls
    (role,) = h.rows(
        "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = :r", r=h.role
    )
    assert role.rolsuper is False and role.rolbypassrls is False
    for table in _CONNECTOR_TABLES:
        (meta,) = h.rows(
            "SELECT c.relrowsecurity, c.relforcerowsecurity,"
            " pg_get_userbyid(c.relowner) AS owner FROM pg_class c"
            " WHERE c.relname = :t AND c.relnamespace = 'public'::regnamespace",
            t=table,
        )
        assert meta.relrowsecurity and meta.relforcerowsecurity, table
        assert meta.owner != h.role, table  # not the owner
        policies = h.rows(
            "SELECT qual, with_check FROM pg_policies"
            " WHERE schemaname = 'public' AND tablename = :t AND cmd = 'ALL'",
            t=table,
        )
        assert any(
            "app.tenant_id" in (p.qual or "")
            and "IS NOT NULL" in (p.qual or "")
            and "app.tenant_id" in (p.with_check or "")
            for p in policies
        ), table
    a, b = _tenant_pair(h)
    for tenant, visible in ((None, 0), (b, 0), (a, 1)):
        db = h.session(tenant)
        try:
            n = db.execute(
                text("SELECT count(*) FROM fa_scan_results WHERE tenant_id = :t"),
                {"t": a},
            ).scalar()
        finally:
            db.close()
        assert n == visible, tenant  # unbound and foreign contexts see nothing


def test_tenant_binding_is_transaction_scoped(_connector_rls) -> None:
    """commit, rollback and an aborted transaction all clear the binding."""
    h = _connector_rls
    a, _ = _tenant_pair(h)
    count = "SELECT count(*) FROM fa_scan_results WHERE tenant_id = :t"
    db = h.session(a)
    try:
        assert db.execute(text(count), {"t": a}).scalar() == 1
        db.commit()
        assert db.execute(text(count), {"t": a}).scalar() == 0  # cleared by commit
        _bind(db, a)
        assert db.execute(text(count), {"t": a}).scalar() == 1  # re-bind restores
        db.rollback()
        assert db.execute(text(count), {"t": a}).scalar() == 0  # cleared by rollback
        _bind(db, a)
        with pytest.raises(Exception):
            db.execute(text("SELECT 1 / 0"))
        db.rollback()
        assert db.execute(text(count), {"t": a}).scalar() == 0  # cleared after abort
        _bind(db, a)
        assert db.execute(text(count), {"t": a}).scalar() == 1
    finally:
        db.rollback()
        db.close()


def test_pooled_connection_does_not_leak_tenant_context(_connector_rls) -> None:
    """A pooled connection reused after a tenant's request carries no context."""
    from sqlalchemy.orm import sessionmaker

    h = _connector_rls
    a, b = _tenant_pair(h)
    engine = create_engine(
        h.sm.kw["bind"].url, future=True, pool_size=1, max_overflow=0
    )
    sm = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
    pids: set[int] = set()
    try:
        first = sm()
        _bind(first, a)
        pids.add(first.execute(text("SELECT pg_backend_pid()")).scalar())
        assert (
            first.execute(
                text("SELECT count(*) FROM fa_scan_results WHERE tenant_id = :t"),
                {"t": a},
            ).scalar()
            == 1
        )
        first.commit()
        first.close()
        for tenant in (None, b):
            nxt = sm()
            try:
                if tenant is not None:
                    _bind(nxt, tenant)
                pids.add(nxt.execute(text("SELECT pg_backend_pid()")).scalar())
                bound = nxt.execute(
                    text("SELECT current_setting('app.tenant_id', true)")
                ).scalar()
                assert bound in (None, "", tenant)  # never tenant A's value
                assert (
                    nxt.execute(
                        text(
                            "SELECT count(*) FROM fa_scan_results WHERE tenant_id = :t"
                        ),
                        {"t": a},
                    ).scalar()
                    == 0
                )
            finally:
                nxt.rollback()
                nxt.close()
        assert len(pids) == 1  # the same physical connection was reused
    finally:
        engine.dispose()


def test_connectors_complete_under_enforced_rls(_connector_rls) -> None:
    """All three routes complete; job, result and audit agree (pre-fix: 500s)."""
    h = _connector_rls
    a, b = _tenant_pair(h)
    responses = {}
    for route, _, _ in _CONNECTOR_ROUTES:
        status, body = h.run(route, a)
        assert status == 200, (route, body)
        assert body["status"] == "complete"
        responses[route] = body
    jobs = h.jobs(a)
    assert [j.status for j in jobs] == ["complete"] * 3
    results = {
        r.id for r in h.rows("SELECT id FROM fa_scan_results WHERE tenant_id = :t", t=a)
    }
    for job, body in zip(jobs, responses.values()):
        assert job.scan_result_id == body["scan_result_id"] in results
        assert job.attempt_count == 1
    events = h.audit(a)
    for job in jobs:
        assert (job.scanner_type, "scan.initiated", job.id) in events
        assert (job.scanner_type, "scan.completed", job.id) in events
    assert not [e for e in events if e[1] == "scan.failed"]
    assert h.rows("SELECT 1 FROM fa_external_ai_risk_records WHERE tenant_id = :t", t=a)
    assert h.rows(
        "SELECT 1 FROM fa_ai_vendor_governance_records WHERE tenant_id = :t", t=a
    )
    assert h.jobs(b) == []  # nothing written for the other tenant


def test_connector_records_are_isolated_across_tenants(_connector_rls) -> None:
    """Tenant B cannot read, create or modify tenant A's connector state."""
    h = _connector_rls
    a, b = _tenant_pair(h)
    for route, _, _ in _CONNECTOR_ROUTES:
        assert h.run(route, a)[0] == 200
    job_id = h.jobs(a)[0].id
    db = h.session(b)
    try:
        for table in _CONNECTOR_TABLES:
            n = db.execute(
                text(f"SELECT count(*) FROM {table} WHERE tenant_id = :t"), {"t": a}
            ).scalar()
            assert n == 0, table  # read
        updated = db.execute(
            text("UPDATE fa_scan_jobs SET status = 'cancelled' WHERE id = :j"),
            {"j": job_id},
        ).rowcount
        assert updated == 0  # modify
        db.commit()
        _bind(db, b)
        with pytest.raises(Exception, match="row-level security"):
            db.execute(
                text(
                    "INSERT INTO fa_scan_jobs (id, tenant_id, engagement_id,"
                    " verified_target_ids, scanner_type, status, attempt_count,"
                    " max_retries, actor, created_at) VALUES (:i, :t, :e, '[]',"
                    " 'external_ai_risk_register', 'queued', 0, 3, 'x',"
                    " '2026-11-27T00:00:00Z')"
                ),
                {"i": uuid.uuid4().hex[:32], "t": a, "e": h.eng[a]},
            )  # create
        db.rollback()
    finally:
        db.close()
    assert h.jobs(a)[0].status == "complete"
    # Tenant B naming tenant A's engagement finds nothing to run against.
    status, body = h.run("run_external_ai_risk_register", b, engagement_id=h.eng[a])
    assert status == 404, body
    assert h.jobs(b) == []


def test_connector_failure_is_recorded_under_rls(_connector_rls, monkeypatch) -> None:
    """A failed run ends dead_letter with one scan.failed and no partial records."""
    from services.connectors.external_ai_risk_register import risk_engine

    h = _connector_rls
    a, _ = _tenant_pair(h)

    def _boom(**_: Any) -> Any:
        raise RuntimeError("synthetic risk engine failure")

    monkeypatch.setattr(risk_engine, "generate_risk_records", _boom)
    status, body = h.run("run_external_ai_risk_register", a)
    assert status == 500 and body["code"] == "RISK_REGISTER_FAILED"
    assert "synthetic" not in str(body)  # internals stay in the log
    (job,) = h.jobs(a)
    assert job.status == "dead_letter"  # terminal for a non-retryable scanner
    failed = [e for e in h.audit(a) if e[1] == "scan.failed"]
    assert failed == [("external_ai_risk_register", "scan.failed", job.id)]
    assert not h.rows(
        "SELECT 1 FROM fa_external_ai_risk_records WHERE tenant_id = :t", t=a
    )


def test_connector_database_error_is_still_recorded(
    _connector_rls, monkeypatch
) -> None:
    """A database error aborts the work transaction; the failure is still durable."""
    import services.field_assessment.connectors.ai_data_access_mapping_bridge as bridge

    h = _connector_rls
    a, _ = _tenant_pair(h)
    real = bridge.import_ai_data_access_mapping_scan

    def _db_error(*, db, **kwargs: Any) -> Any:
        real(db=db, **kwargs)  # partial writes in the work transaction ...
        db.execute(text("SELECT 1 / 0"))  # ... then the transaction aborts

    monkeypatch.setattr(bridge, "import_ai_data_access_mapping_scan", _db_error)
    import api.field_assessment as fa

    monkeypatch.setattr(fa, "import_ai_data_access_mapping_scan", _db_error)
    status, body = h.run("run_ai_data_access_mapping", a)
    assert status == 500 and body["code"] == "MAPPING_FAILED"
    assert "division" not in str(body) and "Instance" not in str(body)
    (job,) = h.jobs(a)
    assert job.status == "dead_letter" and job.scan_result_id is None
    assert [e[1] for e in h.audit(a)].count("scan.failed") == 1
    sources = {
        r.source_type
        for r in h.rows(
            "SELECT source_type FROM fa_scan_results WHERE tenant_id = :t", t=a
        )
    }
    assert "ai_data_access_mapping" not in sources  # rolled back, nothing partial


def test_lost_completion_transition_is_detected(_connector_rls, monkeypatch) -> None:
    """A job cancelled mid-run is not reported complete and keeps no results."""
    from services.connectors.external_ai_risk_register import risk_engine

    h = _connector_rls
    a, _ = _tenant_pair(h)
    real = risk_engine.generate_risk_records

    def _cancel_then_generate(**kwargs: Any) -> Any:
        with h.su.begin() as conn:  # an operator cancels the running job
            conn.execute(
                text(
                    "UPDATE fa_scan_jobs SET status = 'cancelled' WHERE tenant_id = :t"
                    " AND status = 'running'"
                ),
                {"t": a},
            )
        return real(**kwargs)

    monkeypatch.setattr(risk_engine, "generate_risk_records", _cancel_then_generate)
    status, body = h.run("run_external_ai_risk_register", a)
    assert status == 409 and body["code"] == "SCAN_JOB_SUPERSEDED"
    (job,) = h.jobs(a)
    assert job.status == "cancelled" and job.scan_result_id is None
    events = [e[1] for e in h.audit(a)]
    assert "scan.completed" not in events and "scan.failed" not in events
    assert not h.rows(
        "SELECT 1 FROM fa_external_ai_risk_records WHERE tenant_id = :t", t=a
    )


def test_completion_audit_failure_rolls_back_the_transition(
    _connector_rls, monkeypatch
) -> None:
    """Crash consistency: job state and its audit event commit together or not at all."""
    import api.field_assessment as fa

    h = _connector_rls
    a, _ = _tenant_pair(h)
    real = fa._c6_write_audit_event

    def _fail_completed(db, **kwargs: Any) -> Any:
        if kwargs.get("event_type") == "scan.completed":
            raise RuntimeError("synthetic audit sink failure")
        return real(db, **kwargs)

    monkeypatch.setattr(fa, "_c6_write_audit_event", _fail_completed)
    status, _ = h.run("run_external_ai_risk_register", a)
    assert status == 500
    (job,) = h.jobs(a)
    assert job.status == "dead_letter" and job.scan_result_id is None
    events = [e[1] for e in h.audit(a)]
    assert events.count("scan.completed") == 0 and events.count("scan.failed") == 1
    assert not h.rows(
        "SELECT 1 FROM fa_external_ai_risk_records WHERE tenant_id = :t", t=a
    )


def _insert_running_job(h: _ConnectorRls, tenant: str, scanner: str, lease: str) -> str:
    job_id = uuid.uuid4().hex[:32]
    with h.su.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO fa_scan_jobs (id, tenant_id, engagement_id,"
                " verified_target_ids, scanner_type, status, attempt_count,"
                " max_retries, actor, created_at, started_at, lease_owner,"
                " lease_acquired_at, lease_expires_at) VALUES (:i, :t, :e, '[]',"
                " :s, 'running', 1, 3, 'auth0|rls-assessor',"
                " '2026-11-27T00:00:00Z', '2026-11-27T00:00:00Z', 'crashed:1',"
                " '2026-11-27T00:00:00Z', :lease)"
            ),
            {
                "i": job_id,
                "t": tenant,
                "e": h.eng[tenant],
                "s": scanner,
                "lease": lease,
            },
        )
    return job_id


def test_interrupted_run_is_terminated_not_rerun(_connector_rls) -> None:
    """An expired-lease running job is dead-lettered once, never re-executed."""
    h = _connector_rls
    a, b = _tenant_pair(h)
    stale = _insert_running_job(
        h, a, "external_ai_risk_register", "2000-01-01T00:00:00Z"
    )
    other = _insert_running_job(
        h, b, "external_ai_risk_register", "2000-01-01T00:00:00Z"
    )
    assert h.run("run_external_ai_risk_register", a)[0] == 200
    by_id = {j.id: j for j in h.jobs(a)}
    assert by_id[stale].status == "dead_letter"
    assert by_id[stale].attempt_count == 1  # not re-run
    assert by_id[stale].scan_result_id is None
    assert ("external_ai_risk_register", "scan.failed", stale) in h.audit(a)
    assert [j.status for j in by_id.values() if j.id != stale] == ["complete"]
    # Tenant-scoped: the other tenant's stale job is untouched.
    assert {j.id: j.status for j in h.jobs(b)} == {other: "running"}


def test_live_run_rejects_a_duplicate(_connector_rls) -> None:
    """A run holding a live lease blocks a second concurrent run (409)."""
    h = _connector_rls
    a, _ = _tenant_pair(h)
    live = _insert_running_job(
        h, a, "external_ai_risk_register", "2999-01-01T00:00:00Z"
    )
    status, body = h.run("run_external_ai_risk_register", a)
    assert status == 409 and body["code"] == "SCAN_ALREADY_RUNNING"
    assert [j.id for j in h.jobs(a)] == [live]  # no second job created
    # A different connector is not blocked.
    assert h.run("run_ai_data_access_mapping", a)[0] == 200


def test_repeated_runs_are_idempotent(_connector_rls) -> None:
    """Re-running neither duplicates records nor leaves an open job."""
    h = _connector_rls
    a, _ = _tenant_pair(h)
    count = "SELECT count(*) AS n FROM {} WHERE tenant_id = :t"
    for _ in range(2):
        for route, _, _ in _CONNECTOR_ROUTES:
            assert h.run(route, a)[0] == 200
    assert {j.status for j in h.jobs(a)} == {"complete"}
    assert len(h.jobs(a)) == 6
    for table in ("fa_external_ai_risk_records", "fa_ai_vendor_governance_records"):
        assert h.rows(count.format(table), t=a)[0].n == 1, table


def test_recover_orphans_cannot_recover_under_enforced_rls(_connector_rls) -> None:
    """Evaluation evidence: global orphan recovery sees nothing as the app role.

    DurableJobService.recover_orphans() scans every tenant without binding a
    tenant, so under forced RLS and a non-BYPASSRLS role it finds no rows. It
    is also not invoked by application code. Synchronous connectors therefore
    terminate their own interrupted runs, tenant-scoped (see
    test_interrupted_run_is_terminated_not_rerun).
    """
    from services.field_assessment.durable_job_service import durable_job_svc

    h = _connector_rls
    a, _ = _tenant_pair(h)
    stale = _insert_running_job(
        h, a, "external_ai_risk_register", "2000-01-01T00:00:00Z"
    )
    db = h.session(None)
    try:
        assert durable_job_svc.recover_orphans(db) == 0
        db.commit()
    finally:
        db.close()
    assert {j.id: j.status for j in h.jobs(a)} == {stale: "running"}


@pytest.mark.parametrize("route", [r[0] for r in _CONNECTOR_ROUTES])
def test_each_connector_failure_ends_terminal_with_one_audit(
    _connector_rls, monkeypatch, route: str
) -> None:
    """Every connector: queued -> running -> dead_letter, one scan.failed, no leak."""
    import api.field_assessment as fa

    h = _connector_rls
    a, _ = _tenant_pair(h)
    routes = [r[0] for r in _CONNECTOR_ROUTES]
    for prerequisite in routes[: routes.index(route)]:
        assert h.run(prerequisite, a)[0] == 200
    before = {j.id for j in h.jobs(a)}

    def _boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("synthetic evidence-link failure")

    monkeypatch.setattr(fa, "_auto_link_scan_evidence", _boom)
    status, body = h.run(route, a)
    assert status == 500 and "synthetic" not in str(body)
    (job,) = [j for j in h.jobs(a) if j.id not in before]
    assert job.status == "dead_letter" and job.scan_result_id is None
    assert job.attempt_count == 1  # it was claimed (running) before failing
    events = [e for e in h.audit(a) if e[2] == job.id]
    assert sorted(e[1] for e in events) == ["scan.failed", "scan.initiated"]


# ── Admission serialization (Codex P2 on #929) ──────────────────────────────
# Two overlapping requests must not both pass the live-run check. Sessions are
# genuinely concurrent: separate threads, separate pooled connections, real
# Postgres row locks.


def _slow_risk_engine(monkeypatch, seconds: float = 1.5) -> None:
    """Keep an admitted run in its work phase long enough to overlap."""
    import time

    from services.connectors.external_ai_risk_register import risk_engine

    real = risk_engine.generate_risk_records

    def _slow(**kwargs: Any) -> Any:
        time.sleep(seconds)
        return real(**kwargs)

    monkeypatch.setattr(risk_engine, "generate_risk_records", _slow)


def _run_concurrently(h: _ConnectorRls, calls: list[tuple[str, str]]) -> list[Any]:
    import threading
    from concurrent.futures import ThreadPoolExecutor

    start = threading.Barrier(len(calls))

    def _one(call: tuple[str, str]) -> Any:
        start.wait(timeout=10)
        return h.run(*call)

    with ThreadPoolExecutor(max_workers=len(calls)) as pool:
        return list(pool.map(_one, calls))


def _engagement_lock_free(h: _ConnectorRls, tenant: str) -> bool:
    """True if the tenant's engagement row can be locked without waiting."""
    from sqlalchemy.exc import OperationalError

    db = h.session(tenant)
    try:
        row = db.execute(
            text("SELECT id FROM fa_engagements WHERE id = :e FOR UPDATE NOWAIT"),
            {"e": h.eng[tenant]},
        ).fetchone()
        assert row is not None
        return True
    except OperationalError:
        return False
    finally:
        db.rollback()
        db.close()


def test_overlapping_admissions_admit_exactly_one(_connector_rls, monkeypatch) -> None:
    """Both requests evaluate the live-run check at the same moment; one wins.

    A rendezvous after has_live_running() forces the race Codex described:
    without serialization both requests see "no live run" and both start
    (reproduced on the pre-fix head 793859a81). With the admission lock the
    second request cannot reach the check until the first has committed its
    running job, so it gets a controlled 409.
    """
    import contextlib
    import threading

    import api.field_assessment as fa

    h = _connector_rls
    a, _ = _tenant_pair(h)
    _slow_risk_engine(monkeypatch)
    real_live = fa.durable_job_svc.has_live_running
    rendezvous = threading.Barrier(2, timeout=2)

    def _check_then_meet(*args: Any, **kwargs: Any) -> bool:
        live = real_live(*args, **kwargs)
        with contextlib.suppress(threading.BrokenBarrierError):
            rendezvous.wait()
        return live

    monkeypatch.setattr(fa.durable_job_svc, "has_live_running", _check_then_meet)
    results = _run_concurrently(h, [("run_external_ai_risk_register", a)] * 2)
    statuses = sorted(s for s, _ in results)
    assert statuses == [200, 409], results
    (rejected,) = [b for s, b in results if s == 409]
    assert rejected["code"] == "SCAN_ALREADY_RUNNING"
    (job,) = h.jobs(a)  # exactly one job was ever created
    assert job.status == "complete" and job.attempt_count == 1
    events = [e[1] for e in h.audit(a)]
    assert events.count("scan.initiated") == 1 and events.count("scan.completed") == 1
    assert _engagement_lock_free(h, a)


def test_concurrent_burst_admits_exactly_one(_connector_rls, monkeypatch) -> None:
    """Five simultaneous requests: one job, one result, four controlled 409s.

    A regression check under natural timing, not the reproduction (the burst
    alone did not reproduce the race on the pre-fix head; the rendezvous test
    above does).
    """
    h = _connector_rls
    a, _ = _tenant_pair(h)
    _slow_risk_engine(monkeypatch)
    results = _run_concurrently(h, [("run_external_ai_risk_register", a)] * 5)
    assert sorted(s for s, _ in results) == [200, 409, 409, 409, 409], results
    assert {b["code"] for s, b in results if s == 409} == {"SCAN_ALREADY_RUNNING"}
    assert [j.status for j in h.jobs(a)] == ["complete"]
    assert (
        h.rows(
            "SELECT count(*) AS n FROM fa_external_ai_risk_records WHERE tenant_id = :t",
            t=a,
        )[0].n
        == 1
    )
    assert _engagement_lock_free(h, a)


def test_admission_lock_is_bounded_and_released(_connector_rls, monkeypatch) -> None:
    """Lock contention yields 409 with nothing written; the lock never outlives
    the initiation commit (free during the work phase and after every outcome)."""
    import api.field_assessment as fa
    from services.connectors.external_ai_risk_register import risk_engine

    h = _connector_rls
    a, _ = _tenant_pair(h)
    monkeypatch.setattr(fa, "_SYNC_CONNECTOR_LOCK_TIMEOUT_MS", 300)
    holder = h.session(a)  # e.g. a concurrent engagement edit holding the row
    try:
        holder.execute(
            text("SELECT id FROM fa_engagements WHERE id = :e FOR UPDATE"),
            {"e": h.eng[a]},
        )
        status, body = h.run("run_external_ai_risk_register", a)
        assert status == 409 and body["code"] == "SCAN_ADMISSION_BUSY"
        assert h.jobs(a) == [] and h.audit(a) == []  # nothing admitted
    finally:
        holder.rollback()
        holder.close()
    assert _engagement_lock_free(h, a)

    real = risk_engine.generate_risk_records
    free_during_work: list[bool] = []

    def _probe(**kwargs: Any) -> Any:
        free_during_work.append(_engagement_lock_free(h, a))
        return real(**kwargs)

    monkeypatch.setattr(risk_engine, "generate_risk_records", _probe)
    assert h.run("run_external_ai_risk_register", a)[0] == 200
    assert free_during_work == [True]  # not held while the connector works
    assert _engagement_lock_free(h, a)

    live = _insert_running_job(h, a, "ai_data_access_mapping", "2999-01-01T00:00:00Z")
    assert h.run("run_ai_data_access_mapping", a)[1]["code"] == "SCAN_ALREADY_RUNNING"
    assert _engagement_lock_free(h, a)  # released on the 409 path
    with h.su.begin() as conn:
        conn.execute(text("DELETE FROM fa_scan_jobs WHERE id = :j"), {"j": live})

    def _boom(**_: Any) -> Any:
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(risk_engine, "generate_risk_records", _boom)
    assert h.run("run_external_ai_risk_register", a)[0] == 500
    assert _engagement_lock_free(h, a)  # released on the failure path


def test_admission_lock_is_tenant_scoped(_connector_rls) -> None:
    """Tenant B is neither blocked by nor able to lock tenant A's engagement."""
    h = _connector_rls
    a, b = _tenant_pair(h)
    holder = h.session(a)
    try:
        holder.execute(
            text("SELECT id FROM fa_engagements WHERE id = :e FOR UPDATE"),
            {"e": h.eng[a]},
        )
        assert h.run("run_external_ai_risk_register", b)[0] == 200  # not blocked
        foreign = h.session(b)
        try:
            row = foreign.execute(
                text("SELECT id FROM fa_engagements WHERE id = :e FOR UPDATE NOWAIT"),
                {"e": h.eng[a]},
            ).fetchone()
            assert row is None  # RLS hides the row; no lock, no wait, no error
        finally:
            foreign.rollback()
            foreign.close()
    finally:
        holder.rollback()
        holder.close()
    results = _run_concurrently(
        h, [("run_ai_data_access_mapping", a), ("run_ai_data_access_mapping", b)]
    )
    assert [s for s, _ in results] == [200, 200]  # different tenants both run
    assert {
        j.tenant
        for j in h.rows(
            "SELECT tenant_id AS tenant FROM fa_scan_jobs WHERE scanner_type ="
            " 'ai_data_access_mapping' AND tenant_id IN (:a, :b)",
            a=a,
            b=b,
        )
    } == {a, b}


def test_expired_lease_supersedes_an_in_flight_run(_connector_rls, monkeypatch) -> None:
    """A run that outlives its lease is terminated by the next admission and is
    never also reported complete; exactly one run's outcome is recorded."""
    from services.connectors.external_ai_risk_register import risk_engine

    h = _connector_rls
    a, _ = _tenant_pair(h)
    real = risk_engine.generate_risk_records
    second: list[Any] = []
    nested = [False]

    def _lease_expires_mid_run(**kwargs: Any) -> Any:
        if not nested[0]:
            nested[0] = True  # only the first (outer) run triggers this
            with h.su.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE fa_scan_jobs SET lease_expires_at ="
                        " '2000-01-01T00:00:00Z' WHERE tenant_id = :t"
                        " AND status = 'running'"
                    ),
                    {"t": a},
                )
            second.append(h.run("run_external_ai_risk_register", a))
        return real(**kwargs)

    monkeypatch.setattr(risk_engine, "generate_risk_records", _lease_expires_mid_run)
    status, body = h.run("run_external_ai_risk_register", a)
    assert second[0][0] == 200  # the later admission ran to completion
    assert status == 409 and body["code"] == "SCAN_JOB_SUPERSEDED", body
    jobs = h.jobs(a)
    assert sorted(j.status for j in jobs) == ["complete", "dead_letter"]
    (stale,) = [j for j in jobs if j.status == "dead_letter"]
    assert stale.scan_result_id is None
    failed = [e for e in h.audit(a) if e[1] == "scan.failed"]
    assert failed == [("external_ai_risk_register", "scan.failed", stale.id)]
    (reason,) = h.rows(
        "SELECT failure_reason FROM fa_scan_jobs WHERE id = :j", j=stale.id
    )
    assert reason.failure_reason.startswith("STALE_LEASE_EXPIRED")
    assert (
        h.rows(
            "SELECT count(*) AS n FROM fa_external_ai_risk_records WHERE tenant_id = :t",
            t=a,
        )[0].n
        == 1
    )


@pytest.mark.parametrize("kind", ["exception", "database"])
def test_failure_details_never_persist_or_log(
    _connector_rls, monkeypatch, caplog, kind: str
) -> None:
    """Exception text (SQL, bound parameters, payload data) reaches neither the
    job record, the audit ledger, the log nor the response."""
    import logging

    import api.field_assessment as fa

    h = _connector_rls
    a, _ = _tenant_pair(h)
    marker = f"SENSITIVE-{uuid.uuid4().hex}"
    real = fa.import_ai_data_access_mapping_scan

    def _fail(*, db, **kwargs: Any) -> Any:
        real(db=db, **kwargs)
        if kind == "database":  # the driver error embeds the bound parameter
            db.execute(text("SELECT CAST(:m AS integer)"), {"m": marker})
        raise RuntimeError(f"token={marker} payload={marker}")

    monkeypatch.setattr(fa, "import_ai_data_access_mapping_scan", _fail)
    caplog.set_level(logging.DEBUG)
    status, body = h.run("run_ai_data_access_mapping", a)
    assert status == 500 and body["code"] == "MAPPING_FAILED"
    (job,) = h.jobs(a)
    (reason,) = h.rows(
        "SELECT failure_reason FROM fa_scan_jobs WHERE id = :j", j=job.id
    )
    expected = "DataError" if kind == "database" else "RuntimeError"
    assert reason.failure_reason == f"CONNECTOR_FAILED: {expected}"
    audit = h.rows(
        "SELECT row_to_json(e)::text AS j FROM fa_scan_audit_events e"
        " WHERE tenant_id = :t",
        t=a,
    )
    assert audit and all(marker not in r.j for r in audit)
    assert any("CONNECTOR_FAILED" in r.j for r in audit)  # the code is recorded
    assert marker not in caplog.text
    assert marker not in str(body)
