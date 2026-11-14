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
            su.execute(
                text(
                    "DELETE FROM tenant_identity_audit_events WHERE tenant_id IN (:m, :c)"
                ),
                {"m": msp, "c": cust},
            )
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
