"""Tests for the Ops Governance Manager Foundation (PR 82).

Covers:
- Environment lifecycle state machine (valid + invalid transitions)
- Secret governance registration and state transitions
- Key rotation scheduling and outcome recording
- Retention policy creation, legal hold, and transitions
- Export request creation and state transitions
- Backup and restore record creation
- Recovery record creation and state transitions
- Tenant isolation (cross-tenant access denied)
- Audit event hash chain integrity
- Serialization safety (no raw secrets in responses)
- Optimistic locking (concurrency protection)
- LegalHoldViolation enforcement
- ValidationTokenRequired for failed_recovery → active
- Idempotency key tenant scoping
- API surface (all routes)
- Invalid input rejection (extra fields, bad slug, missing required)

All tests run offline against an in-memory SQLite DB.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "dev")
os.environ.setdefault("FG_AUTH_ENABLED", "0")
os.environ.setdefault("FG_SQLITE_PATH", "state/test_ops_governance_manager.db")
os.environ.setdefault("FG_RL_ENABLED", "0")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.db_models import Base
from services.ops_governance import (
    BackupScope,
    ComplianceClassification,
    EnvironmentLifecycleState,
    ExportClassification,
    ExportScope,
    ExportState,
    OpsGovernanceStore,
    RecoveryState,
    RecoveryType,
    RetentionState,
    RotationOutcome,
    SecretClassification,
    SecretLifecycleState,
    SecretType,
    validate_env_transition,
    validate_secret_transition,
)
from services.ops_governance.models import (
    VALID_ENV_TRANSITIONS,
    VALID_EXPORT_TRANSITIONS,
    VALID_RECOVERY_TRANSITIONS,
    VALID_RETENTION_TRANSITIONS,
    VALID_SECRET_TRANSITIONS,
    RestoreState,
)
from services.ops_governance.store import (
    ConcurrentModificationError,
    DuplicateSlug,
    EnvironmentNotFound,
    InvalidStateTransition,
    LegalHoldViolation,
    ValidationTokenRequired,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    with Session(engine) as session:
        yield session


@pytest.fixture()
def store():
    return OpsGovernanceStore()


@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    from api.auth_scopes import mint_key
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "ops_gov_api_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    app = build_app(auth_enabled=True)
    key = mint_key("control-plane:read", "control-plane:admin")
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


# ---------------------------------------------------------------------------
# 1. State machine coverage
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_all_env_states_in_valid_transitions():
    for state in EnvironmentLifecycleState:
        assert state in VALID_ENV_TRANSITIONS, (
            f"EnvironmentLifecycleState.{state.name} missing from VALID_ENV_TRANSITIONS"
        )


@pytest.mark.smoke
def test_archived_env_is_terminal():
    assert VALID_ENV_TRANSITIONS[EnvironmentLifecycleState.ARCHIVED] == frozenset()


@pytest.mark.smoke
def test_all_secret_states_in_valid_transitions():
    for state in SecretLifecycleState:
        assert state in VALID_SECRET_TRANSITIONS, (
            f"SecretLifecycleState.{state.name} missing from VALID_SECRET_TRANSITIONS"
        )


@pytest.mark.smoke
def test_all_retention_states_in_valid_transitions():
    for state in RetentionState:
        assert state in VALID_RETENTION_TRANSITIONS, (
            f"RetentionState.{state.name} missing from VALID_RETENTION_TRANSITIONS"
        )


@pytest.mark.smoke
def test_all_export_states_in_valid_transitions():
    for state in ExportState:
        assert state in VALID_EXPORT_TRANSITIONS, (
            f"ExportState.{state.name} missing from VALID_EXPORT_TRANSITIONS"
        )


@pytest.mark.smoke
def test_all_recovery_states_in_valid_transitions():
    for state in RecoveryState:
        assert state in VALID_RECOVERY_TRANSITIONS, (
            f"RecoveryState.{state.name} missing from VALID_RECOVERY_TRANSITIONS"
        )


@pytest.mark.smoke
def test_valid_env_transitions():
    validate_env_transition(
        EnvironmentLifecycleState.PROVISIONING, EnvironmentLifecycleState.ACTIVE
    )
    validate_env_transition(
        EnvironmentLifecycleState.ACTIVE, EnvironmentLifecycleState.MAINTENANCE
    )
    validate_env_transition(
        EnvironmentLifecycleState.ACTIVE, EnvironmentLifecycleState.ARCHIVED
    )


@pytest.mark.smoke
def test_invalid_env_transition_raises():
    with pytest.raises(ValueError):
        validate_env_transition(
            EnvironmentLifecycleState.ARCHIVED, EnvironmentLifecycleState.ACTIVE
        )


@pytest.mark.smoke
def test_invalid_secret_transition_raises():
    with pytest.raises(ValueError):
        validate_secret_transition(
            SecretLifecycleState.ARCHIVED, SecretLifecycleState.ACTIVE
        )


# ---------------------------------------------------------------------------
# 2. Store — environment CRUD
# ---------------------------------------------------------------------------


def test_create_and_get_environment(db, store):
    env = store.create_environment(
        db,
        env_name="prod-west",
        slug="prod-west",
        created_by="op1",
        tenant_id="t1",
    )
    db.commit()

    assert env.environment_id is not None
    assert env.lifecycle_state == EnvironmentLifecycleState.PROVISIONING
    assert env.tenant_id == "t1"

    fetched = store.get_environment(db, env_id=env.environment_id, tenant_id="t1")
    assert fetched.environment_id == env.environment_id
    assert fetched.env_name == "prod-west"


def test_duplicate_slug_raises(db, store):
    store.create_environment(db, env_name="e1", slug="shared-slug", created_by="op1")
    db.commit()
    with pytest.raises(DuplicateSlug):
        store.create_environment(
            db, env_name="e2", slug="shared-slug", created_by="op1"
        )


def test_environment_not_found_raises(db, store):
    with pytest.raises(EnvironmentNotFound):
        store.get_environment(db, env_id="nonexistent")


def test_list_environments_tenant_scoped(db, store):
    store.create_environment(
        db, env_name="e-t1", slug="e-t1", created_by="op", tenant_id="t1"
    )
    store.create_environment(
        db, env_name="e-t2", slug="e-t2", created_by="op", tenant_id="t2"
    )
    db.commit()
    results_t1 = store.list_environments(db, tenant_id="t1")
    assert all(e.tenant_id == "t1" or e.tenant_id is None for e in results_t1)
    env_names = [e.env_name for e in results_t1]
    assert "e-t2" not in env_names


def test_transition_environment_state(db, store):
    env = store.create_environment(
        db, env_name="env1", slug="env1", created_by="op", tenant_id="t1"
    )
    db.commit()

    updated = store.transition_environment_state(
        db,
        env_id=env.environment_id,
        to_state=EnvironmentLifecycleState.ACTIVE,
        actor="op",
        tenant_id="t1",
    )
    db.commit()
    assert updated.lifecycle_state == EnvironmentLifecycleState.ACTIVE


def test_invalid_env_transition_at_store(db, store):
    env = store.create_environment(
        db, env_name="e2", slug="e2", created_by="op", tenant_id="t1"
    )
    db.commit()
    # Archived is terminal; can't go to ACTIVE.
    store.transition_environment_state(
        db,
        env_id=env.environment_id,
        to_state=EnvironmentLifecycleState.ACTIVE,
        actor="op",
        tenant_id="t1",
    )
    store.transition_environment_state(
        db,
        env_id=env.environment_id,
        to_state=EnvironmentLifecycleState.ARCHIVED,
        actor="op",
        tenant_id="t1",
    )
    db.commit()
    with pytest.raises(InvalidStateTransition):
        store.transition_environment_state(
            db,
            env_id=env.environment_id,
            to_state=EnvironmentLifecycleState.ACTIVE,
            actor="op",
            tenant_id="t1",
        )


def test_failed_recovery_to_active_requires_validation_token(db, store):
    env = store.create_environment(db, env_name="e3", slug="e3", created_by="op")
    db.commit()
    # provisioning -> active -> maintenance -> failed_recovery
    store.transition_environment_state(
        db,
        env_id=env.environment_id,
        to_state=EnvironmentLifecycleState.ACTIVE,
        actor="op",
    )
    store.transition_environment_state(
        db,
        env_id=env.environment_id,
        to_state=EnvironmentLifecycleState.MAINTENANCE,
        actor="op",
    )
    store.transition_environment_state(
        db,
        env_id=env.environment_id,
        to_state=EnvironmentLifecycleState.FAILED_RECOVERY,
        actor="op",
    )
    db.commit()
    with pytest.raises(ValidationTokenRequired):
        store.transition_environment_state(
            db,
            env_id=env.environment_id,
            to_state=EnvironmentLifecycleState.ACTIVE,
            actor="op",
        )


def test_failed_recovery_to_active_with_valid_token(db, store):
    env = store.create_environment(db, env_name="e4", slug="e4", created_by="op")
    db.commit()
    store.transition_environment_state(
        db,
        env_id=env.environment_id,
        to_state=EnvironmentLifecycleState.ACTIVE,
        actor="op",
    )
    store.transition_environment_state(
        db,
        env_id=env.environment_id,
        to_state=EnvironmentLifecycleState.MAINTENANCE,
        actor="op",
    )
    store.transition_environment_state(
        db,
        env_id=env.environment_id,
        to_state=EnvironmentLifecycleState.FAILED_RECOVERY,
        actor="op",
    )
    db.commit()
    store.set_environment_validation_token(
        db,
        env_id=env.environment_id,
        actor="admin",
        validation_token="secret-token-123",
    )
    db.commit()
    updated = store.transition_environment_state(
        db,
        env_id=env.environment_id,
        to_state=EnvironmentLifecycleState.ACTIVE,
        actor="op",
        validation_token="secret-token-123",
    )
    db.commit()
    assert updated.lifecycle_state == EnvironmentLifecycleState.ACTIVE
    # Token must be consumed.
    assert updated.validation_token is None


def test_env_idempotency_tenant_scoped(db, store):
    env_t1 = store.create_environment(
        db,
        env_name="e-idem",
        slug="e-idem-t1",
        created_by="op",
        tenant_id="t1",
        idempotency_key="idem-key-env",
    )
    db.commit()
    env_t2 = store.create_environment(
        db,
        env_name="e-idem",
        slug="e-idem-t2",
        created_by="op",
        tenant_id="t2",
        idempotency_key="idem-key-env",
    )
    db.commit()
    # Same key, different tenant → different records.
    assert env_t1.environment_id != env_t2.environment_id
    # Replaying same key for same tenant → same record.
    replay = store.create_environment(
        db,
        env_name="e-idem",
        slug="e-idem-t1-replay",
        created_by="op",
        tenant_id="t1",
        idempotency_key="idem-key-env",
    )
    assert replay.environment_id == env_t1.environment_id


def test_env_optimistic_locking(db, store):
    from unittest.mock import patch
    import sqlalchemy.orm.query as q_mod

    env = store.create_environment(
        db, env_name="e-lock", slug="e-lock", created_by="op"
    )
    db.commit()

    original_update = q_mod.Query.update
    intercepted: list[bool] = []

    def _zero_on_first(self, values, synchronize_session="evaluate"):
        if not intercepted and isinstance(values, dict) and "state_version" in values:
            intercepted.append(True)
            return 0  # simulate concurrent modification
        return original_update(self, values, synchronize_session=synchronize_session)

    with patch.object(q_mod.Query, "update", _zero_on_first):
        with pytest.raises(ConcurrentModificationError):
            store.transition_environment_state(
                db,
                env_id=env.environment_id,
                to_state=EnvironmentLifecycleState.ACTIVE,
                actor="op",
            )


def test_env_audit_hash_chain(db, store):
    env = store.create_environment(
        db, env_name="e-chain", slug="e-chain", created_by="op", tenant_id="t1"
    )
    db.commit()
    store.transition_environment_state(
        db,
        env_id=env.environment_id,
        to_state=EnvironmentLifecycleState.ACTIVE,
        actor="op",
        tenant_id="t1",
    )
    db.commit()
    events = store.list_environment_history(
        db, env_id=env.environment_id, tenant_id="t1"
    )
    assert len(events) == 2
    assert events[0].event_hash is not None
    assert events[1].previous_event_hash == events[0].event_hash


# ---------------------------------------------------------------------------
# 3. Store — secret governance
# ---------------------------------------------------------------------------


def test_register_secret_governance(db, store):
    secret = store.register_secret_governance(
        db,
        secret_name="db-password",
        secret_classification=SecretClassification.CRITICAL,
        secret_type=SecretType.DB_CREDENTIAL,
        created_by="op",
        tenant_id="t1",
    )
    db.commit()
    assert secret.secret_governance_id is not None
    assert secret.lifecycle_state == SecretLifecycleState.ACTIVE
    assert secret.secret_name == "db-password"


def test_secret_governance_idempotency_tenant_scoped(db, store):
    s1 = store.register_secret_governance(
        db,
        secret_name="sk",
        secret_classification=SecretClassification.STANDARD,
        secret_type=SecretType.API_KEY,
        created_by="op",
        tenant_id="t1",
        idempotency_key="sk-idem",
    )
    db.commit()
    s2 = store.register_secret_governance(
        db,
        secret_name="sk",
        secret_classification=SecretClassification.STANDARD,
        secret_type=SecretType.API_KEY,
        created_by="op",
        tenant_id="t2",
        idempotency_key="sk-idem",
    )
    db.commit()
    assert s1.secret_governance_id != s2.secret_governance_id
    replay = store.register_secret_governance(
        db,
        secret_name="sk",
        secret_classification=SecretClassification.STANDARD,
        secret_type=SecretType.API_KEY,
        created_by="op",
        tenant_id="t1",
        idempotency_key="sk-idem",
    )
    assert replay.secret_governance_id == s1.secret_governance_id


def test_transition_secret_state(db, store):
    secret = store.register_secret_governance(
        db,
        secret_name="sk2",
        secret_classification=SecretClassification.STANDARD,
        secret_type=SecretType.API_KEY,
        created_by="op",
    )
    db.commit()
    updated = store.transition_secret_state(
        db,
        secret_id=secret.secret_governance_id,
        to_state=SecretLifecycleState.PENDING_ROTATION,
        actor="op",
    )
    db.commit()
    assert updated.lifecycle_state == SecretLifecycleState.PENDING_ROTATION


def test_archived_secret_is_terminal(db, store):
    secret = store.register_secret_governance(
        db,
        secret_name="sk3",
        secret_classification=SecretClassification.STANDARD,
        secret_type=SecretType.API_KEY,
        created_by="op",
    )
    db.commit()
    store.transition_secret_state(
        db,
        secret_id=secret.secret_governance_id,
        to_state=SecretLifecycleState.REVOKED,
        actor="op",
    )
    store.transition_secret_state(
        db,
        secret_id=secret.secret_governance_id,
        to_state=SecretLifecycleState.ARCHIVED,
        actor="op",
    )
    db.commit()
    with pytest.raises(InvalidStateTransition):
        store.transition_secret_state(
            db,
            secret_id=secret.secret_governance_id,
            to_state=SecretLifecycleState.ACTIVE,
            actor="op",
        )


def test_secret_response_contains_no_secret_values(db, store):
    secret = store.register_secret_governance(
        db,
        secret_name="api-key-name",
        secret_classification=SecretClassification.STANDARD,
        secret_type=SecretType.API_KEY,
        created_by="op",
        external_reference_id="ref-but-not-value",
    )
    db.commit()
    # The external_reference_id (pointer, not value) should be persisted,
    # but no actual key material should exist in any domain field.
    assert not hasattr(secret, "secret_value")
    assert not hasattr(secret, "key_material")
    assert not hasattr(secret, "raw_credential")


# ---------------------------------------------------------------------------
# 4. Store — key rotation
# ---------------------------------------------------------------------------


def test_schedule_key_rotation(db, store):
    from datetime import datetime, timezone

    secret = store.register_secret_governance(
        db,
        secret_name="rot-key",
        secret_classification=SecretClassification.STANDARD,
        secret_type=SecretType.API_KEY,
        created_by="op",
    )
    db.commit()
    scheduled = datetime(2026, 6, 1, tzinfo=timezone.utc)
    rotation = store.schedule_key_rotation(
        db, secret_id=secret.secret_governance_id, scheduled_at=scheduled, actor="op"
    )
    db.commit()
    assert rotation.rotation_id is not None
    assert rotation.rotation_state.value == "scheduled"
    assert rotation.scheduled_at == scheduled


def test_record_rotation_outcome_success(db, store):
    from datetime import datetime, timezone

    secret = store.register_secret_governance(
        db,
        secret_name="rot-key2",
        secret_classification=SecretClassification.STANDARD,
        secret_type=SecretType.API_KEY,
        created_by="op",
    )
    db.commit()
    rotation = store.schedule_key_rotation(
        db,
        secret_id=secret.secret_governance_id,
        scheduled_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        actor="op",
    )
    db.commit()
    updated = store.record_rotation_outcome(
        db,
        rotation_id=rotation.rotation_id,
        outcome=RotationOutcome.SUCCESS,
        actor="op",
    )
    db.commit()
    assert updated.rotation_state.value == "completed"
    assert updated.outcome == RotationOutcome.SUCCESS


def test_emergency_rotation(db, store):
    from datetime import datetime, timezone

    secret = store.register_secret_governance(
        db,
        secret_name="emergency-key",
        secret_classification=SecretClassification.CRITICAL,
        secret_type=SecretType.SIGNING_KEY,
        created_by="op",
    )
    db.commit()
    rotation = store.schedule_key_rotation(
        db,
        secret_id=secret.secret_governance_id,
        scheduled_at=datetime(2026, 5, 15, tzinfo=timezone.utc),
        actor="op",
        emergency_rotation=True,
    )
    db.commit()
    assert rotation.emergency_rotation is True
    assert rotation.rotation_state.value == "emergency"


# ---------------------------------------------------------------------------
# 5. Store — retention policies
# ---------------------------------------------------------------------------


def test_create_retention_policy(db, store):
    policy = store.create_retention_policy(
        db,
        policy_name="standard-30d",
        retention_days=30,
        created_by="op",
        tenant_id="t1",
    )
    db.commit()
    assert policy.retention_policy_id is not None
    assert policy.retention_state == RetentionState.ACTIVE
    assert policy.legal_hold is False


def test_legal_hold_blocks_deletion_transition(db, store):
    policy = store.create_retention_policy(
        db,
        policy_name="held-policy",
        retention_days=90,
        created_by="op",
        tenant_id="t1",
    )
    db.commit()
    store.set_legal_hold(
        db,
        policy_id=policy.retention_policy_id,
        actor="legal",
        reason="litigation hold",
        tenant_id="t1",
    )
    db.commit()
    with pytest.raises(LegalHoldViolation):
        store.transition_retention_state(
            db,
            policy_id=policy.retention_policy_id,
            to_state=RetentionState.SCHEDULED_FOR_DELETION,
            actor="op",
            tenant_id="t1",
        )


def test_legal_hold_sets_policy_to_legal_hold_state(db, store):
    policy = store.create_retention_policy(
        db, policy_name="hold-state-policy", retention_days=90, created_by="op"
    )
    db.commit()
    updated = store.set_legal_hold(
        db,
        policy_id=policy.retention_policy_id,
        actor="legal",
        reason="regulatory hold",
    )
    db.commit()
    assert updated.legal_hold is True
    assert updated.retention_state == RetentionState.LEGAL_HOLD
    assert updated.legal_hold_set_by == "legal"


def test_retention_idempotency_tenant_scoped(db, store):
    p1 = store.create_retention_policy(
        db,
        policy_name="p",
        retention_days=30,
        created_by="op",
        tenant_id="t1",
        idempotency_key="p-idem",
    )
    db.commit()
    p2 = store.create_retention_policy(
        db,
        policy_name="p",
        retention_days=30,
        created_by="op",
        tenant_id="t2",
        idempotency_key="p-idem",
    )
    db.commit()
    assert p1.retention_policy_id != p2.retention_policy_id
    replay = store.create_retention_policy(
        db,
        policy_name="p",
        retention_days=30,
        created_by="op",
        tenant_id="t1",
        idempotency_key="p-idem",
    )
    assert replay.retention_policy_id == p1.retention_policy_id


# ---------------------------------------------------------------------------
# 6. Store — export requests
# ---------------------------------------------------------------------------


def test_create_export_request(db, store):
    export = store.create_export_request(
        db,
        export_scope=ExportScope.TENANT,
        export_classification=ExportClassification.STANDARD,
        requested_by="op",
        tenant_id="t1",
    )
    db.commit()
    assert export.export_id is not None
    assert export.export_state == ExportState.REQUESTED


def test_transition_export_approved(db, store):
    export = store.create_export_request(
        db,
        export_scope=ExportScope.TENANT,
        export_classification=ExportClassification.STANDARD,
        requested_by="op",
    )
    db.commit()
    # requested → validating → approved
    store.transition_export_state(
        db,
        export_id=export.export_id,
        to_state=ExportState.VALIDATING,
        actor="approver",
    )
    db.commit()
    updated = store.transition_export_state(
        db,
        export_id=export.export_id,
        to_state=ExportState.APPROVED,
        actor="approver",
        approval_reason="audit",
    )
    db.commit()
    assert updated.export_state == ExportState.APPROVED
    assert updated.approved_by == "approver"


def test_export_idempotency_tenant_scoped(db, store):
    e1 = store.create_export_request(
        db,
        export_scope=ExportScope.TENANT,
        export_classification=ExportClassification.STANDARD,
        requested_by="op",
        tenant_id="t1",
        idempotency_key="e-idem",
    )
    db.commit()
    e2 = store.create_export_request(
        db,
        export_scope=ExportScope.TENANT,
        export_classification=ExportClassification.STANDARD,
        requested_by="op",
        tenant_id="t2",
        idempotency_key="e-idem",
    )
    db.commit()
    assert e1.export_id != e2.export_id
    replay = store.create_export_request(
        db,
        export_scope=ExportScope.TENANT,
        export_classification=ExportClassification.STANDARD,
        requested_by="op",
        tenant_id="t1",
        idempotency_key="e-idem",
    )
    assert replay.export_id == e1.export_id


# ---------------------------------------------------------------------------
# 7. Store — backup records
# ---------------------------------------------------------------------------


def test_record_backup(db, store):
    backup = store.record_backup(
        db,
        backup_scope=BackupScope.FULL,
        backup_classification=ComplianceClassification.STANDARD,
        initiated_by="op",
        tenant_id="t1",
    )
    db.commit()
    assert backup.backup_id is not None
    assert backup.backup_state.value == "initiated"


def test_get_backup_record(db, store):
    backup = store.record_backup(
        db,
        backup_scope=BackupScope.INCREMENTAL,
        backup_classification=ComplianceClassification.STANDARD,
        initiated_by="op",
    )
    db.commit()
    fetched = store.get_backup_record(db, backup_id=backup.backup_id)
    assert fetched.backup_id == backup.backup_id
    assert fetched.backup_scope == BackupScope.INCREMENTAL


# ---------------------------------------------------------------------------
# 8. Store — restore records
# ---------------------------------------------------------------------------


def test_record_restore_attempt(db, store):
    backup = store.record_backup(
        db,
        backup_scope=BackupScope.FULL,
        backup_classification=ComplianceClassification.STANDARD,
        initiated_by="op",
    )
    db.commit()
    restore = store.record_restore_attempt(
        db, source_backup_id=backup.backup_id, initiated_by="op", tenant_id="t1"
    )
    db.commit()
    assert restore.restore_id is not None
    assert restore.source_backup_id == backup.backup_id
    assert restore.restore_state == RestoreState.INITIATED


def test_restore_response_no_backup_path(db, store):
    backup = store.record_backup(
        db,
        backup_scope=BackupScope.FULL,
        backup_classification=ComplianceClassification.STANDARD,
        initiated_by="op",
    )
    db.commit()
    restore = store.record_restore_attempt(
        db, source_backup_id=backup.backup_id, initiated_by="op"
    )
    assert not hasattr(restore, "backup_path")
    assert not hasattr(restore, "storage_location")
    assert not hasattr(restore, "storage_uri")


# ---------------------------------------------------------------------------
# 9. Store — recovery records
# ---------------------------------------------------------------------------


def test_initiate_recovery(db, store):
    record = store.initiate_recovery(
        db, recovery_type=RecoveryType.STANDARD, initiated_by="op", tenant_id="t1"
    )
    db.commit()
    assert record.recovery_id is not None
    assert record.recovery_state == RecoveryState.INITIATED
    assert record.drill_mode is False


def test_initiate_drill_mode_recovery(db, store):
    record = store.initiate_recovery(
        db,
        recovery_type=RecoveryType.DRILL,
        initiated_by="op",
        tenant_id="t1",
        drill_mode=True,
    )
    db.commit()
    assert record.drill_mode is True
    assert record.recovery_type == RecoveryType.DRILL


def test_transition_recovery_state(db, store):
    record = store.initiate_recovery(
        db, recovery_type=RecoveryType.STANDARD, initiated_by="op"
    )
    db.commit()
    # initiated → validating → validated
    store.transition_recovery_state(
        db,
        recovery_id=record.recovery_id,
        to_state=RecoveryState.VALIDATING,
        actor="op",
    )
    db.commit()
    updated = store.transition_recovery_state(
        db, recovery_id=record.recovery_id, to_state=RecoveryState.VALIDATED, actor="op"
    )
    db.commit()
    assert updated.recovery_state == RecoveryState.VALIDATED
    assert updated.validated_at is not None


def test_invalid_recovery_transition_raises(db, store):
    record = store.initiate_recovery(
        db, recovery_type=RecoveryType.STANDARD, initiated_by="op"
    )
    db.commit()
    # Go to a terminal state via: initiated → validating → validated → in_progress → completed
    store.transition_recovery_state(
        db,
        recovery_id=record.recovery_id,
        to_state=RecoveryState.VALIDATING,
        actor="op",
    )
    store.transition_recovery_state(
        db, recovery_id=record.recovery_id, to_state=RecoveryState.VALIDATED, actor="op"
    )
    store.transition_recovery_state(
        db,
        recovery_id=record.recovery_id,
        to_state=RecoveryState.IN_PROGRESS,
        actor="op",
    )
    store.transition_recovery_state(
        db, recovery_id=record.recovery_id, to_state=RecoveryState.COMPLETED, actor="op"
    )
    db.commit()
    with pytest.raises(InvalidStateTransition):
        store.transition_recovery_state(
            db,
            recovery_id=record.recovery_id,
            to_state=RecoveryState.VALIDATED,
            actor="op",
        )


# ---------------------------------------------------------------------------
# 10. API surface
# ---------------------------------------------------------------------------


def test_list_environments_empty(api_client):
    r = api_client.get("/control-plane/ops/environments")
    assert r.status_code == 200
    assert r.json()["environments"] == []


def test_create_environment_201(api_client):
    r = api_client.post(
        "/control-plane/ops/environments",
        json={"env_name": "staging", "slug": "staging"},
    )
    assert r.status_code == 201
    data = r.json()
    assert data["env_name"] == "staging"
    assert data["lifecycle_state"] == "provisioning"
    assert "validation_token" not in data


def test_get_environment_not_found(api_client):
    r = api_client.get("/control-plane/ops/environments/does-not-exist")
    assert r.status_code == 404


def test_create_environment_invalid_slug(api_client):
    r = api_client.post(
        "/control-plane/ops/environments",
        json={"env_name": "bad slug", "slug": "Bad Slug!"},
    )
    assert r.status_code == 422


def test_create_environment_extra_fields_rejected(api_client):
    r = api_client.post(
        "/control-plane/ops/environments",
        json={"env_name": "e", "slug": "e", "tenant_id": "injected"},
    )
    assert r.status_code == 422


def test_transition_environment_via_api(api_client):
    r = api_client.post(
        "/control-plane/ops/environments",
        json={"env_name": "e-api", "slug": "e-api"},
    )
    assert r.status_code == 201
    env_id = r.json()["environment_id"]

    r2 = api_client.post(
        f"/control-plane/ops/environments/{env_id}/transition",
        json={"to_state": "active"},
    )
    assert r2.status_code == 200
    assert r2.json()["lifecycle_state"] == "active"


def test_create_env_duplicate_slug_409(api_client):
    api_client.post(
        "/control-plane/ops/environments",
        json={"env_name": "dup", "slug": "dup-slug"},
    )
    r = api_client.post(
        "/control-plane/ops/environments",
        json={"env_name": "dup2", "slug": "dup-slug"},
    )
    assert r.status_code == 409


def test_list_secrets_empty(api_client):
    r = api_client.get("/control-plane/ops/secrets")
    assert r.status_code == 200
    assert r.json()["secrets"] == []


def test_register_secret_201(api_client):
    r = api_client.post(
        "/control-plane/ops/secrets",
        json={"secret_name": "my-api-key", "secret_type": "api_key"},
    )
    assert r.status_code == 201
    data = r.json()
    assert data["secret_name"] == "my-api-key"
    assert "secret_value" not in data
    assert "key_material" not in data
    assert data["lifecycle_state"] == "active"


def test_register_secret_extra_fields_rejected(api_client):
    r = api_client.post(
        "/control-plane/ops/secrets",
        json={"secret_name": "sk", "secret_type": "api_key", "tenant_id": "injected"},
    )
    assert r.status_code == 422


def test_transition_secret_state_api(api_client):
    r = api_client.post(
        "/control-plane/ops/secrets",
        json={"secret_name": "sk-trans", "secret_type": "api_key"},
    )
    assert r.status_code == 201
    sid = r.json()["secret_governance_id"]

    r2 = api_client.post(
        f"/control-plane/ops/secrets/{sid}/transition",
        json={"to_state": "pending_rotation"},
    )
    assert r2.status_code == 200
    assert r2.json()["lifecycle_state"] == "pending_rotation"


def test_create_retention_policy_201(api_client):
    r = api_client.post(
        "/control-plane/ops/retention-policies",
        json={"policy_name": "30-day", "retention_days": 30},
    )
    assert r.status_code == 201
    data = r.json()
    assert data["retention_days"] == 30
    assert data["legal_hold"] is False


def test_retention_transition_api(api_client):
    r = api_client.post(
        "/control-plane/ops/retention-policies",
        json={"policy_name": "trans-policy", "retention_days": 90},
    )
    assert r.status_code == 201
    pid = r.json()["retention_policy_id"]

    r2 = api_client.post(
        f"/control-plane/ops/retention-policies/{pid}/transition",
        json={"to_state": "scheduled_for_deletion"},
    )
    assert r2.status_code == 200
    assert r2.json()["retention_state"] == "scheduled_for_deletion"


def test_create_export_request_201(api_client):
    r = api_client.post(
        "/control-plane/ops/exports",
        json={"export_scope": "tenant", "export_classification": "standard"},
    )
    assert r.status_code == 201
    data = r.json()
    assert data["export_state"] == "requested"


def test_export_approve_api(api_client):
    r = api_client.post(
        "/control-plane/ops/exports",
        json={"export_scope": "tenant"},
    )
    assert r.status_code == 201
    eid = r.json()["export_id"]
    assert r.json()["export_state"] == "requested"

    # requested → validating → approved
    api_client.post(
        f"/control-plane/ops/exports/{eid}/transition",
        json={"to_state": "validating"},
    )
    r2 = api_client.post(
        f"/control-plane/ops/exports/{eid}/transition",
        json={"to_state": "approved", "approval_reason": "compliance audit"},
    )
    assert r2.status_code == 200
    assert r2.json()["export_state"] == "approved"


def test_initiate_backup_201(api_client):
    r = api_client.post(
        "/control-plane/ops/backups",
        json={"backup_scope": "full"},
    )
    assert r.status_code == 201
    data = r.json()
    assert data["backup_state"] == "initiated"
    assert "backup_path" not in data
    assert "storage_location" not in data


def test_initiate_restore_201(api_client):
    # Create a backup first.
    rb = api_client.post("/control-plane/ops/backups", json={"backup_scope": "full"})
    backup_id = rb.json()["backup_id"]

    r = api_client.post(
        "/control-plane/ops/restores",
        json={"source_backup_id": backup_id},
    )
    assert r.status_code == 201
    data = r.json()
    assert data["source_backup_id"] == backup_id
    assert data["restore_state"] == "initiated"


def test_initiate_recovery_201(api_client):
    r = api_client.post(
        "/control-plane/ops/recoveries",
        json={"recovery_type": "standard"},
    )
    assert r.status_code == 201
    data = r.json()
    assert data["recovery_state"] == "initiated"
    assert data["drill_mode"] is False


def test_transition_recovery_api(api_client):
    r = api_client.post(
        "/control-plane/ops/recoveries",
        json={"recovery_type": "standard"},
    )
    assert r.status_code == 201
    rid = r.json()["recovery_id"]

    # initiated → validating → validated
    api_client.post(
        f"/control-plane/ops/recoveries/{rid}/transition",
        json={"to_state": "validating"},
    )
    r2 = api_client.post(
        f"/control-plane/ops/recoveries/{rid}/transition",
        json={"to_state": "validated"},
    )
    assert r2.status_code == 200
    assert r2.json()["recovery_state"] == "validated"


def test_env_history_via_api(api_client):
    r = api_client.post(
        "/control-plane/ops/environments",
        json={"env_name": "hist-env", "slug": "hist-env"},
    )
    env_id = r.json()["environment_id"]

    r2 = api_client.get(f"/control-plane/ops/environments/{env_id}/history")
    assert r2.status_code == 200
    events = r2.json()["events"]
    assert len(events) >= 1
    assert events[0]["event_hash"] is not None


def test_validation_token_gate_via_api(api_client):
    r = api_client.post(
        "/control-plane/ops/environments",
        json={"env_name": "fr-env", "slug": "fr-env"},
    )
    env_id = r.json()["environment_id"]
    # provisioning -> active -> maintenance -> failed_recovery
    api_client.post(
        f"/control-plane/ops/environments/{env_id}/transition",
        json={"to_state": "active"},
    )
    api_client.post(
        f"/control-plane/ops/environments/{env_id}/transition",
        json={"to_state": "maintenance"},
    )
    api_client.post(
        f"/control-plane/ops/environments/{env_id}/transition",
        json={"to_state": "failed_recovery"},
    )
    # Attempting active without token must return 422.
    r2 = api_client.post(
        f"/control-plane/ops/environments/{env_id}/transition",
        json={"to_state": "active"},
    )
    assert r2.status_code == 422


def test_read_only_scope_blocks_write(tmp_path, monkeypatch):
    from api.auth_scopes import mint_key
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "ops_gov_ro.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    app = build_app(auth_enabled=True)
    ro_key = mint_key("control-plane:read")
    client = TestClient(
        app, raise_server_exceptions=False, headers={"X-API-Key": ro_key}
    )

    r = client.post(
        "/control-plane/ops/environments",
        json={"env_name": "blocked", "slug": "blocked"},
    )
    assert r.status_code in (401, 403)


def test_ops_router_has_required_routes():
    from api.ops_governance_manager import router

    paths = {r.path for r in router.routes}
    required = {
        "/control-plane/ops/environments",
        "/control-plane/ops/environments/{env_id}",
        "/control-plane/ops/environments/{env_id}/transition",
        "/control-plane/ops/environments/{env_id}/history",
        "/control-plane/ops/secrets",
        "/control-plane/ops/secrets/{secret_id}",
        "/control-plane/ops/retention-policies",
        "/control-plane/ops/exports",
        "/control-plane/ops/backups",
        "/control-plane/ops/restores",
        "/control-plane/ops/recoveries",
    }
    missing = required - paths
    assert not missing, f"Missing ops routes: {missing}"
    assert len(router.routes) >= 20, f"Expected ≥20 routes, got {len(router.routes)}"
