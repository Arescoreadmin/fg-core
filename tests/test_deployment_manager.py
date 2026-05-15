"""Tests for the Deployment Manager Foundation (PR 80).

Covers:
- Deployment lifecycle state transitions (valid + invalid)
- Audit event creation on every mutation
- Rollback lineage integrity
- Environment isolation (tenant-dedicated vs platform-level)
- Tenant isolation (cross-tenant access denied)
- Serialization safety (no secrets in API responses)
- Deployment health state handling
- Approval hook behavior (approval gate blocks deploying without grant)
- Safe failure behavior (store errors map to deterministic HTTP codes)

All tests run offline against an in-memory SQLite DB.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "dev")
os.environ.setdefault("FG_AUTH_ENABLED", "0")
os.environ.setdefault("FG_SQLITE_PATH", "state/test_deployment_manager.db")
os.environ.setdefault("FG_RL_ENABLED", "0")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.db_models import Base
from services.deployment import (
    ComplianceClassification,
    DeploymentState,
    DeploymentStore,
    DeploymentStrategy,
    EnvironmentType,
    HealthResult,
    VALID_TRANSITIONS,
)
from services.deployment.models import validate_transition
from services.deployment.store import (
    ApprovalRequired,
    DeploymentNotFound,
    EnvironmentNotFound,
    InvalidStateTransition,
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
    return DeploymentStore()


@pytest.fixture()
def platform_env(store, db):
    """Platform-level (no tenant) dev environment."""
    env = store.create_environment(
        db,
        env_type=EnvironmentType.DEV,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op-key-abc123",
    )
    db.commit()
    return env


@pytest.fixture()
def prod_env(store, db):
    """Production environment — requires approval."""
    env = store.create_environment(
        db,
        env_type=EnvironmentType.PRODUCTION,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op-key-abc123",
    )
    db.commit()
    return env


@pytest.fixture()
def tenant_env(store, db):
    """Tenant-dedicated environment for tenant 'acme'."""
    env = store.create_environment(
        db,
        env_type=EnvironmentType.TENANT_DEDICATED,
        region="eu-west-1",
        compliance_classification=ComplianceClassification.HIPAA,
        created_by="op-key-abc123",
        tenant_id="acme",
    )
    db.commit()
    return env


@pytest.fixture()
def pending_deployment(store, db, platform_env):
    dep = store.create_deployment(
        db,
        env_id=platform_env.env_id,
        version_ref="v1.2.3",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op-key-abc123",
    )
    db.commit()
    return dep


# ---------------------------------------------------------------------------
# State machine — valid transitions
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_valid_transitions_are_enumerated():
    """Every DeploymentState must appear in VALID_TRANSITIONS."""
    for state in DeploymentState:
        assert state in VALID_TRANSITIONS, (
            f"DeploymentState.{state.name} missing from VALID_TRANSITIONS"
        )


@pytest.mark.smoke
def test_terminal_states_have_no_outbound():
    """failed and rolled_back must be terminal (no outbound transitions)."""
    assert VALID_TRANSITIONS[DeploymentState.FAILED] == frozenset()
    assert VALID_TRANSITIONS[DeploymentState.ROLLED_BACK] == frozenset()


@pytest.mark.smoke
def test_valid_pending_to_validating(store, db, pending_deployment):
    dep = store.transition_state(
        db,
        deployment_id=pending_deployment.deployment_id,
        to_state=DeploymentState.VALIDATING,
        actor="op-key-abc123",
    )
    db.commit()
    assert dep.state == DeploymentState.VALIDATING


@pytest.mark.smoke
def test_valid_full_happy_path(store, db, pending_deployment):
    dep_id = pending_deployment.deployment_id

    for state in (
        DeploymentState.VALIDATING,
        DeploymentState.DEPLOYING,
        DeploymentState.HEALTHY,
    ):
        store.transition_state(db, deployment_id=dep_id, to_state=state, actor="op")
    db.commit()
    dep = store.get_deployment(db, deployment_id=dep_id)
    assert dep.state == DeploymentState.HEALTHY
    assert dep.completed_at is not None


@pytest.mark.smoke
def test_valid_degraded_to_rolled_back(store, db, pending_deployment):
    dep_id = pending_deployment.deployment_id
    for state in (
        DeploymentState.VALIDATING,
        DeploymentState.DEPLOYING,
        DeploymentState.DEGRADED,
    ):
        store.transition_state(db, deployment_id=dep_id, to_state=state, actor="op")
    store.transition_state(
        db,
        deployment_id=dep_id,
        to_state=DeploymentState.ROLLED_BACK,
        actor="op",
    )
    db.commit()
    dep = store.get_deployment(db, deployment_id=dep_id)
    assert dep.state == DeploymentState.ROLLED_BACK
    assert dep.completed_at is not None


# ---------------------------------------------------------------------------
# State machine — invalid transitions
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_invalid_pending_to_healthy_raises(store, db, pending_deployment):
    with pytest.raises(InvalidStateTransition):
        store.transition_state(
            db,
            deployment_id=pending_deployment.deployment_id,
            to_state=DeploymentState.HEALTHY,
            actor="op",
        )


@pytest.mark.smoke
def test_invalid_failed_to_any_raises():
    """Failed is terminal — any transition from it is invalid."""
    for target in DeploymentState:
        if target == DeploymentState.FAILED:
            continue
        with pytest.raises(ValueError):
            validate_transition(DeploymentState.FAILED, target)


@pytest.mark.smoke
def test_invalid_rolled_back_to_any_raises():
    """Rolled_back is terminal — any transition from it is invalid."""
    for target in DeploymentState:
        if target == DeploymentState.ROLLED_BACK:
            continue
        with pytest.raises(ValueError):
            validate_transition(DeploymentState.ROLLED_BACK, target)


@pytest.mark.smoke
def test_same_state_transition_is_invalid(store, db, pending_deployment):
    """Transitioning to the current state is not allowed."""
    with pytest.raises(InvalidStateTransition):
        store.transition_state(
            db,
            deployment_id=pending_deployment.deployment_id,
            to_state=DeploymentState.PENDING,
            actor="op",
        )


# ---------------------------------------------------------------------------
# Audit event creation
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_create_deployment_emits_created_event(store, db, platform_env):
    dep = store.create_deployment(
        db,
        env_id=platform_env.env_id,
        version_ref="v1.0.0",
        strategy=DeploymentStrategy.DIRECT,
        initiated_by="op-key",
    )
    db.commit()

    events = store.list_events(db, deployment_id=dep.deployment_id)
    assert len(events) == 1
    assert events[0].event_type.value == "created"
    assert events[0].actor == "op-key"
    assert events[0].to_state == DeploymentState.PENDING


@pytest.mark.smoke
def test_state_transition_emits_event(store, db, pending_deployment):
    dep_id = pending_deployment.deployment_id
    store.transition_state(
        db,
        deployment_id=dep_id,
        to_state=DeploymentState.VALIDATING,
        actor="op-key",
    )
    db.commit()

    events = store.list_events(db, deployment_id=dep_id)
    transition_events = [e for e in events if e.event_type.value == "state_transition"]
    assert len(transition_events) == 1
    assert transition_events[0].from_state == DeploymentState.PENDING
    assert transition_events[0].to_state == DeploymentState.VALIDATING


@pytest.mark.smoke
def test_health_record_emits_event(store, db, pending_deployment):
    store.record_health(
        db,
        deployment_id=pending_deployment.deployment_id,
        readiness_result=HealthResult.PASS,
        liveness_result=HealthResult.PASS,
        smoke_test_result=HealthResult.PASS,
        validation_result=HealthResult.PASS,
        checked_by="monitor-key",
    )
    db.commit()

    events = store.list_events(db, deployment_id=pending_deployment.deployment_id)
    health_events = [e for e in events if e.event_type.value == "health_recorded"]
    assert len(health_events) == 1
    assert health_events[0].actor == "monitor-key"


@pytest.mark.smoke
def test_approval_grant_emits_event(store, db, prod_env):
    dep = store.create_deployment(
        db,
        env_id=prod_env.env_id,
        version_ref="v2.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )
    db.commit()

    store.record_approval(
        db,
        deployment_id=dep.deployment_id,
        approved=True,
        actor="approver-key",
    )
    db.commit()

    events = store.list_events(db, deployment_id=dep.deployment_id)
    approval_events = [e for e in events if "approval" in e.event_type.value]
    assert len(approval_events) == 1
    assert approval_events[0].event_type.value == "approval_granted"


# ---------------------------------------------------------------------------
# Rollback lineage
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_rollback_lineage_single_hop(store, db, platform_env):
    dep1 = store.create_deployment(
        db,
        env_id=platform_env.env_id,
        version_ref="v1.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )
    db.commit()

    dep2 = store.create_deployment(
        db,
        env_id=platform_env.env_id,
        version_ref="v1.1.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
        rollback_from_id=dep1.deployment_id,
        rollback_reason="smoke test failure",
    )
    db.commit()

    lineage = store.get_rollback_lineage(db, deployment_id=dep2.deployment_id)
    assert len(lineage) == 2
    assert lineage[0].deployment_id == dep2.deployment_id
    assert lineage[1].deployment_id == dep1.deployment_id


@pytest.mark.smoke
def test_rollback_lineage_no_parent(store, db, platform_env):
    dep = store.create_deployment(
        db,
        env_id=platform_env.env_id,
        version_ref="v1.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )
    db.commit()

    lineage = store.get_rollback_lineage(db, deployment_id=dep.deployment_id)
    assert len(lineage) == 1
    assert lineage[0].deployment_id == dep.deployment_id


@pytest.mark.smoke
def test_rollback_lineage_respects_depth_cap(store, db, platform_env):
    dep_ids: list[str] = []
    prev_id = None
    for i in range(25):
        dep = store.create_deployment(
            db,
            env_id=platform_env.env_id,
            version_ref=f"v{i}.0",
            strategy=DeploymentStrategy.DIRECT,
            initiated_by="op",
            rollback_from_id=prev_id,
        )
        dep_ids.append(dep.deployment_id)
        prev_id = dep.deployment_id
    db.commit()

    lineage = store.get_rollback_lineage(db, deployment_id=dep_ids[-1], max_depth=10)
    assert len(lineage) <= 10


# ---------------------------------------------------------------------------
# Environment isolation
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_platform_env_visible_to_any_tenant(store, db, platform_env):
    env = store.get_environment(db, env_id=platform_env.env_id, tenant_id="acme")
    assert env.env_id == platform_env.env_id


@pytest.mark.smoke
def test_tenant_env_visible_to_owning_tenant(store, db, tenant_env):
    env = store.get_environment(db, env_id=tenant_env.env_id, tenant_id="acme")
    assert env.env_id == tenant_env.env_id


@pytest.mark.smoke
def test_tenant_env_not_visible_to_other_tenant(store, db, tenant_env):
    with pytest.raises(EnvironmentNotFound):
        store.get_environment(db, env_id=tenant_env.env_id, tenant_id="other-tenant")


@pytest.mark.smoke
def test_production_env_requires_approval(store, db, prod_env):
    assert prod_env.requires_approval() is True


@pytest.mark.smoke
def test_dev_env_does_not_require_approval(store, db, platform_env):
    assert platform_env.requires_approval() is False


@pytest.mark.smoke
def test_hipaa_env_requires_approval(store, db, tenant_env):
    # tenant_env is HIPAA-classified TENANT_DEDICATED — always requires approval.
    assert tenant_env.requires_approval() is True


# ---------------------------------------------------------------------------
# Tenant isolation — deployment records
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_deployment_not_visible_to_wrong_tenant(store, db):
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    with Session(eng) as s2:
        env = store.create_environment(
            s2,
            env_type=EnvironmentType.DEV,
            region="us-east-1",
            compliance_classification=ComplianceClassification.STANDARD,
            created_by="op",
            tenant_id="tenant-a",
        )
        dep = store.create_deployment(
            s2,
            env_id=env.env_id,
            version_ref="v1.0",
            strategy=DeploymentStrategy.ROLLING,
            initiated_by="op",
            tenant_id="tenant-a",
        )
        s2.commit()

        with pytest.raises(DeploymentNotFound):
            store.get_deployment(
                s2, deployment_id=dep.deployment_id, tenant_id="tenant-b"
            )
    eng.dispose()


# ---------------------------------------------------------------------------
# Approval gate
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_approval_gate_blocks_deploying_without_grant(store, db, prod_env):
    dep = store.create_deployment(
        db,
        env_id=prod_env.env_id,
        version_ref="v1.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )
    db.commit()
    assert dep.approval_required is True

    store.transition_state(
        db,
        deployment_id=dep.deployment_id,
        to_state=DeploymentState.VALIDATING,
        actor="op",
    )
    db.commit()

    with pytest.raises(ApprovalRequired):
        store.transition_state(
            db,
            deployment_id=dep.deployment_id,
            to_state=DeploymentState.DEPLOYING,
            actor="op",
        )


@pytest.mark.smoke
def test_approval_gate_allows_deploying_after_grant(store, db, prod_env):
    dep = store.create_deployment(
        db,
        env_id=prod_env.env_id,
        version_ref="v1.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )
    db.commit()

    store.transition_state(
        db,
        deployment_id=dep.deployment_id,
        to_state=DeploymentState.VALIDATING,
        actor="op",
    )
    store.record_approval(
        db, deployment_id=dep.deployment_id, approved=True, actor="approver"
    )
    dep2 = store.transition_state(
        db,
        deployment_id=dep.deployment_id,
        to_state=DeploymentState.DEPLOYING,
        actor="op",
    )
    db.commit()
    assert dep2.state == DeploymentState.DEPLOYING


@pytest.mark.smoke
def test_dev_env_skips_approval_gate(store, db, platform_env):
    dep = store.create_deployment(
        db,
        env_id=platform_env.env_id,
        version_ref="v1.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )
    db.commit()
    assert dep.approval_required is False

    store.transition_state(
        db,
        deployment_id=dep.deployment_id,
        to_state=DeploymentState.VALIDATING,
        actor="op",
    )
    dep2 = store.transition_state(
        db,
        deployment_id=dep.deployment_id,
        to_state=DeploymentState.DEPLOYING,
        actor="op",
    )
    db.commit()
    assert dep2.state == DeploymentState.DEPLOYING


# ---------------------------------------------------------------------------
# Health record handling
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_health_fail_does_not_auto_transition(store, db, pending_deployment):
    """Recording a failing health check does NOT auto-transition state.

    State changes are explicit operator actions only.
    """
    store.record_health(
        db,
        deployment_id=pending_deployment.deployment_id,
        readiness_result=HealthResult.FAIL,
        liveness_result=HealthResult.FAIL,
        smoke_test_result=HealthResult.FAIL,
        validation_result=HealthResult.FAIL,
        checked_by="monitor",
        rollback_trigger_reason="all probes failed",
    )
    db.commit()

    dep = store.get_deployment(db, deployment_id=pending_deployment.deployment_id)
    assert dep.state == DeploymentState.PENDING, (
        "Health check failure must not auto-transition state"
    )


@pytest.mark.smoke
def test_health_record_stores_rollback_trigger_reason(store, db, pending_deployment):
    record = store.record_health(
        db,
        deployment_id=pending_deployment.deployment_id,
        readiness_result=HealthResult.FAIL,
        liveness_result=HealthResult.UNKNOWN,
        smoke_test_result=HealthResult.SKIP,
        validation_result=HealthResult.SKIP,
        checked_by="monitor",
        rollback_trigger_reason="readiness probe timeout",
    )
    db.commit()
    assert record.rollback_trigger_reason == "readiness probe timeout"


@pytest.mark.smoke
def test_multiple_health_records_ordered_desc(store, db, pending_deployment):
    for i in range(3):
        store.record_health(
            db,
            deployment_id=pending_deployment.deployment_id,
            readiness_result=HealthResult.PASS,
            liveness_result=HealthResult.PASS,
            smoke_test_result=HealthResult.SKIP,
            validation_result=HealthResult.SKIP,
            checked_by=f"monitor-{i}",
        )
    db.commit()

    records = store.list_health_records(
        db, deployment_id=pending_deployment.deployment_id
    )
    assert len(records) == 3
    # Most recent first (desc order)
    assert records[0].checked_by == "monitor-2"


# ---------------------------------------------------------------------------
# Not-found behavior
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_get_deployment_not_found(store, db):
    with pytest.raises(DeploymentNotFound):
        store.get_deployment(db, deployment_id="nonexistent-id")


@pytest.mark.smoke
def test_get_environment_not_found(store, db):
    with pytest.raises(EnvironmentNotFound):
        store.get_environment(db, env_id="nonexistent-env")


@pytest.mark.smoke
def test_transition_not_found(store, db):
    with pytest.raises(DeploymentNotFound):
        store.transition_state(
            db,
            deployment_id="no-such-id",
            to_state=DeploymentState.VALIDATING,
            actor="op",
        )


# ---------------------------------------------------------------------------
# Serialization safety — API responses
# ---------------------------------------------------------------------------


@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    from api.auth_scopes import mint_key
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "deploy_api_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    app = build_app(auth_enabled=True)
    key = mint_key("control-plane:read", "control-plane:admin")
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


@pytest.mark.smoke
def test_list_environments_returns_200(api_client):
    resp = api_client.get("/control-plane/deployments/environments")
    assert resp.status_code == 200
    body = resp.json()
    assert "environments" in body
    assert isinstance(body["environments"], list)


@pytest.mark.smoke
def test_create_environment_returns_201(api_client):
    resp = api_client.post(
        "/control-plane/deployments/environments",
        json={
            "env_type": "dev",
            "region": "us-east-1",
            "compliance_classification": "standard",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert "env_id" in body
    assert body["env_type"] == "dev"


@pytest.mark.smoke
def test_create_deployment_returns_201(api_client):
    env_resp = api_client.post(
        "/control-plane/deployments/environments",
        json={"env_type": "dev", "region": "us-east-1"},
    )
    assert env_resp.status_code == 201
    env_id = env_resp.json()["env_id"]

    resp = api_client.post(
        "/control-plane/deployments",
        json={"env_id": env_id, "version_ref": "v1.0.0", "strategy": "rolling"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["state"] == "pending"
    assert body["version_ref"] == "v1.0.0"


@pytest.mark.smoke
def test_api_response_contains_no_secrets(api_client):
    """API responses must not expose secrets, credentials, or internal topology."""
    env_resp = api_client.post(
        "/control-plane/deployments/environments",
        json={"env_type": "dev", "region": "us-east-1"},
    )
    env_id = env_resp.json()["env_id"]
    dep_resp = api_client.post(
        "/control-plane/deployments",
        json={"env_id": env_id, "version_ref": "v1.0.0"},
    )
    body_text = dep_resp.text

    forbidden_patterns = [
        "password",
        "secret",
        "api_key",
        "token",
        "credential",
        "private_key",
        "authorization",
    ]
    for pattern in forbidden_patterns:
        assert pattern not in body_text.lower(), (
            f"Deployment API response contains forbidden field pattern: {pattern!r}"
        )


@pytest.mark.smoke
def test_get_deployment_not_found_returns_404(api_client):
    resp = api_client.get("/control-plane/deployments/no-such-id")
    assert resp.status_code == 404
    body = resp.json()
    assert "DEPLOY-API-001" in str(body)


@pytest.mark.smoke
def test_invalid_state_transition_returns_409(api_client):
    env_resp = api_client.post(
        "/control-plane/deployments/environments",
        json={"env_type": "dev", "region": "us-east-1"},
    )
    env_id = env_resp.json()["env_id"]
    dep_resp = api_client.post(
        "/control-plane/deployments",
        json={"env_id": env_id, "version_ref": "v1.0.0"},
    )
    dep_id = dep_resp.json()["deployment_id"]

    # pending → healthy is invalid
    resp = api_client.post(
        f"/control-plane/deployments/{dep_id}/transition",
        json={"to_state": "healthy"},
    )
    assert resp.status_code == 409
    body = resp.json()
    assert "DEPLOY-API-003" in str(body)


@pytest.mark.smoke
def test_unknown_env_type_returns_422(api_client):
    resp = api_client.post(
        "/control-plane/deployments/environments",
        json={"env_type": "not-a-real-env", "region": "us-east-1"},
    )
    assert resp.status_code == 422


@pytest.mark.smoke
def test_extra_fields_rejected(api_client):
    resp = api_client.post(
        "/control-plane/deployments/environments",
        json={
            "env_type": "dev",
            "region": "us-east-1",
            "injection_field": "should be rejected",
        },
    )
    assert resp.status_code == 422


@pytest.mark.smoke
def test_deployment_history_returns_events(api_client):
    env_resp = api_client.post(
        "/control-plane/deployments/environments",
        json={"env_type": "dev", "region": "us-east-1"},
    )
    env_id = env_resp.json()["env_id"]
    dep_resp = api_client.post(
        "/control-plane/deployments",
        json={"env_id": env_id, "version_ref": "v1.0.0"},
    )
    dep_id = dep_resp.json()["deployment_id"]

    resp = api_client.get(f"/control-plane/deployments/{dep_id}/history")
    assert resp.status_code == 200
    body = resp.json()
    assert "events" in body
    assert len(body["events"]) >= 1
    assert body["events"][0]["event_type"] == "created"


@pytest.mark.smoke
def test_rollback_lineage_endpoint(api_client):
    env_resp = api_client.post(
        "/control-plane/deployments/environments",
        json={"env_type": "dev", "region": "us-east-1"},
    )
    env_id = env_resp.json()["env_id"]
    dep1_resp = api_client.post(
        "/control-plane/deployments",
        json={"env_id": env_id, "version_ref": "v1.0.0"},
    )
    dep1_id = dep1_resp.json()["deployment_id"]

    dep2_resp = api_client.post(
        "/control-plane/deployments",
        json={
            "env_id": env_id,
            "version_ref": "v1.1.0",
            "rollback_from_id": dep1_id,
            "rollback_reason": "regression detected",
        },
    )
    dep2_id = dep2_resp.json()["deployment_id"]

    resp = api_client.get(f"/control-plane/deployments/{dep2_id}/rollback-lineage")
    assert resp.status_code == 200
    body = resp.json()
    lineage = body["lineage"]
    assert len(lineage) == 2
    assert lineage[0]["deployment_id"] == dep2_id
    assert lineage[1]["deployment_id"] == dep1_id


@pytest.mark.smoke
def test_health_endpoint_create_and_retrieve(api_client):
    env_resp = api_client.post(
        "/control-plane/deployments/environments",
        json={"env_type": "dev", "region": "us-east-1"},
    )
    env_id = env_resp.json()["env_id"]
    dep_resp = api_client.post(
        "/control-plane/deployments",
        json={"env_id": env_id, "version_ref": "v1.0.0"},
    )
    dep_id = dep_resp.json()["deployment_id"]

    post_resp = api_client.post(
        f"/control-plane/deployments/{dep_id}/health",
        json={
            "readiness_result": "pass",
            "liveness_result": "pass",
            "smoke_test_result": "pass",
            "validation_result": "pass",
        },
    )
    assert post_resp.status_code == 201
    assert post_resp.json()["readiness_result"] == "pass"

    get_resp = api_client.get(f"/control-plane/deployments/{dep_id}/health")
    assert get_resp.status_code == 200
    records = get_resp.json()["health_records"]
    assert len(records) == 1
    assert records[0]["readiness_result"] == "pass"


@pytest.mark.smoke
def test_list_deployments_pagination(api_client):
    env_resp = api_client.post(
        "/control-plane/deployments/environments",
        json={"env_type": "dev", "region": "us-east-1"},
    )
    env_id = env_resp.json()["env_id"]
    for i in range(5):
        api_client.post(
            "/control-plane/deployments",
            json={"env_id": env_id, "version_ref": f"v{i}.0.0"},
        )

    resp = api_client.get("/control-plane/deployments?limit=3&offset=0")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["deployments"]) <= 3
    assert body["limit"] == 3
