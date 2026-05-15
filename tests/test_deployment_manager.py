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


# ===========================================================================
# PR 80 Hardening — new tests for items 1–10
# ===========================================================================


# ---------------------------------------------------------------------------
# 1. Approval Integrity Hardening
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_approval_integrity_fields_stored(store, db):
    """approval_granted_at, approval_reason, approval_policy_version are persisted."""
    env = store.create_environment(
        db,
        env_type=EnvironmentType.PRODUCTION,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op",
    )
    dep = store.create_deployment(
        db,
        env_id=env.env_id,
        version_ref="v1.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )
    assert dep.approval_required is True

    updated = store.record_approval(
        db,
        deployment_id=dep.deployment_id,
        approved=True,
        actor="approver-1",
        approval_reason="reviewed by security team",
        approval_policy_version="policy-v2.3",
    )
    assert updated.approval_granted_by == "approver-1"
    assert updated.approval_granted_at is not None
    assert updated.approval_reason == "reviewed by security team"
    assert updated.approval_policy_version == "policy-v2.3"


@pytest.mark.smoke
def test_approval_denial_stores_reason(store, db):
    env = store.create_environment(
        db,
        env_type=EnvironmentType.PRODUCTION,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op",
    )
    dep = store.create_deployment(
        db,
        env_id=env.env_id,
        version_ref="v1.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )
    assert dep.approval_required is True
    updated = store.record_approval(
        db,
        deployment_id=dep.deployment_id,
        approved=False,
        actor="auditor",
        approval_reason="failed compliance review",
        approval_policy_version="policy-v2.3",
    )
    # reason/version stored, granted_by never set
    assert updated.approval_granted_by is None
    assert updated.approval_reason == "failed compliance review"
    assert updated.approval_policy_version == "policy-v2.3"
    # approval-required deployment transitions to FAILED on denial
    assert updated.state == DeploymentState.FAILED
    assert updated.completed_at is not None


def test_approval_denial_increments_state_version(store, db):
    env = store.create_environment(
        db,
        env_type=EnvironmentType.PRODUCTION,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op",
    )
    dep = store.create_deployment(
        db,
        env_id=env.env_id,
        version_ref="v1.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )
    initial_version = dep.state_version
    updated = store.record_approval(
        db,
        deployment_id=dep.deployment_id,
        approved=False,
        actor="auditor",
    )
    assert updated.state_version == initial_version + 1


def test_denied_deployment_cannot_transition_to_deploying(store, db):
    env = store.create_environment(
        db,
        env_type=EnvironmentType.PRODUCTION,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op",
    )
    dep = store.create_deployment(
        db,
        env_id=env.env_id,
        version_ref="v1.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )
    store.record_approval(
        db,
        deployment_id=dep.deployment_id,
        approved=False,
        actor="auditor",
        approval_reason="denied",
    )
    db.commit()
    # Deployment is now FAILED — any further transition must raise.
    with pytest.raises(Exception):
        store.transition_state(
            db,
            deployment_id=dep.deployment_id,
            to_state=DeploymentState.DEPLOYING,
            actor="op",
        )


def test_approval_denial_emits_denial_and_transition_events(store, db):
    env = store.create_environment(
        db,
        env_type=EnvironmentType.PRODUCTION,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op",
    )
    dep = store.create_deployment(
        db,
        env_id=env.env_id,
        version_ref="v1.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )
    store.record_approval(
        db,
        deployment_id=dep.deployment_id,
        approved=False,
        actor="auditor",
        approval_reason="denied",
    )
    db.commit()
    events = store.list_events(db, deployment_id=dep.deployment_id)
    event_types = [e.event_type.value for e in events]
    assert "approval_denied" in event_types
    assert "state_transition" in event_types
    # state_transition event records the failed terminal state
    transition_ev = next(
        e
        for e in events
        if e.event_type.value == "state_transition"
        and e.to_state
        and e.to_state.value == "failed"
    )
    assert transition_ev.from_state is not None


def test_rollback_lineage_missing_initial_raises_not_found(store, db):
    with pytest.raises(Exception) as exc_info:
        store.get_rollback_lineage(db, deployment_id="does-not-exist")
    assert "does-not-exist" in str(exc_info.value)


def test_rollback_lineage_missing_initial_returns_404_api(api_client):
    resp = api_client.get("/control-plane/deployments/does-not-exist/rollback-lineage")
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "DEPLOY-API-001"


def test_rollback_lineage_missing_ancestor_returns_partial(store, db):
    """Valid initial deployment with a dangling rollback_from_id stops cleanly."""
    env = store.create_environment(
        db,
        env_type=EnvironmentType.DEV,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op",
    )
    dep = store.create_deployment(
        db,
        env_id=env.env_id,
        version_ref="v1.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
        rollback_from_id="nonexistent-ancestor",
    )
    db.commit()
    # The store enforces rollback_from_id exists, so patch it directly.
    from api.db_models import DeploymentRecordORM

    db.query(DeploymentRecordORM).filter(
        DeploymentRecordORM.deployment_id == dep.deployment_id
    ).update(
        {"rollback_from_id": "nonexistent-ancestor"}, synchronize_session="evaluate"
    )
    db.commit()

    lineage = store.get_rollback_lineage(db, deployment_id=dep.deployment_id)
    # Initial deployment is in chain; missing ancestor stops traversal.
    assert len(lineage) == 1
    assert lineage[0].deployment_id == dep.deployment_id


# ---------------------------------------------------------------------------
# 2. Immutable Deployment Spec Snapshot
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_spec_snapshot_stored_and_retrieved(store, db):
    from services.deployment.models import DeploymentSpec

    env = store.create_environment(
        db,
        env_type=EnvironmentType.DEV,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op",
    )
    spec = DeploymentSpec(
        image_digest="a" * 64,
        commit_sha="b" * 40,
        contract_hash="c" * 64,
        topology_hash="d" * 64,
        policy_bundle_version="bundle-v1.2",
        migration_fingerprint="mig-abc123",
    )
    dep = store.create_deployment(
        db,
        env_id=env.env_id,
        version_ref="v2.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
        spec=spec,
    )
    assert dep.spec.image_digest == "a" * 64
    assert dep.spec.commit_sha == "b" * 40
    assert dep.spec.contract_hash == "c" * 64
    assert dep.spec.topology_hash == "d" * 64
    assert dep.spec.policy_bundle_version == "bundle-v1.2"
    assert dep.spec.migration_fingerprint == "mig-abc123"


@pytest.mark.smoke
def test_spec_persists_through_state_transition(store, db):
    from services.deployment.models import DeploymentSpec

    env = store.create_environment(
        db,
        env_type=EnvironmentType.DEV,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op",
    )
    spec = DeploymentSpec(commit_sha="e" * 40)
    dep = store.create_deployment(
        db,
        env_id=env.env_id,
        version_ref="v1.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
        spec=spec,
    )
    updated = store.transition_state(
        db,
        deployment_id=dep.deployment_id,
        to_state=DeploymentState.VALIDATING,
        actor="ci",
    )
    assert updated.spec.commit_sha == "e" * 40


# ---------------------------------------------------------------------------
# 3. Event hash chaining (tamper-evident audit trail)
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_events_have_hash_chain(store, db):
    env = store.create_environment(
        db,
        env_type=EnvironmentType.DEV,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op",
    )
    dep = store.create_deployment(
        db,
        env_id=env.env_id,
        version_ref="v1.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )
    store.transition_state(
        db,
        deployment_id=dep.deployment_id,
        to_state=DeploymentState.VALIDATING,
        actor="ci",
    )
    events = store.list_events(db, deployment_id=dep.deployment_id)
    assert len(events) >= 2
    # First event has no previous hash
    assert events[0].event_hash is not None
    assert events[0].previous_event_hash is None
    # Second event chains to first
    assert events[1].previous_event_hash == events[0].event_hash


@pytest.mark.smoke
def test_event_hashes_are_distinct(store, db):
    env = store.create_environment(
        db,
        env_type=EnvironmentType.DEV,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op",
    )
    dep = store.create_deployment(
        db,
        env_id=env.env_id,
        version_ref="v1.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )
    store.transition_state(
        db,
        deployment_id=dep.deployment_id,
        to_state=DeploymentState.VALIDATING,
        actor="ci",
    )
    events = store.list_events(db, deployment_id=dep.deployment_id)
    hashes = [e.event_hash for e in events if e.event_hash]
    assert len(hashes) == len(set(hashes)), "all event hashes must be unique"


# ---------------------------------------------------------------------------
# 4. Concurrency protection (optimistic locking)
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_concurrent_modification_guard_fires_on_zero_rowcount(store, db):
    """ConcurrentModificationError fires when the ORM update returns 0 rows.

    SQLite's single-connection "read your own writes" makes it impossible to
    simulate a true concurrent race in a unit test. We patch Query.update to
    return 0 — the exact condition that occurs in production when two workers
    race on the same deployment and one commits first.
    """
    from unittest.mock import patch

    import sqlalchemy.orm.query as q_mod

    from services.deployment.store import ConcurrentModificationError

    env = store.create_environment(
        db,
        env_type=EnvironmentType.DEV,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op",
    )
    dep = store.create_deployment(
        db,
        env_id=env.env_id,
        version_ref="v1.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )

    original_update = q_mod.Query.update
    intercepted: list[bool] = []

    def _zero_on_first(self, values, synchronize_session="evaluate"):
        if not intercepted and isinstance(values, dict) and "state_version" in values:
            intercepted.append(True)
            return 0
        return original_update(self, values, synchronize_session=synchronize_session)

    with patch.object(q_mod.Query, "update", _zero_on_first):
        with pytest.raises(ConcurrentModificationError):
            store.transition_state(
                db,
                deployment_id=dep.deployment_id,
                to_state=DeploymentState.VALIDATING,
                actor="stale-worker",
            )


@pytest.mark.smoke
def test_state_version_increments_on_each_transition(store, db):
    env = store.create_environment(
        db,
        env_type=EnvironmentType.DEV,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op",
    )
    dep = store.create_deployment(
        db,
        env_id=env.env_id,
        version_ref="v1.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )
    assert dep.state_version == 0
    v1 = store.transition_state(
        db,
        deployment_id=dep.deployment_id,
        to_state=DeploymentState.VALIDATING,
        actor="ci",
    )
    assert v1.state_version == 1
    v2 = store.transition_state(
        db,
        deployment_id=dep.deployment_id,
        to_state=DeploymentState.DEPLOYING,
        actor="ci",
    )
    assert v2.state_version == 2


# ---------------------------------------------------------------------------
# 5. Strategy governance
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_direct_strategy_forbidden_in_production(store, db):
    from services.deployment.store import StrategyGovernanceViolation

    env = store.create_environment(
        db,
        env_type=EnvironmentType.PRODUCTION,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op",
    )
    with pytest.raises(StrategyGovernanceViolation):
        store.create_deployment(
            db,
            env_id=env.env_id,
            version_ref="v1.0.0",
            strategy=DeploymentStrategy.DIRECT,
            initiated_by="op",
        )


@pytest.mark.smoke
def test_direct_strategy_forbidden_for_hipaa(store, db):
    from services.deployment.store import StrategyGovernanceViolation

    env = store.create_environment(
        db,
        env_type=EnvironmentType.DEV,
        region="us-east-1",
        compliance_classification=ComplianceClassification.HIPAA,
        created_by="op",
    )
    with pytest.raises(StrategyGovernanceViolation):
        store.create_deployment(
            db,
            env_id=env.env_id,
            version_ref="v1.0.0",
            strategy=DeploymentStrategy.DIRECT,
            initiated_by="op",
        )


@pytest.mark.smoke
def test_rolling_strategy_allowed_everywhere(store, db):
    for env_type in (
        EnvironmentType.DEV,
        EnvironmentType.STAGING,
        EnvironmentType.PRODUCTION,
    ):
        env = store.create_environment(
            db,
            env_type=env_type,
            region="us-east-1",
            compliance_classification=ComplianceClassification.STANDARD,
            created_by="op",
        )
        dep = store.create_deployment(
            db,
            env_id=env.env_id,
            version_ref="v1.0.0",
            strategy=DeploymentStrategy.ROLLING,
            initiated_by="op",
        )
        assert dep.strategy == DeploymentStrategy.ROLLING


@pytest.mark.smoke
def test_fedramp_forbids_canary_strategy(store, db):
    from services.deployment.store import StrategyGovernanceViolation

    env = store.create_environment(
        db,
        env_type=EnvironmentType.DEV,
        region="us-gov-west-1",
        compliance_classification=ComplianceClassification.FEDRAMP,
        created_by="op",
    )
    with pytest.raises(StrategyGovernanceViolation):
        store.create_deployment(
            db,
            env_id=env.env_id,
            version_ref="v1.0.0",
            strategy=DeploymentStrategy.CANARY,
            initiated_by="op",
        )


# ---------------------------------------------------------------------------
# 6. Health probe retention (expires_at TTL)
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_health_record_expires_at_stored(store, db):
    from datetime import timezone

    env = store.create_environment(
        db,
        env_type=EnvironmentType.DEV,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op",
    )
    dep = store.create_deployment(
        db,
        env_id=env.env_id,
        version_ref="v1.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )
    from datetime import datetime, timedelta

    expiry = datetime.now(timezone.utc) + timedelta(days=30)
    record = store.record_health(
        db,
        deployment_id=dep.deployment_id,
        readiness_result=HealthResult.PASS,
        liveness_result=HealthResult.PASS,
        smoke_test_result=HealthResult.SKIP,
        validation_result=HealthResult.SKIP,
        checked_by="probe-agent",
        expires_at=expiry,
    )
    assert record.expires_at is not None
    assert record.expires_at.year == expiry.year


# ---------------------------------------------------------------------------
# 7. Classification enforcement
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_classification_policies_cover_all_classifications(store, db):
    from services.deployment.models import (
        CLASSIFICATION_POLICIES,
        ComplianceClassification,
    )

    for classification in ComplianceClassification:
        assert classification in CLASSIFICATION_POLICIES, (
            f"{classification} missing from CLASSIFICATION_POLICIES"
        )


@pytest.mark.smoke
def test_fedramp_policy_requires_approval_depth_2():
    from services.deployment.models import (
        CLASSIFICATION_POLICIES,
        ComplianceClassification,
    )

    policy = CLASSIFICATION_POLICIES[ComplianceClassification.FEDRAMP]
    assert policy.required_approval_depth >= 2
    assert policy.export_restricted is True
    assert policy.telemetry_restricted is True


@pytest.mark.smoke
def test_standard_policy_has_no_restricted_strategies():
    from services.deployment.models import (
        CLASSIFICATION_POLICIES,
        ComplianceClassification,
    )

    policy = CLASSIFICATION_POLICIES[ComplianceClassification.STANDARD]
    assert len(policy.restricted_strategies) == 0
    assert policy.export_restricted is False


# ---------------------------------------------------------------------------
# 8. Rollback safety constraints
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_rollback_safety_blocked_for_failed_target(store, db):
    from services.deployment.store import RollbackSafetyViolation

    env = store.create_environment(
        db,
        env_type=EnvironmentType.DEV,
        region="us-east-1",
        compliance_classification=ComplianceClassification.STANDARD,
        created_by="op",
    )
    # Original deployment goes to failed state.
    dep_orig = store.create_deployment(
        db,
        env_id=env.env_id,
        version_ref="v1.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
    )
    store.transition_state(
        db,
        deployment_id=dep_orig.deployment_id,
        to_state=DeploymentState.VALIDATING,
        actor="ci",
    )
    store.transition_state(
        db,
        deployment_id=dep_orig.deployment_id,
        to_state=DeploymentState.FAILED,
        actor="ci",
    )

    # New deployment tries to "rollback" to the failed one.
    dep_new = store.create_deployment(
        db,
        env_id=env.env_id,
        version_ref="v2.0.0",
        strategy=DeploymentStrategy.ROLLING,
        initiated_by="op",
        rollback_from_id=dep_orig.deployment_id,
    )
    store.transition_state(
        db,
        deployment_id=dep_new.deployment_id,
        to_state=DeploymentState.VALIDATING,
        actor="ci",
    )
    store.transition_state(
        db,
        deployment_id=dep_new.deployment_id,
        to_state=DeploymentState.DEPLOYING,
        actor="ci",
    )
    store.transition_state(
        db,
        deployment_id=dep_new.deployment_id,
        to_state=DeploymentState.HEALTHY,
        actor="ci",
    )

    with pytest.raises(RollbackSafetyViolation):
        store.transition_state(
            db,
            deployment_id=dep_new.deployment_id,
            to_state=DeploymentState.ROLLED_BACK,
            actor="ci",
        )


# ---------------------------------------------------------------------------
# 9. Deployment SLO metrics
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_metrics_module_importable():
    from services.deployment import metrics as deploy_metrics

    assert hasattr(deploy_metrics, "DEPLOYMENT_TRANSITIONS_TOTAL")
    assert hasattr(deploy_metrics, "DEPLOYMENT_FAILURES_TOTAL")
    assert hasattr(deploy_metrics, "ROLLBACK_TOTAL")
    assert hasattr(deploy_metrics, "APPROVAL_DECISIONS_TOTAL")
    assert hasattr(deploy_metrics, "DEPLOYMENT_DURATION_SECONDS")
    assert hasattr(deploy_metrics, "APPROVAL_WAIT_DURATION_SECONDS")
    assert hasattr(deploy_metrics, "HEALTH_PROBE_RESULTS_TOTAL")


# ---------------------------------------------------------------------------
# 10. Dry-run / validation mode
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_dry_run_allowed_transition(api_client):
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

    resp = api_client.post(
        f"/control-plane/deployments/{dep_id}/transition?dry_run=true",
        json={"to_state": "validating"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["dry_run"] is True
    assert body["allowed"] is True
    assert body["blocked"] is False
    assert body["from_state"] == "pending"
    assert body["to_state"] == "validating"
    # No side effects: deployment state must still be pending.
    get_resp = api_client.get(f"/control-plane/deployments/{dep_id}")
    assert get_resp.json()["state"] == "pending"


@pytest.mark.smoke
def test_dry_run_blocked_invalid_transition(api_client):
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

    resp = api_client.post(
        f"/control-plane/deployments/{dep_id}/transition?dry_run=true",
        json={"to_state": "healthy"},  # pending → healthy is invalid
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["dry_run"] is True
    assert body["allowed"] is False
    assert body["blocked"] is True
    assert len(body["block_reasons"]) > 0


@pytest.mark.smoke
def test_dry_run_detects_missing_approval(api_client):
    # Production env requires approval before deploying.
    env_resp = api_client.post(
        "/control-plane/deployments/environments",
        json={"env_type": "production", "region": "us-east-1"},
    )
    env_id = env_resp.json()["env_id"]
    dep_resp = api_client.post(
        "/control-plane/deployments",
        json={"env_id": env_id, "version_ref": "v1.0.0"},
    )
    dep_id = dep_resp.json()["deployment_id"]

    # Advance to validating (no approval needed yet).
    api_client.post(
        f"/control-plane/deployments/{dep_id}/transition",
        json={"to_state": "validating"},
    )

    # Dry-run the deploying transition without approval.
    resp = api_client.post(
        f"/control-plane/deployments/{dep_id}/transition?dry_run=true",
        json={"to_state": "deploying"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["approval_required"] is True
    assert body["missing_approval_granted_by"] is True
    assert body["blocked"] is True


@pytest.mark.smoke
def test_approval_api_exposes_integrity_fields(api_client):
    env_resp = api_client.post(
        "/control-plane/deployments/environments",
        json={"env_type": "production", "region": "us-east-1"},
    )
    env_id = env_resp.json()["env_id"]
    dep_resp = api_client.post(
        "/control-plane/deployments",
        json={"env_id": env_id, "version_ref": "v1.0.0"},
    )
    dep_id = dep_resp.json()["deployment_id"]

    resp = api_client.post(
        f"/control-plane/deployments/{dep_id}/approval",
        json={
            "approved": True,
            "approval_reason": "compliant with policy",
            "approval_policy_version": "p-v3.1",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["approval_granted_at"] is not None
    assert body["approval_reason"] == "compliant with policy"
    assert body["approval_policy_version"] == "p-v3.1"


@pytest.mark.smoke
def test_spec_snapshot_in_create_deployment_api(api_client):
    env_resp = api_client.post(
        "/control-plane/deployments/environments",
        json={"env_type": "dev", "region": "us-east-1"},
    )
    env_id = env_resp.json()["env_id"]
    resp = api_client.post(
        "/control-plane/deployments",
        json={
            "env_id": env_id,
            "version_ref": "v1.0.0",
            "spec": {
                "commit_sha": "a" * 40,
                "policy_bundle_version": "bundle-v1.0",
            },
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["spec"]["commit_sha"] == "a" * 40
    assert body["spec"]["policy_bundle_version"] == "bundle-v1.0"


@pytest.mark.smoke
def test_event_hashes_exposed_in_history_api(api_client):
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

    api_client.post(
        f"/control-plane/deployments/{dep_id}/transition",
        json={"to_state": "validating"},
    )

    resp = api_client.get(f"/control-plane/deployments/{dep_id}/history")
    assert resp.status_code == 200
    events = resp.json()["events"]
    assert len(events) >= 2
    for evt in events:
        assert "event_hash" in evt
    # Second event chains to first.
    assert events[1]["previous_event_hash"] == events[0]["event_hash"]


@pytest.mark.smoke
def test_strategy_governance_violation_returns_422(api_client):
    env_resp = api_client.post(
        "/control-plane/deployments/environments",
        json={"env_type": "production", "region": "us-east-1"},
    )
    env_id = env_resp.json()["env_id"]
    resp = api_client.post(
        "/control-plane/deployments",
        json={"env_id": env_id, "version_ref": "v1.0.0", "strategy": "direct"},
    )
    assert resp.status_code == 422
    assert "DEPLOY-API-009" in str(resp.json())
