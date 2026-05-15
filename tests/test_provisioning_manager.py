"""Tests for the Provisioning Manager Foundation (PR 81).

Covers:
- Org lifecycle state machine (valid + invalid transitions)
- Provisioning workflow lifecycle (start, complete, fail, retry)
- Atomic activation gate (precondition enforcement)
- Suspension behavior
- Environment assignment
- Tenant isolation (cross-tenant access denied)
- Audit event hash chain integrity
- Serialization safety (no secrets in API responses)
- Optimistic locking (concurrency protection)
- API surface (all 14 routes)
- Invalid input rejection (extra fields, bad slug, missing required)

All tests run offline against an in-memory SQLite DB.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "dev")
os.environ.setdefault("FG_AUTH_ENABLED", "0")
os.environ.setdefault("FG_SQLITE_PATH", "state/test_provisioning_manager.db")
os.environ.setdefault("FG_RL_ENABLED", "0")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.db_models import Base
from services.provisioning import (
    ComplianceClassification,
    DeploymentTier,
    FailureCategory,
    OrgLifecycleStatus,
    ProvisioningStore,
    WorkflowState,
    VALID_ORG_TRANSITIONS,
    VALID_WORKFLOW_TRANSITIONS,
)
from services.provisioning.models import validate_org_transition
from services.provisioning.store import (
    ActivationPreconditionFailed,
    ConcurrentModificationError,
    DuplicateSlug,
    OrgNotFound,
    WorkflowTransitionError,
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
    return ProvisioningStore()


@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    from api.auth_scopes import mint_key
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "prov_api_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    app = build_app(auth_enabled=True)
    key = mint_key("control-plane:read", "control-plane:admin")
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


# ---------------------------------------------------------------------------
# 1. State machine
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_all_org_statuses_in_valid_transitions():
    for status in OrgLifecycleStatus:
        assert status in VALID_ORG_TRANSITIONS, (
            f"OrgLifecycleStatus.{status.name} missing from VALID_ORG_TRANSITIONS"
        )


@pytest.mark.smoke
def test_all_workflow_states_in_valid_transitions():
    for state in WorkflowState:
        assert state in VALID_WORKFLOW_TRANSITIONS, (
            f"WorkflowState.{state.name} missing from VALID_WORKFLOW_TRANSITIONS"
        )


@pytest.mark.smoke
def test_terminal_org_states_have_no_outbound():
    assert VALID_ORG_TRANSITIONS[OrgLifecycleStatus.ARCHIVED] == frozenset()


@pytest.mark.smoke
def test_terminal_workflow_states_have_no_outbound():
    assert VALID_WORKFLOW_TRANSITIONS[WorkflowState.COMPLETED] == frozenset()
    assert VALID_WORKFLOW_TRANSITIONS[WorkflowState.FAILED] == frozenset()
    assert VALID_WORKFLOW_TRANSITIONS[WorkflowState.CANCELLED] == frozenset()


@pytest.mark.smoke
def test_valid_org_transitions_exist():
    assert (
        OrgLifecycleStatus.PROVISIONING
        in VALID_ORG_TRANSITIONS[OrgLifecycleStatus.PENDING]
    )
    assert (
        OrgLifecycleStatus.ACTIVE
        in VALID_ORG_TRANSITIONS[OrgLifecycleStatus.PROVISIONING]
    )
    assert (
        OrgLifecycleStatus.SUSPENDED in VALID_ORG_TRANSITIONS[OrgLifecycleStatus.ACTIVE]
    )


@pytest.mark.smoke
def test_invalid_org_transition_raises():
    with pytest.raises(ValueError):
        validate_org_transition(OrgLifecycleStatus.ARCHIVED, OrgLifecycleStatus.ACTIVE)


@pytest.mark.smoke
def test_archived_blocked_from_active():
    with pytest.raises(ValueError):
        validate_org_transition(OrgLifecycleStatus.ARCHIVED, OrgLifecycleStatus.ACTIVE)


@pytest.mark.smoke
def test_failed_to_provisioning_allowed():
    validate_org_transition(OrgLifecycleStatus.FAILED, OrgLifecycleStatus.PROVISIONING)


# ---------------------------------------------------------------------------
# 2. Org create
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_create_org_returns_org(store, db):
    org = store.create_organization(
        db,
        org_name="Acme Corp",
        slug="acme-corp",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op-key",
    )
    db.commit()
    assert org.organization_id is not None
    assert org.lifecycle_status == OrgLifecycleStatus.PENDING
    assert org.slug == "acme-corp"


@pytest.mark.smoke
def test_create_org_slug_uniqueness_enforced(store, db):
    store.create_organization(
        db,
        org_name="Org One",
        slug="unique-slug",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()
    with pytest.raises(DuplicateSlug):
        store.create_organization(
            db,
            org_name="Org Two",
            slug="unique-slug",
            compliance_classification=ComplianceClassification.STANDARD,
            deployment_tier=DeploymentTier.SHARED,
            created_by="op",
        )


@pytest.mark.smoke
def test_create_org_idempotency_key_returns_same(store, db):
    org1 = store.create_organization(
        db,
        org_name="Idem Org",
        slug="idem-org-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
        idempotency_key="key-abc-123",
    )
    db.commit()
    org2 = store.create_organization(
        db,
        org_name="Different Name",
        slug="idem-org-2",
        compliance_classification=ComplianceClassification.HIPAA,
        deployment_tier=DeploymentTier.DEDICATED,
        created_by="op",
        idempotency_key="key-abc-123",
    )
    assert org1.organization_id == org2.organization_id
    assert org2.org_name == "Idem Org"


# ---------------------------------------------------------------------------
# 3. Provisioning workflow
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_start_workflow_transitions_org_to_provisioning(store, db):
    org = store.create_organization(
        db,
        org_name="Wf Test",
        slug="wf-test-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()

    wf = store.start_provisioning_workflow(
        db, org_id=org.organization_id, initiated_by="op"
    )
    db.commit()

    updated_org = store.get_organization(db, org_id=org.organization_id)
    assert wf.workflow_state == WorkflowState.RUNNING
    assert updated_org.lifecycle_status == OrgLifecycleStatus.PROVISIONING


@pytest.mark.smoke
def test_complete_workflow_transitions_to_pending_activation(store, db):
    org = store.create_organization(
        db,
        org_name="Complete Test",
        slug="complete-test-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()

    wf = store.start_provisioning_workflow(
        db, org_id=org.organization_id, initiated_by="op"
    )
    db.commit()

    completed_wf = store.complete_provisioning_workflow(
        db, provisioning_id=wf.provisioning_id, actor="op"
    )
    db.commit()

    from services.provisioning.models import OnboardingState

    updated_org = store.get_organization(db, org_id=org.organization_id)
    assert completed_wf.workflow_state == WorkflowState.COMPLETED
    assert updated_org.onboarding_state == OnboardingState.PENDING_ACTIVATION


@pytest.mark.smoke
def test_fail_workflow_transitions_org_to_failed(store, db):
    org = store.create_organization(
        db,
        org_name="Fail Test",
        slug="fail-test-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()

    wf = store.start_provisioning_workflow(
        db, org_id=org.organization_id, initiated_by="op"
    )
    db.commit()

    failed_wf = store.fail_provisioning_workflow(
        db,
        provisioning_id=wf.provisioning_id,
        actor="op",
        failure_reason="infra timeout",
        failure_category=FailureCategory.RETRYABLE,
    )
    db.commit()

    updated_org = store.get_organization(db, org_id=org.organization_id)
    assert failed_wf.workflow_state == WorkflowState.FAILED
    assert updated_org.lifecycle_status == OrgLifecycleStatus.FAILED


@pytest.mark.smoke
def test_retry_creates_new_workflow_with_incremented_retry_count(store, db):
    org = store.create_organization(
        db,
        org_name="Retry Test",
        slug="retry-test-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()

    wf = store.start_provisioning_workflow(
        db, org_id=org.organization_id, initiated_by="op"
    )
    db.commit()

    store.fail_provisioning_workflow(
        db,
        provisioning_id=wf.provisioning_id,
        actor="op",
        failure_reason="timeout",
        failure_category=FailureCategory.RETRYABLE,
    )
    db.commit()

    retry_wf = store.retry_provisioning_workflow(
        db, org_id=org.organization_id, initiated_by="op"
    )
    db.commit()

    assert retry_wf.provisioning_id != wf.provisioning_id
    assert retry_wf.retry_count == 1
    assert retry_wf.workflow_state == WorkflowState.RUNNING


@pytest.mark.smoke
def test_concurrent_workflow_start_raises(store, db):
    org = store.create_organization(
        db,
        org_name="Concurrent Test",
        slug="concurrent-test-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()

    store.start_provisioning_workflow(db, org_id=org.organization_id, initiated_by="op")
    db.commit()

    with pytest.raises(WorkflowTransitionError):
        store.start_provisioning_workflow(
            db, org_id=org.organization_id, initiated_by="op"
        )


@pytest.mark.smoke
def test_start_workflow_idempotency(store, db):
    org = store.create_organization(
        db,
        org_name="Idem Wf Test",
        slug="idem-wf-test-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()

    wf1 = store.start_provisioning_workflow(
        db,
        org_id=org.organization_id,
        initiated_by="op",
        idempotency_key="wf-idem-key-1",
    )
    db.commit()

    wf2 = store.start_provisioning_workflow(
        db,
        org_id=org.organization_id,
        initiated_by="op",
        idempotency_key="wf-idem-key-1",
    )
    assert wf1.provisioning_id == wf2.provisioning_id


# ---------------------------------------------------------------------------
# 4. Activation gate
# ---------------------------------------------------------------------------


def _make_activated_org(store, db, slug_suffix=""):
    """Helper: create org, run full workflow, return (org, wf)."""
    org = store.create_organization(
        db,
        org_name=f"Activate Test {slug_suffix}",
        slug=f"activate-test{slug_suffix}",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()

    wf = store.start_provisioning_workflow(
        db, org_id=org.organization_id, initiated_by="op"
    )
    db.commit()

    store.complete_provisioning_workflow(
        db, provisioning_id=wf.provisioning_id, actor="op"
    )
    db.commit()

    return store.get_organization(db, org_id=org.organization_id), wf


@pytest.mark.smoke
def test_activation_blocked_no_completed_workflow(store, db):
    org = store.create_organization(
        db,
        org_name="Block Test",
        slug="block-test-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()

    with pytest.raises(ActivationPreconditionFailed):
        store.activate_organization(db, org_id=org.organization_id, actor="op")


@pytest.mark.smoke
def test_activation_blocked_if_org_not_in_provisioning(store, db):
    org = store.create_organization(
        db,
        org_name="Status Block",
        slug="status-block-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()

    with pytest.raises(ActivationPreconditionFailed):
        store.activate_organization(db, org_id=org.organization_id, actor="op")


@pytest.mark.smoke
def test_activation_succeeds_when_preconditions_met(store, db):
    org, _ = _make_activated_org(store, db, "-ok1")
    activated = store.activate_organization(db, org_id=org.organization_id, actor="op")
    db.commit()
    assert activated.lifecycle_status == OrgLifecycleStatus.ACTIVE


@pytest.mark.smoke
def test_activation_transitions_to_active(store, db):
    org, _ = _make_activated_org(store, db, "-ok2")
    activated = store.activate_organization(db, org_id=org.organization_id, actor="op")
    db.commit()
    assert activated.lifecycle_status == OrgLifecycleStatus.ACTIVE


@pytest.mark.smoke
def test_activation_sets_activated_at(store, db):
    org, _ = _make_activated_org(store, db, "-ok3")
    activated = store.activate_organization(db, org_id=org.organization_id, actor="op")
    db.commit()
    assert activated.activated_at is not None


# ---------------------------------------------------------------------------
# 5. Suspension
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_active_to_suspended_works(store, db):
    org, _ = _make_activated_org(store, db, "-susp1")
    store.activate_organization(db, org_id=org.organization_id, actor="op")
    db.commit()

    suspended = store.suspend_organization(
        db, org_id=org.organization_id, actor="op", reason="billing issue"
    )
    db.commit()
    assert suspended.lifecycle_status == OrgLifecycleStatus.SUSPENDED


@pytest.mark.smoke
def test_suspended_org_shows_suspended_at(store, db):
    org, _ = _make_activated_org(store, db, "-susp2")
    store.activate_organization(db, org_id=org.organization_id, actor="op")
    db.commit()

    suspended = store.suspend_organization(db, org_id=org.organization_id, actor="op")
    db.commit()
    assert suspended.suspended_at is not None


# ---------------------------------------------------------------------------
# 6. Environment assignment
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_assign_environment_updates_env_id(store, db):
    org = store.create_organization(
        db,
        org_name="Env Test",
        slug="env-test-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()

    updated = store.assign_environment(
        db,
        org_id=org.organization_id,
        env_assignment_id="env-xyz-123",
        actor="op",
    )
    db.commit()
    assert updated.env_assignment_id == "env-xyz-123"


@pytest.mark.smoke
def test_assign_environment_emits_audit_event(store, db):
    org = store.create_organization(
        db,
        org_name="Env Audit Test",
        slug="env-audit-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()

    store.assign_environment(
        db,
        org_id=org.organization_id,
        env_assignment_id="env-audit-xyz",
        actor="op",
    )
    db.commit()

    events = store.list_audit_events(db, org_id=org.organization_id)
    event_types = [e.event_type.value for e in events]
    assert "environment_assigned" in event_types


# ---------------------------------------------------------------------------
# 7. Tenant isolation
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_tenant_org_hidden_from_other_tenant(store, db):
    org = store.create_organization(
        db,
        org_name="Tenant A Org",
        slug="tenant-a-org-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
        tenant_id="tenant-a",
    )
    db.commit()

    with pytest.raises(OrgNotFound):
        store.get_organization(db, org_id=org.organization_id, tenant_id="tenant-b")


@pytest.mark.smoke
def test_platform_org_visible_to_any_tenant(store, db):
    org = store.create_organization(
        db,
        org_name="Platform Org",
        slug="platform-org-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()

    found = store.get_organization(
        db, org_id=org.organization_id, tenant_id="some-tenant"
    )
    assert found.organization_id == org.organization_id


@pytest.mark.smoke
def test_cross_tenant_org_returns_not_found(store, db):
    org = store.create_organization(
        db,
        org_name="Isolated Org",
        slug="isolated-org-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
        tenant_id="owner-tenant",
    )
    db.commit()

    with pytest.raises(OrgNotFound):
        store.get_organization(db, org_id=org.organization_id, tenant_id="other-tenant")


@pytest.mark.smoke
def test_list_filtered_to_tenant(store, db):
    store.create_organization(
        db,
        org_name="Tenant X Org",
        slug="tenant-x-org-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
        tenant_id="tenant-x",
    )
    store.create_organization(
        db,
        org_name="Tenant Y Org",
        slug="tenant-y-org-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
        tenant_id="tenant-y",
    )
    db.commit()

    orgs = store.list_organizations(db, tenant_id="tenant-x")
    org_ids_tenant = {o.tenant_id for o in orgs}
    assert "tenant-y" not in org_ids_tenant


# ---------------------------------------------------------------------------
# 8. Audit events
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_create_org_emits_event(store, db):
    org = store.create_organization(
        db,
        org_name="Audit Test",
        slug="audit-test-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()

    events = store.list_audit_events(db, org_id=org.organization_id)
    assert len(events) == 1
    assert events[0].event_type.value == "organization_created"
    assert events[0].actor == "op"


@pytest.mark.smoke
def test_events_have_hash_chain(store, db):
    org = store.create_organization(
        db,
        org_name="Hash Chain Test",
        slug="hash-chain-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()

    store.start_provisioning_workflow(db, org_id=org.organization_id, initiated_by="op")
    db.commit()

    events = store.list_audit_events(db, org_id=org.organization_id)
    assert len(events) >= 2
    assert events[0].event_hash is not None
    assert events[0].previous_event_hash is None
    assert events[1].previous_event_hash == events[0].event_hash


@pytest.mark.smoke
def test_all_event_hashes_distinct(store, db):
    org = store.create_organization(
        db,
        org_name="Distinct Hash Test",
        slug="distinct-hash-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    wf = store.start_provisioning_workflow(
        db, org_id=org.organization_id, initiated_by="op"
    )
    store.complete_provisioning_workflow(
        db, provisioning_id=wf.provisioning_id, actor="op"
    )
    db.commit()

    events = store.list_audit_events(db, org_id=org.organization_id)
    hashes = [e.event_hash for e in events if e.event_hash]
    assert len(hashes) == len(set(hashes)), "all event hashes must be unique"


@pytest.mark.smoke
def test_event_history_accessible_via_api(api_client):
    create_resp = api_client.post(
        "/control-plane/provisioning/organizations",
        json={
            "org_name": "History Org",
            "slug": "history-org-api-1",
            "compliance_classification": "standard",
            "deployment_tier": "shared",
        },
    )
    assert create_resp.status_code == 201
    org_id = create_resp.json()["organization_id"]

    resp = api_client.get(f"/control-plane/provisioning/organizations/{org_id}/history")
    assert resp.status_code == 200
    body = resp.json()
    assert "events" in body
    assert len(body["events"]) >= 1
    assert body["events"][0]["event_type"] == "organization_created"


# ---------------------------------------------------------------------------
# 9. Concurrency
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_optimistic_locking_fires_on_zero_rowcount(store, db):
    from unittest.mock import patch

    import sqlalchemy.orm.query as q_mod

    org = store.create_organization(
        db,
        org_name="Lock Test",
        slug="lock-test-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()

    original_update = q_mod.Query.update
    intercepted: list[bool] = []

    def _zero_on_first(self, values, synchronize_session="evaluate"):
        if not intercepted and isinstance(values, dict) and "state_version" in values:
            intercepted.append(True)
            return 0
        return original_update(self, values, synchronize_session=synchronize_session)

    with patch.object(q_mod.Query, "update", _zero_on_first):
        with pytest.raises(ConcurrentModificationError):
            store.start_provisioning_workflow(
                db, org_id=org.organization_id, initiated_by="stale-worker"
            )


@pytest.mark.smoke
def test_state_version_increments_on_transition(store, db):
    org = store.create_organization(
        db,
        org_name="Version Test",
        slug="version-test-1",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()
    assert org.state_version == 0

    wf = store.start_provisioning_workflow(
        db, org_id=org.organization_id, initiated_by="op"
    )
    db.commit()

    updated = store.get_organization(db, org_id=org.organization_id)
    assert updated.state_version == 1

    store.complete_provisioning_workflow(
        db, provisioning_id=wf.provisioning_id, actor="op"
    )
    db.commit()

    updated2 = store.get_organization(db, org_id=org.organization_id)
    assert updated2.state_version == 2


# ---------------------------------------------------------------------------
# 10. API surface
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_list_orgs_returns_200(api_client):
    resp = api_client.get("/control-plane/provisioning/organizations")
    assert resp.status_code == 200
    body = resp.json()
    assert "organizations" in body
    assert isinstance(body["organizations"], list)


@pytest.mark.smoke
def test_create_org_returns_201(api_client):
    resp = api_client.post(
        "/control-plane/provisioning/organizations",
        json={
            "org_name": "Test Org API",
            "slug": "test-org-api-1",
            "compliance_classification": "standard",
            "deployment_tier": "shared",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert "organization_id" in body
    assert body["lifecycle_status"] == "pending"


@pytest.mark.smoke
def test_get_org_404_for_missing(api_client):
    resp = api_client.get("/control-plane/provisioning/organizations/does-not-exist")
    assert resp.status_code == 404
    body = resp.json()
    assert "PROV-API-001" in str(body)


@pytest.mark.smoke
def test_start_workflow_returns_201(api_client):
    create_resp = api_client.post(
        "/control-plane/provisioning/organizations",
        json={
            "org_name": "Workflow API Test",
            "slug": "workflow-api-test-1",
        },
    )
    org_id = create_resp.json()["organization_id"]

    resp = api_client.post(
        f"/control-plane/provisioning/organizations/{org_id}/provision",
        json={},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["workflow_state"] == "running"


@pytest.mark.smoke
def test_complete_workflow_api(api_client):
    create_resp = api_client.post(
        "/control-plane/provisioning/organizations",
        json={"org_name": "Complete API Test", "slug": "complete-api-test-1"},
    )
    org_id = create_resp.json()["organization_id"]

    wf_resp = api_client.post(
        f"/control-plane/provisioning/organizations/{org_id}/provision",
        json={},
    )
    prov_id = wf_resp.json()["provisioning_id"]

    resp = api_client.post(
        f"/control-plane/provisioning/workflows/{prov_id}/complete",
        json={"validation_results": {}},
    )
    assert resp.status_code == 200
    assert resp.json()["workflow_state"] == "completed"


@pytest.mark.smoke
def test_fail_workflow_api(api_client):
    create_resp = api_client.post(
        "/control-plane/provisioning/organizations",
        json={"org_name": "Fail API Test", "slug": "fail-api-test-1"},
    )
    org_id = create_resp.json()["organization_id"]

    wf_resp = api_client.post(
        f"/control-plane/provisioning/organizations/{org_id}/provision",
        json={},
    )
    prov_id = wf_resp.json()["provisioning_id"]

    resp = api_client.post(
        f"/control-plane/provisioning/workflows/{prov_id}/fail",
        json={"failure_reason": "infra timeout", "failure_category": "retryable"},
    )
    assert resp.status_code == 200
    assert resp.json()["workflow_state"] == "failed"


@pytest.mark.smoke
def test_onboarding_state_endpoint(api_client):
    create_resp = api_client.post(
        "/control-plane/provisioning/organizations",
        json={"org_name": "Onboarding Test", "slug": "onboarding-test-1"},
    )
    org_id = create_resp.json()["organization_id"]

    resp = api_client.get(
        f"/control-plane/provisioning/organizations/{org_id}/onboarding"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "onboarding_state" in body
    assert body["onboarding_state"] == "not_started"


@pytest.mark.smoke
def test_history_endpoint(api_client):
    create_resp = api_client.post(
        "/control-plane/provisioning/organizations",
        json={"org_name": "History Endpoint Test", "slug": "history-endpoint-1"},
    )
    org_id = create_resp.json()["organization_id"]

    resp = api_client.get(f"/control-plane/provisioning/organizations/{org_id}/history")
    assert resp.status_code == 200
    body = resp.json()
    assert "events" in body
    assert len(body["events"]) >= 1


@pytest.mark.smoke
def test_list_workflows_endpoint(api_client):
    resp = api_client.get("/control-plane/provisioning/workflows")
    assert resp.status_code == 200
    body = resp.json()
    assert "workflows" in body


@pytest.mark.smoke
def test_get_workflow_404_for_missing(api_client):
    resp = api_client.get("/control-plane/provisioning/workflows/does-not-exist")
    assert resp.status_code == 404
    body = resp.json()
    assert "PROV-API-002" in str(body)


# ---------------------------------------------------------------------------
# 11. Serialization safety
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_no_secrets_in_org_response(api_client):
    resp = api_client.post(
        "/control-plane/provisioning/organizations",
        json={
            "org_name": "Safety Check Org",
            "slug": "safety-check-org-1",
            "compliance_classification": "standard",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    body_keys = set(body.keys())

    forbidden_field_names = {
        "password",
        "api_key",
        "token",
        "credential",
        "private_key",
        "authorization",
        "secret_key",
    }
    for field_name in forbidden_field_names:
        assert field_name not in body_keys, (
            f"Provisioning API response contains forbidden field: {field_name!r}"
        )


@pytest.mark.smoke
def test_no_internal_topology_in_response(api_client):
    resp = api_client.post(
        "/control-plane/provisioning/organizations",
        json={"org_name": "Topology Test", "slug": "topology-test-1"},
    )
    assert resp.status_code == 201
    body = resp.json()
    topology_fields = {"db_url", "connection_string", "host", "port", "internal_ip"}
    for field_name in topology_fields:
        assert field_name not in body, (
            f"Topology field {field_name!r} must not appear in org response"
        )


# ---------------------------------------------------------------------------
# 12. Invalid input
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_extra_fields_rejected(api_client):
    resp = api_client.post(
        "/control-plane/provisioning/organizations",
        json={
            "org_name": "Extra Field Test",
            "slug": "extra-field-test-1",
            "injection_field": "should be rejected",
        },
    )
    assert resp.status_code == 422


@pytest.mark.smoke
def test_bad_slug_rejected(api_client):
    resp = api_client.post(
        "/control-plane/provisioning/organizations",
        json={
            "org_name": "Bad Slug Test",
            "slug": "UPPERCASE-NOT-ALLOWED",
        },
    )
    assert resp.status_code == 422


@pytest.mark.smoke
def test_missing_required_fields_rejected(api_client):
    resp = api_client.post(
        "/control-plane/provisioning/organizations",
        json={"org_name": "Missing Slug Test"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 12. Idempotency tenant isolation (1A fix)
# ---------------------------------------------------------------------------


def test_org_idempotency_key_is_tenant_scoped(store, db):
    """Tenant A's idempotency key must not be returned to tenant B."""
    store.create_organization(
        db,
        org_name="Tenant A Org",
        slug="tenant-a-org-idem",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
        tenant_id="tenant-a",
        idempotency_key="shared-key-xyz",
    )
    db.commit()

    # Tenant B uses the same idempotency key — must get a new record, not tenant A's.
    org_b = store.create_organization(
        db,
        org_name="Tenant B Org",
        slug="tenant-b-org-idem",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
        tenant_id="tenant-b",
        idempotency_key="shared-key-xyz",
    )
    db.commit()

    assert org_b.org_name == "Tenant B Org"
    assert org_b.tenant_id == "tenant-b"


def test_workflow_idempotency_key_is_tenant_scoped(store, db):
    """Workflow idempotency lookup must not cross tenant boundaries."""
    org_a = store.create_organization(
        db,
        org_name="WF Idem Tenant A",
        slug="wf-idem-tenant-a",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
        tenant_id="tenant-a",
    )
    db.commit()

    org_b = store.create_organization(
        db,
        org_name="WF Idem Tenant B",
        slug="wf-idem-tenant-b",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
        tenant_id="tenant-b",
    )
    db.commit()

    wf_a = store.start_provisioning_workflow(
        db,
        org_id=org_a.organization_id,
        initiated_by="op",
        tenant_id="tenant-a",
        idempotency_key="wf-shared-key",
    )
    db.commit()

    # Tenant B uses the same key — must create a new workflow for org_b.
    wf_b = store.start_provisioning_workflow(
        db,
        org_id=org_b.organization_id,
        initiated_by="op",
        tenant_id="tenant-b",
        idempotency_key="wf-shared-key",
    )
    db.commit()

    assert wf_a.provisioning_id != wf_b.provisioning_id
    assert wf_b.organization_id == org_b.organization_id


# ---------------------------------------------------------------------------
# 13. Idempotent activation (1B fix)
# ---------------------------------------------------------------------------


def test_activate_already_active_org_is_idempotent(store, db):
    """Activating an already-active org must return current state, not 422."""
    org, _ = _make_activated_org(store, db, slug_suffix="-idem-act")

    # Second activation call must succeed and return the same org unchanged.
    org2 = store.activate_organization(db, org_id=org.organization_id, actor="op")
    assert org2.lifecycle_status == OrgLifecycleStatus.ACTIVE
    assert org2.organization_id == org.organization_id


def test_activate_already_active_returns_200_via_api(api_client):
    """API must return 200 (not 422) when activating an already-active org."""
    # Create org and run through full provisioning workflow.
    resp = api_client.post(
        "/control-plane/provisioning/organizations",
        json={"org_name": "Idem Act API Org", "slug": "idem-act-api-org"},
    )
    assert resp.status_code == 201
    org_id = resp.json()["organization_id"]

    api_client.post(
        f"/control-plane/provisioning/organizations/{org_id}/provision", json={}
    )

    wf_resp = api_client.get("/control-plane/provisioning/workflows")
    wf_id = next(
        w["provisioning_id"]
        for w in wf_resp.json()["workflows"]
        if w["organization_id"] == org_id
    )

    api_client.post(f"/control-plane/provisioning/workflows/{wf_id}/complete", json={})
    api_client.post(f"/control-plane/provisioning/organizations/{org_id}/activate")

    # Second activation — must be 200, not 422.
    resp2 = api_client.post(
        f"/control-plane/provisioning/organizations/{org_id}/activate"
    )
    assert resp2.status_code == 200
    assert resp2.json()["lifecycle_status"] == "active"


# ---------------------------------------------------------------------------
# 14. Retry lineage — parent_provisioning_id (fix #4)
# ---------------------------------------------------------------------------


def test_retry_workflow_sets_parent_provisioning_id(store, db):
    """A retry workflow must record the failed workflow's ID as its parent."""
    org = store.create_organization(
        db,
        org_name="Retry Lineage Org",
        slug="retry-lineage-org",
        compliance_classification=ComplianceClassification.STANDARD,
        deployment_tier=DeploymentTier.SHARED,
        created_by="op",
    )
    db.commit()

    wf = store.start_provisioning_workflow(
        db, org_id=org.organization_id, initiated_by="op"
    )
    db.commit()

    store.fail_provisioning_workflow(
        db,
        provisioning_id=wf.provisioning_id,
        actor="op",
        failure_reason="infra timeout",
    )
    db.commit()

    retry_wf = store.retry_provisioning_workflow(
        db, org_id=org.organization_id, initiated_by="op"
    )
    db.commit()

    assert retry_wf.parent_provisioning_id == wf.provisioning_id


def test_retry_lineage_exposed_in_workflow_response(api_client):
    """parent_provisioning_id must appear in the workflow API response."""
    resp = api_client.post(
        "/control-plane/provisioning/organizations",
        json={"org_name": "Lineage API Org", "slug": "lineage-api-org"},
    )
    org_id = resp.json()["organization_id"]

    api_client.post(
        f"/control-plane/provisioning/organizations/{org_id}/provision", json={}
    )

    wf_list = api_client.get("/control-plane/provisioning/workflows").json()[
        "workflows"
    ]
    first_wf_id = next(
        w["provisioning_id"] for w in wf_list if w["organization_id"] == org_id
    )

    api_client.post(
        f"/control-plane/provisioning/workflows/{first_wf_id}/fail",
        json={"failure_reason": "test failure"},
    )

    retry_resp = api_client.post(
        f"/control-plane/provisioning/workflows/{first_wf_id}/retry", json={}
    )
    assert retry_resp.status_code == 201
    assert retry_resp.json()["parent_provisioning_id"] == first_wf_id
