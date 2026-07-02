"""Tests for PR 18.4 — Governance Orchestration approval engine."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from api.db import get_engine
from services.governance_orchestration.approvals import ApprovalChain
from services.governance_orchestration.engine import (
    GovernanceOrchestrationEngine,
)
from services.governance_orchestration.models import ApprovalState
from services.governance_orchestration.schemas import (
    ApproveRequest,
    CreateApprovalRequest,
    CreateWorkflowRequest,
    GovernanceOrchestrationApprovalError,
    GovernanceOrchestrationNotFound,
)


_TENANT = "tenant-go-appr-001"


@pytest.fixture()
def db(build_app):
    build_app(auth_enabled=False)
    engine = get_engine()
    with Session(engine) as session:
        yield session


@pytest.fixture()
def svc(db):
    return GovernanceOrchestrationEngine(db, tenant_id=_TENANT)


def _wf(svc, name="wf"):
    return svc.create_workflow(CreateWorkflowRequest(name=name), actor_id="x")


def _ap(svc, workflow_id, actor="alice", stage=1, quorum=1):
    return svc.create_approval(
        CreateApprovalRequest(
            workflow_id=workflow_id,
            actor_id=actor,
            stage=stage,
            quorum=quorum,
        ),
        actor_id="x",
    )


# ---------------------------------------------------------------------------
# ApprovalChain construction
# ---------------------------------------------------------------------------


def test_AP_1_chain_requires_stages():
    with pytest.raises(GovernanceOrchestrationApprovalError):
        ApprovalChain([])


def test_AP_2_chain_stage_missing_key():
    with pytest.raises(GovernanceOrchestrationApprovalError):
        ApprovalChain([{"quorum": 1}])


def test_AP_3_chain_stage_bad_quorum():
    with pytest.raises(GovernanceOrchestrationApprovalError):
        ApprovalChain([{"stage": 1, "quorum": 0}])


def test_AP_4_chain_ok():
    chain = ApprovalChain([{"stage": 1, "quorum": 1}])
    assert chain.stages == [{"stage": 1, "quorum": 1}]


def test_AP_5_chain_stages_is_copy():
    stages = [{"stage": 1, "quorum": 1}]
    chain = ApprovalChain(stages)
    stages.append({"stage": 2, "quorum": 1})
    assert len(chain.stages) == 1


# ---------------------------------------------------------------------------
# advance()
# ---------------------------------------------------------------------------


def test_AP_6_advance_approve(db, svc):
    wf = _wf(svc)
    ap = _ap(svc, wf.id)
    chain = ApprovalChain([{"stage": 1, "quorum": 1}])
    result = chain.advance(db, _TENANT, wf.id, ap.id, "APPROVE", "alice")
    assert result["approval_state"] == "APPROVED"


def test_AP_7_advance_reject(db, svc):
    wf = _wf(svc)
    ap = _ap(svc, wf.id)
    chain = ApprovalChain([{"stage": 1, "quorum": 1}])
    result = chain.advance(db, _TENANT, wf.id, ap.id, "REJECT", "alice")
    assert result["approval_state"] == "REJECTED"


def test_AP_8_advance_delegate(db, svc):
    wf = _wf(svc)
    ap = _ap(svc, wf.id)
    chain = ApprovalChain([{"stage": 1, "quorum": 1}])
    result = chain.advance(db, _TENANT, wf.id, ap.id, "DELEGATE", "bob")
    assert result["approval_state"] == "DELEGATED"


def test_AP_9_advance_invalid_decision(db, svc):
    wf = _wf(svc)
    ap = _ap(svc, wf.id)
    chain = ApprovalChain([{"stage": 1, "quorum": 1}])
    with pytest.raises(GovernanceOrchestrationApprovalError):
        chain.advance(db, _TENANT, wf.id, ap.id, "BOGUS", "alice")


def test_AP_10_advance_missing_approval(db, svc):
    wf = _wf(svc)
    chain = ApprovalChain([{"stage": 1, "quorum": 1}])
    with pytest.raises(GovernanceOrchestrationNotFound):
        chain.advance(db, _TENANT, wf.id, "does-not-exist", "APPROVE", "a")


def test_AP_11_advance_double_approve_forbidden(db, svc):
    wf = _wf(svc)
    ap = _ap(svc, wf.id)
    chain = ApprovalChain([{"stage": 1, "quorum": 1}])
    chain.advance(db, _TENANT, wf.id, ap.id, "APPROVE", "alice")
    with pytest.raises(GovernanceOrchestrationApprovalError):
        chain.advance(db, _TENANT, wf.id, ap.id, "APPROVE", "alice")


# ---------------------------------------------------------------------------
# check_quorum()
# ---------------------------------------------------------------------------


def test_AP_12_quorum_zero_approvals_fails():
    chain = ApprovalChain([{"stage": 1, "quorum": 2}])
    assert chain.check_quorum([], {"stage": 1, "quorum": 2}) is False


def test_AP_13_quorum_one_approval_meets_1():
    chain = ApprovalChain([{"stage": 1, "quorum": 1}])
    approvals = [{"approval_state": "APPROVED"}]
    assert chain.check_quorum(approvals, {"stage": 1, "quorum": 1}) is True


def test_AP_14_quorum_pending_not_counted():
    chain = ApprovalChain([{"stage": 1, "quorum": 1}])
    approvals = [{"approval_state": "PENDING"}]
    assert chain.check_quorum(approvals, {"stage": 1, "quorum": 1}) is False


def test_AP_15_quorum_multi_approve():
    chain = ApprovalChain([{"stage": 1, "quorum": 2}])
    approvals = [
        {"approval_state": "APPROVED"},
        {"approval_state": "APPROVED"},
    ]
    assert chain.check_quorum(approvals, {"stage": 1, "quorum": 2}) is True


# ---------------------------------------------------------------------------
# get_pending_stage() / is_complete()
# ---------------------------------------------------------------------------


def test_AP_16_pending_stage_returned_when_incomplete(db, svc):
    wf = _wf(svc)
    _ap(svc, wf.id, stage=1)
    chain = ApprovalChain([{"stage": 1, "quorum": 1}, {"stage": 2, "quorum": 1}])
    pending = chain.get_pending_stage(db, _TENANT, wf.id)
    assert pending is not None
    assert pending["stage"] == 1


def test_AP_17_pending_stage_none_when_all_met(db, svc):
    wf = _wf(svc)
    ap = _ap(svc, wf.id, stage=1)
    chain = ApprovalChain([{"stage": 1, "quorum": 1}])
    chain.advance(db, _TENANT, wf.id, ap.id, "APPROVE", "a")
    assert chain.get_pending_stage(db, _TENANT, wf.id) is None


def test_AP_18_is_complete_true(db, svc):
    wf = _wf(svc)
    ap = _ap(svc, wf.id)
    chain = ApprovalChain([{"stage": 1, "quorum": 1}])
    chain.advance(db, _TENANT, wf.id, ap.id, "APPROVE", "a")
    assert chain.is_complete(db, _TENANT, wf.id) is True


def test_AP_19_is_complete_false(db, svc):
    wf = _wf(svc)
    _ap(svc, wf.id)
    chain = ApprovalChain([{"stage": 1, "quorum": 1}])
    assert chain.is_complete(db, _TENANT, wf.id) is False


def test_AP_20_multi_stage_advance(db, svc):
    wf = _wf(svc)
    ap1 = _ap(svc, wf.id, actor="alice", stage=1)
    ap2 = _ap(svc, wf.id, actor="bob", stage=2)
    chain = ApprovalChain([{"stage": 1, "quorum": 1}, {"stage": 2, "quorum": 1}])
    chain.advance(db, _TENANT, wf.id, ap1.id, "APPROVE", "alice")
    assert not chain.is_complete(db, _TENANT, wf.id)
    chain.advance(db, _TENANT, wf.id, ap2.id, "APPROVE", "bob")
    assert chain.is_complete(db, _TENANT, wf.id)


# ---------------------------------------------------------------------------
# Engine-facing approvals
# ---------------------------------------------------------------------------


def test_AP_21_engine_approve(svc):
    wf = _wf(svc)
    ap = _ap(svc, wf.id)
    result = svc.approve_approval(
        ap.id, ApproveRequest(decision="APPROVE"), actor_id="alice"
    )
    assert result.approval_state == "APPROVED"


def test_AP_22_engine_reject(svc):
    wf = _wf(svc)
    ap = _ap(svc, wf.id)
    result = svc.approve_approval(
        ap.id, ApproveRequest(decision="REJECT", reason="no"), actor_id="alice"
    )
    assert result.approval_state == "REJECTED"


def test_AP_23_engine_delegate(svc):
    wf = _wf(svc)
    ap = _ap(svc, wf.id)
    result = svc.approve_approval(
        ap.id,
        ApproveRequest(decision="DELEGATE", delegated_to="bob"),
        actor_id="alice",
    )
    assert result.approval_state == "DELEGATED"
    assert result.delegated_to == "bob"


def test_AP_24_engine_list_approvals_by_workflow(svc):
    wf = _wf(svc)
    _ap(svc, wf.id, actor="alice")
    _ap(svc, wf.id, actor="bob", stage=2)
    resp = svc.list_approvals(workflow_id=wf.id)
    assert resp.total == 2


def test_AP_25_engine_list_approvals_by_state(svc):
    wf = _wf(svc)
    ap = _ap(svc, wf.id)
    svc.approve_approval(ap.id, ApproveRequest(decision="APPROVE"), actor_id="a")
    resp = svc.list_approvals(approval_state="APPROVED")
    for a in resp.items:
        assert a.approval_state == "APPROVED"


def test_AP_26_engine_create_approval_missing_workflow(svc):
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc.create_approval(
            CreateApprovalRequest(workflow_id="missing", actor_id="a"),
            actor_id="x",
        )


def test_AP_27_engine_approve_not_found(svc):
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc.approve_approval(
            "missing", ApproveRequest(decision="APPROVE"), actor_id="a"
        )


def test_AP_28_active_states_include_pending_and_delegated():
    from services.governance_orchestration.models import ACTIVE_APPROVAL_STATES

    assert ApprovalState.PENDING in ACTIVE_APPROVAL_STATES
    assert ApprovalState.DELEGATED in ACTIVE_APPROVAL_STATES


def test_AP_29_engine_approve_reason_persisted(svc):
    wf = _wf(svc)
    ap = _ap(svc, wf.id)
    result = svc.approve_approval(
        ap.id, ApproveRequest(decision="APPROVE", reason="because"), actor_id="a"
    )
    assert result.reason == "because"


def test_AP_30_engine_approve_timeline_recorded(svc):
    wf = _wf(svc)
    ap = _ap(svc, wf.id)
    svc.approve_approval(ap.id, ApproveRequest(decision="APPROVE"), actor_id="alice")
    tl = svc.get_timeline(entity_type="approval", entity_id=ap.id)
    assert any(e.event_type == "approval_approve" for e in tl.events)
