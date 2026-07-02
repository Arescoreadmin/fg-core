"""Tests for PR 18.4 — Governance Orchestration reassessment lifecycle."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from api.db import get_engine
from services.governance_orchestration.engine import (
    GovernanceOrchestrationEngine,
)
from services.governance_orchestration.reassessment import (
    complete_reassessment,
    get_reassessment_readiness,
    request_reassessment,
    schedule_reassessment,
)
from services.governance_orchestration.schemas import (
    CreateReassessmentRequest,
    GovernanceOrchestrationInvalidTransition,
    GovernanceOrchestrationNotFound,
    GovernanceOrchestrationValidationError,
)


_TENANT = "tenant-go-re-001"


@pytest.fixture()
def db(build_app):
    build_app(auth_enabled=False)
    engine = get_engine()
    with Session(engine) as session:
        yield session


@pytest.fixture()
def svc(db):
    return GovernanceOrchestrationEngine(db, tenant_id=_TENANT)


# ---------------------------------------------------------------------------
# request_reassessment
# ---------------------------------------------------------------------------


def test_RE_1_request_ok(db):
    r = request_reassessment(db, _TENANT, "a-1", None, "reason")
    assert r["assessment_id"] == "a-1"
    assert r["reassessment_state"] == "REQUESTED"


def test_RE_2_request_empty_assessment_id_raises(db):
    with pytest.raises(GovernanceOrchestrationValidationError):
        request_reassessment(db, _TENANT, "", None, None)


def test_RE_3_request_none_assessment_id_raises(db):
    with pytest.raises(GovernanceOrchestrationValidationError):
        request_reassessment(db, _TENANT, None, None, None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# schedule_reassessment
# ---------------------------------------------------------------------------


def test_RE_4_schedule_ok(db):
    r = request_reassessment(db, _TENANT, "a-1", None, None)
    scheduled = schedule_reassessment(
        db, _TENANT, r["id"], "2026-01-01T00:00:00Z"
    )
    assert scheduled["reassessment_state"] == "SCHEDULED"


def test_RE_5_schedule_not_found(db):
    with pytest.raises(GovernanceOrchestrationNotFound):
        schedule_reassessment(db, _TENANT, "missing", "2026-01-01T00:00:00Z")


def test_RE_6_schedule_empty_at_raises(db):
    r = request_reassessment(db, _TENANT, "a-1", None, None)
    with pytest.raises(GovernanceOrchestrationValidationError):
        schedule_reassessment(db, _TENANT, r["id"], "")


def test_RE_7_schedule_terminal_state_raises(db):
    r = request_reassessment(db, _TENANT, "a-1", None, None)
    schedule_reassessment(db, _TENANT, r["id"], "2026-01-01T00:00:00Z")
    complete_reassessment(db, _TENANT, r["id"], "PASS")
    with pytest.raises(GovernanceOrchestrationInvalidTransition):
        schedule_reassessment(db, _TENANT, r["id"], "2026-02-01T00:00:00Z")


# ---------------------------------------------------------------------------
# complete_reassessment
# ---------------------------------------------------------------------------


def test_RE_8_complete_ok(db):
    r = request_reassessment(db, _TENANT, "a-1", None, None)
    schedule_reassessment(db, _TENANT, r["id"], "2026-01-01T00:00:00Z")
    completed = complete_reassessment(db, _TENANT, r["id"], "PASS")
    assert completed["outcome"] == "PASS"


def test_RE_9_complete_not_found(db):
    with pytest.raises(GovernanceOrchestrationNotFound):
        complete_reassessment(db, _TENANT, "missing", "PASS")


def test_RE_10_complete_already_terminal(db):
    r = request_reassessment(db, _TENANT, "a-1", None, None)
    schedule_reassessment(db, _TENANT, r["id"], "2026-01-01T00:00:00Z")
    complete_reassessment(db, _TENANT, r["id"], "PASS")
    with pytest.raises(GovernanceOrchestrationInvalidTransition):
        complete_reassessment(db, _TENANT, r["id"], "PASS")


# ---------------------------------------------------------------------------
# get_reassessment_readiness
# ---------------------------------------------------------------------------


def test_RE_11_readiness_ready_when_scheduled(db):
    r = request_reassessment(db, _TENANT, "a-1", None, None)
    schedule_reassessment(db, _TENANT, r["id"], "2026-01-01T00:00:00Z")
    readiness = get_reassessment_readiness(db, _TENANT, r["id"])
    assert readiness["ready"] is True


def test_RE_12_readiness_not_ready_when_requested(db):
    r = request_reassessment(db, _TENANT, "a-1", None, None)
    readiness = get_reassessment_readiness(db, _TENANT, r["id"])
    assert readiness["ready"] is False


def test_RE_13_readiness_not_found(db):
    with pytest.raises(GovernanceOrchestrationNotFound):
        get_reassessment_readiness(db, _TENANT, "missing")


# ---------------------------------------------------------------------------
# Engine wrapper
# ---------------------------------------------------------------------------


def test_RE_14_engine_create(svc):
    r = svc.create_reassessment(
        CreateReassessmentRequest(assessment_id="a-1"), actor_id="x"
    )
    assert r.reassessment_state == "REQUESTED"


def test_RE_15_engine_schedule(svc):
    r = svc.create_reassessment(
        CreateReassessmentRequest(assessment_id="a-1"), actor_id="x"
    )
    scheduled = svc.schedule_reassessment(
        r.id, "2026-01-01T00:00:00Z", actor_id="x"
    )
    assert scheduled.reassessment_state == "SCHEDULED"


def test_RE_16_engine_complete(svc):
    r = svc.create_reassessment(
        CreateReassessmentRequest(assessment_id="a-1"), actor_id="x"
    )
    svc.schedule_reassessment(r.id, "2026-01-01T00:00:00Z", actor_id="x")
    completed = svc.complete_reassessment(r.id, "PASS", actor_id="x")
    assert completed.outcome == "PASS"


def test_RE_17_engine_list(svc):
    svc.create_reassessment(
        CreateReassessmentRequest(assessment_id="a-1"), actor_id="x"
    )
    resp = svc.list_reassessments()
    assert resp.total >= 1


def test_RE_18_engine_get_not_found(svc):
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc.get_reassessment("missing")


def test_RE_19_engine_timeline_records_request(svc):
    r = svc.create_reassessment(
        CreateReassessmentRequest(assessment_id="a-1"), actor_id="x"
    )
    tl = svc.get_timeline(entity_type="reassessment", entity_id=r.id)
    assert any(e.event_type == "reassessment_requested" for e in tl.events)


def test_RE_20_engine_timeline_records_scheduled(svc):
    r = svc.create_reassessment(
        CreateReassessmentRequest(assessment_id="a-1"), actor_id="x"
    )
    svc.schedule_reassessment(r.id, "2026-01-01T00:00:00Z", actor_id="x")
    tl = svc.get_timeline(entity_type="reassessment", entity_id=r.id)
    assert any(e.event_type == "reassessment_scheduled" for e in tl.events)


def test_RE_21_engine_timeline_records_completed(svc):
    r = svc.create_reassessment(
        CreateReassessmentRequest(assessment_id="a-1"), actor_id="x"
    )
    svc.schedule_reassessment(r.id, "2026-01-01T00:00:00Z", actor_id="x")
    svc.complete_reassessment(r.id, "PASS", actor_id="x")
    tl = svc.get_timeline(entity_type="reassessment", entity_id=r.id)
    assert any(e.event_type == "reassessment_completed" for e in tl.events)


def test_RE_22_reason_persisted(svc):
    r = svc.create_reassessment(
        CreateReassessmentRequest(assessment_id="a-1", reason="because"),
        actor_id="x",
    )
    got = svc.get_reassessment(r.id)
    assert got.reason == "because"


def test_RE_23_trigger_id_persisted(svc):
    r = svc.create_reassessment(
        CreateReassessmentRequest(assessment_id="a-1", trigger_id="t-1"),
        actor_id="x",
    )
    assert r.trigger_id == "t-1"
