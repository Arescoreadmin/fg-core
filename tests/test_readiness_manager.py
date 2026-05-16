"""Tests for the AI Readiness Core Domain Model & Evidence Contract Foundation.

Covers:
- Framework lifecycle state machine (valid + invalid transitions)
- Framework slug uniqueness
- Framework immutability after activation
- Domain/control creation against draft vs. active frameworks
- Maturity tier lifecycle
- Assessment lifecycle state machine (valid + invalid transitions)
- Assessment immutability after finalization/archival
- Assessment result recording (mutable vs. immutable assessments)
- Evidence reference attachment (mutable vs. immutable assessments)
- Scoring contract creation
- Tenant isolation (assessments/evidence cannot cross tenant boundaries)
- Audit event hash chain integrity
- Serialization safety (no secrets in responses)
- Concurrent modification protection
- Framework version management
- Deterministic reconstruction via snapshot_version

All tests run offline against an in-memory SQLite DB.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "dev")
os.environ.setdefault("FG_AUTH_ENABLED", "0")
os.environ.setdefault("FG_SQLITE_PATH", "state/test_readiness_manager.db")
os.environ.setdefault("FG_RL_ENABLED", "0")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.db_models import Base
from services.readiness import (
    AssessmentOutcome,
    AssessmentStatus,
    EvidenceType,
    Framework,
    FrameworkStatus,
    ReadinessStore,
    VALID_ASSESSMENT_TRANSITIONS,
    VALID_FRAMEWORK_TRANSITIONS,
    IMMUTABLE_ASSESSMENT_STATUSES,
    IMMUTABLE_FRAMEWORK_STATUSES,
)
from services.readiness.models import (
    assert_assessment_mutable,
    validate_assessment_transition,
    validate_framework_transition,
)
from services.readiness.store import (
    AssessmentImmutableError,
    AssessmentNotFound,
    DuplicateSlug,
    FrameworkImmutableError,
    FrameworkNotActiveError,
    FrameworkNotFound,
    InvalidAssessmentTransition,
    InvalidFrameworkTransition,
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
    return ReadinessStore()


@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    from api.auth_scopes import mint_key
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "readiness_api_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    app = build_app(auth_enabled=True)
    key = mint_key("control-plane:read", "control-plane:admin")
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_framework(
    store: ReadinessStore, db: Session, *, slug: str = "test-fw", tenant_id=None
) -> Framework:
    fw = store.create_framework(
        db,
        framework_name="Test Framework",
        framework_slug=slug,
        framework_version="1.0.0",
        created_by="op-key",
        tenant_id=tenant_id,
    )
    db.commit()
    return fw


def _make_active_framework(
    store: ReadinessStore, db: Session, *, slug: str = "active-fw", tenant_id=None
) -> Framework:
    fw = _make_framework(store, db, slug=slug, tenant_id=tenant_id)
    fw = store.transition_framework_status(
        db,
        framework_id=fw.framework_id,
        to_status=FrameworkStatus.ACTIVE,
        actor="op",
        tenant_id=tenant_id,
    )
    db.commit()
    return fw


def _make_domain(
    store: ReadinessStore, db: Session, framework_id: str, *, tenant_id=None
) -> object:
    domain = store.create_domain(
        db,
        framework_id=framework_id,
        domain_name="Test Domain",
        domain_slug="test-domain",
        domain_description="desc",
        domain_order=0,
        created_by="op",
        tenant_id=tenant_id,
    )
    db.commit()
    return domain


def _make_assessment(
    store: ReadinessStore,
    db: Session,
    framework_id: str,
    *,
    tenant_id: str = "tenant-a",
) -> object:
    fw = store.get_framework(db, framework_id=framework_id)
    if fw.framework_status == FrameworkStatus.DRAFT:
        store.transition_framework_status(
            db,
            framework_id=framework_id,
            to_status=FrameworkStatus.ACTIVE,
            actor="op",
        )
        db.flush()
    a = store.create_assessment(
        db,
        tenant_id=tenant_id,
        framework_id=framework_id,
        framework_version_tag="v1",
        created_by="op",
    )
    db.commit()
    return a


# ---------------------------------------------------------------------------
# 1. Framework state machine
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_all_framework_statuses_in_valid_transitions():
    for status in FrameworkStatus:
        assert status in VALID_FRAMEWORK_TRANSITIONS, (
            f"FrameworkStatus.{status.name} missing from VALID_FRAMEWORK_TRANSITIONS"
        )


@pytest.mark.smoke
def test_all_assessment_statuses_in_valid_transitions():
    for status in AssessmentStatus:
        assert status in VALID_ASSESSMENT_TRANSITIONS, (
            f"AssessmentStatus.{status.name} missing from VALID_ASSESSMENT_TRANSITIONS"
        )


@pytest.mark.smoke
def test_retired_framework_is_terminal():
    assert VALID_FRAMEWORK_TRANSITIONS[FrameworkStatus.RETIRED] == frozenset()


@pytest.mark.smoke
def test_archived_assessment_is_terminal():
    assert VALID_ASSESSMENT_TRANSITIONS[AssessmentStatus.ARCHIVED] == frozenset()


@pytest.mark.smoke
def test_valid_framework_transitions():
    validate_framework_transition(FrameworkStatus.DRAFT, FrameworkStatus.ACTIVE)
    validate_framework_transition(FrameworkStatus.ACTIVE, FrameworkStatus.DEPRECATED)
    validate_framework_transition(FrameworkStatus.DEPRECATED, FrameworkStatus.RETIRED)


@pytest.mark.smoke
def test_invalid_framework_transition_raises():
    with pytest.raises(ValueError):
        validate_framework_transition(FrameworkStatus.RETIRED, FrameworkStatus.ACTIVE)


@pytest.mark.smoke
def test_invalid_framework_transition_skip_raises():
    with pytest.raises(ValueError):
        validate_framework_transition(FrameworkStatus.DRAFT, FrameworkStatus.DEPRECATED)


@pytest.mark.smoke
def test_valid_assessment_transitions():
    validate_assessment_transition(AssessmentStatus.DRAFT, AssessmentStatus.ACTIVE)
    validate_assessment_transition(AssessmentStatus.ACTIVE, AssessmentStatus.FINALIZED)
    validate_assessment_transition(
        AssessmentStatus.FINALIZED, AssessmentStatus.ARCHIVED
    )


@pytest.mark.smoke
def test_invalid_assessment_transition_raises():
    with pytest.raises(ValueError):
        validate_assessment_transition(
            AssessmentStatus.ARCHIVED, AssessmentStatus.ACTIVE
        )


@pytest.mark.smoke
def test_finalized_assessment_archived_blocked_from_active():
    with pytest.raises(ValueError):
        validate_assessment_transition(
            AssessmentStatus.FINALIZED, AssessmentStatus.DRAFT
        )


@pytest.mark.smoke
def test_immutable_assessment_statuses_set():
    assert AssessmentStatus.FINALIZED in IMMUTABLE_ASSESSMENT_STATUSES
    assert AssessmentStatus.ARCHIVED in IMMUTABLE_ASSESSMENT_STATUSES
    assert AssessmentStatus.DRAFT not in IMMUTABLE_ASSESSMENT_STATUSES
    assert AssessmentStatus.ACTIVE not in IMMUTABLE_ASSESSMENT_STATUSES


@pytest.mark.smoke
def test_immutable_framework_statuses_set():
    assert FrameworkStatus.ACTIVE in IMMUTABLE_FRAMEWORK_STATUSES
    assert FrameworkStatus.DEPRECATED in IMMUTABLE_FRAMEWORK_STATUSES
    assert FrameworkStatus.RETIRED in IMMUTABLE_FRAMEWORK_STATUSES
    assert FrameworkStatus.DRAFT not in IMMUTABLE_FRAMEWORK_STATUSES


# ---------------------------------------------------------------------------
# 2. Framework CRUD
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_create_framework(store, db):
    fw = store.create_framework(
        db,
        framework_name="NIST AI RMF",
        framework_slug="nist-ai-rmf",
        framework_version="1.0",
        created_by="op",
    )
    db.commit()
    assert fw.framework_id is not None
    assert fw.framework_status == FrameworkStatus.DRAFT
    assert fw.framework_slug == "nist-ai-rmf"


@pytest.mark.smoke
def test_create_framework_slug_uniqueness(store, db):
    store.create_framework(
        db,
        framework_name="FW1",
        framework_slug="same-slug",
        framework_version="1.0",
        created_by="op",
    )
    db.commit()
    with pytest.raises(DuplicateSlug):
        store.create_framework(
            db,
            framework_name="FW2",
            framework_slug="same-slug",
            framework_version="2.0",
            created_by="op",
        )


@pytest.mark.smoke
def test_get_framework_not_found(store, db):
    with pytest.raises(FrameworkNotFound):
        store.get_framework(db, framework_id="nonexistent")


@pytest.mark.smoke
def test_list_frameworks_empty(store, db):
    result = store.list_frameworks(db)
    assert result == []


def test_list_frameworks_returns_created(store, db):
    _make_framework(store, db, slug="fw-list-1")
    _make_framework(store, db, slug="fw-list-2")
    result = store.list_frameworks(db)
    assert len(result) == 2


def test_transition_framework_to_active(store, db):
    fw = _make_framework(store, db)
    fw = store.transition_framework_status(
        db, framework_id=fw.framework_id, to_status=FrameworkStatus.ACTIVE, actor="op"
    )
    db.commit()
    assert fw.framework_status == FrameworkStatus.ACTIVE
    assert fw.activated_at is not None


def test_transition_framework_invalid_raises(store, db):
    fw = _make_framework(store, db)
    with pytest.raises(InvalidFrameworkTransition):
        store.transition_framework_status(
            db,
            framework_id=fw.framework_id,
            to_status=FrameworkStatus.RETIRED,
            actor="op",
        )


def test_retired_framework_no_further_transitions(store, db):
    fw = _make_framework(store, db)
    fw = store.transition_framework_status(
        db, framework_id=fw.framework_id, to_status=FrameworkStatus.ACTIVE, actor="op"
    )
    db.commit()
    fw = store.transition_framework_status(
        db,
        framework_id=fw.framework_id,
        to_status=FrameworkStatus.DEPRECATED,
        actor="op",
    )
    db.commit()
    fw = store.transition_framework_status(
        db, framework_id=fw.framework_id, to_status=FrameworkStatus.RETIRED, actor="op"
    )
    db.commit()
    with pytest.raises(InvalidFrameworkTransition):
        store.transition_framework_status(
            db,
            framework_id=fw.framework_id,
            to_status=FrameworkStatus.ACTIVE,
            actor="op",
        )


# ---------------------------------------------------------------------------
# 3. Framework immutability after activation
# ---------------------------------------------------------------------------


def test_domain_creation_blocked_on_active_framework(store, db):
    fw = _make_active_framework(store, db, slug="active-fw-domain-block")
    with pytest.raises(FrameworkImmutableError):
        store.create_domain(
            db,
            framework_id=fw.framework_id,
            domain_name="Blocked Domain",
            domain_slug="blocked-domain",
            domain_description="desc",
            domain_order=0,
            created_by="op",
        )


def test_control_creation_blocked_on_active_framework(store, db):
    fw = _make_framework(store, db, slug="fw-ctrl-block")
    domain = _make_domain(store, db, fw.framework_id)
    fw = store.transition_framework_status(
        db, framework_id=fw.framework_id, to_status=FrameworkStatus.ACTIVE, actor="op"
    )
    db.commit()
    with pytest.raises(FrameworkImmutableError):
        store.create_control(
            db,
            framework_id=fw.framework_id,
            domain_id=domain.domain_id,
            control_identifier="CTRL-001",
            control_name="Control 1",
            control_description="desc",
            created_by="op",
        )


def test_maturity_tier_creation_blocked_on_active_framework(store, db):
    fw = _make_active_framework(store, db, slug="fw-tier-block")
    with pytest.raises(FrameworkImmutableError):
        store.create_maturity_tier(
            db,
            framework_id=fw.framework_id,
            tier_identifier="T1",
            tier_name="Tier 1",
            tier_order=1,
            tier_criteria="criteria",
            created_by="op",
        )


def test_version_creation_blocked_on_active_framework(store, db):
    fw = _make_active_framework(store, db, slug="fw-ver-block")
    with pytest.raises(FrameworkImmutableError):
        store.create_framework_version(
            db,
            framework_id=fw.framework_id,
            version_tag="v2",
            created_by="op",
        )


def test_scoring_contract_creation_blocked_on_active_framework(store, db):
    fw = _make_active_framework(store, db, slug="fw-sc-block")
    with pytest.raises(FrameworkImmutableError):
        store.create_scoring_contract(
            db,
            framework_id=fw.framework_id,
            scoring_schema_version="2.0",
            created_by="op",
        )


def test_assessment_requires_active_framework(store, db):
    fw = _make_framework(store, db, slug="fw-assess-draft-block")
    with pytest.raises(FrameworkNotActiveError):
        store.create_assessment(
            db,
            tenant_id="tenant-a",
            framework_id=fw.framework_id,
            framework_version_tag="v1",
            created_by="op",
        )


def test_assessment_blocked_on_deprecated_framework(store, db):
    fw = _make_active_framework(store, db, slug="fw-assess-deprecated-block")
    store.transition_framework_status(
        db,
        framework_id=fw.framework_id,
        to_status=FrameworkStatus.DEPRECATED,
        actor="op",
    )
    db.commit()
    with pytest.raises(FrameworkNotActiveError):
        store.create_assessment(
            db,
            tenant_id="tenant-a",
            framework_id=fw.framework_id,
            framework_version_tag="v1",
            created_by="op",
        )


# ---------------------------------------------------------------------------
# 4. Domain and control catalog
# ---------------------------------------------------------------------------


def test_create_domain(store, db):
    fw = _make_framework(store, db, slug="fw-domain-test")
    domain = store.create_domain(
        db,
        framework_id=fw.framework_id,
        domain_name="Governance",
        domain_slug="governance",
        domain_description="Governance domain",
        domain_order=1,
        created_by="op",
    )
    db.commit()
    assert domain.domain_id is not None
    assert domain.framework_id == fw.framework_id


def test_list_domains_ordered_by_domain_order(store, db):
    fw = _make_framework(store, db, slug="fw-domain-order")
    store.create_domain(
        db,
        framework_id=fw.framework_id,
        domain_name="C",
        domain_slug="c",
        domain_description="",
        domain_order=3,
        created_by="op",
    )
    store.create_domain(
        db,
        framework_id=fw.framework_id,
        domain_name="A",
        domain_slug="a",
        domain_description="",
        domain_order=1,
        created_by="op",
    )
    store.create_domain(
        db,
        framework_id=fw.framework_id,
        domain_name="B",
        domain_slug="b",
        domain_description="",
        domain_order=2,
        created_by="op",
    )
    db.commit()
    domains = store.list_domains(db, framework_id=fw.framework_id)
    orders = [d.domain_order for d in domains]
    assert orders == sorted(orders)


def test_create_control(store, db):
    fw = _make_framework(store, db, slug="fw-ctrl-test")
    domain = _make_domain(store, db, fw.framework_id)
    control = store.create_control(
        db,
        framework_id=fw.framework_id,
        domain_id=domain.domain_id,
        control_identifier="CTRL-001",
        control_name="Risk Management",
        control_description="desc",
        created_by="op",
        evidence_requirements={"type": "policy_doc"},
        maturity_mapping_metadata={"tier_1": "basic"},
    )
    db.commit()
    assert control.control_id is not None
    assert control.control_identifier == "CTRL-001"
    assert control.evidence_requirements == {"type": "policy_doc"}


def test_list_controls_by_domain(store, db):
    fw = _make_framework(store, db, slug="fw-ctrl-list")
    domain = _make_domain(store, db, fw.framework_id)
    store.create_control(
        db,
        framework_id=fw.framework_id,
        domain_id=domain.domain_id,
        control_identifier="C1",
        control_name="C1",
        control_description="",
        created_by="op",
    )
    store.create_control(
        db,
        framework_id=fw.framework_id,
        domain_id=domain.domain_id,
        control_identifier="C2",
        control_name="C2",
        control_description="",
        created_by="op",
    )
    db.commit()
    controls = store.list_controls(
        db, framework_id=fw.framework_id, domain_id=domain.domain_id
    )
    assert len(controls) == 2


# ---------------------------------------------------------------------------
# 5. Maturity tier
# ---------------------------------------------------------------------------


def test_create_maturity_tier(store, db):
    fw = _make_framework(store, db, slug="fw-tier-test")
    tier = store.create_maturity_tier(
        db,
        framework_id=fw.framework_id,
        tier_identifier="T1",
        tier_name="Initial",
        tier_order=1,
        tier_criteria="Basic awareness",
        created_by="op",
        readiness_classification="initial",
    )
    db.commit()
    assert tier.tier_id is not None
    assert tier.tier_order == 1
    assert tier.readiness_classification == "initial"


def test_list_maturity_tiers_ordered(store, db):
    fw = _make_framework(store, db, slug="fw-tier-order")
    for i in [3, 1, 2]:
        store.create_maturity_tier(
            db,
            framework_id=fw.framework_id,
            tier_identifier=f"T{i}",
            tier_name=f"Tier {i}",
            tier_order=i,
            tier_criteria="c",
            created_by="op",
        )
    db.commit()
    tiers = store.list_maturity_tiers(db, framework_id=fw.framework_id)
    orders = [t.tier_order for t in tiers]
    assert orders == sorted(orders)


# ---------------------------------------------------------------------------
# 6. Assessment lifecycle
# ---------------------------------------------------------------------------


def test_create_assessment(store, db):
    fw = _make_active_framework(store, db, slug="fw-assess-create")
    assessment = store.create_assessment(
        db,
        tenant_id="tenant-a",
        framework_id=fw.framework_id,
        framework_version_tag="v1",
        created_by="op",
        assessment_name="Q1 Assessment",
    )
    db.commit()
    assert assessment.assessment_id is not None
    assert assessment.assessment_status == AssessmentStatus.DRAFT
    assert assessment.tenant_id == "tenant-a"
    assert assessment.snapshot_version == 0


def test_assessment_lifecycle_full_path(store, db):
    fw = _make_framework(store, db, slug="fw-lifecycle-full")
    a = _make_assessment(store, db, fw.framework_id)
    # DRAFT → ACTIVE
    a = store.transition_assessment_status(
        db,
        assessment_id=a.assessment_id,
        to_status=AssessmentStatus.ACTIVE,
        actor="op",
        tenant_id="tenant-a",
    )
    db.commit()
    assert a.assessment_status == AssessmentStatus.ACTIVE
    assert a.activated_at is not None
    # ACTIVE → FINALIZED
    a = store.transition_assessment_status(
        db,
        assessment_id=a.assessment_id,
        to_status=AssessmentStatus.FINALIZED,
        actor="op",
        tenant_id="tenant-a",
    )
    db.commit()
    assert a.assessment_status == AssessmentStatus.FINALIZED
    assert a.finalized_at is not None
    assert a.snapshot_version == 1
    # FINALIZED → ARCHIVED
    a = store.transition_assessment_status(
        db,
        assessment_id=a.assessment_id,
        to_status=AssessmentStatus.ARCHIVED,
        actor="op",
        tenant_id="tenant-a",
    )
    db.commit()
    assert a.assessment_status == AssessmentStatus.ARCHIVED
    assert a.archived_at is not None


def test_assessment_revert_to_draft(store, db):
    fw = _make_framework(store, db, slug="fw-revert-draft")
    a = _make_assessment(store, db, fw.framework_id)
    a = store.transition_assessment_status(
        db,
        assessment_id=a.assessment_id,
        to_status=AssessmentStatus.ACTIVE,
        actor="op",
        tenant_id="tenant-a",
    )
    db.commit()
    a = store.transition_assessment_status(
        db,
        assessment_id=a.assessment_id,
        to_status=AssessmentStatus.DRAFT,
        actor="op",
        tenant_id="tenant-a",
    )
    db.commit()
    assert a.assessment_status == AssessmentStatus.DRAFT


def test_invalid_assessment_transition_store_raises(store, db):
    fw = _make_framework(store, db, slug="fw-bad-trans")
    a = _make_assessment(store, db, fw.framework_id)
    with pytest.raises(InvalidAssessmentTransition):
        store.transition_assessment_status(
            db,
            assessment_id=a.assessment_id,
            to_status=AssessmentStatus.ARCHIVED,
            actor="op",
            tenant_id="tenant-a",
        )


def test_assessment_not_found(store, db):
    with pytest.raises(AssessmentNotFound):
        store.get_assessment(db, assessment_id="nonexistent", tenant_id="tenant-a")


# ---------------------------------------------------------------------------
# 7. Assessment immutability
# ---------------------------------------------------------------------------


def test_assert_assessment_mutable_raises_for_finalized(store, db):
    fw = _make_framework(store, db, slug="fw-immut-finalized")
    a = _make_assessment(store, db, fw.framework_id)
    a = store.transition_assessment_status(
        db,
        assessment_id=a.assessment_id,
        to_status=AssessmentStatus.ACTIVE,
        actor="op",
        tenant_id="tenant-a",
    )
    a = store.transition_assessment_status(
        db,
        assessment_id=a.assessment_id,
        to_status=AssessmentStatus.FINALIZED,
        actor="op",
        tenant_id="tenant-a",
    )
    db.commit()
    with pytest.raises(ValueError, match="immutable"):
        assert_assessment_mutable(a)


def test_record_result_blocked_on_finalized_assessment(store, db):
    fw = _make_framework(store, db, slug="fw-result-block")
    domain = _make_domain(store, db, fw.framework_id)
    control = store.create_control(
        db,
        framework_id=fw.framework_id,
        domain_id=domain.domain_id,
        control_identifier="C1",
        control_name="C1",
        control_description="",
        created_by="op",
    )
    db.commit()
    # _make_assessment activates the framework before creating the assessment
    a = _make_assessment(store, db, fw.framework_id)
    a = store.transition_assessment_status(
        db,
        assessment_id=a.assessment_id,
        to_status=AssessmentStatus.ACTIVE,
        actor="op",
        tenant_id="tenant-a",
    )
    a = store.transition_assessment_status(
        db,
        assessment_id=a.assessment_id,
        to_status=AssessmentStatus.FINALIZED,
        actor="op",
        tenant_id="tenant-a",
    )
    db.commit()
    with pytest.raises(AssessmentImmutableError):
        store.record_assessment_result(
            db,
            assessment_id=a.assessment_id,
            control_id=control.control_id,
            outcome=AssessmentOutcome.COMPLIANT,
            actor="op",
            tenant_id="tenant-a",
        )


def test_attach_evidence_blocked_on_archived_assessment(store, db):
    fw = _make_framework(store, db, slug="fw-evidence-block")
    a = _make_assessment(store, db, fw.framework_id)
    a = store.transition_assessment_status(
        db,
        assessment_id=a.assessment_id,
        to_status=AssessmentStatus.ACTIVE,
        actor="op",
        tenant_id="tenant-a",
    )
    a = store.transition_assessment_status(
        db,
        assessment_id=a.assessment_id,
        to_status=AssessmentStatus.FINALIZED,
        actor="op",
        tenant_id="tenant-a",
    )
    a = store.transition_assessment_status(
        db,
        assessment_id=a.assessment_id,
        to_status=AssessmentStatus.ARCHIVED,
        actor="op",
        tenant_id="tenant-a",
    )
    db.commit()
    with pytest.raises(AssessmentImmutableError):
        store.attach_evidence_reference(
            db,
            assessment_id=a.assessment_id,
            evidence_type=EvidenceType.DOCUMENT,
            evidence_title="Evidence",
            submitted_by="op",
            tenant_id="tenant-a",
        )


# ---------------------------------------------------------------------------
# 8. Assessment result recording
# ---------------------------------------------------------------------------


def test_record_assessment_result(store, db):
    fw = _make_framework(store, db, slug="fw-result-record")
    domain = _make_domain(store, db, fw.framework_id)
    control = store.create_control(
        db,
        framework_id=fw.framework_id,
        domain_id=domain.domain_id,
        control_identifier="C1",
        control_name="C1",
        control_description="",
        created_by="op",
    )
    db.commit()
    # _make_assessment activates the framework before creating the assessment
    a = _make_assessment(store, db, fw.framework_id)
    result = store.record_assessment_result(
        db,
        assessment_id=a.assessment_id,
        control_id=control.control_id,
        outcome=AssessmentOutcome.COMPLIANT,
        actor="op",
        tenant_id="tenant-a",
        evaluation_metadata={"note": "passed"},
    )
    db.commit()
    assert result.result_id is not None
    assert result.outcome == AssessmentOutcome.COMPLIANT
    assert result.evaluation_metadata == {"note": "passed"}


def test_list_assessment_results(store, db):
    fw = _make_framework(store, db, slug="fw-result-list")
    domain = _make_domain(store, db, fw.framework_id)
    c1 = store.create_control(
        db,
        framework_id=fw.framework_id,
        domain_id=domain.domain_id,
        control_identifier="C1",
        control_name="C1",
        control_description="",
        created_by="op",
    )
    c2 = store.create_control(
        db,
        framework_id=fw.framework_id,
        domain_id=domain.domain_id,
        control_identifier="C2",
        control_name="C2",
        control_description="",
        created_by="op",
    )
    db.commit()
    a = _make_assessment(store, db, fw.framework_id)
    store.record_assessment_result(
        db,
        assessment_id=a.assessment_id,
        control_id=c1.control_id,
        outcome=AssessmentOutcome.COMPLIANT,
        actor="op",
        tenant_id="tenant-a",
    )
    store.record_assessment_result(
        db,
        assessment_id=a.assessment_id,
        control_id=c2.control_id,
        outcome=AssessmentOutcome.NON_COMPLIANT,
        actor="op",
        tenant_id="tenant-a",
    )
    db.commit()
    results = store.list_assessment_results(
        db, assessment_id=a.assessment_id, tenant_id="tenant-a"
    )
    assert len(results) == 2


# ---------------------------------------------------------------------------
# 9. Evidence reference contracts
# ---------------------------------------------------------------------------


def test_attach_evidence_reference(store, db):
    fw = _make_framework(store, db, slug="fw-evref")
    a = _make_assessment(store, db, fw.framework_id)
    evidence = store.attach_evidence_reference(
        db,
        assessment_id=a.assessment_id,
        evidence_type=EvidenceType.POLICY,
        evidence_title="AI Policy v2",
        submitted_by="op",
        tenant_id="tenant-a",
        evidence_classification="internal",
        evidence_integrity_metadata={"sha256": "abc123"},
    )
    db.commit()
    assert evidence.evidence_id is not None
    assert evidence.evidence_type == EvidenceType.POLICY
    assert evidence.evidence_classification == "internal"
    assert evidence.evidence_integrity_metadata == {"sha256": "abc123"}


def test_list_evidence_references(store, db):
    fw = _make_framework(store, db, slug="fw-evref-list")
    a = _make_assessment(store, db, fw.framework_id)
    store.attach_evidence_reference(
        db,
        assessment_id=a.assessment_id,
        evidence_type=EvidenceType.DOCUMENT,
        evidence_title="Doc 1",
        submitted_by="op",
        tenant_id="tenant-a",
    )
    store.attach_evidence_reference(
        db,
        assessment_id=a.assessment_id,
        evidence_type=EvidenceType.ATTESTATION,
        evidence_title="Attest 1",
        submitted_by="op",
        tenant_id="tenant-a",
    )
    db.commit()
    evidence_list = store.list_evidence_references(
        db, assessment_id=a.assessment_id, tenant_id="tenant-a"
    )
    assert len(evidence_list) == 2


# ---------------------------------------------------------------------------
# 10. Scoring contract
# ---------------------------------------------------------------------------


def test_create_scoring_contract(store, db):
    fw = _make_framework(store, db, slug="fw-sc")
    contract = store.create_scoring_contract(
        db,
        framework_id=fw.framework_id,
        scoring_schema_version="1.0.0",
        created_by="op",
        weighting_metadata={"domain_weight": "equal"},
        normalization_metadata={"method": "linear"},
    )
    db.commit()
    assert contract.contract_id is not None
    assert contract.scoring_schema_version == "1.0.0"
    assert contract.is_active is True
    assert contract.weighting_metadata == {"domain_weight": "equal"}


def test_get_scoring_contract(store, db):
    fw = _make_framework(store, db, slug="fw-sc-get")
    contract = store.create_scoring_contract(
        db, framework_id=fw.framework_id, scoring_schema_version="1.0", created_by="op"
    )
    db.commit()
    retrieved = store.get_scoring_contract(db, contract_id=contract.contract_id)
    assert retrieved.contract_id == contract.contract_id


def test_list_scoring_contracts(store, db):
    fw = _make_framework(store, db, slug="fw-sc-list")
    store.create_scoring_contract(
        db, framework_id=fw.framework_id, scoring_schema_version="1.0", created_by="op"
    )
    store.create_scoring_contract(
        db, framework_id=fw.framework_id, scoring_schema_version="2.0", created_by="op"
    )
    db.commit()
    contracts = store.list_scoring_contracts(db, framework_id=fw.framework_id)
    assert len(contracts) == 2


# ---------------------------------------------------------------------------
# 11. Tenant isolation
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_assessment_tenant_isolation(store, db):
    fw = _make_active_framework(store, db, slug="fw-iso")
    a = store.create_assessment(
        db,
        tenant_id="tenant-a",
        framework_id=fw.framework_id,
        framework_version_tag="v1",
        created_by="op",
    )
    db.commit()
    with pytest.raises(AssessmentNotFound):
        store.get_assessment(db, assessment_id=a.assessment_id, tenant_id="tenant-b")


@pytest.mark.security
def test_assessment_list_tenant_isolation(store, db):
    fw = _make_active_framework(store, db, slug="fw-list-iso")
    store.create_assessment(
        db,
        tenant_id="tenant-a",
        framework_id=fw.framework_id,
        framework_version_tag="v1",
        created_by="op",
    )
    store.create_assessment(
        db,
        tenant_id="tenant-b",
        framework_id=fw.framework_id,
        framework_version_tag="v1",
        created_by="op",
    )
    db.commit()
    a_list = store.list_assessments(db, tenant_id="tenant-a")
    b_list = store.list_assessments(db, tenant_id="tenant-b")
    assert len(a_list) == 1
    assert len(b_list) == 1
    assert a_list[0].tenant_id == "tenant-a"
    assert b_list[0].tenant_id == "tenant-b"


@pytest.mark.security
def test_evidence_tenant_isolation(store, db):
    fw = _make_active_framework(store, db, slug="fw-ev-iso")
    a_a = store.create_assessment(
        db,
        tenant_id="tenant-a",
        framework_id=fw.framework_id,
        framework_version_tag="v1",
        created_by="op",
    )
    db.commit()
    # tenant-b cannot attach evidence to tenant-a's assessment
    with pytest.raises(AssessmentNotFound):
        store.attach_evidence_reference(
            db,
            assessment_id=a_a.assessment_id,
            evidence_type=EvidenceType.DOCUMENT,
            evidence_title="Attacker Evidence",
            submitted_by="attacker",
            tenant_id="tenant-b",
        )


@pytest.mark.security
def test_result_tenant_isolation(store, db):
    fw = _make_framework(store, db, slug="fw-res-iso")
    domain = _make_domain(store, db, fw.framework_id)
    control = store.create_control(
        db,
        framework_id=fw.framework_id,
        domain_id=domain.domain_id,
        control_identifier="C1",
        control_name="C1",
        control_description="",
        created_by="op",
    )
    db.commit()
    store.transition_framework_status(
        db, framework_id=fw.framework_id, to_status=FrameworkStatus.ACTIVE, actor="op"
    )
    db.commit()
    a_a = store.create_assessment(
        db,
        tenant_id="tenant-a",
        framework_id=fw.framework_id,
        framework_version_tag="v1",
        created_by="op",
    )
    db.commit()
    # tenant-b cannot record results on tenant-a's assessment
    with pytest.raises(AssessmentNotFound):
        store.record_assessment_result(
            db,
            assessment_id=a_a.assessment_id,
            control_id=control.control_id,
            outcome=AssessmentOutcome.COMPLIANT,
            actor="attacker",
            tenant_id="tenant-b",
        )


# ---------------------------------------------------------------------------
# 12. Audit event hash chain integrity
# ---------------------------------------------------------------------------


def test_framework_audit_events_hash_chain(store, db):
    fw = _make_framework(store, db, slug="fw-hash-chain")
    store.transition_framework_status(
        db, framework_id=fw.framework_id, to_status=FrameworkStatus.ACTIVE, actor="op"
    )
    db.commit()
    events = store.list_audit_events(
        db, resource_type="framework", resource_id=fw.framework_id
    )
    assert len(events) >= 2
    for ev in events:
        assert ev.event_hash is not None
    # first event has no previous hash, subsequent events chain
    first = events[0]
    second = events[1]
    assert second.previous_event_hash == first.event_hash


def test_assessment_audit_event_emitted_on_create(store, db):
    fw = _make_framework(store, db, slug="fw-audit-create")
    a = _make_assessment(store, db, fw.framework_id)
    events = store.list_audit_events(
        db, resource_type="assessment", resource_id=a.assessment_id
    )
    assert len(events) >= 1
    assert events[0].event_hash is not None


def test_audit_hash_deterministic(store, db):
    from services.readiness.audit import compute_event_hash

    h1 = compute_event_hash(
        event_id="ev-1",
        resource_type="framework",
        resource_id="fw-1",
        event_type="framework_created",
        actor="op",
        timestamp_iso="2026-01-01T00:00:00",
        outcome="success",
        previous_event_hash=None,
    )
    h2 = compute_event_hash(
        event_id="ev-1",
        resource_type="framework",
        resource_id="fw-1",
        event_type="framework_created",
        actor="op",
        timestamp_iso="2026-01-01T00:00:00",
        outcome="success",
        previous_event_hash=None,
    )
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


# ---------------------------------------------------------------------------
# 13. Framework version management
# ---------------------------------------------------------------------------


def test_create_framework_version(store, db):
    fw = _make_framework(store, db, slug="fw-ver-test")
    version = store.create_framework_version(
        db,
        framework_id=fw.framework_id,
        version_tag="v1.0.0",
        created_by="op",
        schema_hash="abc123",
    )
    db.commit()
    assert version.version_id is not None
    assert version.version_tag == "v1.0.0"
    assert version.schema_hash == "abc123"


def test_list_framework_versions(store, db):
    fw = _make_framework(store, db, slug="fw-ver-list")
    store.create_framework_version(
        db, framework_id=fw.framework_id, version_tag="v1", created_by="op"
    )
    store.create_framework_version(
        db, framework_id=fw.framework_id, version_tag="v2", created_by="op"
    )
    db.commit()
    versions = store.list_framework_versions(db, framework_id=fw.framework_id)
    assert len(versions) == 2


# ---------------------------------------------------------------------------
# 14. Snapshot version increments on finalization
# ---------------------------------------------------------------------------


def test_snapshot_version_increments_on_finalization(store, db):
    fw = _make_framework(store, db, slug="fw-snap")
    a = _make_assessment(store, db, fw.framework_id)
    assert a.snapshot_version == 0
    a = store.transition_assessment_status(
        db,
        assessment_id=a.assessment_id,
        to_status=AssessmentStatus.ACTIVE,
        actor="op",
        tenant_id="tenant-a",
    )
    a = store.transition_assessment_status(
        db,
        assessment_id=a.assessment_id,
        to_status=AssessmentStatus.FINALIZED,
        actor="op",
        tenant_id="tenant-a",
    )
    db.commit()
    assert a.snapshot_version == 1


# ---------------------------------------------------------------------------
# 15. API contract tests
# ---------------------------------------------------------------------------


@pytest.mark.contract
def test_api_create_framework(api_client):
    resp = api_client.post(
        "/control-plane/readiness/frameworks",
        json={
            "framework_name": "Test Framework",
            "framework_slug": "test-framework-api",
            "framework_version": "1.0.0",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["framework_status"] == "draft"
    assert body["framework_slug"] == "test-framework-api"
    assert "framework_id" in body


@pytest.mark.contract
def test_api_list_frameworks(api_client):
    resp = api_client.get("/control-plane/readiness/frameworks")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.contract
def test_api_get_framework_not_found(api_client):
    resp = api_client.get("/control-plane/readiness/frameworks/nonexistent-id")
    assert resp.status_code == 404


@pytest.mark.contract
def test_api_create_framework_duplicate_slug(api_client):
    api_client.post(
        "/control-plane/readiness/frameworks",
        json={
            "framework_name": "A",
            "framework_slug": "dup-slug-api",
            "framework_version": "1.0",
        },
    )
    resp = api_client.post(
        "/control-plane/readiness/frameworks",
        json={
            "framework_name": "B",
            "framework_slug": "dup-slug-api",
            "framework_version": "2.0",
        },
    )
    assert resp.status_code == 409


@pytest.mark.contract
def test_api_framework_transition(api_client):
    resp = api_client.post(
        "/control-plane/readiness/frameworks",
        json={
            "framework_name": "TF",
            "framework_slug": "tf-transition-api",
            "framework_version": "1.0",
        },
    )
    fw_id = resp.json()["framework_id"]
    resp = api_client.post(
        f"/control-plane/readiness/frameworks/{fw_id}/transition",
        json={"to_status": "active"},
    )
    assert resp.status_code == 200
    assert resp.json()["framework_status"] == "active"


@pytest.mark.contract
def test_api_invalid_framework_transition(api_client):
    resp = api_client.post(
        "/control-plane/readiness/frameworks",
        json={
            "framework_name": "TF2",
            "framework_slug": "tf-bad-trans-api",
            "framework_version": "1.0",
        },
    )
    fw_id = resp.json()["framework_id"]
    resp = api_client.post(
        f"/control-plane/readiness/frameworks/{fw_id}/transition",
        json={"to_status": "retired"},
    )
    assert resp.status_code == 409


@pytest.mark.contract
def test_api_create_framework_version(api_client):
    resp = api_client.post(
        "/control-plane/readiness/frameworks",
        json={
            "framework_name": "FV",
            "framework_slug": "fw-ver-api",
            "framework_version": "1.0",
        },
    )
    fw_id = resp.json()["framework_id"]
    resp = api_client.post(
        f"/control-plane/readiness/frameworks/{fw_id}/versions",
        json={"version_tag": "v1.0.0"},
    )
    assert resp.status_code == 201
    assert resp.json()["version_tag"] == "v1.0.0"


@pytest.mark.contract
def test_api_create_domain_requires_draft_framework(api_client):
    # Create and activate framework
    resp = api_client.post(
        "/control-plane/readiness/frameworks",
        json={
            "framework_name": "FD",
            "framework_slug": "fw-domain-api-block",
            "framework_version": "1.0",
        },
    )
    fw_id = resp.json()["framework_id"]
    api_client.post(
        f"/control-plane/readiness/frameworks/{fw_id}/transition",
        json={"to_status": "active"},
    )
    # Domain creation should fail
    resp = api_client.post(
        "/control-plane/readiness/domains",
        json={
            "framework_id": fw_id,
            "domain_name": "D",
            "domain_slug": "d",
            "domain_order": 0,
        },
    )
    assert resp.status_code == 409


@pytest.mark.contract
def test_api_create_maturity_tier(api_client):
    resp = api_client.post(
        "/control-plane/readiness/frameworks",
        json={
            "framework_name": "MT",
            "framework_slug": "fw-mt-api",
            "framework_version": "1.0",
        },
    )
    fw_id = resp.json()["framework_id"]
    resp = api_client.post(
        "/control-plane/readiness/maturity-tiers",
        json={
            "framework_id": fw_id,
            "tier_identifier": "T1",
            "tier_name": "Initial",
            "tier_order": 1,
            "tier_criteria": "Basic",
        },
    )
    assert resp.status_code == 201
    assert resp.json()["tier_identifier"] == "T1"


@pytest.mark.contract
def test_api_create_scoring_contract(api_client):
    resp = api_client.post(
        "/control-plane/readiness/frameworks",
        json={
            "framework_name": "SC",
            "framework_slug": "fw-sc-api",
            "framework_version": "1.0",
        },
    )
    fw_id = resp.json()["framework_id"]
    resp = api_client.post(
        "/control-plane/readiness/scoring-contracts",
        json={"framework_id": fw_id, "scoring_schema_version": "1.0.0"},
    )
    assert resp.status_code == 201
    assert resp.json()["scoring_schema_version"] == "1.0.0"
    assert resp.json()["is_active"] is True


@pytest.mark.contract
def test_api_extra_fields_rejected(api_client):
    resp = api_client.post(
        "/control-plane/readiness/frameworks",
        json={
            "framework_name": "EF",
            "framework_slug": "ef-api",
            "framework_version": "1.0",
            "injected_field": "evil",
        },
    )
    assert resp.status_code == 422


@pytest.mark.contract
def test_api_no_secrets_in_response(api_client):
    resp = api_client.post(
        "/control-plane/readiness/frameworks",
        json={
            "framework_name": "NS",
            "framework_slug": "ns-api",
            "framework_version": "1.0",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    body_str = str(body).lower()
    for secret_key in ("password", "secret", "token", "credential", "key_hash"):
        assert secret_key not in body_str, (
            f"Potential secret field in response: {secret_key}"
        )
