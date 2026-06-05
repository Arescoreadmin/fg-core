"""tests/test_pr52_verification_bundle.py — PR 52 Verification Bundle V1.

V1   generate bundle — 201 with bundle_id, bundle_hash, verification_status
V2   generate bundle — wrong tenant returns 404
V3   generate bundle — engagement not found returns 404
V4   generate bundle — bundle_hash is SHA-256 hex (64 chars)
V5   generate bundle — manifest_hash is present and 64 chars
V6   generate bundle — finding_count matches DB
V7   generate bundle — evidence_count matches DB
V8   generate bundle — decision_count matches DB
V9   generate bundle — audit_event_count matches DB (>= seeded count)
V10  generate bundle — verification_status is 'incomplete' when no report
V11  generate bundle — verification_status is 'verified' when report present
V12  generate bundle — multiple generations produce distinct bundle_ids
V13  generate bundle — tamper_detected when finding refs non-existent evidence
V14  get bundle status — returns latest bundle
V15  get bundle status — engagement not found returns 404
V16  get bundle status — tenant isolation
V17  get bundle status — no bundle yet returns 404
V18  get bundle manifest — returns manifest_hash + component_summary
V19  get bundle manifest — engagement not found returns 404
V20  get bundle manifest — tenant isolation
V21  get bundle manifest — no bundle yet returns 404
V22  bundle stores component_summary — each component has name, count, hash
V23  service.generate_bundle — direct service test (no HTTP)
V24  service tamper detection — orphaned risk acceptance (decision_id mismatch)
V25  service tamper detection — clean engagement returns no tamper_details
V26  service hash — component hashes identical for engagements with same empty state
V27  generate bundle — audit event emitted (verification_bundle.generated)
V28  generate bundle — generated_by captures actor from API key
V29  generate bundle — interview_count counts only observation_type=interview
V30  generate bundle — exception_count matches DB
V31  generate bundle — risk_acceptance_count matches DB
V32  component_summary — all 10 required components present (PR 52.5 expanded set)
"""

from __future__ import annotations

import json
import os
import secrets

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)

import pytest
from fastapi.testclient import TestClient

from services.verification_bundle.bundle_service import VerificationBundleService

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT = "tenant-pr52-test"
_OTHER = "tenant-pr52-other"

_BASE = "/field-assessment/engagements"


# ---------------------------------------------------------------------------
# App helpers
# ---------------------------------------------------------------------------


def _sessionmaker():
    from api.db import get_sessionmaker

    return get_sessionmaker()


def _mint_key_with_role(
    *scopes: str, tenant_id: str, role_name: str, session_factory
) -> str:
    from sqlalchemy import text as sa_text
    from api.auth_scopes import mint_key
    from api.tenant_rbac import assign_role

    key = mint_key(*scopes, tenant_id=tenant_id)

    db = session_factory()()
    try:
        key_id = db.execute(
            sa_text(
                """
                SELECT id
                FROM api_keys
                WHERE tenant_id = :tenant_id
                ORDER BY id DESC
                LIMIT 1
                """
            ),
            {"tenant_id": tenant_id},
        ).scalar_one()

        assign_role(
            db,
            tenant_id=tenant_id,
            actor_key_prefix="pytest",
            target_key_id=int(key_id),
            role_name=role_name,
        )
    finally:
        db.close()

    return key


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(build_app):
    app = build_app(auth_enabled=True)
    key = _mint_key_with_role(
        "governance:write",
        "governance:read",
        tenant_id=_TENANT,
        role_name="analyst",
        session_factory=_sessionmaker,
    )
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def other_client(build_app):
    app = build_app(auth_enabled=True)
    key = _mint_key_with_role(
        "governance:write",
        "governance:read",
        tenant_id=_OTHER,
        role_name="analyst",
        session_factory=_sessionmaker,
    )
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def SM(build_app):
    build_app(auth_enabled=True)
    return _sessionmaker()


@pytest.fixture()
def eng_id(SM):
    return _make_engagement(SM, tenant_id=_TENANT)


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _make_engagement(SM, *, tenant_id: str) -> str:
    from api.db_models_field_assessment import FaEngagement
    from services.canonical import utc_iso8601_z_now

    eid = secrets.token_hex(16)
    now = utc_iso8601_z_now()
    db = SM()
    try:
        db.add(
            FaEngagement(
                id=eid,
                tenant_id=tenant_id,
                client_name="VerifyClient",
                assessor_id="assessor-pr52",
                assessment_type="ai_governance",
                status="in_progress",
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
    finally:
        db.close()
    return eid


def _make_finding(
    SM, *, tenant_id: str, engagement_id: str, evidence_ref_ids=None
) -> str:
    from api.db_models_field_assessment import FaNormalizedFinding
    from services.canonical import utc_iso8601_z_now

    fid = secrets.token_hex(16)
    now = utc_iso8601_z_now()
    db = SM()
    try:
        db.add(
            FaNormalizedFinding(
                id=fid,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                finding_type="test",
                findings_hash=secrets.token_hex(16),
                severity="high",
                status="open",
                title="Test Finding PR52",
                description="Test.",
                source_attribution="test",
                framework_mappings=[],
                nist_ai_rmf_mappings=[],
                evidence_ref_ids=evidence_ref_ids or [],
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
    finally:
        db.close()
    return fid


def _make_evidence_link(SM, *, tenant_id: str, engagement_id: str) -> str:
    from api.db_models_field_assessment import FaEvidenceLink
    from services.canonical import utc_iso8601_z_now

    eid = secrets.token_hex(16)
    db = SM()
    try:
        db.add(
            FaEvidenceLink(
                id=eid,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                source_entity_type="finding",
                source_entity_id=secrets.token_hex(8),
                evidence_entity_type="scan_result",
                evidence_entity_id=secrets.token_hex(8),
                link_metadata={},
                created_at=utc_iso8601_z_now(),
            )
        )
        db.commit()
    finally:
        db.close()
    return eid


def _make_decision(SM, *, tenant_id: str, engagement_id: str) -> str:
    from api.db_models_governance_decision import FaGovernanceDecision
    from services.canonical import utc_iso8601_z_now

    did = secrets.token_hex(16)
    db = SM()
    try:
        db.add(
            FaGovernanceDecision(
                id=did,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                decision_type="risk_accepted",
                entity_type="finding",
                entity_id=secrets.token_hex(8),
                actor_id="test-actor",
                actor_auth_source="api_key",
                approver_id="test-actor",
                decision_reason="Test decision.",
                status="active",
                decision_at=utc_iso8601_z_now(),
            )
        )
        db.commit()
    finally:
        db.close()
    return did


def _make_risk_acceptance(
    SM, *, tenant_id: str, engagement_id: str, decision_id: str, finding_id: str
) -> str:
    from api.db_models_governance_decision import FaRiskAcceptance
    from services.canonical import utc_iso8601_z_now

    rid = secrets.token_hex(16)
    db = SM()
    try:
        db.add(
            FaRiskAcceptance(
                id=rid,
                decision_id=decision_id,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                finding_id=finding_id,
                risk_owner="test-owner",
                business_justification="Test.",
                accepted_risk_level="medium",
                expires_at="2027-01-01T00:00:00Z",
                review_date="2026-12-01T00:00:00Z",
                approver_id="test-actor",
                status="active",
                created_at=utc_iso8601_z_now(),
            )
        )
        db.commit()
    finally:
        db.close()
    return rid


def _make_exception(SM, *, tenant_id: str, engagement_id: str, decision_id: str) -> str:
    from api.db_models_governance_decision import FaGovernanceException
    from services.canonical import utc_iso8601_z_now

    eid = secrets.token_hex(16)
    db = SM()
    try:
        db.add(
            FaGovernanceException(
                id=eid,
                decision_id=decision_id,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                exception_type="policy_deviation",
                owner="test-owner",
                business_justification="Test.",
                expires_at="2027-01-01T00:00:00Z",
                approver_id="test-actor",
                status="active",
                created_at=utc_iso8601_z_now(),
            )
        )
        db.commit()
    finally:
        db.close()
    return eid


def _make_observation_interview(SM, *, tenant_id: str, engagement_id: str) -> str:
    from api.db_models_field_assessment import FaFieldObservation
    from services.canonical import utc_iso8601_z_now

    oid = secrets.token_hex(16)
    db = SM()
    try:
        db.add(
            FaFieldObservation(
                id=oid,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                domain="ai_governance",
                observation_type="interview",
                severity="info",
                title="Test Interview",
                description="Interview observation.",
                interview_role="ciso",
                structured_evidence={},
                linked_finding_ids=[],
                assessor_id="assessor-pr52",
                created_at=utc_iso8601_z_now(),
            )
        )
        db.commit()
    finally:
        db.close()
    return oid


def _make_report(SM, *, tenant_id: str, engagement_id: str) -> str:
    from api.db_models_governance_report import GovernanceReportRecord
    from services.canonical import utc_iso8601_z_now

    rid = secrets.token_hex(16)
    db = SM()
    try:
        db.add(
            GovernanceReportRecord(
                id=rid,
                tenant_id=tenant_id,
                assessment_id=engagement_id,
                version=1,
                manifest_hash=secrets.token_hex(16),
                report_json={"sections": []},
                generated_at=utc_iso8601_z_now(),
                is_finalized=True,
            )
        )
        db.commit()
    finally:
        db.close()
    return rid


def _make_scan_audit_event(SM, *, tenant_id: str, engagement_id: str) -> str:
    from api.db_models_field_assessment import FaScanAuditEvent
    from services.canonical import utc_iso8601_z_now

    aeid = secrets.token_hex(16)
    db = SM()
    try:
        db.add(
            FaScanAuditEvent(
                id=aeid,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                event_type="scan.completed",
                actor="test-actor",
                created_at=utc_iso8601_z_now(),
            )
        )
        db.commit()
    finally:
        db.close()
    return aeid


# ---------------------------------------------------------------------------
# Tests — Generate bundle
# ---------------------------------------------------------------------------


def test_v1_generate_bundle_201(client, eng_id):
    r = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 201
    data = r.json()
    assert "bundle_id" in data
    assert "bundle_hash" in data
    assert "verification_status" in data


def test_v2_generate_bundle_wrong_tenant_404(other_client, SM, eng_id):
    r = other_client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 404


def test_v3_generate_bundle_engagement_not_found(client):
    r = client.post(f"{_BASE}/nonexistent-eid/verification-bundle/generate")
    assert r.status_code == 404


def test_v4_bundle_hash_is_sha256_hex(client, eng_id):
    r = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 201
    h = r.json()["bundle_hash"]
    assert len(h) == 64
    int(h, 16)  # valid hex


def test_v5_manifest_hash_present_and_64(client, eng_id):
    r = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 201
    mh = r.json()["manifest_hash"]
    assert len(mh) == 64
    int(mh, 16)


def test_v6_finding_count_matches_db(client, SM, eng_id):
    _make_finding(SM, tenant_id=_TENANT, engagement_id=eng_id)
    _make_finding(SM, tenant_id=_TENANT, engagement_id=eng_id)
    r = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 201
    assert r.json()["finding_count"] == 2


def test_v7_evidence_count_matches_db(client, SM, eng_id):
    _make_evidence_link(SM, tenant_id=_TENANT, engagement_id=eng_id)
    _make_evidence_link(SM, tenant_id=_TENANT, engagement_id=eng_id)
    _make_evidence_link(SM, tenant_id=_TENANT, engagement_id=eng_id)
    r = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 201
    assert r.json()["evidence_count"] == 3


def test_v8_decision_count_matches_db(client, SM, eng_id):
    _make_decision(SM, tenant_id=_TENANT, engagement_id=eng_id)
    r = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 201
    assert r.json()["decision_count"] == 1


def test_v9_audit_event_count_at_least_seeded(client, SM, eng_id):
    _make_scan_audit_event(SM, tenant_id=_TENANT, engagement_id=eng_id)
    _make_scan_audit_event(SM, tenant_id=_TENANT, engagement_id=eng_id)
    r = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 201
    # At least the 2 pre-seeded scan audit events
    assert r.json()["audit_event_count"] >= 2


def test_v10_status_incomplete_when_no_report(client, eng_id):
    r = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 201
    assert r.json()["verification_status"] == "incomplete"
    assert r.json()["has_report"] is False


def test_v11_status_verified_with_report(client, SM, eng_id):
    _make_report(SM, tenant_id=_TENANT, engagement_id=eng_id)
    r = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 201
    assert r.json()["verification_status"] == "verified"
    assert r.json()["has_report"] is True


def test_v12_multiple_generations_distinct_ids(client, eng_id):
    r1 = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    r2 = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["bundle_id"] != r2.json()["bundle_id"]


def test_v13_tamper_detected_broken_finding_refs(client, SM, eng_id):
    _make_finding(
        SM,
        tenant_id=_TENANT,
        engagement_id=eng_id,
        evidence_ref_ids=["nonexistent-evidence-id"],
    )
    r = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 201
    data = r.json()
    assert data["verification_status"] == "tamper_detected"
    assert data["tamper_details"] is not None
    assert len(data["tamper_details"]) >= 1
    assert any("nonexistent-evidence-id" in t for t in data["tamper_details"])


# ---------------------------------------------------------------------------
# Tests — Get bundle
# ---------------------------------------------------------------------------


def test_v14_get_bundle_returns_latest(client, eng_id):
    r_gen = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r_gen.status_code == 201
    bundle_id = r_gen.json()["bundle_id"]
    r_get = client.get(f"{_BASE}/{eng_id}/verification-bundle")
    assert r_get.status_code == 200
    assert r_get.json()["bundle_id"] == bundle_id


def test_v15_get_bundle_engagement_not_found(client):
    r = client.get(f"{_BASE}/nonexistent/verification-bundle")
    assert r.status_code == 404


def test_v16_get_bundle_tenant_isolation(client, other_client, eng_id):
    client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    r = other_client.get(f"{_BASE}/{eng_id}/verification-bundle")
    assert r.status_code == 404


def test_v17_get_bundle_no_bundle_yet_404(client, eng_id):
    r = client.get(f"{_BASE}/{eng_id}/verification-bundle")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Tests — Get manifest
# ---------------------------------------------------------------------------


def test_v18_get_manifest_returns_hash_and_summary(client, eng_id):
    client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    r = client.get(f"{_BASE}/{eng_id}/verification-bundle/manifest")
    assert r.status_code == 200
    data = r.json()
    assert "manifest_hash" in data
    assert "bundle_hash" in data
    assert "component_summary" in data
    assert isinstance(data["component_summary"], list)


def test_v19_get_manifest_engagement_not_found(client):
    r = client.get(f"{_BASE}/nonexistent/verification-bundle/manifest")
    assert r.status_code == 404


def test_v20_get_manifest_tenant_isolation(client, other_client, eng_id):
    client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    r = other_client.get(f"{_BASE}/{eng_id}/verification-bundle/manifest")
    assert r.status_code == 404


def test_v21_get_manifest_no_bundle_404(client, eng_id):
    r = client.get(f"{_BASE}/{eng_id}/verification-bundle/manifest")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Tests — Component summary
# ---------------------------------------------------------------------------


def test_v22_component_summary_has_name_count_hash(client, eng_id):
    r = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 201
    summary = r.json()["component_summary"]
    assert len(summary) > 0
    for c in summary:
        assert "name" in c
        assert "count" in c
        assert "hash" in c
        assert len(c["hash"]) == 64


# ---------------------------------------------------------------------------
# Tests — Direct service
# ---------------------------------------------------------------------------


def test_v23_service_direct_generate(SM, eng_id):
    svc = VerificationBundleService()
    db = SM()
    try:
        bundle = svc.generate_bundle(
            db, tenant_id=_TENANT, engagement_id=eng_id, actor_id="direct-test"
        )
        db.commit()
        assert bundle.id is not None
        assert len(bundle.bundle_hash) == 64
        assert bundle.verification_status in (
            "verified",
            "incomplete",
            "tamper_detected",
        )
        assert bundle.generated_by == "direct-test"
    finally:
        db.close()


def test_v24_service_tamper_orphaned_risk_acceptance(SM, eng_id):
    fid = _make_finding(SM, tenant_id=_TENANT, engagement_id=eng_id)
    # Risk acceptance with a decision_id that doesn't exist in this engagement
    _make_risk_acceptance(
        SM,
        tenant_id=_TENANT,
        engagement_id=eng_id,
        decision_id="orphaned-decision-id",
        finding_id=fid,
    )
    svc = VerificationBundleService()
    db = SM()
    try:
        bundle = svc.generate_bundle(
            db, tenant_id=_TENANT, engagement_id=eng_id, actor_id="test"
        )
        db.commit()
        assert bundle.verification_status == "tamper_detected"
        tamper = json.loads(bundle.tamper_details)
        assert any("orphaned-decision-id" in t for t in tamper)
    finally:
        db.close()


def test_v25_service_clean_engagement_no_tamper(SM, eng_id):
    _make_report(SM, tenant_id=_TENANT, engagement_id=eng_id)
    svc = VerificationBundleService()
    db = SM()
    try:
        bundle = svc.generate_bundle(
            db, tenant_id=_TENANT, engagement_id=eng_id, actor_id="test"
        )
        db.commit()
        assert bundle.verification_status == "verified"
        assert bundle.tamper_details is None
    finally:
        db.close()


def test_v26_component_hashes_identical_for_empty_engagements(SM):
    eid1 = _make_engagement(SM, tenant_id=_TENANT)
    eid2 = _make_engagement(SM, tenant_id=_TENANT)
    svc = VerificationBundleService()
    db = SM()
    try:
        b1 = svc.generate_bundle(
            db, tenant_id=_TENANT, engagement_id=eid1, actor_id="a"
        )
        b2 = svc.generate_bundle(
            db, tenant_id=_TENANT, engagement_id=eid2, actor_id="a"
        )
        db.commit()
        cs1 = {c["name"]: c["hash"] for c in json.loads(b1.component_summary)}
        cs2 = {c["name"]: c["hash"] for c in json.loads(b2.component_summary)}
        assert cs1["findings"] == cs2["findings"]
        assert cs1["evidence"] == cs2["evidence"]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Tests — Audit event + actor
# ---------------------------------------------------------------------------


def test_v27_audit_event_emitted_on_generate(client, SM, eng_id):
    from api.db_models_field_assessment import FaEngagementAuditEvent
    from sqlalchemy import select as sa_select

    client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")

    db = SM()
    try:
        events = (
            db.execute(
                sa_select(FaEngagementAuditEvent).where(
                    FaEngagementAuditEvent.engagement_id == eng_id,
                    FaEngagementAuditEvent.event_type
                    == "verification_bundle.generated",
                )
            )
            .scalars()
            .all()
        )
        assert len(events) >= 1
    finally:
        db.close()


def test_v28_generated_by_captures_actor(client, eng_id):
    r = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 201
    generated_by = r.json()["generated_by"]
    assert isinstance(generated_by, str)
    assert len(generated_by) > 0


# ---------------------------------------------------------------------------
# Tests — Interview / exception / risk counts
# ---------------------------------------------------------------------------


def test_v29_interview_count_only_interview_type(client, SM, eng_id):
    _make_observation_interview(SM, tenant_id=_TENANT, engagement_id=eng_id)
    # Add a non-interview observation
    from api.db_models_field_assessment import FaFieldObservation
    from services.canonical import utc_iso8601_z_now

    oid = secrets.token_hex(16)
    db = SM()
    try:
        db.add(
            FaFieldObservation(
                id=oid,
                tenant_id=_TENANT,
                engagement_id=eng_id,
                domain="ai_governance",
                observation_type="gap",
                severity="high",
                title="Gap Obs",
                description=".",
                structured_evidence={},
                linked_finding_ids=[],
                assessor_id="assessor-pr52",
                created_at=utc_iso8601_z_now(),
            )
        )
        db.commit()
    finally:
        db.close()
    r = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 201
    assert r.json()["interview_count"] == 1


def test_v30_exception_count_matches_db(client, SM, eng_id):
    did = _make_decision(SM, tenant_id=_TENANT, engagement_id=eng_id)
    _make_exception(SM, tenant_id=_TENANT, engagement_id=eng_id, decision_id=did)
    _make_exception(SM, tenant_id=_TENANT, engagement_id=eng_id, decision_id=did)
    r = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 201
    assert r.json()["exception_count"] == 2


def test_v31_risk_acceptance_count_matches_db(client, SM, eng_id):
    did = _make_decision(SM, tenant_id=_TENANT, engagement_id=eng_id)
    fid = _make_finding(SM, tenant_id=_TENANT, engagement_id=eng_id)
    _make_risk_acceptance(
        SM, tenant_id=_TENANT, engagement_id=eng_id, decision_id=did, finding_id=fid
    )
    r = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 201
    assert r.json()["risk_acceptance_count"] == 1


def test_v32_component_summary_has_required_components(client, eng_id):
    # PR 52.5 expanded the component set; verify all required names are present
    r = client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")
    assert r.status_code == 201
    summary = r.json()["component_summary"]
    names = {c["name"] for c in summary}
    required = {
        "findings",
        "evidence",
        "interviews",
        "decisions",
        "risk_acceptances",
        "exceptions",
        "scan_audit_trail",
        "engagement_audit_trail",
        "chain_of_custody",
        "report",
    }
    assert required.issubset(names)
