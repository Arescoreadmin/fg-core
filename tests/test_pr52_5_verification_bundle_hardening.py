"""tests/test_pr52_5_verification_bundle_hardening.py — PR 52.5 Hardening Tests.

H1   append-only — service has no update/delete methods
H2   engagement_audit_event_count — separate from scan audit, counted correctly
H3a  export_bundle_zip — returns bytes of a valid ZIP
H3b  export_bundle_zip — ZIP contains manifest.json, bundle.json, verification_report.json
H3c  export_bundle_zip — raises BundleNotFound when no bundle exists
H3d  verify_bundle_file — returns verified=True for unmodified ZIP bytes
H3e  verify_bundle_file — tamper_detected=True when bundle_hash tampered in ZIP
H3f  verify_bundle_file — missing bundle.json returns verified=False with issue
H4   signature_metadata — generated_by, tenant_id, engagement_id, bundle_hash present
H5a  report_artifact_hash — 'available' + hash when finalized report exists
H5b  report_artifact_hash_status — 'not_available' when no report
H6a  chain_of_custody_count — zero when no lifecycle events
H6b  chain_of_custody_count — equals distinct evidence items with lifecycle events
H6c  chain_of_custody — legal_hold flag set correctly
H7a  evidence_snapshot_hash — mismatch flags tamper_detected
H7b  evidence_snapshot_hash — matching hash does not flag tamper
H7c  evidence_snapshot_hash — None causes snapshot_validation_unavailable, not tamper
H8a  coverage_status — 'missing_report' when no finalized report
H8b  coverage_status — 'missing_evidence' when report present but no evidence
H8c  coverage_status — 'complete' when report + evidence + decisions + findings
H8d  coverage_status — 'tampered' when tamper issues exist
H9   regulatory_context — contains assessment_type and generated_for from engagement
H10  governance_activity — contains decision entries sorted chronologically
API  download route returns 200 with application/zip content-type
ISO  download route — tenant isolation (other tenant cannot download)
"""

from __future__ import annotations

import io
import json
import os
import secrets
import zipfile

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)

import pytest
from fastapi.testclient import TestClient

from services.verification_bundle.bundle_service import (
    VerificationBundleService,
    verify_bundle_file,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT = "tenant-pr525-test"
_OTHER = "tenant-pr525-other"
_BASE = "/field-assessment/engagements"


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
                client_name="HardeningClient",
                assessor_id="assessor-pr525",
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
                title="Hardening Test Finding",
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


def _make_decision(
    SM,
    *,
    tenant_id: str,
    engagement_id: str,
    evidence_snapshot_hash: str | None = None,
    evidence_refs: list | None = None,
) -> str:
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
                decision_reason="Test.",
                status="active",
                decision_at=utc_iso8601_z_now(),
                evidence_snapshot_hash=evidence_snapshot_hash,
                evidence_refs=json.dumps(evidence_refs) if evidence_refs else None,
            )
        )
        db.commit()
    finally:
        db.close()
    return did


def _make_report(SM, *, tenant_id: str, engagement_id: str) -> str:
    from api.db_models_governance_report import GovernanceReportRecord
    from services.canonical import utc_iso8601_z_now

    rid = secrets.token_hex(16)
    manifest_hash = secrets.token_hex(16)
    db = SM()
    try:
        db.add(
            GovernanceReportRecord(
                id=rid,
                tenant_id=tenant_id,
                assessment_id=engagement_id,
                version=1,
                manifest_hash=manifest_hash,
                report_json={"sections": []},
                generated_at=utc_iso8601_z_now(),
                is_finalized=True,
            )
        )
        db.commit()
    finally:
        db.close()
    return rid


def _make_engagement_audit_event(SM, *, tenant_id: str, engagement_id: str) -> str:
    from api.db_models_field_assessment import FaEngagementAuditEvent
    from services.canonical import utc_iso8601_z_now

    aeid = secrets.token_hex(16)
    db = SM()
    try:
        db.add(
            FaEngagementAuditEvent(
                id=aeid,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                event_type="test.event",
                actor="test-actor",
                reason_code="TEST",
                payload={},
                schema_version="1.0",
                created_at=utc_iso8601_z_now(),
            )
        )
        db.commit()
    finally:
        db.close()
    return aeid


def _make_lifecycle_event(
    SM,
    *,
    tenant_id: str,
    engagement_id: str,
    evidence_type: str,
    evidence_id: str,
    old_state: str,
    new_state: str,
) -> str:
    from api.db_models_field_assessment import FaEvidenceLifecycleEvent
    from services.canonical import utc_iso8601_z_now

    lid = secrets.token_hex(16)
    db = SM()
    try:
        db.add(
            FaEvidenceLifecycleEvent(
                id=lid,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                evidence_type=evidence_type,
                evidence_id=evidence_id,
                old_state=old_state,
                new_state=new_state,
                actor="test-actor",
                actor_type="api_key",
                reason="Test transition.",
                transaction_id=secrets.token_hex(8),
                created_at=utc_iso8601_z_now(),
                schema_version="1.0",
            )
        )
        db.commit()
    finally:
        db.close()
    return lid


def _make_legal_hold(
    SM,
    *,
    tenant_id: str,
    engagement_id: str,
    evidence_type: str,
    evidence_id: str,
    action: str = "applied",
) -> str:
    from api.db_models_field_assessment import FaLegalHold
    from services.canonical import utc_iso8601_z_now

    lid = secrets.token_hex(16)
    db = SM()
    try:
        db.add(
            FaLegalHold(
                id=lid,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                evidence_type=evidence_type,
                evidence_id=evidence_id,
                action=action,
                reason="Legal hold test.",
                actor="test-actor",
                actor_type="api_key",
                created_at=utc_iso8601_z_now(),
                schema_version="1.0",
            )
        )
        db.commit()
    finally:
        db.close()
    return lid


def _generate(client, eng_id: str):
    return client.post(f"{_BASE}/{eng_id}/verification-bundle/generate")


def _build_service_bundle(SM, *, tenant_id: str, engagement_id: str) -> object:
    """Generate a bundle directly via service layer for offline tests."""
    svc = VerificationBundleService()
    db = SM()
    try:
        record = svc.generate_bundle(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            actor_id="test-actor",
        )
        db.commit()
        db.refresh(record)
        return record
    finally:
        db.close()


# ---------------------------------------------------------------------------
# H1 — Append-only enforcement (structural)
# ---------------------------------------------------------------------------


def test_h1_service_has_no_update_method():
    svc = VerificationBundleService()
    assert not hasattr(svc, "update_bundle"), "service must not expose update_bundle"
    assert not hasattr(svc, "delete_bundle"), "service must not expose delete_bundle"


# ---------------------------------------------------------------------------
# H2 — Engagement audit events as separate component
# ---------------------------------------------------------------------------


def test_h2_engagement_audit_event_count_zero_initially(client, eng_id):
    r = _generate(client, eng_id)
    assert r.status_code == 201
    data = r.json()
    assert data["engagement_audit_event_count"] == 0


def test_h2_engagement_audit_event_count_matches_seeded(client, SM, eng_id):
    _make_engagement_audit_event(SM, tenant_id=_TENANT, engagement_id=eng_id)
    _make_engagement_audit_event(SM, tenant_id=_TENANT, engagement_id=eng_id)
    r = _generate(client, eng_id)
    assert r.status_code == 201
    data = r.json()
    # At least 2 seeded; may have more from the generate call itself
    assert data["engagement_audit_event_count"] >= 2


def test_h2_engagement_audit_component_in_summary(client, eng_id):
    r = _generate(client, eng_id)
    assert r.status_code == 201
    names = [c["name"] for c in r.json()["component_summary"]]
    assert "engagement_audit_trail" in names
    assert "scan_audit_trail" in names


# ---------------------------------------------------------------------------
# H3 — ZIP export and offline verifier
# ---------------------------------------------------------------------------


def test_h3a_export_bundle_zip_returns_bytes(SM, eng_id):
    _build_service_bundle(SM, tenant_id=_TENANT, engagement_id=eng_id)
    svc = VerificationBundleService()
    db = SM()
    try:
        zb = svc.export_bundle_zip(db, tenant_id=_TENANT, engagement_id=eng_id)
    finally:
        db.close()
    assert isinstance(zb, bytes)
    assert len(zb) > 0


def test_h3b_zip_contains_required_files(SM, eng_id):
    _build_service_bundle(SM, tenant_id=_TENANT, engagement_id=eng_id)
    svc = VerificationBundleService()
    db = SM()
    try:
        zb = svc.export_bundle_zip(db, tenant_id=_TENANT, engagement_id=eng_id)
    finally:
        db.close()
    with zipfile.ZipFile(io.BytesIO(zb)) as zf:
        names = zf.namelist()
    assert "manifest.json" in names
    assert "bundle.json" in names
    assert "verification_report.json" in names


def test_h3c_export_bundle_zip_raises_when_no_bundle(SM):
    import services.verification_bundle.bundle_service as bsvc

    fake_id = secrets.token_hex(16)
    svc = VerificationBundleService()
    db = SM()
    try:
        with pytest.raises(bsvc.BundleNotFound):
            svc.export_bundle_zip(db, tenant_id=_TENANT, engagement_id=fake_id)
    finally:
        db.close()


def test_h3d_verify_bundle_file_valid_zip(SM, eng_id):
    _build_service_bundle(SM, tenant_id=_TENANT, engagement_id=eng_id)
    svc = VerificationBundleService()
    db = SM()
    try:
        zb = svc.export_bundle_zip(db, tenant_id=_TENANT, engagement_id=eng_id)
    finally:
        db.close()
    result = verify_bundle_file(zb)
    assert result["verified"] is True
    assert result["tamper_detected"] is False
    assert not result["issues"]


def test_h3e_verify_bundle_file_tamper_detected(SM, eng_id):
    _build_service_bundle(SM, tenant_id=_TENANT, engagement_id=eng_id)
    svc = VerificationBundleService()
    db = SM()
    try:
        zb = svc.export_bundle_zip(db, tenant_id=_TENANT, engagement_id=eng_id)
    finally:
        db.close()

    # Tamper with verification_report.json to change bundle_hash
    buf = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(zb)) as src,
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst,
    ):
        for name in src.namelist():
            data = src.read(name)
            if name == "verification_report.json":
                vr = json.loads(data)
                vr["bundle_hash"] = "a" * 64  # corrupt
                data = json.dumps(vr).encode()
            dst.writestr(name, data)

    result = verify_bundle_file(buf.getvalue())
    assert result["verified"] is False
    assert result["tamper_detected"] is True


def test_h3f_verify_bundle_file_missing_bundle_json():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps({"test": 1}))
    result = verify_bundle_file(buf.getvalue())
    assert result["verified"] is False
    assert any("missing bundle.json" in i for i in result["issues"])


# ---------------------------------------------------------------------------
# H4 — Signature metadata
# ---------------------------------------------------------------------------


def test_h4_signature_metadata_present(client, eng_id):
    r = _generate(client, eng_id)
    assert r.status_code == 201
    # signature_metadata is stored in bundle_json; verify via service
    SM = _sessionmaker()
    db = SM()
    try:
        svc = VerificationBundleService()
        bundle = svc.get_latest_bundle(db, tenant_id=_TENANT, engagement_id=eng_id)
        assert bundle is not None
        sig = json.loads(bundle.signature_metadata)
    finally:
        db.close()
    assert sig["tenant_id"] == _TENANT
    assert sig["engagement_id"] == eng_id
    assert "bundle_hash" in sig
    assert "manifest_hash" in sig
    assert sig["signature_version"] == "1.0"
    assert "generated_by" in sig


# ---------------------------------------------------------------------------
# H5 — Report artifact hash
# ---------------------------------------------------------------------------


def test_h5a_report_artifact_hash_available_with_report(client, SM, eng_id):
    _make_report(SM, tenant_id=_TENANT, engagement_id=eng_id)
    r = _generate(client, eng_id)
    assert r.status_code == 201
    data = r.json()
    assert data["report_artifact_hash_status"] == "available"
    assert data["report_artifact_hash"] is not None
    assert (
        len(data["report_artifact_hash"]) == 32
    )  # manifest_hash is token_hex(16) = 32 chars


def test_h5b_report_artifact_hash_not_available_without_report(client, eng_id):
    r = _generate(client, eng_id)
    assert r.status_code == 201
    data = r.json()
    assert data["report_artifact_hash_status"] == "not_available"
    assert data["report_artifact_hash"] is None


# ---------------------------------------------------------------------------
# H6 — Chain of custody
# ---------------------------------------------------------------------------


def test_h6a_chain_of_custody_count_zero_no_lifecycle_events(client, eng_id):
    r = _generate(client, eng_id)
    assert r.status_code == 201
    assert r.json()["chain_of_custody_count"] == 0


def test_h6b_chain_of_custody_count_matches_distinct_evidence_items(client, SM, eng_id):
    ev1 = secrets.token_hex(8)
    ev2 = secrets.token_hex(8)
    _make_lifecycle_event(
        SM,
        tenant_id=_TENANT,
        engagement_id=eng_id,
        evidence_type="scan_result",
        evidence_id=ev1,
        old_state="collected",
        new_state="locked",
    )
    _make_lifecycle_event(
        SM,
        tenant_id=_TENANT,
        engagement_id=eng_id,
        evidence_type="scan_result",
        evidence_id=ev2,
        old_state="collected",
        new_state="locked",
    )
    r = _generate(client, eng_id)
    assert r.status_code == 201
    assert r.json()["chain_of_custody_count"] == 2


def test_h6c_chain_of_custody_legal_hold_flag(SM, eng_id):
    ev_id = secrets.token_hex(8)
    _make_lifecycle_event(
        SM,
        tenant_id=_TENANT,
        engagement_id=eng_id,
        evidence_type="scan_result",
        evidence_id=ev_id,
        old_state="collected",
        new_state="locked",
    )
    _make_legal_hold(
        SM,
        tenant_id=_TENANT,
        engagement_id=eng_id,
        evidence_type="scan_result",
        evidence_id=ev_id,
        action="applied",
    )
    bundle_record = _build_service_bundle(SM, tenant_id=_TENANT, engagement_id=eng_id)
    bundle_doc = json.loads(bundle_record.bundle_json)
    coc = bundle_doc.get("chain_of_custody", [])
    matching = [c for c in coc if c["evidence_id"] == ev_id]
    assert len(matching) == 1
    assert matching[0]["legal_hold"] is True


# ---------------------------------------------------------------------------
# H7 — Evidence snapshot hash validation
# ---------------------------------------------------------------------------


def test_h7a_snapshot_hash_mismatch_flags_tamper(SM, eng_id):
    ev_id = _make_evidence_link(SM, tenant_id=_TENANT, engagement_id=eng_id)
    # Decision records a snapshot hash for evidence [ev_id], but it's wrong
    _make_decision(
        SM,
        tenant_id=_TENANT,
        engagement_id=eng_id,
        evidence_snapshot_hash="a" * 64,
        evidence_refs=[ev_id],
    )
    bundle_record = _build_service_bundle(SM, tenant_id=_TENANT, engagement_id=eng_id)
    assert bundle_record.verification_status == "tamper_detected"
    tamper = json.loads(bundle_record.tamper_details)
    assert any("evidence_snapshot_hash mismatch" in t for t in tamper)


def test_h7b_snapshot_hash_match_no_tamper(SM, eng_id):
    import hashlib

    ev_id = _make_evidence_link(SM, tenant_id=_TENANT, engagement_id=eng_id)
    # Compute the correct snapshot hash as the service would
    db = SM()
    try:
        from api.db_models_field_assessment import FaEvidenceLink
        from sqlalchemy import select

        ev = db.execute(
            select(FaEvidenceLink).where(FaEvidenceLink.id == ev_id)
        ).scalar_one()
        canonical = json.dumps(
            [
                {
                    "id": ev.id,
                    "source_entity_type": ev.source_entity_type,
                    "source_entity_id": ev.source_entity_id,
                    "evidence_entity_type": ev.evidence_entity_type,
                    "evidence_entity_id": ev.evidence_entity_id,
                }
            ],
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        correct_hash = hashlib.sha256(canonical.encode()).hexdigest()
    finally:
        db.close()

    _make_decision(
        SM,
        tenant_id=_TENANT,
        engagement_id=eng_id,
        evidence_snapshot_hash=correct_hash,
        evidence_refs=[ev_id],
    )
    bundle_record = _build_service_bundle(SM, tenant_id=_TENANT, engagement_id=eng_id)
    tamper = (
        json.loads(bundle_record.tamper_details) if bundle_record.tamper_details else []
    )
    assert not any("evidence_snapshot_hash" in t for t in tamper)


def test_h7c_none_snapshot_hash_is_not_tamper(SM, eng_id):
    ev_id = _make_evidence_link(SM, tenant_id=_TENANT, engagement_id=eng_id)
    _make_decision(
        SM,
        tenant_id=_TENANT,
        engagement_id=eng_id,
        evidence_snapshot_hash=None,
        evidence_refs=[ev_id],
    )
    bundle_record = _build_service_bundle(SM, tenant_id=_TENANT, engagement_id=eng_id)
    tamper = (
        json.loads(bundle_record.tamper_details) if bundle_record.tamper_details else []
    )
    assert not any("evidence_snapshot_hash" in t for t in tamper)


# ---------------------------------------------------------------------------
# H8 — Coverage status
# ---------------------------------------------------------------------------


def test_h8a_coverage_status_missing_report_when_no_report(client, eng_id):
    r = _generate(client, eng_id)
    assert r.status_code == 201
    assert r.json()["coverage_status"] == "missing_report"


def test_h8b_coverage_status_missing_evidence_when_report_no_evidence(
    client, SM, eng_id
):
    _make_report(SM, tenant_id=_TENANT, engagement_id=eng_id)
    r = _generate(client, eng_id)
    assert r.status_code == 201
    assert r.json()["coverage_status"] == "missing_evidence"


def test_h8c_coverage_status_complete(client, SM, eng_id):
    _make_report(SM, tenant_id=_TENANT, engagement_id=eng_id)
    _make_evidence_link(SM, tenant_id=_TENANT, engagement_id=eng_id)
    _make_finding(SM, tenant_id=_TENANT, engagement_id=eng_id)
    _make_decision(SM, tenant_id=_TENANT, engagement_id=eng_id)
    r = _generate(client, eng_id)
    assert r.status_code == 201
    assert r.json()["coverage_status"] == "complete"


def test_h8d_coverage_status_tampered_when_tamper_issues(client, SM, eng_id):
    _make_report(SM, tenant_id=_TENANT, engagement_id=eng_id)
    # Finding referencing a non-existent evidence ID → tamper
    _make_finding(
        SM,
        tenant_id=_TENANT,
        engagement_id=eng_id,
        evidence_ref_ids=["non-existent-ev-id"],
    )
    r = _generate(client, eng_id)
    assert r.status_code == 201
    assert r.json()["coverage_status"] == "tampered"


# ---------------------------------------------------------------------------
# H9 — Regulatory context
# ---------------------------------------------------------------------------


def test_h9_regulatory_context_present_in_bundle(SM, eng_id):
    bundle_record = _build_service_bundle(SM, tenant_id=_TENANT, engagement_id=eng_id)
    reg = json.loads(bundle_record.regulatory_context)
    assert reg["assessment_type"] == "ai_governance"
    assert reg["generated_for"] == "HardeningClient"


# ---------------------------------------------------------------------------
# H10 — Governance activity timeline
# ---------------------------------------------------------------------------


def test_h10_governance_activity_contains_decisions(SM, eng_id):
    _make_decision(SM, tenant_id=_TENANT, engagement_id=eng_id)
    _make_decision(SM, tenant_id=_TENANT, engagement_id=eng_id)
    bundle_record = _build_service_bundle(SM, tenant_id=_TENANT, engagement_id=eng_id)
    activity = json.loads(bundle_record.governance_activity)
    decision_entries = [
        a for a in activity if "governance.decision" in a.get("type", "")
    ]
    assert len(decision_entries) >= 2


def test_h10_governance_activity_sorted_chronologically(SM, eng_id):
    _make_decision(SM, tenant_id=_TENANT, engagement_id=eng_id)
    _make_decision(SM, tenant_id=_TENANT, engagement_id=eng_id)
    bundle_record = _build_service_bundle(SM, tenant_id=_TENANT, engagement_id=eng_id)
    activity = json.loads(bundle_record.governance_activity)
    timestamps = [a.get("at", "") for a in activity if "at" in a]
    assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------------------
# API — Download route
# ---------------------------------------------------------------------------


def test_api_download_returns_zip(client, SM, eng_id):
    _build_service_bundle(SM, tenant_id=_TENANT, engagement_id=eng_id)
    r = client.get(f"{_BASE}/{eng_id}/verification-bundle/download")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    # Verify it's a valid ZIP
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        assert "bundle.json" in zf.namelist()


def test_api_download_404_when_no_bundle(client, eng_id):
    r = client.get(f"{_BASE}/{eng_id}/verification-bundle/download")
    assert r.status_code == 404


def test_api_download_404_wrong_engagement(client):
    r = client.get(f"{_BASE}/nonexistent-eng/verification-bundle/download")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Tenant isolation — download
# ---------------------------------------------------------------------------


def test_iso_download_tenant_isolation(client, other_client, SM, eng_id):
    _build_service_bundle(SM, tenant_id=_TENANT, engagement_id=eng_id)
    r = other_client.get(f"{_BASE}/{eng_id}/verification-bundle/download")
    assert r.status_code == 404
