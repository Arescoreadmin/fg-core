"""CZ-23 — canonical provenance drives every trust decision.

Reproduces the PR #815 defect (strict mode rejected legitimate scanner-backed
reports because legacy ``evidence_provenance`` rows were absent) and proves the
canonical evaluator accepts valid runtime evidence and rejects tampered,
missing, cross-engagement and cross-tenant evidence.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from tests.test_assessment_assurance.conftest import (
    code,
    export,
    generate,
    human,
    qa_approve,
)
from tests.test_customer_zero_e2e import _northstar as N


def _decision(eid: str, tenant: str = N.TENANT):
    from api.db import get_sessionmaker
    from services.field_assessment.assessment_assurance import (
        evaluate_engagement_provenance,
    )

    db = get_sessionmaker()()
    try:
        return evaluate_engagement_provenance(db, tenant_id=tenant, engagement_id=eid)
    finally:
        db.close()


def _legacy_rows(eid: str) -> int:
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaEvidenceProvenance

    db = get_sessionmaker()()
    try:
        return (
            db.query(FaEvidenceProvenance)
            .filter_by(tenant_id=N.TENANT, engagement_id=eid)
            .count()
        )
    finally:
        db.close()


def test_strict_mode_accepts_canonical_scanner_evidence_without_legacy_rows(
    platform, northstar_clean, monkeypatch
):
    eid, rep = northstar_clean["eid"], northstar_clean["report"]
    assert _legacy_rows(eid) == 0  # the exact CZ-23 precondition
    d = _decision(eid)
    assert d.evidence_count > 0
    assert d.integrity_failure_count == 0 and d.scope_violation_count == 0
    t = d.to_trust_inputs()
    assert t.chain_valid and t.replay_valid and t.link_valid and t.engagement_valid

    monkeypatch.setenv("FG_PROVENANCE_MODE", "strict")
    resp = export(platform.client("assessor"), eid, rep["version"])
    assert resp.status_code == 200, resp.text  # PR #815: 403 TRUST_ENFORCEMENT_BLOCKED
    prov = resp.json()["report_state"]["provenance"]
    assert prov["decision"] == "VERIFIED"
    assert prov["legacy_record_count"] == 0


def test_integrity_only_is_never_reported_as_authentic(northstar_clean):
    d = _decision(northstar_clean["eid"])
    assert set(d.classification_counts) == {"VERIFIED_INTEGRITY_ONLY"}
    assert d.source_authenticated is False
    assert "SOURCE_AUTHENTICITY_NOT_ESTABLISHED" in d.disclosure_codes()


def test_strict_mode_rejects_tampered_evidence(platform, northstar, monkeypatch):
    eid, rep = northstar["eid"], northstar["report"]
    d = _decision(eid)
    assert d.integrity_failure_count >= 1
    assert "PROVENANCE_INTEGRITY_FAILED" in d.release_blockers()
    monkeypatch.setenv("FG_PROVENANCE_MODE", "strict")
    resp = export(platform.client("assessor"), eid, rep["version"])
    assert resp.status_code == 403 and code(resp) == "TRUST_ENFORCEMENT_BLOCKED"


@pytest.mark.parametrize("mode", ["warn", "off"])
def test_observation_modes_cannot_bypass_integrity_on_approval_or_release(
    platform, northstar, monkeypatch, mode
):
    monkeypatch.setenv("FG_PROVENANCE_MODE", mode)
    eid, rep = northstar["eid"], northstar["report"]
    # Draft export for internal review still works and stays marked …
    state = export(platform.client("assessor"), eid, rep["version"]).json()[
        "report_state"
    ]
    assert state["state"] != "FINAL"
    assert "PROVENANCE_INTEGRITY_FAILED" in state["release_blockers"]
    # … but the security-sensitive approval is refused in every mode.
    resp = qa_approve(human(platform), eid, rep["report_id"])
    assert resp.status_code == 422 and code(resp) == "ASSURANCE_PROVENANCE_BLOCKED"


def test_missing_evidence_strict_blocks_and_warn_discloses(platform, monkeypatch):
    from tests.test_customer_zero_e2e.test_customer_zero_journey import _engagement

    eid = _engagement(platform)
    rep = generate(platform, eid)
    d = _decision(eid)
    assert d.evidence_absent and "PROVENANCE_EVIDENCE_ABSENT" in d.disclosure_codes()
    assert d.to_trust_inputs().chain_valid is False  # never defaults to trusted
    monkeypatch.setenv("FG_PROVENANCE_MODE", "strict")
    assert export(platform.client("assessor"), eid, rep["version"]).status_code == 403


def test_deleted_source_scan_result_is_unverifiable(platform, northstar_clean):
    from api.db import get_engine
    from sqlalchemy import text

    eid = northstar_clean["eid"]
    with get_engine().begin() as conn:
        sr = conn.execute(
            text(
                "SELECT scan_result_id FROM fa_scan_evidence_envelopes "
                "WHERE engagement_id = :e AND scan_result_id IS NOT NULL LIMIT 1"
            ),
            {"e": eid},
        ).scalar_one()
        conn.execute(text("DELETE FROM fa_scan_results WHERE id = :i"), {"i": sr})
    d = _decision(eid)
    assert d.unverifiable_count >= 1
    assert "PROVENANCE_EVIDENCE_UNVERIFIABLE" in d.release_blockers()
    assert d.to_trust_inputs().replay_valid is False


def _point_finding_at(eid: str, envelope_id: str) -> None:
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaNormalizedFinding

    db = get_sessionmaker()()
    try:
        f = (
            db.execute(
                select(FaNormalizedFinding).where(
                    FaNormalizedFinding.tenant_id == N.TENANT,
                    FaNormalizedFinding.engagement_id == eid,
                )
            )
            .scalars()
            .first()
        )
        f.evidence_envelope_id = envelope_id
        db.commit()
    finally:
        db.close()


def _insert_envelope(*, tenant: str, engagement: str) -> str:
    from api.db import get_sessionmaker
    from api.db_models_field_assessment import FaScanEvidenceEnvelope
    import uuid

    db = get_sessionmaker()()
    try:
        eid = uuid.uuid4().hex
        db.add(
            FaScanEvidenceEnvelope(
                id=eid,
                tenant_id=tenant,
                engagement_id=engagement,
                scanner_id="web_headers",
                collected_at=N.now_iso(),
                collection_status="COMPLETE",
                source_type="web_headers",
                payload_digest="0" * 64,
                provenance_status="VERIFIED_INTEGRITY_ONLY",
                created_at=N.now_iso(),
                updated_at=N.now_iso(),
            )
        )
        db.commit()
        return eid
    finally:
        db.close()


@pytest.mark.parametrize(
    "tenant,engagement",
    [(N.TENANT, "other-engagement-0001"), (N.OTHER_TENANT, "other-engagement-0002")],
    ids=["cross_engagement", "cross_tenant"],
)
def test_out_of_scope_evidence_reference_is_rejected(
    platform, northstar_clean, monkeypatch, tenant, engagement
):
    eid, rep = northstar_clean["eid"], northstar_clean["report"]
    foreign = _insert_envelope(tenant=tenant, engagement=engagement)
    _point_finding_at(eid, foreign)
    d = _decision(eid)
    assert d.scope_violation_count == 1
    assert "PROVENANCE_SCOPE_VIOLATION" in d.release_blockers()
    t = d.to_trust_inputs()
    assert t.chain_valid is False and t.engagement_valid is False
    resp = qa_approve(human(platform), eid, rep["report_id"])
    assert resp.status_code == 422 and code(resp) == "ASSURANCE_PROVENANCE_BLOCKED"
    monkeypatch.setenv("FG_PROVENANCE_MODE", "strict")
    assert export(platform.client("assessor"), eid, rep["version"]).status_code == 403


def test_decision_is_deterministic_for_a_snapshot(northstar):
    a, b = _decision(northstar["eid"]), _decision(northstar["eid"])
    assert a.snapshot_fingerprint == b.snapshot_fingerprint
    assert a.release_blockers() == b.release_blockers()
    summary = a.summary()
    # Audit-safe: counts and codes only.
    assert "raw_payload" not in str(summary) and N.TAMPERED_HOST not in str(summary)
