"""Report proof assembly — L14-SCAN-REPORT-PROOF-001 (unit level, real persistence).

File-backed SQLite built from the real ORM metadata; the production bridges,
evidence capture, manifest and proof builder run unmocked.  Synthetic data only.
"""

from __future__ import annotations

import uuid

import pytest

from api.db_models_field_assessment import FaNormalizedFinding, FaScanResult
from services.field_assessment.report_proof import (
    MARKING_DRAFT,
    MARKING_FINAL,
    MARKING_FINAL_LIMITED,
    MARKING_SYNTHETIC,
    build_report_proof,
    evaluate_report_state,
    release_blockers_now,
)
from services.field_assessment.runtime_evidence import capture_scan_result_evidence
from services.governance.report.result_truth_gate import evaluate_result_truth_gate
from tests.test_scan_runner_integrity._fixtures import (
    T1,
    T2,
    auth_context,
    make_db,
    now_iso,
    seed_engagement,
    seed_job,
    tamper_raw_payload,
)

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


@pytest.fixture()
def env(tmp_path):
    engine, Session = make_db(tmp_path)
    return engine, Session


def _web(
    db,
    eid,
    *,
    statuses=("COMPLETE", "COMPLETE"),
    scan_status="COMPLETE",
    synthetic=False,
    tenant=T1,
):
    from services.field_assessment.connectors.web_headers_bridge import (
        import_web_headers_scan,
    )

    hosts = [f"https://h{i}.example" for i in range(len(statuses))]
    payload = {
        "targets": [
            {"url": h, "collection_status": s} for h, s in zip(hosts, statuses)
        ],
        "findings": [
            {
                "type": f"missing_hsts_{i}",
                "severity": "high",
                "title": f"T{i}",
                "description": "d",
                "target": h,
            }
            for i, h in enumerate(hosts)
        ],
        "collection_status": scan_status,
        "synthetic": synthetic,
        "authorization_context": auth_context(
            tenant_id=tenant, engagement_id=eid, job_id="j", scanner="web_headers"
        ),
    }
    res = import_web_headers_scan(
        db=db, tenant_id=tenant, engagement_id=eid, actor="a", scan_result=payload
    )
    db.flush()
    capture_scan_result_evidence(
        db,
        tenant_id=tenant,
        engagement_id=eid,
        scan_result_id=res.scan_result_id,
        scanner_id="web_headers",
    )
    db.commit()
    return res.scan_result_id


def _finding(
    db, eid, *, severity="medium", status="open", tenant=T1, title=None, confidence=None
):
    fid = uuid.uuid4().hex[:16]
    db.add(
        FaNormalizedFinding(
            id=fid,
            tenant_id=tenant,
            engagement_id=eid,
            finding_type="manual.observation",
            findings_hash=uuid.uuid4().hex,
            severity=severity,
            status=status,
            title=title or f"Finding {fid}",
            description="desc",
            source_attribution="manual",
            confidence_level=confidence,
            created_at=now_iso(),
            updated_at=now_iso(),
        )
    )
    db.commit()
    return fid


def _proof(db, eid, tenant=T1, findings=None):
    rows = findings
    if rows is None:
        rows = (
            db.query(FaNormalizedFinding)
            .filter_by(tenant_id=tenant, engagement_id=eid)
            .order_by(FaNormalizedFinding.id)
            .all()
        )
    scans = db.query(FaScanResult).filter_by(tenant_id=tenant, engagement_id=eid).all()
    return build_report_proof(
        db,
        tenant_id=tenant,
        engagement_id=eid,
        findings=rows,
        scan_rows=scans,
        data_cutoff="2026-11-08T00:00:00Z",
    )


# ── Finding completeness ────────────────────────────────────────────────────


class TestFindingCompleteness:
    def test_all_findings_reconcile_and_severity_preserved(self, env):
        _, Session = env
        eid = seed_engagement(Session)
        with Session() as db:
            for sev in ("critical", "high", "medium", "low", "informational", "info"):
                _finding(db, eid, severity=sev)
            p = _proof(db, eid)
        rec = p["finding_reconciliation"]
        assert rec == {
            **rec,
            "persisted_total": 6,
            "included_total": 6,
            "excluded_total": 0,
            "reconciled": True,
        }
        assert p["severity_counts"]["informational"] == 2  # "info" alias, never dropped
        assert [f["severity"] for f in p["findings"]] == sorted(
            [f["severity"] for f in p["findings"]],
            key=["critical", "high", "medium", "low", "informational"].index,
        )

    def test_distinct_findings_with_same_title_are_not_collapsed(self, env):
        _, Session = env
        eid = seed_engagement(Session)
        with Session() as db:
            a = _finding(db, eid, title="Same title")
            b = _finding(db, eid, title="Same title")
            p = _proof(db, eid)
        assert {f["finding_id"] for f in p["findings"]} == {a, b}

    def test_false_positive_excluded_with_explicit_reason(self, env):
        _, Session = env
        eid = seed_engagement(Session)
        with Session() as db:
            _finding(db, eid)
            fp = _finding(db, eid, status="false_positive")
            p = _proof(db, eid)
        rec = p["finding_reconciliation"]
        assert rec["persisted_total"] == 2 and rec["included_total"] == 1
        assert rec["excluded"] == [
            {"finding_id": fp, "reason": "FALSE_POSITIVE_DISPOSITION"}
        ]
        assert rec["reconciled"] is True and not p["release_blockers"]

    def test_dropped_finding_is_a_reconciliation_blocker(self, env):
        _, Session = env
        eid = seed_engagement(Session)
        with Session() as db:
            _finding(db, eid)
            _finding(db, eid)
            rows = db.query(FaNormalizedFinding).filter_by(engagement_id=eid).all()
            p = _proof(db, eid, findings=rows[:1])  # simulated pagination defect
        assert p["finding_reconciliation"]["reconciled"] is False
        assert "FINDING_RECONCILIATION_MISMATCH" in p["release_blockers"]

    def test_duplicate_and_cross_scope_rows_block(self, env):
        _, Session = env
        eid = seed_engagement(Session)
        other = seed_engagement(Session, tenant_id=T2)
        with Session() as db:
            _finding(db, eid)
            _finding(db, other, tenant=T2)
            mine = db.query(FaNormalizedFinding).filter_by(engagement_id=eid).all()
            theirs = db.query(FaNormalizedFinding).filter_by(engagement_id=other).all()
            p = _proof(db, eid, findings=mine + mine + theirs)
        assert {"DUPLICATE_FINDING_IDENTITY", "CROSS_SCOPE_FINDING_REFERENCE"} <= set(
            p["release_blockers"]
        )
        assert len(p["findings"]) == 1

    def test_finding_without_evidence_is_disclosed_not_dropped(self, env):
        _, Session = env
        eid = seed_engagement(Session)
        with Session() as db:
            legacy = _finding(db, eid, confidence=None)
            claimed = _finding(db, eid, confidence="CONFIRMED")
            p = _proof(db, eid)
        by = {f["finding_id"]: f for f in p["findings"]}
        assert by[legacy]["confidence_effective"] == "UNKNOWN"
        assert "CONFIDENCE_UNCLASSIFIED" in by[legacy]["limitations"]
        # A stored CONFIRMED without evidence is capped, never presented as confirmed.
        assert by[claimed]["confidence_effective"] != "CONFIRMED"
        assert by[claimed]["evidence"]["provenance_status"] == "MISSING"
        assert "EVIDENCE_NOT_CAPTURED" in by[claimed]["limitations"]


# ── Coverage ────────────────────────────────────────────────────────────────


class TestCoverage:
    def test_complete_collection_allows_full_coverage_but_no_percentage(self, env):
        _, Session = env
        eid = seed_engagement(Session)
        with Session() as db:
            _web(db, eid)
            p = _proof(db, eid)
        cov = p["coverage"]
        assert (
            cov["may_claim_full_coverage"] is True
            and p["assurance_label"] == "FULL_RECORDED_COVERAGE"
        )
        assert (
            cov["coverage_percentage"] is None and cov["coverage_determinable"] is False
        )
        assert p["release_blockers"] == []
        assert {f["confidence_effective"] for f in p["findings"]} == {"CONFIRMED"}

    @pytest.mark.parametrize(
        "status", ["PARTIAL", "DENIED", "CANCELLED", "FAILED", "TIMEOUT", "TRUNCATED"]
    )
    def test_incomplete_observation_prevents_full_coverage(self, env, status):
        _, Session = env
        eid = seed_engagement(Session)
        with Session() as db:
            _web(db, eid, statuses=("COMPLETE", status), scan_status="PARTIAL")
            p = _proof(db, eid)
        cov = p["coverage"]
        assert (
            cov["may_claim_full_coverage"] is False
            and p["assurance_label"] == "LIMITED_COVERAGE"
        )
        assert any(c.endswith(f":{status}") for c in cov["limitations"])
        # Valid observed findings on the complete target stay CONFIRMED.
        assert "CONFIRMED" in {f["confidence_effective"] for f in p["findings"]}

    def test_unknown_status_never_becomes_complete(self, env):
        _, Session = env
        eid = seed_engagement(Session)
        with Session() as db:
            _web(db, eid, scan_status=None)
            p = _proof(db, eid)
        assert p["coverage"]["scan_status_counts"] == {"UNKNOWN": 1}
        assert p["coverage"]["may_claim_full_coverage"] is False

    def test_unfinished_job_blocks_full_coverage_and_release(self, env):
        _, Session = env
        eid = seed_engagement(Session)
        seed_job(
            Session,
            tenant_id=T1,
            engagement_id=eid,
            scanner_type="dns_email",
            status="running",
        )
        with Session() as db:
            _web(db, eid)
            p = _proof(db, eid)
        assert p["coverage"]["may_claim_full_coverage"] is False
        assert "SCAN_JOBS_IN_PROGRESS" in p["release_blockers"]

    def test_failed_job_is_a_limitation_not_a_blocker(self, env):
        _, Session = env
        eid = seed_engagement(Session)
        seed_job(
            Session,
            tenant_id=T1,
            engagement_id=eid,
            scanner_type="dns_email",
            status="failed",
        )
        with Session() as db:
            _web(db, eid)
            p = _proof(db, eid)
        assert any(":FAILED" in c for c in p["coverage"]["limitations"])
        assert p["release_blockers"] == []

    def test_no_collection_is_not_assessed(self, env):
        _, Session = env
        eid = seed_engagement(Session)
        with Session() as db:
            p = _proof(db, eid)
        assert p["coverage"]["coverage_statement"].startswith("NOT_ASSESSED")
        assert p["coverage"]["may_claim_full_coverage"] is False

    def test_coverage_is_reproducible(self, env):
        _, Session = env
        eid = seed_engagement(Session)
        with Session() as db:
            _web(db, eid, statuses=("COMPLETE", "DENIED"), scan_status="PARTIAL")
            a, b = _proof(db, eid), _proof(db, eid)
        assert a["proof_fingerprint"] == b["proof_fingerprint"]
        assert a["coverage"] == b["coverage"]


# ── Evidence ────────────────────────────────────────────────────────────────


class TestEvidence:
    def test_valid_digest_is_integrity_only_never_authenticated(self, env):
        _, Session = env
        eid = seed_engagement(Session)
        with Session() as db:
            _web(db, eid)
            p = _proof(db, eid)
        assert p["provenance_counts"] == {"VERIFIED_INTEGRITY_ONLY": 2}
        assert p["report_constraints"]["may_claim_authenticated_evidence"] is False
        assert p["report_constraints"]["may_claim_zero_risk"] is False
        assert all(
            e["provenance_status"] == "VERIFIED_INTEGRITY_ONLY"
            for e in p["evidence_index"].values()
        )

    def test_tampered_evidence_downgrades_and_blocks(self, env):
        engine, Session = env
        eid = seed_engagement(Session)
        with Session() as db:
            sr = _web(db, eid)
        tamper_raw_payload(
            engine,
            sr,
            lambda pl: pl["targets"][0].update(
                {"collection_status": "COMPLETE", "x": 1}
            ),
        )
        with Session() as db:
            p = _proof(db, eid)
        assert "EVIDENCE_INTEGRITY_FAILED" in p["release_blockers"]
        bad = [
            f for f in p["findings"] if f["evidence"]["provenance_status"] == "INVALID"
        ]
        assert bad and all(f["confidence_effective"] != "CONFIRMED" for f in bad)
        assert all(f["severity"] == "high" for f in bad)  # severity untouched

    def test_cross_tenant_proof_sees_nothing(self, env):
        _, Session = env
        eid = seed_engagement(Session)
        with Session() as db:
            _web(db, eid)
            p = _proof(db, eid, tenant=T2)
        assert p["findings"] == [] and p["evidence_index"] == {}


# ── Release state and truth gate ────────────────────────────────────────────


class TestReleaseState:
    def _state(self, db, eid, proof, *, qa=True, qualified=True):
        return evaluate_report_state(
            db,
            tenant_id=T1,
            engagement_id=eid,
            report_json={"report_proof": proof},
            qa_approved_by="qa@x" if qa else None,
            qa_approved_at="t" if qa else None,
            qualified=qualified,
        )

    def test_marking_matrix(self, env):
        _, Session = env
        eid = seed_engagement(Session)
        with Session() as db:
            _web(db, eid)
            proof = _proof(db, eid)
            assert self._state(db, eid, proof)["marking"] == MARKING_FINAL
            assert self._state(db, eid, proof, qa=False)["marking"] == MARKING_DRAFT
            assert (
                self._state(db, eid, proof, qualified=False)["marking"] == MARKING_DRAFT
            )
            limited = {
                **proof,
                "report_constraints": {
                    **proof["report_constraints"],
                    "may_claim_full_coverage": False,
                },
            }
            assert self._state(db, eid, limited)["marking"] == MARKING_FINAL_LIMITED
            synth = {**proof, "synthetic": {"is_synthetic": True, "sources": ["x"]}}
            assert self._state(db, eid, synth)["marking"] == MARKING_SYNTHETIC
            missing = evaluate_report_state(
                db,
                tenant_id=T1,
                engagement_id=eid,
                report_json={},
                qa_approved_by="q",
                qa_approved_at="t",
                qualified=True,
            )
            assert missing["marking"] == MARKING_DRAFT and missing[
                "release_blockers"
            ] == ["REPORT_PROOF_MISSING"]

    def test_evidence_changed_after_generation_blocks(self, env):
        engine, Session = env
        eid = seed_engagement(Session)
        with Session() as db:
            sr = _web(db, eid)
            proof = _proof(db, eid)
        tamper_raw_payload(engine, sr, lambda pl: pl.update({"late": True}))
        with Session() as db:
            blockers = release_blockers_now(
                db, tenant_id=T1, engagement_id=eid, report_json={"report_proof": proof}
            )
            assert "EVIDENCE_CHANGED_SINCE_GENERATION" in blockers
            assert self._state(db, eid, proof)["marking"] == MARKING_DRAFT

    def test_proof_scope_mismatch_blocks(self, env):
        _, Session = env
        eid = seed_engagement(Session)
        with Session() as db:
            proof = _proof(db, eid)
            assert "REPORT_PROOF_SCOPE_MISMATCH" in release_blockers_now(
                db,
                tenant_id=T1,
                engagement_id="other",
                report_json={"report_proof": proof},
            )

    def test_truth_gate_consumes_proof_blockers(self):
        base = {"tenant_id": T1, "engagement_id": "e"}
        bad = evaluate_result_truth_gate(
            {
                **base,
                "report_proof": {
                    "tenant_id": T1,
                    "engagement_id": "e",
                    "release_blockers": ["SYNTHETIC_DATA"],
                },
            },
            tenant_id=T1,
            engagement_id="e",
            raise_on_failure=False,
        )
        assert "REPORT_PROOF_BLOCKED:SYNTHETIC_DATA" in bad.failure_reasons
        malformed = evaluate_result_truth_gate(
            {**base, "report_proof": "nope"},
            tenant_id=T1,
            engagement_id="e",
            raise_on_failure=False,
        )
        assert "REPORT_PROOF_MALFORMED" in malformed.failure_reasons
        legacy = evaluate_result_truth_gate(
            base, tenant_id=T1, engagement_id="e", raise_on_failure=False
        )
        assert not any(r.startswith("REPORT_PROOF") for r in legacy.failure_reasons)
