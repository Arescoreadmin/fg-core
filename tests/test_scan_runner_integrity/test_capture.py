"""Canonical runtime evidence capture — persistence, idempotency, custody,
authorization provenance, collection truth, tamper detection, tenant isolation.

Real bridges, real EvidenceIntegrityService / EvidenceCustodyService /
classify_confidence, real SQLite persistence.  L14-SCAN-RUNNER-INTEGRITY-001.
"""

from __future__ import annotations

import copy
import os

import pytest

os.environ.setdefault("FG_ENV", "test")

from services.connectors.collection_status import CollectionStatus
from services.field_assessment import runtime_evidence as rte
from services.field_assessment.connectors.dns_email_bridge import import_dns_email_scan
from services.field_assessment.connectors.network_scan_bridge import import_network_scan
from services.field_assessment.connectors.web_headers_bridge import (
    import_web_headers_scan,
)
from services.field_assessment.custody import custody_svc
from services.field_assessment.evidence_integrity import (
    ProvenanceStatus,
    compute_payload_digest,
)
from services.field_assessment.finding_confidence import ConfidenceLevel

from ._fixtures import (
    T1,
    T2,
    auth_context,
    custody,
    envelopes,
    findings,
    make_db,
    seed_engagement,
    seed_job,
    tamper_raw_payload,
)


@pytest.fixture()
def env(tmp_path):
    engine, Session = make_db(tmp_path)
    eid = seed_engagement(Session)
    return engine, Session, eid


def _web_payload(**over):
    p = {
        "targets": [
            {
                "url": "https://app.example.com",
                "status_code": 200,
                "headers_present": [],
                "findings": [],
                "error": None,
                "collection_status": "COMPLETE",
            },
            {
                "url": "https://api.example.com",
                "status_code": None,
                "headers_present": [],
                "findings": [],
                "error": "Request timed out",
                "collection_status": "FAILED",
            },
        ],
        "findings": [
            {
                "type": "missing_hsts",
                "severity": "high",
                "title": "Missing HSTS",
                "description": "d",
                "target": "app.example.com",
            },
        ],
        "collection_status": "PARTIAL",
        "interrupted": None,
    }
    p.update(over)
    return p


def _import_web(Session, eid, payload, *, job=None, tenant=T1):
    with Session() as db:
        res = import_web_headers_scan(
            db=db, tenant_id=tenant, engagement_id=eid, scan_result=payload, actor="a"
        )
        db.commit()
    return res.scan_result_id


def _capture(Session, eid, sr, scanner="web_headers", job=None, tenant=T1):
    with Session() as db:
        out = rte.capture_with_retry(
            db,
            tenant_id=tenant,
            engagement_id=eid,
            scan_result_id=sr,
            scanner_id=scanner,
            scan_job_id=job,
        )
        db.commit()
    return out


def _web_scan(Session, eid, **over):
    job = seed_job(Session, tenant_id=T1, engagement_id=eid, scanner_type="web_headers")
    payload = _web_payload(**over)
    payload["authorization_context"] = auth_context(
        tenant_id=T1, engagement_id=eid, job_id=job, scanner="web_headers"
    )
    sr = _import_web(Session, eid, payload)
    return job, sr, payload


class TestEnvelopePersistence:
    def test_scan_and_observation_envelopes_persisted_with_digests(self, env):
        engine, Session, eid = env
        job, sr, payload = _web_scan(Session, eid)
        res = _capture(Session, eid, sr, job=job)
        with Session() as db:
            rows = envelopes(db, scan_result_id=sr)
            assert {r.source_type for r in rows} == {"scan_result", "web_target"}
            whole = next(r for r in rows if r.source_type == "scan_result")
            stored = db.get(rte.FaScanResult, sr).raw_payload
            # Digest is over the evidence AS STORED, via the canonical service.
            assert whole.payload_digest == compute_payload_digest(
                stored, schema_version="1.0"
            )
            assert whole.observation_path == "$"
            obs = {r.source_id: r for r in rows if r.source_type == "web_target"}
            assert obs["https://app.example.com"].observation_path == "targets[0]"
            assert obs[
                "https://app.example.com"
            ].payload_digest == compute_payload_digest(
                stored["targets"][0], schema_version="1.0"
            )
            assert all(r.provenance_status == "VERIFIED_INTEGRITY_ONLY" for r in rows)
            assert all(r.scan_job_id == job and r.tenant_id == T1 for r in rows)
        assert res.created == 3 and res.reused == 0

    def test_collection_status_persisted_per_observation(self, env):
        _, Session, eid = env
        job, sr, _ = _web_scan(Session, eid)
        _capture(Session, eid, sr, job=job)
        with Session() as db:
            st = {
                r.source_id: r.collection_status
                for r in envelopes(db, scan_result_id=sr)
            }
        assert st[sr] == "PARTIAL"
        assert st["https://app.example.com"] == "COMPLETE"
        assert st["https://api.example.com"] == "FAILED"

    @pytest.mark.parametrize(
        "status",
        [
            "COMPLETE",
            "PARTIAL",
            "DENIED",
            "TIMEOUT",
            "TRUNCATED",
            "CANCELLED",
            "NOT_ASSESSED",
        ],
    )
    def test_every_canonical_status_preserved(self, env, status):
        _, Session, eid = env
        job, sr, _ = _web_scan(Session, eid, collection_status=status, targets=[])
        _capture(Session, eid, sr, job=job)
        with Session() as db:
            (whole,) = envelopes(db, scan_result_id=sr)
        assert whole.collection_status == status

    def test_unknown_status_fails_closed_to_unknown(self, env):
        _, Session, eid = env
        job, sr, _ = _web_scan(Session, eid, collection_status="looks-fine", targets=[])
        _capture(Session, eid, sr, job=job)
        with Session() as db:
            (whole,) = envelopes(db, scan_result_id=sr)
        assert whole.collection_status == "UNKNOWN"

    def test_capture_and_source_timestamps_distinct(self, env):
        _, Session, eid = env
        job, sr, _ = _web_scan(
            Session, eid, scan_completed_at="2026-01-01T00:00:00+00:00"
        )
        _capture(Session, eid, sr, job=job)
        with Session() as db:
            whole = envelopes(db, scan_result_id=sr, source_type="scan_result")[0]
        assert whole.collected_at == "2026-01-01T00:00:00+00:00"  # runner-reported
        assert whole.created_at != whole.collected_at  # FrostGate capture time


class TestAuthorizationProvenance:
    def test_worker_start_authorization_recorded(self, env):
        _, Session, eid = env
        job, sr, payload = _web_scan(Session, eid)
        _capture(Session, eid, sr, job=job)
        ctx = payload["authorization_context"]
        with Session() as db:
            for r in envelopes(db, scan_result_id=sr):
                assert r.authorization_ref == ctx["authorization_id"]
                assert r.authorization_version == 2
                assert r.customer_receipt_id == ctx["customer_receipt_id"]
                assert (
                    r.authorization_proof_level
                    == "SERVER_ATTESTED_AUTHENTICATED_APPROVAL"
                )

    @pytest.mark.parametrize(
        "field, value, code",
        [
            ("tenant_id", T2, "AUTHORIZATION_TENANT_MISMATCH"),
            ("engagement_id", "eng-other", "AUTHORIZATION_ENGAGEMENT_MISMATCH"),
            (
                "scan_job_id",
                "00000000-0000-0000-0000-000000000000",
                "AUTHORIZATION_SCAN_MISMATCH",
            ),
            ("scanner_type", "network_scan", "AUTHORIZATION_SCANNER_MISMATCH"),
            ("customer_receipt_id", "not-a-uuid", "AUTHORIZATION_REF_MALFORMED"),
            ("authorization_id", None, "AUTHORIZATION_REF_MISSING"),
        ],
    )
    def test_mismatched_authorization_rejected(self, env, field, value, code):
        _, Session, eid = env
        job = seed_job(
            Session, tenant_id=T1, engagement_id=eid, scanner_type="web_headers"
        )
        payload = _web_payload()
        payload["authorization_context"] = auth_context(
            tenant_id=T1, engagement_id=eid, job_id=job, scanner="web_headers"
        )
        payload["authorization_context"][field] = value
        sr = _import_web(Session, eid, payload)
        with pytest.raises(rte.EvidenceCaptureError) as ei:
            _capture(Session, eid, sr, job=job)
        assert ei.value.code == code
        with Session() as db:
            assert envelopes(db, scan_result_id=sr) == []

    def test_target_scan_without_guarded_context_refused(self, env):
        _, Session, eid = env
        sr = _import_web(Session, eid, _web_payload())
        with pytest.raises(rte.EvidenceCaptureError) as ei:
            _capture(Session, eid, sr)
        assert ei.value.code == "AUTHORIZATION_CONTEXT_MISSING"

    def test_graph_family_labelled_without_receipt(self, env):
        _, Session, eid = env
        from services.field_assessment.store import create_scan_result

        with Session() as db:
            sr = create_scan_result(
                db,
                tenant_id=T1,
                engagement_id=eid,
                source_type="sharepoint_onedrive",
                schema_version="1.0",
                collected_at="2026-11-08T00:00:00Z",
                raw_payload={"sites": [], "collection_status": "TRUNCATED"},
                normalized_payload=None,
                object_count=0,
            ).id
            db.commit()
        _capture(Session, eid, sr, scanner="sharepoint_onedrive")
        with Session() as db:
            (r,) = envelopes(db, scan_result_id=sr)
        assert r.authorization_ref is None and r.customer_receipt_id is None
        assert r.authorization_proof_level == "GRAPH_CUSTOMER_DEVICE_CODE_LOGIN_ONLY"
        assert r.collection_status == "TRUNCATED"

    def test_graph_payload_claiming_receipt_rejected(self, env):
        _, Session, eid = env
        from services.field_assessment.store import create_scan_result

        with Session() as db:
            sr = create_scan_result(
                db,
                tenant_id=T1,
                engagement_id=eid,
                source_type="oauth_risk",
                schema_version="1.0",
                collected_at="x",
                raw_payload={
                    "apps": [],
                    "authorization_context": {"customer_receipt_id": "x"},
                },
                normalized_payload=None,
                object_count=0,
            ).id
            db.commit()
        with pytest.raises(rte.EvidenceCaptureError) as ei:
            _capture(Session, eid, sr, scanner="oauth_risk")
        assert ei.value.code == "AUTHORIZATION_CONTEXT_UNEXPECTED"


class TestOwnershipAndIsolation:
    def test_wrong_tenant_cannot_capture(self, env):
        _, Session, eid = env
        job, sr, _ = _web_scan(Session, eid)
        with pytest.raises(rte.EvidenceCaptureError) as ei:
            _capture(Session, eid, sr, job=None, tenant=T2)
        assert ei.value.code == "ENGAGEMENT_NOT_FOUND"

    def test_wrong_engagement_cannot_capture(self, env):
        _, Session, eid = env
        other = seed_engagement(Session)
        job, sr, _ = _web_scan(Session, eid)
        with pytest.raises(rte.EvidenceCaptureError) as ei:
            _capture(Session, other, sr)
        assert ei.value.code == "SCAN_RESULT_NOT_FOUND"

    def test_job_from_other_engagement_rejected(self, env):
        _, Session, eid = env
        other = seed_engagement(Session)
        foreign_job = seed_job(
            Session, tenant_id=T1, engagement_id=other, scanner_type="web_headers"
        )
        _, sr, _ = _web_scan(Session, eid)
        with pytest.raises(rte.EvidenceCaptureError) as ei:
            _capture(Session, eid, sr, job=foreign_job)
        assert ei.value.code == "SCAN_JOB_NOT_FOUND"

    def test_cross_tenant_custody_and_verification_denied(self, env):
        _, Session, eid = env
        job, sr, _ = _web_scan(Session, eid)
        res = _capture(Session, eid, sr, job=job)
        with Session() as db:
            with pytest.raises(PermissionError):
                custody_svc.get_history(
                    db, evidence_id=res.scan_envelope_id, tenant_id=T2
                )
            assert (
                rte.verify_stored_evidence(
                    db, tenant_id=T2, evidence_id=res.scan_envelope_id
                )
                == ProvenanceStatus.MISSING
            )
            assert (
                rte.build_evidence_manifest(db, tenant_id=T2, engagement_id=eid)[
                    "findings"
                ]
                == []
            )

    def test_unsupported_scanner_and_payload(self, env):
        _, Session, eid = env
        job, sr, _ = _web_scan(Session, eid)
        with pytest.raises(rte.EvidenceCaptureError) as ei:
            _capture(Session, eid, sr, scanner="nmap_custom")
        assert ei.value.code == "SCANNER_NOT_SUPPORTED"
        from services.field_assessment.store import create_scan_result

        with Session() as db:
            empty = create_scan_result(
                db,
                tenant_id=T1,
                engagement_id=eid,
                source_type="oauth_risk",
                schema_version="1.0",
                collected_at="x",
                raw_payload={},
                normalized_payload=None,
                object_count=0,
            ).id
            db.commit()
        with pytest.raises(rte.EvidenceCaptureError) as ei:
            _capture(Session, eid, empty, scanner="oauth_risk")
        assert ei.value.code == "UNSUPPORTED_PAYLOAD"


class TestIdempotencyAndCustody:
    def test_retry_reuses_envelopes_and_custody(self, env):
        _, Session, eid = env
        job, sr, _ = _web_scan(Session, eid)
        first = _capture(Session, eid, sr, job=job)
        second = _capture(Session, eid, sr, job=job)
        assert second.created == 0 and second.reused == first.created
        assert second.scan_envelope_id == first.scan_envelope_id
        with Session() as db:
            assert len(envelopes(db, scan_result_id=sr)) == 3
            events = [e.event_type for e in custody(db, first.scan_envelope_id)]
        assert events.count("COLLECTED") == 1 and events.count("INGESTED") == 1

    def test_duplicate_payload_import_maps_to_same_evidence(self, env):
        _, Session, eid = env
        job, sr, payload = _web_scan(Session, eid)
        _capture(Session, eid, sr, job=job)
        sr2 = _import_web(Session, eid, copy.deepcopy(payload))  # duplicate delivery
        assert sr2 == sr
        res = _capture(Session, eid, sr2, job=job)
        assert res.created == 0

    def test_custody_lifecycle_describes_real_actions(self, env):
        _, Session, eid = env
        job, sr, _ = _web_scan(Session, eid)
        res = _capture(Session, eid, sr, job=job)
        app_env = res.observation_envelope_ids["https://app.example.com"]
        api_env = res.observation_envelope_ids["https://api.example.com"]
        with Session() as db:
            app_events = [e.event_type for e in custody(db, app_env)]
            api_events = [e.event_type for e in custody(db, api_env)]
            normalized = [
                e for e in custody(db, app_env) if e.event_type == "NORMALIZED"
            ]
        assert app_events == ["COLLECTED", "INGESTED", "NORMALIZED"]
        assert api_events == ["COLLECTED", "INGESTED"]  # no finding used it
        assert normalized[0].reason.startswith("finding:")
        with Session() as db:
            assert all(
                e.digest_ref
                for e in custody(db, app_env)
                if e.event_type != "NORMALIZED"
            )

    def test_custody_history_cannot_be_rewritten(self, env):
        _, Session, eid = env
        job, sr, _ = _web_scan(Session, eid)
        res = _capture(Session, eid, sr, job=job)
        with Session() as db:
            ev = custody(db, res.scan_envelope_id)[0]
            ev.reason = "rewritten"
            with pytest.raises(Exception):
                db.flush()

    def test_envelope_digest_is_immutable(self, env):
        _, Session, eid = env
        job, sr, _ = _web_scan(Session, eid)
        res = _capture(Session, eid, sr, job=job)
        with Session() as db:
            row = envelopes(db, id=res.scan_envelope_id)[0]
            row.payload_digest = "sha256:" + "0" * 64
            with pytest.raises(ValueError, match="immutable"):
                db.flush()

    def test_provenance_cannot_be_upgraded(self, env):
        _, Session, eid = env
        job, sr, _ = _web_scan(Session, eid)
        res = _capture(Session, eid, sr, job=job)
        with Session() as db:
            row = envelopes(db, id=res.scan_envelope_id)[0]
            row.provenance_status = "VERIFIED_AUTHENTIC"
            with pytest.raises(ValueError, match="INVALID"):
                db.flush()


class TestTamperDetection:
    def test_stored_payload_tamper_detected_and_sticky(self, env):
        engine, Session, eid = env
        job, sr, _ = _web_scan(Session, eid)
        res = _capture(Session, eid, sr, job=job)
        app_env = res.observation_envelope_ids["https://app.example.com"]
        with Session() as db:
            assert (
                rte.verify_stored_evidence(db, tenant_id=T1, evidence_id=app_env)
                == ProvenanceStatus.VERIFIED_INTEGRITY_ONLY
            )
            original_digest = envelopes(db, id=app_env)[0].payload_digest
        tamper_raw_payload(
            engine, sr, lambda p: p["targets"][0].update(status_code=500)
        )
        with Session() as db:
            assert (
                rte.verify_stored_evidence(
                    db, tenant_id=T1, evidence_id=app_env, record_custody=True
                )
                == ProvenanceStatus.INVALID
            )
            db.commit()
        with Session() as db:
            row = envelopes(db, id=app_env)[0]
            assert row.provenance_status == "INVALID"
            assert row.payload_digest == original_digest  # never re-baselined
            last = custody(db, app_env)[-1]
            assert last.event_type == "VERIFIED" and last.to_state == "INVALID"
        # Restoring the payload cannot silently re-verify (sticky INVALID).
        tamper_raw_payload(
            engine, sr, lambda p: p["targets"][0].update(status_code=200)
        )
        with Session() as db:
            assert (
                rte.verify_stored_evidence(db, tenant_id=T1, evidence_id=app_env)
                == ProvenanceStatus.INVALID
            )

    def test_digest_never_recomputed_after_tamper(self, env):
        engine, Session, eid = env
        job, sr, _ = _web_scan(Session, eid)
        res = _capture(Session, eid, sr, job=job)
        with Session() as db:
            before = envelopes(db, id=res.scan_envelope_id)[0].payload_digest
        tamper_raw_payload(engine, sr, lambda p: p.update(collection_status="COMPLETE"))
        with pytest.raises(rte.EvidenceCaptureError) as ei:
            _capture(Session, eid, sr, job=job)  # retry must not re-baseline
        assert ei.value.code == "STORED_EVIDENCE_INTEGRITY_FAILURE"
        with Session() as db:
            assert envelopes(db, id=res.scan_envelope_id)[0].payload_digest == before

    def test_removed_observation_is_invalid(self, env):
        engine, Session, eid = env
        job, sr, _ = _web_scan(Session, eid)
        res = _capture(Session, eid, sr, job=job)
        api_env = res.observation_envelope_ids["https://api.example.com"]
        tamper_raw_payload(engine, sr, lambda p: p["targets"].pop())
        with Session() as db:
            assert (
                rte.verify_stored_evidence(db, tenant_id=T1, evidence_id=api_env)
                == ProvenanceStatus.INVALID
            )

    def test_key_order_does_not_change_digest(self):
        a = {"b": 1, "a": {"y": [1, 2], "x": "é"}}
        b = {"a": {"x": "é", "y": [1, 2]}, "b": 1}  # NFC-equivalent unicode
        assert compute_payload_digest(a) == compute_payload_digest(b)
        assert compute_payload_digest(a) != compute_payload_digest({**a, "b": 2})


class TestBoundedCapture:
    def test_oversized_observation_refused(self, env, monkeypatch):
        _, Session, eid = env
        monkeypatch.setattr(rte, "MAX_OBSERVATION_BYTES", 64)
        job, sr, _ = _web_scan(Session, eid)
        with pytest.raises(rte.EvidenceCaptureError) as ei:
            _capture(Session, eid, sr, job=job)
        assert ei.value.code == "EVIDENCE_PAYLOAD_TOO_LARGE"
        with Session() as db:
            assert (
                envelopes(db, scan_result_id=sr) == []
            )  # savepoint rolled back, nothing partial


class TestConfidenceLinkage:
    def test_directly_observed_finding_confirmed_in_partial_scan(self, env):
        _, Session, eid = env
        job, sr, _ = _web_scan(Session, eid)  # scan PARTIAL; app target COMPLETE
        res = _capture(Session, eid, sr, job=job)
        with Session() as db:
            (f,) = findings(db, eid)
            assert (
                f.evidence_envelope_id
                == res.observation_envelope_ids["https://app.example.com"]
            )
            assert f.confidence_level == ConfidenceLevel.CONFIRMED.value
            assert f.collection_status == "COMPLETE"
            assert f.verification_method == "DIRECT_TECHNICAL_OBSERVATION"
            assert f.severity == "high"  # independent of confidence
            assert "provenance=VERIFIED_INTEGRITY_ONLY" in f.confidence_justification

    def test_finding_on_incomplete_observation_capped(self, env):
        _, Session, eid = env
        p = _web_payload()
        p["findings"][0]["target"] = "api.example.com"  # FAILED observation
        job = seed_job(
            Session, tenant_id=T1, engagement_id=eid, scanner_type="web_headers"
        )
        p["authorization_context"] = auth_context(
            tenant_id=T1, engagement_id=eid, job_id=job, scanner="web_headers"
        )
        sr = _import_web(Session, eid, p)
        _capture(Session, eid, sr, job=job)
        with Session() as db:
            (f,) = findings(db, eid)
        assert f.confidence_level == ConfidenceLevel.PROBABLE.value
        assert f.collection_status == "FAILED"

    def test_unattributable_finding_uses_scan_evidence_and_scan_status(self, env):
        _, Session, eid = env
        p = _web_payload()
        p["findings"][0]["target"] = "unlisted.example.com"
        job = seed_job(
            Session, tenant_id=T1, engagement_id=eid, scanner_type="web_headers"
        )
        p["authorization_context"] = auth_context(
            tenant_id=T1, engagement_id=eid, job_id=job, scanner="web_headers"
        )
        sr = _import_web(Session, eid, p)
        res = _capture(Session, eid, sr, job=job)
        with Session() as db:
            (f,) = findings(db, eid)
        assert f.evidence_envelope_id == res.scan_envelope_id
        assert f.confidence_level == ConfidenceLevel.PROBABLE.value  # scan was PARTIAL

    def test_capture_failure_marks_findings_unknown(self, env):
        _, Session, eid = env
        sr = _import_web(Session, eid, _web_payload())  # no authorization context
        with Session() as db:
            n = rte.mark_findings_evidence_missing(
                db,
                tenant_id=T1,
                engagement_id=eid,
                scanner_id="web_headers",
                scan_result_id=sr,
                code="AUTHORIZATION_CONTEXT_MISSING",
            )
            db.commit()
            (f,) = findings(db, eid)
        assert n == 1 and f.confidence_level == ConfidenceLevel.UNKNOWN.value
        assert f.evidence_envelope_id is None

    def test_retry_does_not_reclassify(self, env):
        _, Session, eid = env
        job, sr, _ = _web_scan(Session, eid)
        _capture(Session, eid, sr, job=job)
        with Session() as db:
            f = findings(db, eid)[0]
            f.confidence_level = (
                ConfidenceLevel.SUSPECTED.value
            )  # e.g. reviewer downgrade
            db.commit()
        _capture(Session, eid, sr, job=job)
        with Session() as db:
            assert (
                findings(db, eid)[0].confidence_level == ConfidenceLevel.SUSPECTED.value
            )


class TestNetworkAndDnsLinkage:
    def test_network_finding_links_to_affected_host_evidence(self, env):
        _, Session, eid = env
        job = seed_job(
            Session, tenant_id=T1, engagement_id=eid, scanner_type="network_scan"
        )
        payload = {
            "scan_completed_at": "2026-11-08T00:00:00Z",
            "collection_status": "PARTIAL",
            "hosts": [
                {"host": "203.0.113.1", "open_ports": [3389], "tls": {}},
                {
                    "host": "203.0.113.2",
                    "open_ports": [],
                    "tls": {},
                    "error": "scan_failed",
                },
            ],
            "findings": [
                {
                    "finding_type": "network.unsafe_services_exposed",
                    "severity": "high",
                    "title": "t",
                    "description": "d",
                    "control_id": "NIST-AI-RMF-MANAGE-2.2",
                    "affected_hosts": ["203.0.113.1"],
                },
            ],
            "authorization_context": auth_context(
                tenant_id=T1, engagement_id=eid, job_id=job, scanner="network_scan"
            ),
        }
        with Session() as db:
            sr = import_network_scan(
                db=db, tenant_id=T1, engagement_id=eid, scan_result=payload, actor="a"
            ).scan_result_id
            db.commit()
        res = _capture(Session, eid, sr, scanner="network_scan", job=job)
        with Session() as db:
            (f,) = findings(db, eid)
            st = {
                r.source_id: r.collection_status
                for r in envelopes(db, scan_result_id=sr)
            }
        assert f.evidence_envelope_id == res.observation_envelope_ids["203.0.113.1"]
        assert f.confidence_level == ConfidenceLevel.CONFIRMED.value
        assert st["203.0.113.2"] == "FAILED"

    def test_dns_timeout_domain_never_confirmed(self, env):
        _, Session, eid = env
        job = seed_job(
            Session, tenant_id=T1, engagement_id=eid, scanner_type="dns_email"
        )
        payload = {
            "collection_status": "PARTIAL",
            "domains": [
                {
                    "domain": "slow.example.com",
                    "findings": [],
                    "collection_status": "TIMEOUT",
                }
            ],
            "findings": [
                {
                    "type": "missing_dmarc",
                    "severity": "medium",
                    "title": "t",
                    "description": "d",
                    "domain": "slow.example.com",
                }
            ],
            "authorization_context": auth_context(
                tenant_id=T1, engagement_id=eid, job_id=job, scanner="dns_email"
            ),
        }
        with Session() as db:
            sr = import_dns_email_scan(
                db=db, tenant_id=T1, engagement_id=eid, scan_result=payload, actor="a"
            ).scan_result_id
            db.commit()
        _capture(Session, eid, sr, scanner="dns_email", job=job)
        with Session() as db:
            (f,) = findings(db, eid)
        assert f.confidence_level != ConfidenceLevel.CONFIRMED.value
        assert f.collection_status == CollectionStatus.TIMEOUT.value
