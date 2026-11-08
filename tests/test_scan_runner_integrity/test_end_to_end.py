"""End-to-end synthetic assessment through the PRODUCTION worker path.

authorized engagement → _c6_run_guarded_target_scan → real runner (network I/O
mocked) → real bridge → fa_scan_results → runtime evidence capture → envelopes
+ custody → findings linked + confidence → evidence manifest rebuilt from a
fresh session.

Mocked: outbound network (httpx client, SSRF validator DNS, port probes, DNS
resolver) and the Postgres-only authorization store.  Authorization DECISIONS
are still computed by the real ``check_scan_authorized()`` + customer receipt
verification, over the PR #812 stateful harness store, because that store's SQL
is Postgres-specific.  NOT mocked: evidence integrity, custody, confidence,
bridges, job state machine, persistence.  L14-SCAN-RUNNER-INTEGRITY-001.
"""

from __future__ import annotations

import ast
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

os.environ.setdefault("FG_ENV", "test")

import api.field_assessment as fa
from api.db_models_field_assessment import FaScanAuditEvent, FaScanJob
from services.connectors.collection_status import CollectionStatus
from services.field_assessment import runtime_evidence as rte
from services.field_assessment import scan_execution_guard as seg
from services.field_assessment.finding_confidence import ConfidenceLevel
from services.field_assessment.scan_authorization import check_scan_authorized
from tests.test_scan_authorization_hardening import _harness as h

from ._fixtures import T1, envelopes, findings, make_db, seed_engagement, seed_job

ROOT = Path(__file__).resolve().parents[2]

# Test-environment only: cancel_scan() binds a datetime, which Python 3.12's
# sqlite3 flags as deprecated.  Postgres (production) is unaffected.
pytestmark = pytest.mark.filterwarnings(
    "ignore:The default datetime adapter is deprecated:DeprecationWarning"
)


@pytest.fixture()
def world(tmp_path, monkeypatch):
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.delenv("FG_SCAN_REQUIRE_CUSTOMER_CONSENT", raising=False)
    engine, Session = make_db(tmp_path)
    eid = seed_engagement(Session, engagement_id=h.E1)
    auth = h.Store()
    receipt = h.approved_receipt(auth)
    auth.receipt_id = str(receipt["id"])
    auth.scope_id = auth.add_scope(
        receipt_id=auth.receipt_id,
        targets=[
            {
                "target": "app.example.com",
                "type": "fqdn",
                "operations": ["web_headers", "dns_email"],
            },
            {
                "target": "203.0.113.0/28",
                "type": "cidr",
                "operations": ["network_scan"],
            },
        ],
    )

    def decide(db, **kw):  # real decision logic, emulated Postgres auth store
        return check_scan_authorized(auth.session(), **kw)

    with (
        patch("api.db.get_sessionmaker", return_value=Session),
        patch.object(seg, "check_scan_authorized", decide),
    ):
        yield SimpleNamespace(engine=engine, Session=Session, eid=eid, auth=auth)


def _run(w, *, scanner, targets, run_fn, import_fn, job=None, summary_fn=None):
    job = job or seed_job(
        w.Session, tenant_id=T1, engagement_id=w.eid, scanner_type=scanner
    )
    fa._c6_run_guarded_target_scan(
        run_id=job,
        job_id=job,
        tenant_id=T1,
        engagement_id=w.eid,
        actor="assessor-1",
        scanner_type=scanner,
        operation=scanner,
        targets=targets,
        run_fn=run_fn,
        import_fn=import_fn,
        summary_fn=summary_fn,
    )
    return job


def _job(w, jid):
    with w.Session() as db:
        return db.get(FaScanJob, jid)


def _audit(w, jid):
    with w.Session() as db:
        return [
            e.event_type
            for e in db.query(FaScanAuditEvent).filter(
                FaScanAuditEvent.scan_job_id == jid
            )
        ]


# ---------------------------------------------------------------------------
# Web headers — full happy path
# ---------------------------------------------------------------------------


class _Resp(SimpleNamespace):
    pass


class _Client:
    def __init__(self, headers):
        self.headers = headers

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def head(self, url, follow_redirects=False):
        return _Resp(status_code=200, headers=self.headers.get(url, {}), url=url)


def _web(w, targets, headers):
    from services.connectors.web_headers import runner
    from services.field_assessment.connectors.web_headers_bridge import (
        import_web_headers_scan,
    )

    ok = SimpleNamespace(ok=True, rejection_code=None, rejection_reason=None)
    with (
        patch.object(runner._validator, "validate", return_value=ok),
        patch.object(runner.httpx, "Client", lambda **k: _Client(headers)),
    ):
        return _run(
            w,
            scanner="web_headers",
            targets=targets,
            run_fn=lambda cp: runner.run(targets=targets, checkpoint=cp),
            import_fn=lambda db, p: import_web_headers_scan(
                db=db,
                tenant_id=T1,
                engagement_id=w.eid,
                scan_result=p,
                actor="assessor-1",
            ),
        )


GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=()",
}


class TestWebHeadersEndToEnd:
    def test_full_pipeline_to_persisted_manifest(self, world):
        w = world
        job = _web(w, ["https://app.example.com"], {"https://app.example.com": {}})
        j = _job(w, job)
        assert j.status == "complete" and j.collection_status == "COMPLETE"
        assert "scan.evidence.captured" in _audit(w, job)
        with w.Session() as db:
            envs = envelopes(db, scan_job_id=job)
            fs = findings(db, w.eid)
        assert {e.source_type for e in envs} == {"scan_result", "web_target"}
        assert all(e.customer_receipt_id == w.auth.receipt_id for e in envs)
        assert all(e.authorization_ref == w.auth.scope_id for e in envs)
        assert fs and all(f.evidence_envelope_id for f in fs)
        assert all(f.confidence_level == ConfidenceLevel.CONFIRMED.value for f in fs)
        # The manifest is reproducible from persisted records alone.
        with w.Session() as db:
            m1 = rte.build_evidence_manifest(db, tenant_id=T1, engagement_id=w.eid)
        with w.Session() as db:
            m2 = rte.build_evidence_manifest(db, tenant_id=T1, engagement_id=w.eid)

        def strip(m):
            return json.dumps(
                {k: v for k, v in m.items() if k != "generated_at"},
                default=str,
                sort_keys=True,
            ).replace(m["generated_at"], "")

        assert strip(m1) == strip(m2)
        entry = m1["findings"][0]
        assert entry["evidence_integrity_status"] == "INTEGRITY_VERIFIED"
        assert (
            entry["provenance_status"] == "VERIFIED_INTEGRITY_ONLY"
        )  # never AUTHENTIC
        assert entry["authorization"]["customer_receipt_id"] == w.auth.receipt_id
        # Exactly the proof level the real authorization decision produced
        # (no attestation key in the test env → digest-only, never upgraded).
        decision = check_scan_authorized(
            w.auth.session(),
            tenant_id=T1,
            engagement_id=w.eid,
            target="app.example.com",
            target_type="fqdn",
            operation="web_headers",
        )
        assert entry["authorization"]["proof_level"] == decision["proof_level"]
        rc = m1["report_constraints"]
        assert rc["may_claim_authenticated_evidence"] is False
        assert rc["may_claim_zero_risk"] is False
        assert rc["may_claim_full_coverage"] is True

    def test_clean_complete_scan_still_not_zero_risk(self, world):
        w = world
        _web(w, ["https://app.example.com"], {"https://app.example.com": GOOD_HEADERS})
        with w.Session() as db:
            m = rte.build_evidence_manifest(db, tenant_id=T1, engagement_id=w.eid)
        assert m["report_constraints"]["may_claim_zero_risk"] is False

    def test_tamper_after_capture_downgrades_manifest(self, world):
        w = world
        job = _web(w, ["https://app.example.com"], {"https://app.example.com": {}})
        with w.Session() as db:
            sr = envelopes(db, scan_job_id=job, source_type="scan_result")[
                0
            ].scan_result_id
        from ._fixtures import tamper_raw_payload

        tamper_raw_payload(
            w.engine,
            sr,
            lambda p: p["targets"][0].update(headers_present=["all-of-them"]),
        )
        with w.Session() as db:
            m = rte.build_evidence_manifest(db, tenant_id=T1, engagement_id=w.eid)
        e = m["findings"][0]
        assert e["evidence_integrity_status"] == "INTEGRITY_FAILED"
        assert e["confidence_stored"] == ConfidenceLevel.CONFIRMED.value
        assert e["confidence_effective"] == ConfidenceLevel.SUSPECTED.value
        assert e["finding_id"] not in m["report_constraints"]["confirmed_finding_ids"]
        assert m["report_constraints"]["integrity_failed_evidence_ids"]

    def test_capture_failure_is_explicit_and_blocks_claims(self, world, monkeypatch):
        w = world
        monkeypatch.setattr(rte, "MAX_OBSERVATION_BYTES", 16)
        job = _web(w, ["https://app.example.com"], {"https://app.example.com": {}})
        assert _job(w, job).status == "complete"  # scan data kept
        assert "scan.evidence.capture_failed" in _audit(w, job)
        with w.Session() as db:
            assert envelopes(db, scan_job_id=job) == []
            fs = findings(db, w.eid)
            m = rte.build_evidence_manifest(db, tenant_id=T1, engagement_id=w.eid)
        assert fs and all(
            f.confidence_level == ConfidenceLevel.UNKNOWN.value for f in fs
        )
        assert all(x["provenance_status"] == "MISSING" for x in m["findings"])
        assert m["report_constraints"]["confirmed_finding_ids"] == []


# ---------------------------------------------------------------------------
# Network — revocation / emergency stop between observations
# ---------------------------------------------------------------------------


def _network(w, hosts, on_scan=None):
    from services.connectors.network_scan import runner
    from services.field_assessment.connectors.network_scan_bridge import (
        import_network_scan,
    )

    def fake_scan(host):
        if on_scan:
            on_scan(host)
        return {"host": host, "open_ports": [3389], "tls": {}}

    with (
        patch.object(runner, "_scan_host", side_effect=fake_scan),
        patch.object(runner, "_expand_targets", return_value=(hosts, [])),
    ):
        return _run(
            w,
            scanner="network_scan",
            targets=["203.0.113.0/28"],
            run_fn=lambda cp: runner.run_network_scan(
                target_hosts=["203.0.113.0/28"], engagement_id=w.eid, checkpoint=cp
            ),
            import_fn=lambda db, p: import_network_scan(
                db=db,
                tenant_id=T1,
                engagement_id=w.eid,
                scan_result=p,
                actor="assessor-1",
            ),
        )


class TestNetworkEndToEnd:
    def test_revocation_between_hosts_keeps_attributed_partial_evidence(self, world):
        w = world
        probed = []

        def revoke_after_first(host):
            probed.append(host)
            w.auth.receipts[w.auth.receipt_id].update(
                status="revoked", revoked_at=h.utcnow()
            )

        job = _network(
            w, ["203.0.113.1", "203.0.113.2", "203.0.113.3"], revoke_after_first
        )
        assert probed == ["203.0.113.1"]  # no outbound work after revocation
        j = _job(w, job)
        assert j.status == "cancelled" and j.collection_status == "CANCELLED"
        with w.Session() as db:
            envs = envelopes(db, scan_job_id=job)
            m = rte.build_evidence_manifest(db, tenant_id=T1, engagement_id=w.eid)
        whole = next(e for e in envs if e.source_type == "scan_result")
        assert whole.collection_status == "CANCELLED"
        assert {e.source_id for e in envs if e.source_type == "network_host"} == {
            "203.0.113.1"
        }
        # Evidence keeps the authorization that permitted it, not the revoked state.
        assert all(e.customer_receipt_id == w.auth.receipt_id for e in envs)
        assert m["report_constraints"]["may_claim_full_coverage"] is False
        assert any("CANCELLED" in x for x in m["coverage_limitations"])
        # The observed host's finding stays CONFIRMED on its own complete evidence.
        (entry,) = m["findings"]
        assert entry["confidence_effective"] == ConfidenceLevel.CONFIRMED.value
        assert entry["collection_status"] == "COMPLETE"

    def test_emergency_stop_does_not_discard_captured_evidence(self, world):
        w = world
        job = _network(
            w, ["203.0.113.1", "203.0.113.2"], lambda host: w.auth.stop("platform")
        )
        assert _job(w, job).status == "cancelled"
        with w.Session() as db:
            hosts = {
                e.source_id
                for e in envelopes(db, scan_job_id=job, source_type="network_host")
            }
        assert hosts == {"203.0.113.1"}

    def test_late_success_after_cancel_keeps_evidence_job_cancelled(self, world):
        w = world
        jid = seed_job(
            w.Session, tenant_id=T1, engagement_id=w.eid, scanner_type="network_scan"
        )

        def cancel_in_flight(host):
            with w.Session() as db:
                db.get(FaScanJob, jid).status = "cancel_requested"
                db.commit()

        from services.connectors.network_scan import runner
        from services.field_assessment.connectors.network_scan_bridge import (
            import_network_scan,
        )

        def run_fn(cp):
            with (
                patch.object(
                    runner,
                    "_scan_host",
                    side_effect=lambda h_: {
                        "host": h_,
                        "open_ports": [3389],
                        "tls": {},
                    },
                ),
                patch.object(
                    runner, "_expand_targets", return_value=(["203.0.113.1"], [])
                ),
            ):
                out = runner.run_network_scan(
                    target_hosts=["x"], engagement_id=w.eid, checkpoint=cp
                )
            cancel_in_flight(None)  # cancel lands after the last checkpoint
            return out

        _run(
            w,
            scanner="network_scan",
            targets=["203.0.113.0/28"],
            job=jid,
            run_fn=run_fn,
            import_fn=lambda db, p: import_network_scan(
                db=db, tenant_id=T1, engagement_id=w.eid, scan_result=p, actor="a"
            ),
        )
        assert _job(w, jid).status == "cancelled"
        assert "scan.late_completion_rejected" in _audit(w, jid)
        with w.Session() as db:
            assert envelopes(
                db, scan_job_id=jid
            )  # evidence persisted before the terminal CAS


# ---------------------------------------------------------------------------
# DNS — real runner with mocked resolver
# ---------------------------------------------------------------------------


class TestDnsEndToEnd:
    def test_dns_timeout_never_becomes_confirmed_absence(self, world):
        w = world
        from services.connectors.collection_status import DnsQueryStatus
        from services.connectors.dns_email import runner
        from services.connectors.dns_email.runner import DnsQueryOutcome
        from services.field_assessment.connectors.dns_email_bridge import (
            import_dns_email_scan,
        )

        timeout = DnsQueryOutcome(records=[], status=DnsQueryStatus.TIMEOUT)
        with patch.object(runner, "_dns_query", return_value=timeout):
            job = _run(
                w,
                scanner="dns_email",
                targets=["app.example.com"],
                run_fn=lambda cp: runner.run(
                    domains=["app.example.com"], checkpoint=cp
                ),
                import_fn=lambda db, p: import_dns_email_scan(
                    db=db, tenant_id=T1, engagement_id=w.eid, scan_result=p, actor="a"
                ),
            )
        with w.Session() as db:
            envs = envelopes(db, scan_job_id=job)
            fs = findings(db, w.eid)
        dom = next(e for e in envs if e.source_type == "dns_domain")
        assert dom.collection_status != CollectionStatus.COMPLETE.value
        assert all(f.confidence_level != ConfidenceLevel.CONFIRMED.value for f in fs)


# ---------------------------------------------------------------------------
# Concurrency, static wiring proof, performance
# ---------------------------------------------------------------------------


class TestConcurrencyAndWiring:
    def test_concurrent_capture_race_resolves_to_single_envelope_set(self, world):
        w = world
        job = _web(w, ["https://app.example.com"], {"https://app.example.com": {}})
        with w.Session() as db:
            sr = envelopes(db, scan_job_id=job)[0].scan_result_id
            before = len(envelopes(db, scan_result_id=sr))
        real = rte._existing_envelopes
        calls = {"n": 0}

        def stale_first(
            db, **kw
        ):  # simulate a loser that read before the winner committed
            calls["n"] += 1
            return {} if calls["n"] == 1 else real(db, **kw)

        with patch.object(rte, "_existing_envelopes", stale_first), w.Session() as db:
            res = rte.capture_with_retry(
                db,
                tenant_id=T1,
                engagement_id=w.eid,
                scan_result_id=sr,
                scanner_id="web_headers",
                scan_job_id=job,
            )
            db.commit()
        assert calls["n"] == 2 and res.created == 0
        with w.Session() as db:
            assert len(envelopes(db, scan_result_id=sr)) == before

    def test_every_wired_worker_captures_before_completion(self):
        src = (ROOT / "api" / "field_assessment.py").read_text()
        tree = ast.parse(src)
        workers = {
            "_c6_run_guarded_target_scan",
            "_msgraph_scan_background",
            "_oauth_inventory_scan_background",
            "_endpoint_inventory_scan_background",
            "_entra_governance_scan_background",
            "_sharepoint_scan_background",
            "_oauth_risk_scan_background",
            "_ai_tool_discovery_scan_background",
        }
        seen = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in workers:
                body = ast.get_source_segment(src, node)
                cap = body.find("_c6_capture_runtime_evidence(")
                assert cap != -1, f"{node.name} does not capture evidence"
                done = [
                    i
                    for i in (
                        body.find('status="complete"'),
                        body.find("mark_complete("),
                    )
                    if i != -1
                ]
                assert done and cap < min(done), (
                    f"{node.name} completes before capturing"
                )
                seen.add(node.name)
        assert seen == workers

    def test_capture_overhead_measured(self, world, capsys):
        w = world
        from services.field_assessment.connectors.network_scan_bridge import (
            import_network_scan,
        )

        jid = seed_job(
            w.Session, tenant_id=T1, engagement_id=w.eid, scanner_type="network_scan"
        )
        hosts = [f"203.0.113.{i}" for i in range(1, 51)]
        payload = {
            "collection_status": "COMPLETE",
            "hosts": [
                {"host": x, "open_ports": list(range(20, 60)), "tls": {"cn": x * 20}}
                for x in hosts
            ],
            "findings": [
                {
                    "finding_type": "network.unsafe_services_exposed",
                    "severity": "high",
                    "title": "t",
                    "description": "d",
                    "affected_hosts": hosts,
                }
            ],
            "authorization_context": {**rte_ctx(w, jid)},
        }
        with w.Session() as db:
            sr = import_network_scan(
                db=db, tenant_id=T1, engagement_id=w.eid, scan_result=payload, actor="a"
            ).scan_result_id
            db.commit()
        with w.Session() as db:
            t0 = time.perf_counter()
            res = rte.capture_with_retry(
                db,
                tenant_id=T1,
                engagement_id=w.eid,
                scan_result_id=sr,
                scanner_id="network_scan",
                scan_job_id=jid,
            )
            db.commit()
            ms = (time.perf_counter() - t0) * 1000
        assert res.created == 51 and res.findings_linked == 1
        with capsys.disabled():
            print(
                f"\n[runtime-evidence perf] 50 hosts + scan envelope: {ms:.1f} ms (SQLite, test env)"
            )
        assert ms < 10_000


def rte_ctx(w, jid):
    from ._fixtures import auth_context

    return auth_context(
        tenant_id=T1, engagement_id=w.eid, job_id=jid, scanner="network_scan"
    )
