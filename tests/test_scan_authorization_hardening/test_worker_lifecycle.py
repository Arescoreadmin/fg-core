"""Guarded worker lifecycle — cancellation races, late completion, evidence,
coverage truth and authorization decision records.

Drives the real ``_c6_run_guarded_target_scan`` from api/field_assessment.py
over the stateful harness store.  L14-SCAN-AUTH-HARDENING-001.
"""

from __future__ import annotations

import json
import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest

os.environ.setdefault("FG_ENV", "test")

import api.field_assessment as fa
from services.field_assessment.scan_authorization import (
    ScanAuthorizationError,
    clear_emergency_stop,
)

from ._harness import E1, T1, T2, FakeDurableJobs, Store, approved_receipt, utcnow


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.delenv("FG_SCAN_REQUIRE_CUSTOMER_CONSENT", raising=False)


@pytest.fixture()
def store() -> Store:
    s = Store()
    r = approved_receipt(s)
    s.receipt_id = str(r["id"])
    s.scope_id = s.add_scope(receipt_id=s.receipt_id)
    return s


@pytest.fixture()
def wired(store):
    with (
        patch("api.db.get_sessionmaker", return_value=store.session),
        patch.object(fa, "durable_job_svc", FakeDurableJobs(store)),
        patch.object(fa, "_auto_link_scan_evidence", lambda *a, **k: None),
    ):
        yield store


class _Importer:
    def __init__(self):
        self.payloads: list[dict] = []

    def __call__(self, db, scan_result):
        self.payloads.append(json.loads(json.dumps(scan_result, default=str)))
        return SimpleNamespace(
            scan_result_id=f"sr-{len(self.payloads)}",
            targets_scanned=1,
            findings_imported=0,
        )


def _run(store, jid, run_fn, importer, targets=("app.example.com",)):
    fa._c6_run_guarded_target_scan(
        run_id=jid,
        job_id=jid,
        tenant_id=T1,
        engagement_id=E1,
        actor="assessor-1",
        scanner_type="web_headers",
        operation="web_headers",
        targets=list(targets),
        run_fn=run_fn,
        import_fn=importer,
    )


def _ok_result(**extra):
    return {
        "targets": [{"url": "https://app.example.com"}],
        "findings": [],
        "collection_status": "COMPLETE",
        "interrupted": None,
        **extra,
    }


class TestHappyPath:
    def test_valid_authorized_scan_completes_with_provenance(self, wired):
        store = wired
        jid = store.add_job()
        imp = _Importer()
        _run(
            store,
            jid,
            lambda cp: (cp("target", "app.example.com"), _ok_result())[1],
            imp,
        )
        assert store.jobs[jid]["status"] == "complete"
        assert store.jobs[jid]["collection_status"] == "COMPLETE"
        ctx = imp.payloads[0]["authorization_context"]
        assert ctx["customer_receipt_id"] == store.receipt_id
        assert ctx["authorization_id"] == store.scope_id
        assert ctx["consent_status"] == "CUSTOMER_APPROVED"
        assert ctx["scan_job_id"] == jid and ctx["tenant_id"] == T1
        assert ctx["execution_checkpoints_passed"] >= 2
        ev = store.events("scan.")
        assert "scan.authorization.worker_start_authorized" in ev
        assert "scan.completed" in ev


class TestWorkerStartDenial:
    def test_revoked_before_start_no_outbound_and_job_cancelled(self, wired):
        store = wired
        jid = store.add_job()
        store.receipts[store.receipt_id].update(status="revoked", revoked_at=utcnow())
        calls = []
        _run(store, jid, lambda cp: calls.append(1) or _ok_result(), _Importer())
        assert calls == []
        assert store.jobs[jid]["status"] == "cancelled"
        assert store.jobs[jid]["collection_status"] == "CANCELLED"
        assert store.jobs[jid]["cancelled_by"] == "system:scan_execution_guard"
        ev = store.events()
        assert "scan.authorization.worker_start_denied" in ev
        assert "scan.authorization.lost" in ev and "scan.cancelled" in ev
        denial = next(
            e
            for e in store.audit
            if e.event_type == "scan.authorization.worker_start_denied"
        )
        rec = json.loads(denial.payload_summary)
        assert rec["decision"] == "DENIED" and rec["reason_code"] == "RECEIPT_REVOKED"
        assert rec["correlation_id"] == jid and rec["boundary"] == "worker_start"

    def test_emergency_stop_before_start(self, wired):
        store = wired
        jid = store.add_job()
        store.stop("platform")
        calls = []
        _run(store, jid, lambda cp: calls.append(1) or _ok_result(), _Importer())
        assert calls == [] and store.jobs[jid]["status"] == "cancelled"

    def test_cancelled_before_start_confirmed_without_running(self, wired):
        store = wired
        jid = store.add_job(status="cancel_requested")
        calls = []
        _run(store, jid, lambda cp: calls.append(1) or _ok_result(), _Importer())
        assert calls == []
        assert store.jobs[jid]["status"] == "cancelled"

    def test_duplicate_delivery_of_completed_job_does_nothing(self, wired):
        store = wired
        jid = store.add_job(status="complete")
        calls = []
        _run(store, jid, lambda cp: calls.append(1) or _ok_result(), _Importer())
        assert calls == [] and store.jobs[jid]["status"] == "complete"

    def test_cancel_lands_between_start_check_and_running_cas(self, wired):
        store = wired
        jid = store.add_job()

        def hook(sql, p):
            # worker_start already read status='queued'; the cancel lands while
            # it is still checking the receipt, i.e. before the running CAS.
            if "FROM fa_customer_authorization_receipts" in sql:
                store.jobs[jid]["status"] = "cancel_requested"
                store.hook = None

        store.hook = hook
        calls = []
        _run(store, jid, lambda cp: calls.append(1) or _ok_result(), _Importer())
        assert calls == []  # CAS queued→running lost: no outbound work
        assert store.jobs[jid]["status"] == "cancelled"


class TestDuringExecution:
    def test_authorization_lost_mid_scan_preserves_partial_evidence(self, wired):
        store = wired
        jid = store.add_job()
        imp = _Importer()

        def run_fn(cp):
            from services.connectors.execution_checkpoint import (
                ScanCheckpointHalt,
                interruption_record,
            )

            cp("target", "app.example.com")
            store.receipts[store.receipt_id].update(
                status="revoked", revoked_at=utcnow()
            )
            try:
                cp("target", "app.example.com")
            except ScanCheckpointHalt as h:
                return _ok_result(
                    collection_status="CANCELLED",
                    interrupted=interruption_record(h, phase="target", remaining=1),
                )
            raise AssertionError("checkpoint should have halted")

        _run(store, jid, run_fn, imp)
        assert len(imp.payloads) == 1  # partial evidence persisted
        assert (
            imp.payloads[0]["authorization_context"]["interrupted"]["reason_code"]
            == "RECEIPT_REVOKED"
        )
        assert store.jobs[jid]["status"] == "cancelled"
        assert store.jobs[jid]["collection_status"] == "CANCELLED"
        lost = next(e for e in store.audit if e.event_type == "scan.authorization.lost")
        assert lost.rejection_reason == "RECEIPT_REVOKED"
        cancelled = next(e for e in store.audit if e.event_type == "scan.cancelled")
        assert cancelled.scan_result_id == "sr-1"  # evidence stays attributable

    def test_interrupted_scan_never_claims_complete(self, wired):
        store = wired
        jid = store.add_job()
        _run(
            store,
            jid,
            lambda cp: _ok_result(
                collection_status="CANCELLED",
                interrupted={
                    "reason_code": "EMERGENCY_STOP_ACTIVE",
                    "phase": "target",
                    "remaining_targets_not_started": 3,
                },
            ),
            _Importer(),
        )
        assert store.jobs[jid]["status"] == "cancelled"
        assert store.jobs[jid]["collection_status"] != "COMPLETE"
        assert "scan.completed" not in store.events()

    def test_late_success_after_cancellation_rejected(self, wired):
        store = wired
        jid = store.add_job()
        imp = _Importer()

        def run_fn(cp):
            cp("target", "app.example.com")
            # Operator cancels while the last request is in flight; runner
            # finishes "successfully" without passing another checkpoint.
            store.jobs[jid]["status"] = "cancel_requested"
            return _ok_result()

        _run(store, jid, run_fn, imp)
        assert store.jobs[jid]["status"] == "cancelled"
        assert store.jobs[jid]["collection_status"] == "CANCELLED"
        assert "scan.late_completion_rejected" in store.events()
        assert "scan.completed" not in store.events()
        assert len(imp.payloads) == 1  # evidence preserved, not discarded

    def test_scan_failure_after_cancel_does_not_overwrite(self, wired):
        store = wired
        jid = store.add_job()

        def run_fn(cp):
            store.jobs[jid]["status"] = "cancelled"
            raise RuntimeError("socket reset")

        _run(store, jid, run_fn, _Importer())
        assert store.jobs[jid]["status"] == "cancelled"

    def test_execution_target_denials_are_audited(self, wired):
        store = wired
        jid = store.add_job()
        from services.connectors.execution_checkpoint import ScanTargetDenied

        def run_fn(cp):
            try:
                cp("redirect", "evil.example.net")
            except ScanTargetDenied:
                pass
            return _ok_result(collection_status="PARTIAL")

        _run(store, jid, run_fn, _Importer())
        ev = next(
            e for e in store.audit if e.event_type == "scan.authorization.target_denied"
        )
        assert (
            ev.target == "evil.example.net"
            and ev.rejection_reason == "TARGET_NOT_IN_SCOPE"
        )
        assert store.jobs[jid]["status"] == "complete"
        assert store.jobs[jid]["collection_status"] == "PARTIAL"


class TestGraphFamilyGates:
    def test_graph_worker_halts_on_emergency_stop(self, wired):
        store = wired
        jid = store.add_job(status="running", scanner_type="microsoft_graph")
        store.stop(f"tenant:{T1}")
        assert (
            fa._c6_graph_worker_halted(
                store.session,
                run_id=jid,
                job_id=jid,
                tenant_id=T1,
                engagement_id=E1,
                scanner_type="microsoft_graph",
            )
            is True
        )
        assert store.jobs[jid]["status"] == "cancelled"
        assert "scan.authorization.worker_start_denied" in store.events()

    def test_graph_worker_halts_on_cancellation(self, wired):
        store = wired
        jid = store.add_job(status="cancel_requested", scanner_type="microsoft_graph")
        assert (
            fa._c6_graph_worker_halted(
                store.session,
                run_id=jid,
                job_id=jid,
                tenant_id=T1,
                engagement_id=E1,
                scanner_type="microsoft_graph",
            )
            is True
        )
        assert store.jobs[jid]["status"] == "cancelled"

    def test_graph_worker_proceeds_when_clear(self, wired):
        store = wired
        jid = store.add_job(status="running", scanner_type="microsoft_graph")
        assert (
            fa._c6_graph_worker_halted(
                store.session,
                run_id=jid,
                job_id=jid,
                tenant_id=T1,
                engagement_id=E1,
                scanner_type="microsoft_graph",
            )
            is False
        )

    def test_graph_worker_fails_closed_when_store_down(self, wired):
        store = wired
        jid = store.add_job(status="running", scanner_type="microsoft_graph")
        store.unavailable = True
        assert (
            fa._c6_graph_worker_halted(
                store.session,
                run_id=jid,
                job_id=jid,
                tenant_id=T1,
                engagement_id=E1,
                scanner_type="microsoft_graph",
            )
            is True
        )

    def test_graph_dispatch_denied_under_emergency_stop(self, wired):
        store = wired
        store.stop(f"engagement:{E1}")
        with pytest.raises(fa.HTTPException) as ei:
            fa._c6_require_no_emergency_stop(
                store.session(),
                tenant_id=T1,
                engagement_id=E1,
                actor="a",
                scanner_type="microsoft_graph",
            )
        assert ei.value.status_code == 403
        assert "scan.authorization.denied" in store.events()


class TestDispatchRecord:
    def test_dispatch_decision_recorded(self, wired):
        store = wired
        denied = fa._c6_check_all_targets_authorized(
            store.session(),
            tenant_id=T1,
            engagement_id=E1,
            actor="a",
            raw_targets=["https://app.example.com/x"],
            operation="web_headers",
            scanner_type="web_headers",
        )
        assert denied is None
        ev = next(
            e
            for e in store.audit
            if e.event_type == "scan.authorization.dispatch_authorized"
        )
        rec = json.loads(ev.payload_summary)
        assert (
            rec["customer_receipt_id"] == store.receipt_id
            and rec["decision"] == "AUTHORIZED"
        )

    def test_dispatch_denial_recorded(self, wired):
        store = wired
        denied = fa._c6_check_all_targets_authorized(
            store.session(),
            tenant_id=T1,
            engagement_id=E1,
            actor="a",
            raw_targets=["other.example.org"],
            operation="web_headers",
            scanner_type="web_headers",
        )
        assert denied and denied[0]["denial_code"] == "TARGET_NOT_IN_SCOPE"
        assert "scan.authorization.dispatch_authorized" not in store.events()


class TestEmergencyStopRelease:
    def _row(self, scope):
        return SimpleNamespace(fetchone=lambda: ("stop-1", scope, True))

    def test_cross_tenant_engagement_stop_clear_denied(self):
        store = Store()
        sess = store.session()
        calls = []

        def execute(stmt, params=None):
            sql = " ".join(str(stmt).split())
            calls.append(sql)
            if sql.startswith(
                "SELECT id, scope, is_active FROM fa_scan_emergency_stops"
            ):
                return SimpleNamespace(
                    fetchone=lambda: ("stop-1", "engagement:eng-bravo-1", True)
                )
            return store.session().execute(stmt, params)

        sess.execute = execute
        with pytest.raises(ScanAuthorizationError) as ei:
            clear_emergency_stop(
                sess,
                stop_id="stop-1",
                actor="x",
                actor_tenant_id=T1,
                permissions=["scan.emergency_stop"],
            )
        assert ei.value.audit_code == "EMERGENCY_STOP_CLEAR_CROSS_TENANT_DENIED"
        assert not any(c.startswith("UPDATE fa_scan_emergency_stops") for c in calls)

    def test_own_tenant_engagement_stop_clear_allowed(self):
        store = Store()
        sess = store.session()
        updates = []

        def execute(stmt, params=None):
            sql = " ".join(str(stmt).split())
            if sql.startswith(
                "SELECT id, scope, is_active FROM fa_scan_emergency_stops"
            ):
                return SimpleNamespace(
                    fetchone=lambda: ("stop-1", f"engagement:{E1}", True)
                )
            if sql.startswith("UPDATE fa_scan_emergency_stops"):
                updates.append(params)
                return SimpleNamespace(fetchone=lambda: None)
            return store.session().execute(stmt, params)

        sess.execute = execute
        out = clear_emergency_stop(
            sess,
            stop_id="stop-1",
            actor="x",
            actor_tenant_id=T1,
            permissions=["scan.emergency_stop"],
        )
        assert out["is_active"] is False and updates

    def test_tenant_actor_cannot_clear_other_tenant_stop(self):
        store = Store()
        sess = store.session()
        sess.execute = lambda stmt, params=None: SimpleNamespace(
            fetchone=lambda: ("stop-1", f"tenant:{T2}", True)
        )
        with pytest.raises(ScanAuthorizationError) as ei:
            clear_emergency_stop(
                sess,
                stop_id="stop-1",
                actor="x",
                actor_tenant_id=T1,
                permissions=["scan.emergency_stop"],
            )
        assert ei.value.audit_code == "EMERGENCY_STOP_CLEAR_CROSS_TENANT_DENIED"
