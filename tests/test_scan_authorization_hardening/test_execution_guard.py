"""AUTH-GAP-002 — execution-time revalidation and continuous safety.

L14-SCAN-AUTH-HARDENING-001.  All outbound I/O is mocked.
"""

from __future__ import annotations

import os
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest

os.environ.setdefault("FG_ENV", "test")

from services.connectors.collection_status import CollectionStatus
from services.connectors.execution_checkpoint import (
    ScanCheckpointHalt,
    ScanTargetDenied,
)
from services.field_assessment.scan_execution_guard import (
    ExecutionContext,
    ScanExecutionGuard,
    ScanExecutionHalted,
)

from ._harness import E1, E2, T1, T2, Store, approved_receipt, utcnow


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.delenv("FG_SCAN_REQUIRE_CUSTOMER_CONSENT", raising=False)


@pytest.fixture()
def store() -> Store:
    s = Store()
    r = approved_receipt(s)
    s.receipt_id = str(r["id"])
    s.scope_id = s.add_scope(
        receipt_id=s.receipt_id,
        targets=[
            {
                "target": "app.example.com",
                "type": "fqdn",
                "operations": ["web_headers", "dns_email", "network_scan"],
            },
            {
                "target": "203.0.113.0/28",
                "type": "cidr",
                "operations": ["network_scan"],
            },
        ],
    )
    return s


def _guard(
    store, job_id, *, op="web_headers", targets=("app.example.com",), tenant=T1, eng=E1
):
    return ScanExecutionGuard(
        store.session,
        ExecutionContext(
            tenant_id=tenant,
            engagement_id=eng,
            job_id=job_id,
            operation=op,
            scanner_type=op,
            actor="assessor",
            targets=list(targets),
        ),
    )


# ---------------------------------------------------------------------------
# Worker start
# ---------------------------------------------------------------------------


class TestWorkerStart:
    def test_valid_authorization_at_worker_start(self, store):
        jid = store.add_job()
        d = _guard(store, jid).worker_start()
        assert d["consent_status"] == "CUSTOMER_APPROVED"
        assert d["customer_receipt_id"] == store.receipt_id

    def _halt(self, store, jid, **kw):
        with pytest.raises(ScanExecutionHalted) as ei:
            _guard(store, jid, **kw).worker_start()
        return ei.value.reason_code

    def test_receipt_revoked_between_dispatch_and_start(self, store):
        jid = store.add_job()
        store.receipts[store.receipt_id].update(status="revoked", revoked_at=utcnow())
        assert self._halt(store, jid) == "RECEIPT_REVOKED"

    def test_receipt_expired_after_dispatch(self, store):
        jid = store.add_job()
        g = _guard(store, jid)
        g._now = lambda: utcnow() + timedelta(days=30)
        store.scopes[store.scope_id]["expires_at"] = utcnow() + timedelta(days=60)
        with pytest.raises(ScanExecutionHalted) as ei:
            g.worker_start()
        assert ei.value.reason_code == "RECEIPT_EXPIRED"

    def test_scope_expired_after_dispatch(self, store):
        jid = store.add_job()
        store.scopes[store.scope_id]["expires_at"] = utcnow() - timedelta(seconds=1)
        assert self._halt(store, jid) == "AUTHORIZATION_EXPIRED"

    def test_scope_revoked_before_start(self, store):
        jid = store.add_job()
        store.revoke_scope(store.scope_id)
        assert self._halt(store, jid) == "NO_ACTIVE_AUTHORIZATION"

    @pytest.mark.parametrize("scope", ["platform", f"tenant:{T1}", f"engagement:{E1}"])
    def test_emergency_stop_before_start(self, store, scope):
        jid = store.add_job()
        store.stop(scope)
        assert self._halt(store, jid) == "EMERGENCY_STOP_ACTIVE"

    def test_other_tenant_stop_does_not_apply(self, store):
        jid = store.add_job()
        store.stop(f"tenant:{T2}")
        assert _guard(store, jid).worker_start()

    def test_store_unavailable_fails_closed(self, store):
        jid = store.add_job()
        store.unavailable = True
        assert self._halt(store, jid) == "AUTHORIZATION_STORE_UNAVAILABLE"

    def test_store_errors_mid_check_fail_closed(self, store):
        jid = store.add_job()

        def hook(sql, p):
            if sql.startswith("SELECT 1 FROM fa_scan_emergency_stops"):
                raise ConnectionError("x")

        store.hook = hook
        assert self._halt(store, jid) == "EMERGENCY_STOP_CHECK_FAILED"

    def test_worker_with_wrong_engagement(self, store):
        jid = store.add_job(engagement_id=E2)
        assert self._halt(store, jid) == "WORKER_ENGAGEMENT_MISMATCH"

    def test_worker_with_wrong_tenant(self, store):
        jid = store.add_job(tenant_id=T2)
        assert self._halt(store, jid) == "WORKER_TENANT_MISMATCH"

    @pytest.mark.parametrize("status", ["cancel_requested", "cancelled"])
    def test_cancelled_before_start(self, store, status):
        jid = store.add_job(status=status)
        assert self._halt(store, jid) == "JOB_CANCELLED"

    @pytest.mark.parametrize("status", ["complete", "failed", "dead_letter"])
    def test_duplicate_delivery_of_finished_job(self, store, status):
        jid = store.add_job(status=status)
        assert self._halt(store, jid) == "JOB_NOT_EXECUTABLE"

    def test_missing_job(self, store):
        assert self._halt(store, "no-such-job") == "JOB_NOT_FOUND"

    def test_any_unauthorized_target_halts_at_start(self, store):
        jid = store.add_job()
        assert (
            self._halt(store, jid, targets=("app.example.com", "intruder.example.org"))
            == "TARGET_NOT_IN_SCOPE"
        )

    def test_no_targets_halts(self, store):
        jid = store.add_job()
        assert self._halt(store, jid, targets=()) == "NO_TARGETS"

    def test_retry_after_authorization_loss_is_denied(self, store):
        jid = store.add_job()
        _guard(store, jid).worker_start()
        store.receipts[store.receipt_id].update(status="revoked", revoked_at=utcnow())
        # A retry/resumption is a fresh delivery: the same guard path re-reads state.
        assert self._halt(store, jid) == "RECEIPT_REVOKED"

    def test_no_cached_decision_reused(self, store):
        jid = store.add_job()
        g = _guard(store, jid)
        g.worker_start()
        before = len(store.executed)
        store.jobs[jid]["status"] = "running"
        g.checkpoint("target", "app.example.com")
        reads = store.executed[before:]
        assert any("fa_scan_authorizations" in q for q in reads)
        assert any("fa_scan_emergency_stops" in q for q in reads)
        assert any("fa_customer_authorization_receipts" in q for q in reads)
        assert any("fa_scan_jobs" in q for q in reads)


# ---------------------------------------------------------------------------
# Checkpoints (continuous safety)
# ---------------------------------------------------------------------------


class TestCheckpoint:
    def _running(self, store, **kw):
        jid = store.add_job(status="running")
        return jid, _guard(store, jid, **kw)

    def test_checkpoint_requires_running_job(self, store):
        jid = store.add_job(status="queued")
        with pytest.raises(ScanExecutionHalted) as ei:
            _guard(store, jid).checkpoint("target", "app.example.com")
        assert ei.value.reason_code == "JOB_NOT_EXECUTABLE"

    def test_out_of_scope_target_is_target_level_denial(self, store):
        _, g = self._running(store)
        with pytest.raises(ScanTargetDenied):
            g.checkpoint("redirect", "evil.example.net")
        assert g.denied_targets == [
            {
                "target": "evil.example.net",
                "phase": "redirect",
                "code": "TARGET_NOT_IN_SCOPE",
            }
        ]

    def test_cancellation_is_state_level_halt(self, store):
        jid, g = self._running(store)
        store.jobs[jid]["status"] = "cancel_requested"
        with pytest.raises(ScanExecutionHalted) as ei:
            g.checkpoint("target", "app.example.com")
        assert ei.value.reason_code == "JOB_CANCELLED"

    def test_halt_is_a_checkpoint_halt_for_runners(self):
        assert issubclass(ScanExecutionHalted, ScanCheckpointHalt)


# ---------------------------------------------------------------------------
# Runner integration: halts stop new outbound work, partial evidence kept
# ---------------------------------------------------------------------------


class TestNetworkRunner:
    def test_revocation_between_targets_stops_probing(self, store):
        from services.connectors.network_scan import runner

        jid, g = store.add_job(status="running"), None
        g = _guard(store, jid, op="network_scan", targets=["203.0.113.0/30"])
        probed: list[str] = []

        def fake_scan(host):
            probed.append(host)
            if len(probed) == 1:
                store.receipts[store.receipt_id].update(
                    status="revoked", revoked_at=utcnow()
                )
            return {"host": host, "open_ports": [22], "tls": {}}

        with (
            patch.object(runner, "_scan_host", side_effect=fake_scan),
            patch.object(
                runner,
                "_expand_targets",
                return_value=(["203.0.113.1", "203.0.113.2", "203.0.113.3"], []),
            ),
        ):
            out = runner.run_network_scan(
                target_hosts=["203.0.113.0/30"],
                engagement_id=E1,
                checkpoint=g.checkpoint,
            )
        assert probed == ["203.0.113.1"]
        assert out["collection_status"] == CollectionStatus.CANCELLED.value
        assert out["scan_status"] == "interrupted"
        assert out["interrupted"]["reason_code"] == "RECEIPT_REVOKED"
        assert out["interrupted"]["remaining_targets_not_started"] == 2
        assert [h["host"] for h in out["hosts"]] == [
            "203.0.113.1"
        ]  # partial evidence kept

    def test_emergency_stop_between_batches(self, store):
        from services.connectors.network_scan import runner

        jid = store.add_job(status="running")
        g = _guard(store, jid, op="network_scan")
        calls = []

        def fake_scan(host):
            calls.append(host)
            store.stop("platform")
            return {"host": host, "open_ports": [], "tls": {}}

        with (
            patch.object(runner, "_scan_host", side_effect=fake_scan),
            patch.object(
                runner,
                "_expand_targets",
                return_value=(["203.0.113.1", "203.0.113.2"], []),
            ),
        ):
            out = runner.run_network_scan(
                target_hosts=["x"], engagement_id=E1, checkpoint=g.checkpoint
            )
        assert calls == ["203.0.113.1"]
        assert out["interrupted"]["reason_code"] == "EMERGENCY_STOP_ACTIVE"
        assert out["collection_status"] != CollectionStatus.COMPLETE.value

    def test_denied_host_skipped_not_probed(self, store):
        from services.connectors.network_scan import runner

        jid = store.add_job(status="running")
        g = _guard(store, jid, op="network_scan")
        with (
            patch.object(
                runner,
                "_scan_host",
                side_effect=lambda h: {"host": h, "open_ports": [], "tls": {}},
            ) as sh,
            patch.object(
                runner,
                "_expand_targets",
                return_value=(["203.0.113.1", "198.51.100.7"], []),
            ),
        ):
            out = runner.run_network_scan(
                target_hosts=["x"], engagement_id=E1, checkpoint=g.checkpoint
            )
        assert [c.args[0] for c in sh.call_args_list] == ["203.0.113.1"]
        assert out["collection_status"] == CollectionStatus.PARTIAL.value
        assert out["summary"]["host_authorization_denied_count"] == 1

    def test_without_checkpoint_behaviour_unchanged(self):
        from services.connectors.network_scan import runner

        with (
            patch.object(
                runner,
                "_scan_host",
                side_effect=lambda h: {"host": h, "open_ports": [], "tls": {}},
            ),
            patch.object(runner, "_expand_targets", return_value=(["203.0.113.1"], [])),
        ):
            out = runner.run_network_scan(target_hosts=["x"], engagement_id=E1)
        assert out["collection_status"] == CollectionStatus.COMPLETE.value
        assert out["interrupted"] is None


class TestDnsRunner:
    def test_cancellation_during_dns_processing(self, store):
        from services.connectors.dns_email import runner

        jid = store.add_job(status="running")
        g = _guard(store, jid, op="dns_email")
        seen = []

        def fake_domain(domain, selectors):
            seen.append(domain)
            store.jobs[jid]["status"] = "cancel_requested"
            return {
                "domain": domain,
                "findings": [{"f": 1}],
                "collection_status": "COMPLETE",
                "any_collection_failure": False,
            }

        with patch.object(runner, "scan_domain", side_effect=fake_domain):
            out = runner.run(
                ["app.example.com", "app.example.com"], checkpoint=g.checkpoint
            )
        assert seen == ["app.example.com"]
        assert out["collection_status"] == CollectionStatus.CANCELLED.value
        assert out["interrupted"]["reason_code"] == "JOB_CANCELLED"
        assert len(out["domains"]) == 1

    def test_unapproved_domain_denied(self, store):
        from services.connectors.dns_email import runner

        jid = store.add_job(status="running")
        g = _guard(store, jid, op="dns_email")
        with patch.object(runner, "scan_domain") as sd:
            out = runner.run(["victim.example.org"], checkpoint=g.checkpoint)
        sd.assert_not_called()
        assert out["domains"][0]["collection_status"] == CollectionStatus.DENIED.value


class _Resp(SimpleNamespace):
    pass


class _Client:
    def __init__(self, chain):
        self.chain = dict(chain)
        self.requested: list[str] = []

    def head(self, url, follow_redirects=False):
        self.requested.append(url)
        loc = self.chain.get(url)
        if loc:
            return _Resp(status_code=302, headers={"location": loc}, url=url)
        return _Resp(status_code=200, headers={}, url=url)


class TestWebHeadersRedirects:
    def _ok_validator(self):
        return SimpleNamespace(ok=True, rejection_code=None, rejection_reason=None)

    def test_redirect_outside_scope_blocked_before_request(self, store):
        from services.connectors.web_headers import runner

        jid = store.add_job(status="running")
        g = _guard(store, jid)
        client = _Client({"https://app.example.com/": "https://evil.example.net/"})
        with patch.object(
            runner._validator, "validate", return_value=self._ok_validator()
        ):
            resp, block = runner._follow_redirects_safely(
                client, "https://app.example.com/", g.checkpoint
            )
        assert block and "outside authorized scope" in block
        assert "https://evil.example.net/" not in client.requested

    def test_in_scope_redirect_followed(self, store):
        from services.connectors.web_headers import runner

        jid = store.add_job(status="running")
        g = _guard(store, jid)
        client = _Client({"https://app.example.com/": "https://app.example.com/login"})
        with patch.object(
            runner._validator, "validate", return_value=self._ok_validator()
        ):
            resp, block = runner._follow_redirects_safely(
                client, "https://app.example.com/", g.checkpoint
            )
        assert block is None
        assert client.requested[-1] == "https://app.example.com/login"

    def test_ssrf_redirect_still_blocked_by_validator(self, store):
        """Existing SSRF protection remains first: metadata IP literal redirect."""
        from services.connectors.web_headers import runner

        jid = store.add_job(status="running")
        g = _guard(store, jid)
        client = _Client(
            {"https://app.example.com/": "http://169.254.169.254/latest/meta-data"}
        )
        resp, block = runner._follow_redirects_safely(
            client, "https://app.example.com/", g.checkpoint
        )
        assert block and "blocked" in block
        assert len(client.requested) == 1

    def test_dns_rebinding_style_redirect_to_private_ip_literal_blocked(self, store):
        from services.connectors.web_headers import runner

        jid = store.add_job(status="running")
        g = _guard(store, jid)
        client = _Client({"https://app.example.com/": "http://10.0.0.5/"})
        resp, block = runner._follow_redirects_safely(
            client, "https://app.example.com/", g.checkpoint
        )
        assert block is not None
        assert "http://10.0.0.5/" not in client.requested

    def test_halt_before_redirect_hop_interrupts_run(self, store):
        from services.connectors.web_headers import runner

        jid = store.add_job(status="running")
        g = _guard(store, jid)
        client = _Client({"https://app.example.com/": "https://app.example.com/next"})

        class _Ctx:
            def __enter__(self_inner):
                return client

            def __exit__(self_inner, *a):
                return False

        def hook(sql, p):
            if (
                sql.startswith("SELECT 1 FROM fa_scan_emergency_stops")
                and client.requested
            ):
                store.stop(f"engagement:{E1}")

        store.hook = hook
        with (
            patch.object(
                runner._validator, "validate", return_value=self._ok_validator()
            ),
            patch.object(runner.httpx, "Client", return_value=_Ctx()),
        ):
            out = runner.run(["https://app.example.com/"], checkpoint=g.checkpoint)
        assert out["collection_status"] == CollectionStatus.CANCELLED.value
        assert out["interrupted"]["phase"] == "redirect"
        assert "https://app.example.com/next" not in client.requested

    def test_target_denied_at_execution_not_requested(self, store):
        from services.connectors.web_headers import runner

        jid = store.add_job(status="running")
        g = _guard(store, jid)
        with patch.object(runner, "scan_target") as st:
            out = runner.run(["https://other.example.org/"], checkpoint=g.checkpoint)
        st.assert_not_called()
        assert out["targets"][0]["collection_status"] == CollectionStatus.DENIED.value
