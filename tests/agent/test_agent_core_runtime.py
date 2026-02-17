from __future__ import annotations

import hashlib
import hmac
import json
import logging
from pathlib import Path
import threading

import pytest

from agent.adapters.requests_transport import RequestsTransportClient
from agent.core.audit import AuditContext, build_audit_event
from agent.core.config import ConfigError, ConfigManager
from agent.core.queue import (
    QUEUE_CORRUPTION_REASON,
    QueueCorruptionError,
    SQLiteTaskQueue,
)
from agent.core.transport import TransportResponse
from agent.platform.base import PortablePlatform
from agent.runtime.health import get_health_snapshot, is_ready
from agent.runtime.runner import Runner


class FakeClock:
    def __init__(self, value: float = 1000.0) -> None:
        self.value = value

    def now(self) -> float:
        return self.value

    def tick(self, seconds: float) -> None:
        self.value += seconds


class StubResponse:
    def __init__(self, status_code: int, payload: dict, *, headers: dict | None = None):
        self.status_code = status_code
        self._payload = payload
        self.content = b"1"
        self.headers = headers or {}

    def json(self) -> dict:
        return self._payload


class StubSession:
    def __init__(self, response: StubResponse):
        self.response = response

    def request(self, **_: object) -> StubResponse:
        return self.response


class FakeTransport:
    def __init__(self, payload: dict, *, pinned_endpoint: bool = True) -> None:
        self._payload = payload
        self._pinned = pinned_endpoint

    @property
    def pinned_endpoint(self) -> bool:
        return self._pinned

    def request(
        self, method: str, path: str, *, correlation_id: str | None, **_: object
    ) -> TransportResponse:
        assert method == "GET"
        assert path
        _ = correlation_id
        return TransportResponse(status_code=200, json_body=self._payload, headers={})


def _signed_config(
    *, allowed_tasks: list[str] | None = None, hmac_key: str | None = None
) -> dict:
    base = {
        "tenant_id": "tenant-a",
        "policy": {
            "allowed_tasks": allowed_tasks or ["ping", "self_test", "config_refresh"],
            "allow_outbound_network": False,
        },
    }
    canonical = json.dumps(base, sort_keys=True, separators=(",", ":"))
    payload = {
        **base,
        "config_hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }
    if hmac_key:
        payload["config_sig"] = hmac.new(
            hmac_key.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
    return payload


def _runner(
    *,
    queue: SQLiteTaskQueue,
    config: ConfigManager,
    now,
    handlers: dict | None = None,
    refresh_transport_pinned: bool = False,
) -> Runner:
    return Runner(
        queue=queue,
        config=config,
        handlers=handlers or {"ping": lambda _: None},
        audit_sink=lambda _: None,
        agent_id="agent",
        agent_persistent_id="persist-a",
        tenant_id="tenant",
        now=now,
        refresh_transport_pinned=refresh_transport_pinned,
    )


def test_queue_cap_enforcement(tmp_path: pytest.TempPathFactory) -> None:
    clock = FakeClock()
    queue = SQLiteTaskQueue(
        str(tmp_path / "queue1.sqlite"), max_size=1, clock=clock.now
    )
    queue.enqueue("ping", {"n": 1})
    with pytest.raises(RuntimeError, match="queue_capacity_exceeded"):
        queue.enqueue("ping", {"n": 2})


def test_deadletter_after_max_attempts(tmp_path: pytest.TempPathFactory) -> None:
    clock = FakeClock()
    queue = SQLiteTaskQueue(
        str(tmp_path / "queue2.sqlite"),
        max_attempts=2,
        lease_seconds=1,
        clock=clock.now,
    )
    job_id = queue.enqueue("ping", {})
    first = queue.lease_next()
    assert first is not None
    queue.fail(first, "task_failed", retry_delay_seconds=0)
    second = queue.lease_next()
    assert second is not None
    queue.fail(second, "task_failed", retry_delay_seconds=0)
    assert queue.deadletter_count() == 1
    assert queue.get_deadletter_reason(job_id) == "max_attempts_exceeded"


def test_lease_prevents_double_execution(tmp_path: pytest.TempPathFactory) -> None:
    clock = FakeClock()
    queue = SQLiteTaskQueue(
        str(tmp_path / "queue3.sqlite"), lease_seconds=10, clock=clock.now
    )
    queue.enqueue("ping", {})
    first = queue.lease_next()
    assert first is not None
    assert queue.lease_next() is None


def test_concurrent_lease_only_one_wins(tmp_path: pytest.TempPathFactory) -> None:
    db = tmp_path / "queue_concurrent.sqlite"
    q1 = SQLiteTaskQueue(str(db))
    q2 = SQLiteTaskQueue(str(db))
    q1.enqueue("ping", {"x": 1})

    barrier = threading.Barrier(2)
    leased: list[str | None] = [None, None]

    def _lease(slot: int, queue: SQLiteTaskQueue) -> None:
        barrier.wait()
        job = queue.lease_next()
        leased[slot] = None if job is None else job.job_id

    t1 = threading.Thread(target=_lease, args=(0, q1))
    t2 = threading.Thread(target=_lease, args=(1, q2))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    got = [v for v in leased if v is not None]
    assert len(got) == 1


def test_invalid_config_denies_policy_task(tmp_path: pytest.TempPathFactory) -> None:
    clock = FakeClock()
    queue = SQLiteTaskQueue(str(tmp_path / "queue4.sqlite"), clock=clock.now)
    queue.enqueue("inventory_snapshot", {})

    config = ConfigManager()
    with pytest.raises(ConfigError):
        config.load_local({"tenant_id": "x", "policy": {}}, fetched_at=clock.now())

    runner = Runner(
        queue=queue,
        config=config,
        handlers={"inventory_snapshot": lambda _: None},
        audit_sink=lambda _: None,
        agent_id="agent",
        agent_persistent_id="persist-a",
        tenant_id="tenant",
        now=clock.now,
    )
    assert runner.run_once() is True
    assert queue.deadletter_count() == 1


def test_audit_event_has_deterministic_id_and_config_hash() -> None:
    ctx = AuditContext(
        agent_id="a1",
        agent_persistent_id="persist-1",
        tenant_id="t1",
        config_hash="cfg123",
    )
    one = build_audit_event(
        context=ctx,
        job_id="j1",
        task_type="ping",
        stage="start",
        attempt=1,
        outcome="start",
        timestamp=10.0,
    )
    two = build_audit_event(
        context=ctx,
        job_id="j1",
        task_type="ping",
        stage="start",
        attempt=1,
        outcome="start",
        timestamp=999.0,
    )
    retry = build_audit_event(
        context=ctx,
        job_id="j1",
        task_type="ping",
        stage="start",
        attempt=2,
        outcome="start",
        timestamp=10.0,
    )
    assert one["event_id"] == two["event_id"]
    assert one["event_id"] != retry["event_id"]
    assert one["config_hash"] == "cfg123"


def test_transport_log_sanitization(caplog: pytest.LogCaptureFixture) -> None:
    transport = RequestsTransportClient(
        "https://api.example.com",
        session=StubSession(StubResponse(200, {"ok": True})),
    )
    caplog.set_level(logging.INFO)
    transport.request(
        "POST",
        "/v1/submit?token=secret&api_key=very-secret",
        headers={
            "Authorization": "Bearer super-secret",
            "Cookie": "session=bad",
            "Proxy-Authorization": "proxy-secret",
            "X-Custom": "safe value",
        },
        json_body={"a": 1},
        correlation_id="c1",
    )
    assert "super-secret" not in caplog.text
    assert "proxy-secret" not in caplog.text
    assert "token=secret" not in caplog.text
    assert "api_key=very-secret" not in caplog.text
    assert "[REDACTED]" in caplog.text


def test_health_snapshot_reflects_degraded_mode(
    tmp_path: pytest.TempPathFactory,
) -> None:
    clock = FakeClock()
    queue = SQLiteTaskQueue(str(tmp_path / "queue5.sqlite"), clock=clock.now)
    config = ConfigManager()

    runner = _runner(queue=queue, config=config, now=clock.now)
    snap = get_health_snapshot(
        queue=queue, config=config, runner=runner, now=clock.now()
    )
    assert snap.degraded is True
    assert snap.config_hash_age is None
    assert snap.queue_quarantined is False


def test_config_refresh_requires_pinned_transport_when_degraded() -> None:
    key = "k1"
    payload = _signed_config(
        allowed_tasks=["ping", "self_test", "config_refresh"],
        hmac_key=key,
    )
    unpinned_transport = FakeTransport(payload=payload, pinned_endpoint=False)
    config = ConfigManager(hmac_key=key)

    with pytest.raises(ConfigError, match="config_refresh_requires_pinned_transport"):
        config.refresh(unpinned_transport, "/v1/config", now=1.0)

    pinned_transport = FakeTransport(payload=payload, pinned_endpoint=True)
    loaded = config.refresh(pinned_transport, "/v1/config", now=2.0)
    assert loaded.config_hash == payload["config_hash"]


def test_config_hmac_tamper_detection() -> None:
    key = "hmac-secret"
    payload = _signed_config(hmac_key=key)
    payload["policy"]["allow_outbound_network"] = True
    # Keep old hash/sig => should fail integrity first.
    manager = ConfigManager(hmac_key=key)
    with pytest.raises(ConfigError, match="integrity_hash_mismatch"):
        manager.load_local(payload, fetched_at=1.0)


def test_runner_allows_config_refresh_only_with_pinned_transport(
    tmp_path: pytest.TempPathFactory,
) -> None:
    clock = FakeClock()
    queue = SQLiteTaskQueue(str(tmp_path / "queue6.sqlite"), clock=clock.now)
    queue.enqueue("config_refresh", {})
    config = ConfigManager()

    called = {"refresh": 0}
    runner_denied = _runner(
        queue=queue,
        config=config,
        now=clock.now,
        handlers={"config_refresh": lambda _: called.__setitem__("refresh", 1)},
        refresh_transport_pinned=False,
    )
    assert runner_denied.run_once() is True
    assert called["refresh"] == 0

    queue2 = SQLiteTaskQueue(str(tmp_path / "queue7.sqlite"), clock=clock.now)
    queue2.enqueue("config_refresh", {})
    runner_allowed = _runner(
        queue=queue2,
        config=config,
        now=clock.now,
        handlers={"config_refresh": lambda _: called.__setitem__("refresh", 2)},
        refresh_transport_pinned=True,
    )
    assert runner_allowed.run_once() is True
    assert called["refresh"] == 2


def test_queue_corruption_persists_and_blocks_operations(
    tmp_path: pytest.TempPathFactory,
) -> None:
    clock = FakeClock()
    audits: list[dict] = []
    queue = SQLiteTaskQueue(
        str(tmp_path / "queue8.sqlite"),
        clock=clock.now,
        audit_sink=audits.append,
    )

    class _FakeResult:
        def fetchone(self):
            return ["corrupt"]

    class _FakeConn:
        def execute(self, *_args, **_kwargs):
            return _FakeResult()

        def close(self):
            return None

    queue._conn = _FakeConn()  # noqa: SLF001

    with pytest.raises(QueueCorruptionError):
        queue.detect_corruption()

    assert queue.quarantined is True
    assert queue.quarantine_reason == QUEUE_CORRUPTION_REASON
    assert audits and audits[0]["reason_code"] == QUEUE_CORRUPTION_REASON

    queue_reloaded = SQLiteTaskQueue(str(tmp_path / "queue8.sqlite"), clock=clock.now)
    assert queue_reloaded.quarantined is True
    with pytest.raises(QueueCorruptionError):
        queue_reloaded.depth()

    queue_reloaded.clear_quarantine(
        force=True,
        reason="operator_repair",
        expected_sentinel_path=str(
            (tmp_path / "queue8.sqlite").with_suffix(".sqlite.quarantine.json")
        ),
    )
    assert queue_reloaded.quarantined is False
    queue_reloaded._audit_sink = audits.append  # noqa: SLF001
    queue_reloaded._quarantined = True  # noqa: SLF001
    queue_reloaded.clear_quarantine(force=True, reason="operator_repair")
    assert any(evt.get("event") == "queue_quarantine_cleared" for evt in audits)


def test_health_and_readiness_reflect_queue_quarantine(
    tmp_path: pytest.TempPathFactory,
) -> None:
    queue = SQLiteTaskQueue(str(tmp_path / "queue9.sqlite"))
    queue._quarantined = True  # noqa: SLF001
    queue._quarantine_reason = QUEUE_CORRUPTION_REASON  # noqa: SLF001

    config = ConfigManager()
    runner = _runner(queue=queue, config=config, now=lambda: 1.0)
    snap = get_health_snapshot(queue=queue, config=config, runner=runner, now=1.0)
    assert snap.queue_quarantined is True
    assert (
        is_ready(config=config, enabled_task_types={"inventory_snapshot"}, queue=queue)
        is False
    )
    assert (
        is_ready(
            config=config,
            enabled_task_types={"ping", "self_test"},
            queue=queue,
            safe_only_mode=True,
        )
        is True
    )


def test_portable_platform_persistent_id_is_stable(
    tmp_path: pytest.TempPathFactory,
) -> None:
    path = tmp_path / "pid.json"
    p1 = PortablePlatform(str(path))
    p2 = PortablePlatform(str(path))
    assert p1.get_persistent_id() == p2.get_persistent_id()
    assert p1.derive_ephemeral_id()


def test_transport_log_redacts_url_userinfo(caplog: pytest.LogCaptureFixture) -> None:
    transport = RequestsTransportClient(
        "https://user:pass@api.example.com",
        session=StubSession(StubResponse(200, {"ok": True})),
    )
    caplog.set_level(logging.INFO)
    transport.request("GET", "/v1/a?x=1", correlation_id="cid")
    assert "user:pass" not in caplog.text
    assert "?x=1" not in caplog.text


def test_config_integrity_only_mode_without_hmac_key() -> None:
    payload = _signed_config()
    manager = ConfigManager(hmac_keys=[])
    loaded = manager.load_local(payload, fetched_at=2.0)
    assert loaded.config_hash == payload["config_hash"]


def test_config_hmac_key_rotation_accepts_prev_key() -> None:
    payload = _signed_config(hmac_key="prev-k")
    manager = ConfigManager(hmac_keys=["current-k", "prev-k"])
    loaded = manager.load_local(payload, fetched_at=3.0)
    assert loaded.config_hash == payload["config_hash"]


def test_config_hmac_key_requires_signature_when_configured() -> None:
    payload = _signed_config()
    manager = ConfigManager(hmac_keys=["current-k"])
    with pytest.raises(ConfigError, match="missing_config_sig"):
        manager.load_local(payload, fetched_at=4.0)


def test_config_signing_is_deterministic_for_same_canonical_payload() -> None:
    payload = _signed_config()
    canonical = json.dumps(
        {"tenant_id": payload["tenant_id"], "policy": payload["policy"]},
        sort_keys=True,
        separators=(",", ":"),
    )
    manager = ConfigManager(hmac_keys=["current-k", "prev-k"])
    sig1, kid1 = manager.sign_canonical_json(canonical)
    sig2, kid2 = manager.sign_canonical_json(canonical)
    assert sig1 == sig2
    assert kid1 == kid2 == "k0"


def test_config_rejects_malformed_signature_format() -> None:
    payload = _signed_config(hmac_key="current-k")
    payload["config_sig"] = "not-hex!!!"
    manager = ConfigManager(hmac_keys=["current-k"])
    with pytest.raises(ConfigError, match="invalid_config_sig_format"):
        manager.load_local(payload, fetched_at=5.0)


def test_queue_startup_unreadable_sentinel_fails_closed(
    tmp_path: pytest.TempPathFactory,
) -> None:
    db = tmp_path / "queue10.sqlite"
    sentinel = db.with_suffix(".sqlite.quarantine.json")
    sentinel.write_text("{bad-json", encoding="utf-8")
    audits: list[dict] = []
    queue = SQLiteTaskQueue(str(db), audit_sink=audits.append)
    assert queue.quarantined is True
    assert queue.quarantine_reason == "quarantine_sentinel_unreadable"
    assert any(
        evt.get("reason_code") == "quarantine_sentinel_unreadable" for evt in audits
    )


def test_portable_platform_falls_back_to_ephemeral_when_unwritable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pytest.TempPathFactory,
) -> None:
    path = tmp_path / "unwritable" / "pid.json"
    platform_obj = PortablePlatform(str(path))

    def _fail_write(*_args, **_kwargs):
        raise PermissionError("no-write")

    monkeypatch.setattr(Path, "write_text", _fail_write)
    pid = platform_obj.get_persistent_id()
    assert pid == platform_obj.derive_ephemeral_id()
    assert platform_obj.persistent_id_degraded is True


def test_config_keyring_parse_failure_fails_closed() -> None:
    payload = _signed_config()
    manager = ConfigManager(hmac_keys=["ok", 123])  # type: ignore[list-item]
    with pytest.raises(ConfigError, match="config_hmac_keyring_parse_failed"):
        manager.load_local(payload, fetched_at=6.0)


def test_transport_log_redacts_url_fragment(caplog: pytest.LogCaptureFixture) -> None:
    transport = RequestsTransportClient(
        "https://api.example.com",
        session=StubSession(StubResponse(200, {"ok": True})),
    )
    caplog.set_level(logging.INFO)
    transport.request("GET", "/v1/a?x=1#frag", correlation_id="cid")
    assert "#frag" not in caplog.text
    assert "?x=1" not in caplog.text


def test_health_surfaces_assurance_degraded_flags(
    tmp_path: pytest.TempPathFactory,
) -> None:
    queue = SQLiteTaskQueue(str(tmp_path / "queue11.sqlite"))
    queue._sentinel_perm_degraded = True  # noqa: SLF001
    config = ConfigManager(hmac_keys=["ok", 1])  # type: ignore[list-item]
    runner = _runner(queue=queue, config=config, now=lambda: 1.0)
    snap = get_health_snapshot(queue=queue, config=config, runner=runner, now=1.0)
    assert snap.queue_assurance_degraded is True
    assert snap.config_keyring_degraded is True


def test_config_prev_only_env_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FG_CONFIG_HMAC_KEY_CURRENT", raising=False)
    monkeypatch.setenv("FG_CONFIG_HMAC_KEY_PREV", "prev-only")
    monkeypatch.delenv("FG_CONFIG_HMAC_KEY", raising=False)
    monkeypatch.delenv("FG_CONFIG_HMAC_KEYS", raising=False)

    payload = _signed_config()
    manager = ConfigManager()
    with pytest.raises(ConfigError, match="config_hmac_current_required_for_signing"):
        manager.load_local(payload, fetched_at=7.0)
