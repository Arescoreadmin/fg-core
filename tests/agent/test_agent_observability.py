"""
tests/agent/test_agent_observability.py

Tests for task 17.5 — Agent observability.

Coverage:
- Authenticated operator can query per-device status
- Unauthenticated request is rejected (401)
- Wrong scope is rejected (403)
- Tenant A cannot see Tenant B device status (tenant isolation)
- Active device with recent heartbeat reports healthy
- Device with no heartbeat reports no_heartbeat
- Disabled device reports disabled, not healthy
- Revoked device reports revoked, not healthy
- Version below floor reports outdated, not healthy
- Collector failure is visible with actionable reason code
- Collector success is visible
- Multiple collectors are represented deterministically (sorted by name)
- Backlog state is explicit (not_tracked)
- Response includes all required fields
- Missing device returns 404 (anti-enumeration for foreign-tenant device)

All tests are offline-safe and deterministic.
"""

from __future__ import annotations


from fastapi.testclient import TestClient

from tests.agent.helpers import admin_headers, enroll_device, signed_headers

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_STATUS_PATH = "/admin/agent/devices/{device_id}/status"


def _heartbeat_body(
    version: str = "1.0.0",
    collector_statuses: list[dict] | None = None,
) -> dict:
    body: dict = {
        "ts": "2026-01-01T00:00:00Z",
        "agent_version": version,
        "os": "linux",
        "hostname": "host-obs",
    }
    if collector_statuses is not None:
        body["collector_statuses"] = collector_statuses
    return body


def _heartbeat(
    client: TestClient,
    enrolled: dict,
    version: str = "1.0.0",
    nonce: str | None = None,
    collector_statuses: list[dict] | None = None,
) -> object:
    body = _heartbeat_body(version, collector_statuses)
    headers = signed_headers(
        "/agent/heartbeat",
        body,
        enrolled["device_key_prefix"],
        enrolled["device_key"],
        nonce=nonce,
    )
    return client.post("/agent/heartbeat", json=body, headers=headers)


def _get_status(client: TestClient, device_id: str) -> object:
    return client.get(
        _STATUS_PATH.format(device_id=device_id),
        headers=admin_headers(),
    )


def _admin_headers_no_scope() -> dict[str, str]:
    """Return headers with API key but wrong (non-admin) scope."""
    from api.auth_scopes import mint_key

    key = mint_key("keys:read", tenant_id="tenant-a")
    return {"X-API-Key": key, "X-Tenant-Id": "tenant-a"}


# ---------------------------------------------------------------------------
# Authentication & authorization
# ---------------------------------------------------------------------------


def test_agent_obs_unauthenticated_rejected(build_app) -> None:
    """Unauthenticated request to status endpoint returns 401."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    resp = client.get(_STATUS_PATH.format(device_id=enrolled["device_id"]))
    assert resp.status_code == 401  # type: ignore[union-attr, attr-defined]


def test_agent_obs_wrong_scope_rejected(build_app) -> None:
    """Request with non-admin key scope returns 403."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    resp = client.get(
        _STATUS_PATH.format(device_id=enrolled["device_id"]),
        headers=_admin_headers_no_scope(),
    )
    assert resp.status_code == 403  # type: ignore[union-attr, attr-defined]


def test_agent_obs_missing_device_returns_404(build_app) -> None:
    """Status query for unknown device_id returns 404."""
    app = build_app()
    client = TestClient(app)
    resp = _get_status(client, "dev_nonexistent00000000")
    assert resp.status_code == 404  # type: ignore[union-attr, attr-defined]


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


def test_agent_obs_tenant_isolation(build_app) -> None:
    """Tenant A cannot see Tenant B device status — returns 404, not 403."""
    from api.auth_scopes import mint_key

    app = build_app()
    client = TestClient(app)

    # Enroll a device under tenant-a (default admin_headers uses tenant-a).
    enrolled = enroll_device(client)

    # Query as tenant-b.
    key_b = mint_key("keys:admin", tenant_id="tenant-b")
    headers_b = {"X-API-Key": key_b, "X-Tenant-Id": "tenant-b"}
    resp = client.get(
        _STATUS_PATH.format(device_id=enrolled["device_id"]),
        headers=headers_b,
    )
    # 404, not 403 — prevents cross-tenant device enumeration.
    assert resp.status_code == 404  # type: ignore[union-attr, attr-defined]


# ---------------------------------------------------------------------------
# Active device — healthy
# ---------------------------------------------------------------------------


def test_agent_obs_active_device_healthy(build_app) -> None:
    """Active device with recent heartbeat reports healthy."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    _heartbeat(client, enrolled, nonce="n-obs-1")

    resp = _get_status(client, enrolled["device_id"])
    assert resp.status_code == 200  # type: ignore[union-attr, attr-defined]
    data = resp.json()  # type: ignore[union-attr, attr-defined]
    assert data["health_status"] == "healthy"
    assert data["lifecycle_status"] == "active"
    assert data["last_seen_at"] is not None
    assert data["version"] == "1.0.0"
    assert data["backlog_state"] == "not_tracked"
    assert data["backlog_reason"] == "backlog_tracking_not_implemented"
    assert isinstance(data["reasons"], list)


def test_agent_obs_response_required_fields(build_app) -> None:
    """Response contains all required observability fields."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    _heartbeat(client, enrolled, nonce="n-obs-fields")

    resp = _get_status(client, enrolled["device_id"])
    data = resp.json()  # type: ignore[union-attr, attr-defined]
    required = {
        "device_id",
        "tenant_id",
        "health_status",
        "lifecycle_status",
        "last_seen_at",
        "version",
        "version_floor",
        "effective_min_version",
        "collector_statuses",
        "backlog_state",
        "backlog_reason",
        "reasons",
    }
    assert required <= data.keys()


# ---------------------------------------------------------------------------
# No heartbeat — no_heartbeat
# ---------------------------------------------------------------------------


def test_agent_obs_no_heartbeat(build_app, monkeypatch) -> None:
    """
    Stale device (last seen beyond threshold) reports no_heartbeat.

    Enrollment sets last_seen_at.  Setting the threshold to 0 forces any
    non-zero elapsed time to be considered stale, which is the only way to
    trigger no_heartbeat through the normal enrollment + heartbeat flow.
    """
    monkeypatch.setenv("FG_AGENT_NO_HEARTBEAT_SECONDS", "0")
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    # Do NOT send a heartbeat — enrollment last_seen_at is immediately stale
    # because FG_AGENT_NO_HEARTBEAT_SECONDS=0.
    resp = _get_status(client, enrolled["device_id"])
    assert resp.status_code == 200  # type: ignore[union-attr, attr-defined]
    data = resp.json()  # type: ignore[union-attr, attr-defined]
    assert data["health_status"] == "no_heartbeat"
    assert "HEARTBEAT_STALE" in data["reasons"][0]


# ---------------------------------------------------------------------------
# Disabled device
# ---------------------------------------------------------------------------


def test_agent_obs_disabled_device_not_healthy(build_app) -> None:
    """Disabled device reports disabled, not healthy."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    _heartbeat(client, enrolled, nonce="n-obs-dis")

    client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/disable",
        headers=admin_headers(),
    )

    resp = _get_status(client, enrolled["device_id"])
    data = resp.json()  # type: ignore[union-attr, attr-defined]
    assert data["health_status"] == "disabled"
    assert data["lifecycle_status"] == "disabled"
    assert "DEVICE_DISABLED" in data["reasons"]


# ---------------------------------------------------------------------------
# Revoked device
# ---------------------------------------------------------------------------


def test_agent_obs_revoked_device_not_healthy(build_app) -> None:
    """Revoked device reports revoked, not healthy."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    _heartbeat(client, enrolled, nonce="n-obs-rev")

    client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/revoke",
        headers=admin_headers(),
    )

    resp = _get_status(client, enrolled["device_id"])
    data = resp.json()  # type: ignore[union-attr, attr-defined]
    assert data["health_status"] == "revoked"
    assert data["lifecycle_status"] == "revoked"
    assert "DEVICE_REVOKED" in data["reasons"]


# ---------------------------------------------------------------------------
# Version below floor — outdated
# ---------------------------------------------------------------------------


def test_agent_obs_version_below_floor_outdated(build_app) -> None:
    """Version below floor reports outdated, not healthy."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    _heartbeat(client, enrolled, version="1.0.0", nonce="n-obs-vf")

    client.put(
        "/admin/agent/version-floor",
        json={"version_floor": "2.0.0"},
        headers=admin_headers(),
    )

    resp = _get_status(client, enrolled["device_id"])
    data = resp.json()  # type: ignore[union-attr, attr-defined]
    assert data["health_status"] == "outdated"
    assert data["version_floor"] == "2.0.0"
    assert data["effective_min_version"] == "2.0.0"
    assert any("VERSION_BELOW_FLOOR" in r for r in data["reasons"])


def test_agent_obs_version_meets_floor_healthy(build_app) -> None:
    """Version meeting the floor reports healthy."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    _heartbeat(client, enrolled, version="3.0.0", nonce="n-obs-vok")

    client.put(
        "/admin/agent/version-floor",
        json={"version_floor": "2.0.0"},
        headers=admin_headers(),
    )

    resp = _get_status(client, enrolled["device_id"])
    data = resp.json()  # type: ignore[union-attr, attr-defined]
    assert data["health_status"] == "healthy"
    assert data["reasons"] == []


# ---------------------------------------------------------------------------
# Collector statuses
# ---------------------------------------------------------------------------


def test_agent_obs_collector_success_visible(build_app) -> None:
    """Successful collector run is visible in observability response."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    _heartbeat(
        client,
        enrolled,
        nonce="n-obs-cs-ok",
        collector_statuses=[{"collector_name": "process_inventory", "outcome": "ran"}],
    )

    resp = _get_status(client, enrolled["device_id"])
    data = resp.json()  # type: ignore[union-attr, attr-defined]
    assert data["health_status"] == "healthy"
    collectors = {c["collector_name"]: c for c in data["collector_statuses"]}
    assert "process_inventory" in collectors
    assert collectors["process_inventory"]["last_outcome"] == "ran"
    assert collectors["process_inventory"]["last_error"] is None


def test_agent_obs_collector_failure_visible(build_app) -> None:
    """Failed collector run is visible with actionable reason code."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    _heartbeat(
        client,
        enrolled,
        nonce="n-obs-cs-fail",
        collector_statuses=[
            {
                "collector_name": "process_inventory",
                "outcome": "failed",
                "error": "permission denied",
            }
        ],
    )

    resp = _get_status(client, enrolled["device_id"])
    data = resp.json()  # type: ignore[union-attr, attr-defined]
    assert data["health_status"] == "degraded"
    collectors = {c["collector_name"]: c for c in data["collector_statuses"]}
    assert collectors["process_inventory"]["last_outcome"] == "failed"
    assert collectors["process_inventory"]["last_error"] == "permission denied"
    assert any("COLLECTOR_FAILED:process_inventory" in r for r in data["reasons"])


def test_agent_obs_multiple_collectors_deterministic_order(build_app) -> None:
    """Multiple collectors are returned in deterministic (sorted by name) order."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    _heartbeat(
        client,
        enrolled,
        nonce="n-obs-multi",
        collector_statuses=[
            {"collector_name": "z_collector", "outcome": "ran"},
            {"collector_name": "a_collector", "outcome": "ran"},
            {"collector_name": "m_collector", "outcome": "failed", "error": "err"},
        ],
    )

    resp = _get_status(client, enrolled["device_id"])
    data = resp.json()  # type: ignore[union-attr, attr-defined]
    names = [c["collector_name"] for c in data["collector_statuses"]]
    assert names == sorted(names)


def test_agent_obs_empty_collector_list_explicit(build_app) -> None:
    """Device with no collector statuses reported returns empty list explicitly."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    _heartbeat(client, enrolled, nonce="n-obs-nocol")

    resp = _get_status(client, enrolled["device_id"])
    data = resp.json()  # type: ignore[union-attr, attr-defined]
    assert data["collector_statuses"] == []


def test_agent_obs_collector_status_update_on_reheart(build_app) -> None:
    """Subsequent heartbeat with updated collector outcome overwrites previous."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    # First heartbeat: failed
    _heartbeat(
        client,
        enrolled,
        nonce="n-obs-upd1",
        collector_statuses=[
            {"collector_name": "inv", "outcome": "failed", "error": "oops"}
        ],
    )
    # Second heartbeat: recovered
    _heartbeat(
        client,
        enrolled,
        nonce="n-obs-upd2",
        collector_statuses=[{"collector_name": "inv", "outcome": "ran"}],
    )

    resp = _get_status(client, enrolled["device_id"])
    data = resp.json()  # type: ignore[union-attr, attr-defined]
    collectors = {c["collector_name"]: c for c in data["collector_statuses"]}
    assert collectors["inv"]["last_outcome"] == "ran"
    assert collectors["inv"]["last_error"] is None
    assert data["health_status"] == "healthy"


# ---------------------------------------------------------------------------
# Backlog state
# ---------------------------------------------------------------------------


def test_agent_obs_backlog_not_tracked(build_app) -> None:
    """Backlog state is explicitly not_tracked (not silently zero)."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    _heartbeat(client, enrolled, nonce="n-obs-bl")

    resp = _get_status(client, enrolled["device_id"])
    data = resp.json()  # type: ignore[union-attr, attr-defined]
    assert data["backlog_state"] == "not_tracked"
    assert data["backlog_reason"] == "backlog_tracking_not_implemented"


# ---------------------------------------------------------------------------
# Heartbeat collector_statuses validation (malformed input rejected)
# ---------------------------------------------------------------------------


def test_agent_obs_heartbeat_invalid_collector_outcome_rejected(build_app) -> None:
    """Heartbeat with invalid collector outcome value is rejected with 422."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    body = _heartbeat_body(
        collector_statuses=[{"collector_name": "inv", "outcome": "INVALID_VALUE"}]
    )
    headers = signed_headers(
        "/agent/heartbeat",
        body,
        enrolled["device_key_prefix"],
        enrolled["device_key"],
        nonce="n-obs-inv",
    )
    resp = client.post("/agent/heartbeat", json=body, headers=headers)
    assert resp.status_code == 422  # type: ignore[union-attr, attr-defined]
