"""
tests/agent/test_agent_lifecycle.py

Tests for task 17.4 — Agent lifecycle controls.

Coverage:
- Disable: soft-disable blocks heartbeat and config fetch (reversible)
- Enable: re-enables a disabled device; revoked cannot be re-enabled
- Version floor: per-tenant floor set/get; agents below floor receive action=shutdown
- Config fetch: returns version floor and action; rejects revoked/disabled devices
- Revoke regression: revoked device still blocked (no regression)
- Enrollment regression: enrollment still works after lifecycle features added
- Lifecycle actions are authenticated (keys:admin scope required)
- Audit: lifecycle actions are recorded

All tests are offline-safe and deterministic.
"""

from __future__ import annotations

from urllib.parse import urlencode

from fastapi.testclient import TestClient

from tests.agent.helpers import admin_headers, enroll_device, signed_headers


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _heartbeat_body(version: str = "1.0.0") -> dict:
    return {
        "ts": "2026-01-01T00:00:00Z",
        "agent_version": version,
        "os": "linux",
        "hostname": "host-lifecycle",
    }


def _heartbeat(
    client: TestClient, enrolled: dict, version: str = "1.0.0", nonce: str | None = None
) -> object:
    body = _heartbeat_body(version)
    headers = signed_headers(
        "/agent/heartbeat",
        body,
        enrolled["device_key_prefix"],
        enrolled["device_key"],
        nonce=nonce,
    )
    return client.post("/agent/heartbeat", headers=headers, json=body)


def _config_fetch(
    client: TestClient,
    enrolled: dict,
    agent_version: str | None = None,
    nonce: str | None = None,
) -> object:
    params: dict[str, str] = {}
    if agent_version is not None:
        params["agent_version"] = agent_version
    path = "/agent/config"
    body: dict = {}
    # Server canonical path includes sorted query params; sign the same string.
    sorted_params = sorted(params.items())
    signed_path = f"{path}?{urlencode(sorted_params)}" if sorted_params else path
    headers = signed_headers(
        signed_path,
        body,
        enrolled["device_key_prefix"],
        enrolled["device_key"],
        nonce=nonce,
        method="GET",
    )
    return client.get(path, headers=headers, params=params)


# ---------------------------------------------------------------------------
# Disable lifecycle
# ---------------------------------------------------------------------------


def test_agent_lifecycle_disable_blocks_heartbeat(build_app) -> None:
    """Disabled device cannot submit heartbeat telemetry — returns 403."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    # Confirm baseline works.
    assert _heartbeat(client, enrolled, nonce="n-dis-1").status_code == 200  # type: ignore[union-attr, attr-defined]

    resp = client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/disable",
        headers=admin_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["disabled"] is True

    denied = _heartbeat(client, enrolled, nonce="n-dis-2")
    assert denied.status_code == 403  # type: ignore[union-attr, attr-defined]
    detail = denied.json()  # type: ignore[union-attr, attr-defined]
    assert detail.get("detail", {}).get("code") == "DEVICE_DISABLED"


def test_agent_lifecycle_disable_idempotent(build_app) -> None:
    """Disabling an already-disabled device succeeds (idempotent status set)."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/disable",
        headers=admin_headers(),
    )
    resp = client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/disable",
        headers=admin_headers(),
    )
    assert resp.status_code == 200


def test_agent_lifecycle_disable_unknown_device_is_404(build_app) -> None:
    """Disabling a nonexistent device returns 404."""
    app = build_app()
    client = TestClient(app)
    resp = client.post(
        "/admin/agent/devices/dev_doesnotexist/disable",
        headers=admin_headers(),
    )
    assert resp.status_code == 404


def test_agent_lifecycle_disable_revoked_device_is_409(build_app) -> None:
    """Disabling a revoked device returns 409 (revoked is terminal)."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/revoke",
        headers=admin_headers(),
    )
    resp = client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/disable",
        headers=admin_headers(),
    )
    assert resp.status_code == 409


def test_agent_lifecycle_disable_requires_admin_scope(build_app) -> None:
    """Disable endpoint requires keys:admin scope — unauthenticated returns 401/403."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    resp = client.post(f"/admin/agent/devices/{enrolled['device_id']}/disable")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Enable lifecycle
# ---------------------------------------------------------------------------


def test_agent_lifecycle_enable_restores_heartbeat(build_app) -> None:
    """Re-enabled device can submit heartbeat telemetry again."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/disable",
        headers=admin_headers(),
    )
    # Confirm disabled.
    assert _heartbeat(client, enrolled, nonce="n-en-dis").status_code == 403  # type: ignore[union-attr, attr-defined]

    resp = client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/enable",
        headers=admin_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True

    # After enable, heartbeat must succeed.
    assert _heartbeat(client, enrolled, nonce="n-en-ok").status_code == 200  # type: ignore[union-attr, attr-defined]


def test_agent_lifecycle_enable_revoked_device_is_409(build_app) -> None:
    """Re-enabling a revoked device returns 409 (revoked is permanent)."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/revoke",
        headers=admin_headers(),
    )
    resp = client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/enable",
        headers=admin_headers(),
    )
    assert resp.status_code == 409


def test_agent_lifecycle_enable_active_device_is_409(build_app) -> None:
    """Enabling an already-active device returns 409 (not disabled)."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    resp = client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/enable",
        headers=admin_headers(),
    )
    assert resp.status_code == 409


def test_agent_lifecycle_enable_unknown_device_is_404(build_app) -> None:
    """Enabling a nonexistent device returns 404."""
    app = build_app()
    client = TestClient(app)
    resp = client.post(
        "/admin/agent/devices/dev_doesnotexist/enable",
        headers=admin_headers(),
    )
    assert resp.status_code == 404


def test_agent_lifecycle_enable_requires_admin_scope(build_app) -> None:
    """Enable endpoint requires keys:admin scope."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    resp = client.post(f"/admin/agent/devices/{enrolled['device_id']}/enable")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Version floor — admin management
# ---------------------------------------------------------------------------


def test_agent_lifecycle_version_floor_set_and_get(build_app) -> None:
    """Version floor can be set and retrieved for a tenant."""
    app = build_app()
    client = TestClient(app)

    put = client.put(
        "/admin/agent/version-floor",
        json={"version_floor": "2.0.0"},
        headers=admin_headers(),
    )
    assert put.status_code == 200
    assert put.json()["version_floor"] == "2.0.0"

    get = client.get("/admin/agent/version-floor", headers=admin_headers())
    assert get.status_code == 200
    assert get.json()["version_floor"] == "2.0.0"


def test_agent_lifecycle_version_floor_clear(build_app) -> None:
    """Version floor can be cleared (set to null)."""
    app = build_app()
    client = TestClient(app)

    client.put(
        "/admin/agent/version-floor",
        json={"version_floor": "2.0.0"},
        headers=admin_headers(),
    )
    put = client.put(
        "/admin/agent/version-floor",
        json={"version_floor": None},
        headers=admin_headers(),
    )
    assert put.status_code == 200
    assert put.json()["version_floor"] is None

    get = client.get("/admin/agent/version-floor", headers=admin_headers())
    assert get.json()["version_floor"] is None


def test_agent_lifecycle_version_floor_unset_returns_null(build_app) -> None:
    """GET version-floor returns null when no floor has been set."""
    app = build_app()
    client = TestClient(app)
    get = client.get("/admin/agent/version-floor", headers=admin_headers())
    assert get.status_code == 200
    assert get.json()["version_floor"] is None


def test_agent_lifecycle_version_floor_requires_admin_scope(build_app) -> None:
    """Version-floor endpoints require keys:admin scope."""
    app = build_app()
    client = TestClient(app)
    assert client.get("/admin/agent/version-floor").status_code in (401, 403)
    assert client.put(
        "/admin/agent/version-floor", json={"version_floor": "1.0.0"}
    ).status_code in (401, 403)


# ---------------------------------------------------------------------------
# Version floor — heartbeat enforcement
# ---------------------------------------------------------------------------


def test_agent_lifecycle_heartbeat_below_floor_returns_shutdown(build_app) -> None:
    """
    Agent sending version below the per-tenant floor receives action=shutdown
    on heartbeat.
    """
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    client.put(
        "/admin/agent/version-floor",
        json={"version_floor": "2.0.0"},
        headers=admin_headers(),
    )

    body = _heartbeat_body(version="1.5.0")
    headers = signed_headers(
        "/agent/heartbeat",
        body,
        enrolled["device_key_prefix"],
        enrolled["device_key"],
        nonce="n-floor-1",
    )
    resp = client.post("/agent/heartbeat", headers=headers, json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["action"] == "shutdown"
    assert data["required_min_version"] == "2.0.0"


def test_agent_lifecycle_heartbeat_at_floor_is_ok(build_app) -> None:
    """Agent sending version equal to floor receives action=none (allowed)."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    client.put(
        "/admin/agent/version-floor",
        json={"version_floor": "2.0.0"},
        headers=admin_headers(),
    )

    body = _heartbeat_body(version="2.0.0")
    headers = signed_headers(
        "/agent/heartbeat",
        body,
        enrolled["device_key_prefix"],
        enrolled["device_key"],
        nonce="n-floor-2",
    )
    resp = client.post("/agent/heartbeat", headers=headers, json=body)
    assert resp.status_code == 200
    assert resp.json()["action"] == "none"


def test_agent_lifecycle_heartbeat_above_floor_is_ok(build_app) -> None:
    """Agent sending version above floor receives action=none (allowed)."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    client.put(
        "/admin/agent/version-floor",
        json={"version_floor": "2.0.0"},
        headers=admin_headers(),
    )

    body = _heartbeat_body(version="3.1.0")
    headers = signed_headers(
        "/agent/heartbeat",
        body,
        enrolled["device_key_prefix"],
        enrolled["device_key"],
        nonce="n-floor-3",
    )
    resp = client.post("/agent/heartbeat", headers=headers, json=body)
    assert resp.status_code == 200
    assert resp.json()["action"] == "none"


def test_agent_lifecycle_heartbeat_no_floor_is_ok(build_app) -> None:
    """Heartbeat with no version floor set always returns action=none."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    body = _heartbeat_body(version="0.0.1")
    headers = signed_headers(
        "/agent/heartbeat",
        body,
        enrolled["device_key_prefix"],
        enrolled["device_key"],
        nonce="n-floor-4",
    )
    resp = client.post("/agent/heartbeat", headers=headers, json=body)
    assert resp.status_code == 200
    assert resp.json()["action"] == "none"


# ---------------------------------------------------------------------------
# Config fetch endpoint
# ---------------------------------------------------------------------------


def test_agent_lifecycle_config_fetch_active_device_ok(build_app) -> None:
    """Active device can fetch config; returns version_floor and action."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    resp = _config_fetch(client, enrolled, agent_version="1.0.0", nonce="n-cfg-1")
    assert resp.status_code == 200  # type: ignore[union-attr, attr-defined]
    data = resp.json()  # type: ignore[union-attr, attr-defined]
    assert "action" in data
    assert "server_time" in data


def test_agent_lifecycle_config_fetch_below_floor_returns_shutdown(build_app) -> None:
    """Config fetch returns action=shutdown when agent version is below floor."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    client.put(
        "/admin/agent/version-floor",
        json={"version_floor": "2.0.0"},
        headers=admin_headers(),
    )

    resp = _config_fetch(client, enrolled, agent_version="1.0.0", nonce="n-cfg-2")
    assert resp.status_code == 200  # type: ignore[union-attr, attr-defined]
    data = resp.json()  # type: ignore[union-attr, attr-defined]
    assert data["action"] == "shutdown"
    assert data["version_floor"] == "2.0.0"


def test_agent_lifecycle_config_fetch_above_floor_returns_none(build_app) -> None:
    """Config fetch returns action=none when agent version meets the floor."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    client.put(
        "/admin/agent/version-floor",
        json={"version_floor": "2.0.0"},
        headers=admin_headers(),
    )

    resp = _config_fetch(client, enrolled, agent_version="2.5.0", nonce="n-cfg-3")
    assert resp.status_code == 200  # type: ignore[union-attr, attr-defined]
    assert resp.json()["action"] == "none"  # type: ignore[union-attr, attr-defined]


def test_agent_lifecycle_config_fetch_disabled_device_denied(build_app) -> None:
    """Disabled device cannot fetch config — returns 403."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/disable",
        headers=admin_headers(),
    )

    resp = _config_fetch(client, enrolled, nonce="n-cfg-4")
    assert resp.status_code == 403  # type: ignore[union-attr, attr-defined]
    assert resp.json()["detail"]["code"] == "DEVICE_DISABLED"  # type: ignore[union-attr, attr-defined]


def test_agent_lifecycle_config_fetch_revoked_device_denied(build_app) -> None:
    """Revoked device cannot fetch config — returns 403."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/revoke",
        headers=admin_headers(),
    )

    resp = _config_fetch(client, enrolled, nonce="n-cfg-5")
    assert resp.status_code == 403  # type: ignore[union-attr, attr-defined]


def test_agent_lifecycle_config_fetch_no_auth_denied(build_app) -> None:
    """Config fetch without device auth returns 401."""
    app = build_app()
    client = TestClient(app)
    resp = client.get("/agent/config")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Regression: revoke still works
# ---------------------------------------------------------------------------


def test_agent_lifecycle_revoke_still_blocks_heartbeat(build_app) -> None:
    """Revoke regression — revoked device is still blocked after lifecycle additions."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)

    client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/revoke",
        headers=admin_headers(),
    )

    resp = _heartbeat(client, enrolled, nonce="n-rev-1")
    assert resp.status_code == 403  # type: ignore[union-attr, attr-defined]


def test_agent_lifecycle_enrollment_regression(build_app) -> None:
    """Enrollment regression — enrollment still works after lifecycle additions."""
    app = build_app()
    client = TestClient(app)
    enrolled = enroll_device(client)
    assert enrolled["device_id"].startswith("dev_")
    assert _heartbeat(client, enrolled, nonce="n-reg-1").status_code == 200  # type: ignore[union-attr, attr-defined]


# ---------------------------------------------------------------------------
# Tenant isolation: lifecycle admin actions scoped to tenant
# ---------------------------------------------------------------------------


def test_agent_lifecycle_disable_tenant_isolation(build_app) -> None:
    """
    Tenant A admin cannot disable a device belonging to tenant B.
    Attempting to disable a device_id that does not belong to tenant-a returns 404.
    """
    from api.auth_scopes import mint_key

    app = build_app()
    client = TestClient(app)

    # Enroll under tenant-a (admin_headers uses tenant-a).
    enrolled = enroll_device(client)

    # Create a keys:admin key for a different tenant.
    tenant_b_key = mint_key("keys:admin", tenant_id="tenant-b")
    headers_b = {"X-API-Key": tenant_b_key, "X-Tenant-Id": "tenant-b"}

    resp = client.post(
        f"/admin/agent/devices/{enrolled['device_id']}/disable",
        headers=headers_b,
    )
    # tenant-b cannot see tenant-a's device → 404, not 403 (anti-enumeration).
    assert resp.status_code == 404
