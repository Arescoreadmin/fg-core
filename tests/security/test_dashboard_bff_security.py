from __future__ import annotations

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def test_snapshot_tenant_mismatch_denied(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")

    resp = client.post(
        "/ui/dashboard-data/snapshot",
        headers={"X-API-Key": key},
        json={
            "dashboard_id": "posture",
            "widget_ids": ["system_health"],
            "tenant_id": "tenant-b",
        },
    )
    assert resp.status_code == 403


def test_admin_override_requires_scope(build_app, monkeypatch):
    monkeypatch.setenv("FG_UI_ADMIN_OVERRIDE_ENABLED", "1")
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", "admin:read", tenant_id="tenant-a")

    resp = client.post(
        "/ui/dashboard-data/snapshot",
        headers={
            "X-API-Key": key,
            "X-FG-Admin-Override-Tenant": "tenant-b",
            "X-FG-Override-Reason": "override for support",
        },
        json={"dashboard_id": "posture", "widget_ids": ["system_health"]},
    )
    assert resp.status_code == 403


def test_admin_override_requires_reason(build_app, monkeypatch):
    monkeypatch.setenv("FG_UI_ADMIN_OVERRIDE_ENABLED", "1")
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", "admin:tenant_override", tenant_id="tenant-a")

    resp = client.post(
        "/ui/dashboard-data/snapshot",
        headers={"X-API-Key": key, "X-FG-Admin-Override-Tenant": "tenant-b"},
        json={"dashboard_id": "posture", "widget_ids": ["system_health"]},
    )
    assert resp.status_code == 400


def test_override_disabled_without_flag(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", "admin:tenant_override", tenant_id="tenant-a")

    resp = client.post(
        "/ui/dashboard-data/snapshot",
        headers={
            "X-API-Key": key,
            "X-FG-Admin-Override-Tenant": "tenant-b",
            "X-FG-Override-Reason": "override for support",
        },
        json={"dashboard_id": "posture", "widget_ids": ["system_health"]},
    )
    assert resp.status_code == 403


def test_theme_override_emits_audit_fields(build_app, monkeypatch):
    monkeypatch.setenv("FG_UI_ADMIN_OVERRIDE_ENABLED", "1")
    monkeypatch.setenv("FG_THEME_LOGO_HOST_ALLOWLIST", "example.com")
    events = []

    def _audit(**kwargs):
        events.append(kwargs)

    monkeypatch.setattr("api.ui_theme.audit_admin_action", _audit)

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", "admin:tenant_override", tenant_id="tenant-a")

    resp = client.get(
        "/ui/theme",
        headers={
            "X-API-Key": key,
            "X-FG-Admin-Override-Tenant": "tenant-b",
            "X-FG-Override-Reason": "support ticket",
        },
    )
    assert resp.status_code == 200
    assert events
    details = events[-1]["details"]
    assert details["route"] == "/ui/theme"
    assert details.get("parameters_hash")
    assert details["reason"] == "support ticket"
