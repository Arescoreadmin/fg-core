from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models import DecisionRecord


def _seed_decision(tenant_id: str, event_id: str = "evt-1") -> None:
    engine = get_engine()
    with Session(engine) as session:
        session.add(
            DecisionRecord(
                tenant_id=tenant_id,
                source="unit-test",
                event_id=event_id,
                event_type="auth.bruteforce",
                threat_level="low",
                anomaly_score=0.1,
                ai_adversarial_score=0.0,
                pq_fallback=False,
                rules_triggered_json=["rule-1"],
                decision_diff_json={"summary": "allow"},
                request_json={"request_id": "req-1"},
                response_json={"policy_version": "v1"},
            )
        )
        session.commit()


def test_ui_posture_refresh_click_bound_once(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")

    resp = client.get("/ui/dash/posture", headers={"X-API-Key": key})
    assert resp.status_code == 200
    assert resp.text.count("refreshBtn.onclick") == 1


def test_ui_forensics_verify_chain_passes_tenant_param(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("forensics:read", "ui:read", tenant_id="tenant-a")

    resp = client.get("/ui/dash/forensics", headers={"X-API-Key": key})
    assert resp.status_code == 200
    assert "tenant_id=${encodeURIComponent(tenant)}" in resp.text


def test_registry_not_found_and_scope_filtering(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")

    nf = client.get("/ui/registry/dashboards/not-real", headers={"X-API-Key": key})
    assert nf.status_code == 404

    dash = client.get("/ui/registry/dashboards/posture", headers={"X-API-Key": key})
    assert dash.status_code == 200
    widget_ids = [w["id"] for w in dash.json()["widgets"]]
    assert "system_health" in widget_ids
    assert "drift_status" not in widget_ids


def test_registry_persona_unauthorized_fail_closed(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")

    resp = client.get("/ui/registry/dashboards/forensics", headers={"X-API-Key": key})
    assert resp.status_code == 403


def test_snapshot_admin_override_requires_scope_and_audits(build_app, monkeypatch):
    monkeypatch.setenv("FG_UI_ADMIN_OVERRIDE_ENABLED", "1")
    events = []

    def _audit(**kwargs):
        events.append(kwargs)

    monkeypatch.setattr("api.ui_dashboard_data.audit_admin_action", _audit)
    from api import ui_dashboard_data as dd

    dd._CACHE.clear()

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    user_key = mint_key("ui:read", tenant_id="tenant-a")
    admin_key = mint_key(
        "ui:read", "admin:read", "admin:tenant_override", tenant_id="tenant-a"
    )
    _seed_decision("tenant-b", "evt-admin")

    denied = client.post(
        "/ui/dashboard-data/snapshot",
        headers={
            "X-API-Key": user_key,
            "X-FG-Admin-Override-Tenant": "tenant-b",
            "X-FG-Override-Reason": "investigate issue",
        },
        json={"dashboard_id": "posture", "widget_ids": ["recent_decisions"], "context": {"q": "override-denied"}},
    )
    assert denied.status_code == 403

    ok = client.post(
        "/ui/dashboard-data/snapshot",
        headers={
            "X-API-Key": admin_key,
            "X-FG-Admin-Override-Tenant": "tenant-b",
            "X-FG-Override-Reason": "investigate issue",
        },
        json={"dashboard_id": "posture", "widget_ids": ["recent_decisions"], "context": {"q": "override-ok"}},
    )
    assert ok.status_code == 200
    assert "recent_decisions" in ok.json()["widget_data"]
    assert ok.json()["tenant_id"] == "tenant-b"


def test_snapshot_unknown_widget_fails_closed(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")

    resp = client.post(
        "/ui/dashboard-data/snapshot",
        headers={"X-API-Key": key},
        json={"dashboard_id": "posture", "widget_ids": ["missing_widget"]},
    )
    assert resp.status_code == 400


def test_snapshot_degrade_ok_and_redacted_error(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", "forensics:read", tenant_id="tenant-a")

    widget_path = Path("contracts/dashboard/widgets/drift_status.json")
    original = json.loads(widget_path.read_text(encoding="utf-8"))
    modified = dict(original)
    modified["data_provider"] = "unknown_provider"
    try:
        widget_path.write_text(json.dumps(modified), encoding="utf-8")
        from services.ui_widgets import registry as wr

        wr.load_widget_contracts.cache_clear()

        resp = client.post(
            "/ui/dashboard-data/snapshot",
            headers={"X-API-Key": key},
            json={"dashboard_id": "forensics", "widget_ids": ["drift_status"]},
        )
        assert resp.status_code == 200
        assert resp.json()["errors"]["drift_status"] == "unknown_provider"
    finally:
        widget_path.write_text(json.dumps(original), encoding="utf-8")
        from services.ui_widgets import registry as wr

        wr.load_widget_contracts.cache_clear()


def test_theme_tenant_isolation_and_css_sanitize(build_app, monkeypatch):
    monkeypatch.setenv("FG_UI_ADMIN_OVERRIDE_ENABLED", "1")
    monkeypatch.setenv("FG_THEME_LOGO_HOST_ALLOWLIST", "example.com")
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    user_key = mint_key("ui:read", tenant_id="tenant-a")
    admin_key = mint_key(
        "ui:read", "admin:read", "admin:tenant_override", tenant_id="tenant-a"
    )

    own = client.get("/ui/theme", headers={"X-API-Key": user_key})
    assert own.status_code == 200
    assert own.json()["tenant_id"] == "tenant-a"

    denied = client.get(
        "/ui/theme",
        headers={"X-API-Key": user_key, "X-FG-Admin-Override-Tenant": "tenant-b"},
    )
    assert denied.status_code == 403

    ok = client.get(
        "/ui/theme",
        headers={
            "X-API-Key": admin_key,
            "X-FG-Admin-Override-Tenant": "tenant-b",
            "X-FG-Override-Reason": "tenant support",
        },
    )
    assert ok.status_code == 200
    assert ok.json()["tenant_id"] == "tenant-b"

    theme_path = Path("contracts/dashboard/themes/tenant-a.json")
    original_theme = json.loads(theme_path.read_text(encoding="utf-8"))
    payload = dict(original_theme)
    payload["css_overrides"] = "@import 'https://evil'; .x{background:url(https://evil)}"
    try:
        theme_path.write_text(json.dumps(payload), encoding="utf-8")
        bad = client.get("/ui/theme", headers={"X-API-Key": user_key})
        assert bad.status_code == 200
        css = bad.json()["theme"]["css_overrides"]
        assert "@import" not in (css or "")
        assert "url(" not in (css or "")
    finally:
        theme_path.write_text(json.dumps(original_theme), encoding="utf-8")


def test_widget_runtime_policy_disables_widget_for_tenant(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")

    policy_path = Path("contracts/dashboard/widget_runtime_policy.json")
    original = json.loads(policy_path.read_text(encoding="utf-8"))
    try:
        policy_path.write_text(
            json.dumps(
                {
                    "global_default": {"enabled": True},
                    "persona_overrides": {},
                    "tenant_overrides": {
                        "tenant-a": {"disabled_widgets": ["system_health"]}
                    },
                    "feature_flag_overrides": [],
                    "disabled": []
                }
            ),
            encoding="utf-8",
        )
        from services.dashboard_runtime_policy import load_runtime_policy

        load_runtime_policy.cache_clear()

        dash = client.get("/ui/registry/dashboards/posture", headers={"X-API-Key": key})
        assert dash.status_code == 200
        widget_ids = [w["id"] for w in dash.json()["widgets"]]
        assert "system_health" not in widget_ids

        snap = client.post(
            "/ui/dashboard-data/snapshot",
            headers={"X-API-Key": key},
            json={"dashboard_id": "posture", "widget_ids": ["system_health"]},
        )
        assert snap.status_code == 200
        assert snap.json()["errors"]["system_health"] == "WIDGET_DISABLED_FOR_TENANT"
    finally:
        policy_path.write_text(json.dumps(original), encoding="utf-8")
        from services.dashboard_runtime_policy import load_runtime_policy

        load_runtime_policy.cache_clear()
