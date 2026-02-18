from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from api.ui_theme import sanitize_css
from services.dashboard_contracts import ContractLoadError, load_json_contract


@pytest.mark.parametrize(
    "payload",
    [
        "@import url('https://evil')",
        "body{background:url(https://evil/a.png)}",
        "x{width:expression(alert(1))}",
        "</style><script>alert(1)</script>",
        "<div>bad</div>",
    ],
)
def test_css_sanitizer_strips_banned_tokens(payload: str):
    cleaned = sanitize_css(payload) or ""
    for tok in ("@import", "url(", "expression(", "</style>", "<", ">"):
        assert tok.lower() not in cleaned.lower()


def test_theme_logo_url_blocks_private_ip(build_app, monkeypatch):
    monkeypatch.setenv("FG_THEME_LOGO_HOST_ALLOWLIST", "")
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")

    path = Path("contracts/dashboard/themes/tenant-a.json")
    orig = json.loads(path.read_text(encoding="utf-8"))
    modified = dict(orig)
    modified["logo_url"] = "https://127.0.0.1/logo.png"
    try:
        path.write_text(json.dumps(modified), encoding="utf-8")
        resp = client.get("/ui/theme", headers={"X-API-Key": key})
        assert resp.status_code == 400
    finally:
        path.write_text(json.dumps(orig), encoding="utf-8")


def test_theme_logo_url_blocks_userinfo(build_app, monkeypatch):
    monkeypatch.setenv("FG_THEME_LOGO_HOST_ALLOWLIST", "example.com")
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")

    path = Path("contracts/dashboard/themes/tenant-a.json")
    orig = json.loads(path.read_text(encoding="utf-8"))
    modified = dict(orig)
    modified["logo_url"] = "https://user:pass@example.com/logo.png"
    try:
        path.write_text(json.dumps(modified), encoding="utf-8")
        resp = client.get("/ui/theme", headers={"X-API-Key": key})
        assert resp.status_code == 400
    finally:
        path.write_text(json.dumps(orig), encoding="utf-8")


def test_theme_logo_url_blocks_http(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")

    path = Path("contracts/dashboard/themes/tenant-a.json")
    orig = json.loads(path.read_text(encoding="utf-8"))
    modified = dict(orig)
    modified["logo_url"] = "http://example.com/logo.png"
    try:
        path.write_text(json.dumps(modified), encoding="utf-8")
        resp = client.get("/ui/theme", headers={"X-API-Key": key})
        assert resp.status_code == 400
    finally:
        path.write_text(json.dumps(orig), encoding="utf-8")


def test_theme_logo_url_blocks_redirect_to_private(build_app, monkeypatch):
    monkeypatch.setenv("FG_THEME_VALIDATE_REDIRECTS", "1")
    monkeypatch.setenv("FG_THEME_LOGO_HOST_ALLOWLIST", "example.com")

    class _Resp:
        is_redirect = True
        is_permanent_redirect = False
        headers = {"location": "https://127.0.0.1/logo.png"}

    monkeypatch.setattr("api.ui_theme.requests.get", lambda *a, **k: _Resp())
    monkeypatch.setattr(
        "api.ui_theme.socket.getaddrinfo",
        lambda host, _: [(None, None, None, None, ("93.184.216.34", 0))],
    )

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")
    resp = client.get("/ui/theme", headers={"X-API-Key": key})
    assert resp.status_code == 400


def test_contract_loader_rejects_symlink(tmp_path):
    root = tmp_path / "contracts"
    root.mkdir()
    target = tmp_path / "real.json"
    target.write_text('{"id":"x"}', encoding="utf-8")
    link = root / "bad.json"
    link.symlink_to(target)

    with pytest.raises(ContractLoadError):
        load_json_contract(link, root=root)


def test_contract_loader_rejects_path_traversal(tmp_path):
    root = tmp_path / "contracts"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(ContractLoadError):
        load_json_contract(root / ".." / "outside.json", root=root)


def test_contract_loader_rejects_oversize(tmp_path):
    root = tmp_path / "contracts"
    root.mkdir()
    big = root / "big.json"
    big.write_text("{" + ('"x":' + '"a"' * 300000) + "}", encoding="utf-8")

    with pytest.raises(ContractLoadError):
        load_json_contract(big, root=root, max_bytes=1024)


def test_widget_timeout_degrades(build_app, monkeypatch):
    mod = __import__("api.ui_dashboard_data", fromlist=["_WIDGET_TIMEOUT_MS", "_CACHE"])
    monkeypatch.setattr(mod, "_WIDGET_TIMEOUT_MS", 50)
    mod._CACHE.clear()
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")

    def slow_provider(**kwargs):
        time.sleep(0.2)
        return {"ok": True}

    monkeypatch.setitem(
        __import__("api.ui_dashboard_data", fromlist=["_PROVIDERS"])._PROVIDERS,
        "recent_decisions",
        slow_provider,
    )

    resp = client.post(
        "/ui/dashboard-data/snapshot",
        headers={"X-API-Key": key},
        json={
            "dashboard_id": "posture",
            "widget_ids": ["recent_decisions"],
            "context": {"q": "timeout-a"},
        },
    )
    assert resp.status_code == 200
    assert resp.json()["errors"]["recent_decisions"] == "timeout"


def test_widget_payload_cap(build_app, monkeypatch):
    mod = __import__(
        "api.ui_dashboard_data", fromlist=["_WIDGET_MAX_PAYLOAD_BYTES", "_CACHE"]
    )
    monkeypatch.setattr(mod, "_WIDGET_MAX_PAYLOAD_BYTES", 128)
    mod._CACHE.clear()
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")

    def huge_provider(**kwargs):
        return {"blob": "x" * 5000}

    monkeypatch.setitem(
        __import__("api.ui_dashboard_data", fromlist=["_PROVIDERS"])._PROVIDERS,
        "recent_decisions",
        huge_provider,
    )

    resp = client.post(
        "/ui/dashboard-data/snapshot",
        headers={"X-API-Key": key},
        json={
            "dashboard_id": "posture",
            "widget_ids": ["recent_decisions"],
            "context": {"q": "payload-a"},
        },
    )
    assert resp.status_code == 200
    assert resp.json()["errors"]["recent_decisions"] == "payload_too_large"


def test_degrade_redacts_error(build_app, monkeypatch):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")

    def bad_provider(**kwargs):
        raise RuntimeError("psycopg OperationalError: secret")

    monkeypatch.setitem(
        __import__("api.ui_dashboard_data", fromlist=["_PROVIDERS"])._PROVIDERS,
        "recent_decisions",
        bad_provider,
    )

    resp = client.post(
        "/ui/dashboard-data/snapshot",
        headers={"X-API-Key": key},
        json={
            "dashboard_id": "posture",
            "widget_ids": ["recent_decisions"],
            "context": {"q": "err-a"},
        },
    )
    assert resp.status_code == 200
    assert resp.json()["errors"]["recent_decisions"] == "provider_failed"


def test_theme_redirect_rejects_scheme_relative(build_app, monkeypatch):
    monkeypatch.setenv("FG_THEME_VALIDATE_REDIRECTS", "1")
    monkeypatch.setenv("FG_THEME_LOGO_HOST_ALLOWLIST", "example.com")

    class _Resp:
        is_redirect = True
        is_permanent_redirect = False
        headers = {"location": "//127.0.0.1/logo.png"}

    monkeypatch.setattr("api.ui_theme.requests.get", lambda *a, **k: _Resp())
    monkeypatch.setattr(
        "api.ui_theme.socket.getaddrinfo",
        lambda host, _: [(None, None, None, None, ("93.184.216.34", 0))],
    )
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")
    resp = client.get("/ui/theme", headers={"X-API-Key": key})
    assert resp.status_code == 400


def test_theme_redirect_rejects_scheme_downgrade(build_app, monkeypatch):
    monkeypatch.setenv("FG_THEME_VALIDATE_REDIRECTS", "1")
    monkeypatch.setenv("FG_THEME_LOGO_HOST_ALLOWLIST", "example.com")

    class _Resp:
        is_redirect = True
        is_permanent_redirect = False
        headers = {"location": "http://example.com/logo.png"}

    monkeypatch.setattr("api.ui_theme.requests.get", lambda *a, **k: _Resp())
    monkeypatch.setattr(
        "api.ui_theme.socket.getaddrinfo",
        lambda host, _: [(None, None, None, None, ("93.184.216.34", 0))],
    )
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")
    resp = client.get("/ui/theme", headers={"X-API-Key": key})
    assert resp.status_code == 400


def test_theme_redirect_missing_location_fails_closed(build_app, monkeypatch):
    monkeypatch.setenv("FG_THEME_VALIDATE_REDIRECTS", "1")
    monkeypatch.setenv("FG_THEME_LOGO_HOST_ALLOWLIST", "example.com")

    class _Resp:
        is_redirect = True
        is_permanent_redirect = False
        headers = {}

    monkeypatch.setattr("api.ui_theme.requests.get", lambda *a, **k: _Resp())
    monkeypatch.setattr(
        "api.ui_theme.socket.getaddrinfo",
        lambda host, _: [(None, None, None, None, ("93.184.216.34", 0))],
    )
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")
    resp = client.get("/ui/theme", headers={"X-API-Key": key})
    assert resp.status_code == 400


def test_contract_loader_rejects_hardlink(tmp_path):
    root = tmp_path / "contracts"
    root.mkdir()
    real = root / "real.json"
    real.write_text('{"id":"x"}', encoding="utf-8")
    hl = root / "hard.json"
    try:
        hl.hardlink_to(real)
    except (AttributeError, OSError):
        pytest.skip("hardlink unsupported on this filesystem")
    with pytest.raises(ContractLoadError):
        load_json_contract(hl, root=root)


def test_cache_isolation_different_tenant_etag(build_app):
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key_a = mint_key("ui:read", tenant_id="tenant-a")
    key_b = mint_key("ui:read", tenant_id="tenant-b")

    body = {
        "dashboard_id": "posture",
        "widget_ids": ["system_health"],
        "context": {"q": "cache-1"},
    }
    ra = client.post(
        "/ui/dashboard-data/snapshot", headers={"X-API-Key": key_a}, json=body
    )
    rb = client.post(
        "/ui/dashboard-data/snapshot", headers={"X-API-Key": key_b}, json=body
    )
    assert ra.status_code == 200
    assert rb.status_code == 200
    assert ra.headers.get("etag") != rb.headers.get("etag")


def test_cache_isolation_override_flag(build_app, monkeypatch):
    monkeypatch.setenv("FG_UI_ADMIN_OVERRIDE_ENABLED", "1")
    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", "admin:tenant_override", tenant_id="tenant-a")

    body = {
        "dashboard_id": "posture",
        "widget_ids": ["system_health"],
        "context": {"q": "cache-ovr"},
    }
    base = client.post(
        "/ui/dashboard-data/snapshot", headers={"X-API-Key": key}, json=body
    )
    override = client.post(
        "/ui/dashboard-data/snapshot",
        headers={
            "X-API-Key": key,
            "X-FG-Admin-Override-Tenant": "tenant-b",
            "X-FG-Override-Reason": "support case",
        },
        json=body,
    )
    assert base.status_code == 200
    assert override.status_code == 200
    assert base.headers.get("etag") != override.headers.get("etag")


def test_runtime_policy_precedence_reason_codes(build_app):
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
                    "persona_overrides": {
                        "analyst": {"disabled_widgets": ["recent_decisions"]}
                    },
                    "tenant_overrides": {
                        "tenant-a": {"disabled_widgets": ["system_health"]}
                    },
                    "feature_flag_overrides": [
                        {
                            "env_flag": "FG_FLAG_DISABLE_DRIFT",
                            "widget_id": "drift_status",
                            "enabled": False,
                        }
                    ],
                    "disabled": [],
                }
            ),
            encoding="utf-8",
        )
        from services.dashboard_runtime_policy import load_runtime_policy

        load_runtime_policy.cache_clear()

        s1 = client.post(
            "/ui/dashboard-data/snapshot",
            headers={"X-API-Key": key},
            json={"dashboard_id": "posture", "widget_ids": ["system_health"]},
        )
        assert s1.json()["errors"]["system_health"] == "WIDGET_DISABLED_FOR_TENANT"

        s2 = client.post(
            "/ui/dashboard-data/snapshot",
            headers={"X-API-Key": key},
            json={"dashboard_id": "posture", "widget_ids": ["recent_decisions"]},
        )
        assert (
            s2.json()["errors"]["recent_decisions"] == "WIDGET_NOT_ALLOWED_FOR_PERSONA"
        )

        os.environ["FG_FLAG_DISABLE_DRIFT"] = "1"
        s3 = client.post(
            "/ui/dashboard-data/snapshot",
            headers={"X-API-Key": key},
            json={"dashboard_id": "posture", "widget_ids": ["drift_status"]},
        )
        assert s3.json()["errors"]["drift_status"] == "WIDGET_DISABLED_BY_FEATURE_FLAG"
    finally:
        policy_path.write_text(json.dumps(original), encoding="utf-8")
        from services.dashboard_runtime_policy import load_runtime_policy

        load_runtime_policy.cache_clear()
        os.environ.pop("FG_FLAG_DISABLE_DRIFT", None)


def test_degraded_response_not_cached(build_app, monkeypatch):
    mod = __import__("api.ui_dashboard_data", fromlist=["_CACHE"])
    mod._CACHE.clear()

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")

    calls = {"n": 0}

    def flaky_provider(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("temporary")
        return {"ok": True}

    monkeypatch.setitem(
        __import__("api.ui_dashboard_data", fromlist=["_PROVIDERS"])._PROVIDERS,
        "recent_decisions",
        flaky_provider,
    )

    body = {
        "dashboard_id": "posture",
        "widget_ids": ["recent_decisions"],
        "context": {"q": "nocache-degraded"},
    }
    first = client.post(
        "/ui/dashboard-data/snapshot", headers={"X-API-Key": key}, json=body
    )
    assert first.status_code == 200
    assert first.json()["errors"]["recent_decisions"] == "provider_failed"

    second = client.post(
        "/ui/dashboard-data/snapshot", headers={"X-API-Key": key}, json=body
    )
    assert second.status_code == 200
    assert "recent_decisions" in second.json()["widget_data"]


def test_widget_logging_redaction_safe(build_app, monkeypatch):
    records = []

    class _Logger:
        def info(self, event, extra=None):
            records.append({"event": event, "extra": extra or {}})

    monkeypatch.setattr("api.ui_dashboard_data.log", _Logger())
    mod = __import__("api.ui_dashboard_data", fromlist=["_CACHE"])
    mod._CACHE.clear()

    app = build_app(auth_enabled=True)
    client = TestClient(app)
    key = mint_key("ui:read", tenant_id="tenant-a")

    resp = client.post(
        "/ui/dashboard-data/snapshot",
        headers={"X-API-Key": key},
        json={
            "dashboard_id": "posture",
            "widget_ids": ["system_health"],
            "context": {"q": "sensitive-filter"},
        },
    )
    assert resp.status_code == 200
    assert records
    seen = records[0]["extra"]
    assert "widget_id" in seen
    assert "tenant_id" in seen
    assert "persona" in seen
    assert "correlation_id" in seen
    assert "outcome" in seen
    assert "filter_hash" in seen
    assert "sensitive-filter" not in str(seen)
