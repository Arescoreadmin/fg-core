from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from api.auth_scopes import mint_key
import importlib
from api.db import get_engine
from api.db_models import TenantAIConfig
from api.ai.pii import redact_pii
from api.ai.quota import enforce_and_consume_quota
from api.db_models import TenantAIUsage

ai_router_module = importlib.import_module("api.ai.router")


class _StubLLM:
    def __init__(self, output: str):
        self.output = output

    def generate(self, **kwargs) -> str:
        _ = kwargs
        return self.output


def _enable_ai_for_tenant(tenant_id: str) -> None:
    with Session(get_engine()) as db:
        row = db.get(TenantAIConfig, tenant_id)
        if row is None:
            row = TenantAIConfig(tenant_id=tenant_id, ai_enabled=True)
            db.add(row)
        else:
            row.ai_enabled = True
        db.commit()


def test_ai_requires_scope_and_tenant(build_app, monkeypatch):
    app = build_app()
    client = TestClient(app)
    tenant_id = "tenant-ai-authz"
    _enable_ai_for_tenant(tenant_id)

    monkeypatch.setattr(
        ai_router_module,
        "get_llm_client",
        lambda: _StubLLM(
            '{"answer":"ok","citations":[],"confidence":0.5,"warnings":[]}'
        ),
    )

    missing_scope_key = mint_key("stats:read", tenant_id=tenant_id)
    denied = client.post(
        "/ai/query",
        headers={"X-API-Key": missing_scope_key},
        json={"question": "hello"},
    )
    assert denied.status_code == 403

    unbound_tenant_key = mint_key("ai:query")
    no_tenant = client.post(
        "/ai/query",
        headers={"X-API-Key": unbound_tenant_key},
        json={"question": "hello"},
    )
    assert no_tenant.status_code == 400


def test_ai_disabled_global_kill_switch(build_app, monkeypatch):
    monkeypatch.setenv("FG_AI_DISABLED", "true")
    app = build_app()
    client = TestClient(app)
    key = mint_key("ai:query", tenant_id="tenant-kill")

    resp = client.post(
        "/ai/query",
        headers={"X-API-Key": key},
        json={"question": "health?"},
    )
    assert resp.status_code == 503
    assert resp.json()["detail"]["error_code"] == "AI_DISABLED"


def test_ai_tenant_disabled(build_app):
    app = build_app()
    client = TestClient(app)
    key = mint_key("ai:query", tenant_id="tenant-off")

    resp = client.post(
        "/ai/query",
        headers={"X-API-Key": key},
        json={"question": "hello"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error_code"] == "AI_TENANT_DISABLED"


def test_ai_pii_redaction_input_and_output(build_app, monkeypatch, caplog):
    app = build_app()
    client = TestClient(app)
    tenant_id = "tenant-pii"
    _enable_ai_for_tenant(tenant_id)
    caplog.set_level("INFO", logger="frostgate.security")

    monkeypatch.setattr(
        ai_router_module,
        "get_llm_client",
        lambda: _StubLLM(
            '{"answer":"email me at alice@example.com and Bearer abcdefghijklmnopqrstuv","citations":[],"confidence":0.8,"warnings":[]}'
        ),
    )

    key = mint_key("ai:query", tenant_id=tenant_id)
    resp = client.post(
        "/ai/query",
        headers={"X-API-Key": key},
        json={"question": "my email is bob@example.com and ip 203.0.113.20"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "[REDACTED_EMAIL]" in body["answer"]
    assert any("redacted" in w for w in body["warnings"])

    logs_joined = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "bob@example.com" not in logs_joined
    assert "alice@example.com" not in logs_joined
    audit_records = [
        r
        for r in caplog.records
        if getattr(r, "reason", "") in {"ai_query:ok", "ai_query:pii_redacted"}
    ]
    assert audit_records
    assert getattr(audit_records[-1], "details", {}).get("breaker_state") in {
        "closed",
        "open",
        "half_open",
    }


def test_ai_schema_fail_closed(build_app, monkeypatch, caplog):
    app = build_app()
    client = TestClient(app)
    tenant_id = "tenant-schema"
    _enable_ai_for_tenant(tenant_id)
    caplog.set_level("INFO", logger="frostgate.security")

    monkeypatch.setattr(
        ai_router_module, "get_llm_client", lambda: _StubLLM("not-json")
    )

    key = mint_key("ai:query", tenant_id=tenant_id)
    resp = client.post(
        "/ai/query",
        headers={"X-API-Key": key},
        json={"question": "hello"},
    )
    assert resp.status_code == 502
    assert resp.json()["detail"]["error_code"] == "AI_SCHEMA_INVALID"

    assert any(
        getattr(r, "reason", "") == "ai_query:schema_failed" for r in caplog.records
    )


def test_ai_oversized_query_fail_closed(build_app):
    app = build_app()
    client = TestClient(app)
    tenant_id = "tenant-big"
    _enable_ai_for_tenant(tenant_id)
    key = mint_key("ai:query", tenant_id=tenant_id)

    big = "A" * (20 * 1024)
    resp = client.post(
        "/ai/query",
        headers={"X-API-Key": key},
        json={"question": big},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["error_code"] == "AI_BAD_REQUEST"


def test_pii_false_positive_guardrails():
    text = "Order ID 12345 status code 200 for lane 9 and roadmap v2"
    redacted = redact_pii(text)
    assert redacted.redacted is False
    assert redacted.text == text


def test_ai_evil_model_output_redacted(build_app, monkeypatch):
    app = build_app()
    client = TestClient(app)
    tenant_id = "tenant-evil"
    _enable_ai_for_tenant(tenant_id)
    key = mint_key("ai:query", tenant_id=tenant_id)

    monkeypatch.setattr(
        ai_router_module,
        "get_llm_client",
        lambda: _StubLLM(
            '{"answer":"Authorization: Bearer thisisnotgoodtokenvalue and traceback (most recent call last)","citations":[],"confidence":0.8,"warnings":[]}'
        ),
    )

    resp = client.post(
        "/ai/query",
        headers={"X-API-Key": key},
        json={"question": "hello"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "REDACTED" in body["answer"]
    assert any("redacted" in w for w in body["warnings"])


def test_ai_rate_limit(build_app, monkeypatch):
    monkeypatch.setenv("FG_AI_RPM", "1")
    app = build_app()
    client = TestClient(app)
    tenant_id = "tenant-rpm"
    _enable_ai_for_tenant(tenant_id)
    key = mint_key("ai:query", tenant_id=tenant_id)
    monkeypatch.setattr(
        ai_router_module,
        "get_llm_client",
        lambda: _StubLLM(
            '{"answer":"ok","citations":[],"confidence":0.5,"warnings":[]}'
        ),
    )

    ok = client.post("/ai/query", headers={"X-API-Key": key}, json={"question": "a"})
    assert ok.status_code == 200
    limited = client.post(
        "/ai/query", headers={"X-API-Key": key}, json={"question": "b"}
    )
    assert limited.status_code == 429
    assert limited.json()["detail"]["error_code"] == "AI_RATE_LIMITED"


def test_ai_rate_limit_emits_audit_counters(build_app, monkeypatch, caplog):
    caplog.set_level("INFO", logger="frostgate.security")
    monkeypatch.setenv("FG_AI_RPM", "1")
    app = build_app()
    client = TestClient(app)
    tenant_id = "tenant-rpm-audit"
    _enable_ai_for_tenant(tenant_id)
    key = mint_key("ai:query", tenant_id=tenant_id)
    monkeypatch.setattr(
        ai_router_module,
        "get_llm_client",
        lambda: _StubLLM(
            '{"answer":"ok","citations":[],"confidence":0.5,"warnings":[]}'
        ),
    )

    client.post("/ai/query", headers={"X-API-Key": key}, json={"question": "a"})
    limited = client.post(
        "/ai/query", headers={"X-API-Key": key}, json={"question": "b"}
    )
    assert limited.status_code == 429
    records = [
        r for r in caplog.records if getattr(r, "reason", "") == "ai_query:rate_limited"
    ]
    assert records
    counters = getattr(records[-1], "details", {}).get("counters", {})
    assert counters.get("rpm_limit") == 1


def test_ai_budget_exceeded(build_app, monkeypatch):
    monkeypatch.setenv("FG_AI_DAILY_TOKEN_BUDGET", "10")
    app = build_app()
    client = TestClient(app)
    tenant_id = "tenant-budget"
    _enable_ai_for_tenant(tenant_id)
    key = mint_key("ai:query", tenant_id=tenant_id)
    monkeypatch.setattr(
        ai_router_module,
        "get_llm_client",
        lambda: _StubLLM(
            '{"answer":"ok","citations":[],"confidence":0.5,"warnings":[]}'
        ),
    )

    resp = client.post(
        "/ai/query", headers={"X-API-Key": key}, json={"question": "tiny"}
    )
    assert resp.status_code == 429
    assert resp.json()["detail"]["error_code"] == "AI_BUDGET_EXCEEDED"


def test_ai_budget_exceeded_emits_audit_counters(build_app, monkeypatch, caplog):
    caplog.set_level("INFO", logger="frostgate.security")
    monkeypatch.setenv("FG_AI_DAILY_TOKEN_BUDGET", "10")
    app = build_app()
    client = TestClient(app)
    tenant_id = "tenant-budget-audit"
    _enable_ai_for_tenant(tenant_id)
    key = mint_key("ai:query", tenant_id=tenant_id)
    monkeypatch.setattr(
        ai_router_module,
        "get_llm_client",
        lambda: _StubLLM(
            '{"answer":"ok","citations":[],"confidence":0.5,"warnings":[]}'
        ),
    )
    resp = client.post(
        "/ai/query", headers={"X-API-Key": key}, json={"question": "tiny"}
    )
    assert resp.status_code == 429
    records = [
        r
        for r in caplog.records
        if getattr(r, "reason", "") == "ai_query:budget_exceeded"
    ]
    assert records
    counters = getattr(records[-1], "details", {}).get("counters", {})
    assert counters.get("daily_budget") == 100


def test_ai_model_allowlist_enforced(build_app, monkeypatch):
    monkeypatch.setenv("FG_AI_MODEL", "not-allowed")
    monkeypatch.setenv("FG_AI_MODEL_ALLOWLIST", "gpt-4o-mini")
    app = build_app()
    client = TestClient(app)
    tenant_id = "tenant-model"
    _enable_ai_for_tenant(tenant_id)
    key = mint_key("ai:query", tenant_id=tenant_id)
    resp = client.post(
        "/ai/query", headers={"X-API-Key": key}, json={"question": "hello"}
    )
    assert resp.status_code == 503
    assert resp.json()["detail"]["error_code"] == "AI_MODEL_NOT_ALLOWED"


def test_quota_reset_uses_utc_midnight(build_app):
    app = build_app()
    _ = app
    tenant_id = "tenant-utc-reset"
    _enable_ai_for_tenant(tenant_id)
    with Session(get_engine()) as db:
        enforce_and_consume_quota(
            db,
            tenant_id=tenant_id,
            estimated_tokens=5,
            now_utc=datetime(2026, 1, 1, 23, 59, tzinfo=timezone.utc),
        )
        enforce_and_consume_quota(
            db,
            tenant_id=tenant_id,
            estimated_tokens=5,
            now_utc=datetime(2026, 1, 2, 0, 0, tzinfo=timezone.utc),
        )
        day1 = db.get(TenantAIUsage, (tenant_id, "2026-01-01"))
        day2 = db.get(TenantAIUsage, (tenant_id, "2026-01-02"))
        assert day1 is not None and day2 is not None
        assert day1.daily_tokens == 5
        assert day2.daily_tokens == 5
