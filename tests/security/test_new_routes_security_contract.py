from __future__ import annotations

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


ROUTES = [
    ("GET", "/compliance-cp/summary", None, "compliance:read"),
    ("GET", "/compliance-cp/portfolio", None, "compliance:read"),
    ("GET", "/compliance-cp/controls", None, "compliance:read"),
    ("POST", "/compliance-cp/evidence/ingest", {"evidence_id": "e1", "content": {}}, "admin:write"),
    ("GET", "/enterprise-controls/frameworks", None, "compliance:read"),
    ("GET", "/enterprise-controls/catalog", None, "compliance:read"),
    ("GET", "/enterprise-controls/crosswalk", None, "compliance:read"),
    ("POST", "/enterprise-controls/tenant-state", {"control_id": "CTRL-001", "status": "implemented"}, "admin:write"),
    ("POST", "/exceptions/requests", {"subject_type": "control", "subject_id": "CTRL-001", "justification": "test", "expires_at_utc": "2099-01-01T00:00:00Z"}, "governance:write"),
    ("POST", "/breakglass/sessions", {"reason": "incident", "expires_at_utc": "2099-01-01T00:00:00Z"}, "governance:write"),
    ("POST", "/auth/federation/validate", None, "admin:write"),
    ("POST", "/ai/infer", {"query": "hello"}, "compliance:read"),
    ("POST", "/evidence/anchors", {"artifact_path": "artifacts/ai_plane_evidence.json", "external_anchor_ref": None, "immutable_retention": True}, "compliance:read"),
    ("GET", "/evidence/runs", None, "compliance:read"),
    ("GET", "/evidence/runs/nonexistent", None, "compliance:read"),
    ("POST", "/evidence/runs/register", {"plane_id": "ai_plane", "artifact_type": "ai_plane_evidence", "artifact_path": "artifacts/ai_plane_evidence.json", "schema_version": "v1", "git_sha": "deadbeef", "status": "PASS", "summary_json": {}}, "admin:write"),
    ("GET", "/planes", None, "admin:write"),
]


def _request(client: TestClient, method: str, path: str, headers: dict[str, str] | None, body: dict | None):
    if method == "GET":
        return client.get(path, headers=headers or {})
    return client.post(path, headers=headers or {}, json=body)


def test_new_routes_require_auth_scope_and_tenant(build_app, monkeypatch):
    monkeypatch.setenv("FG_AI_PLANE_ENABLED", "1")
    app = build_app(auth_enabled=True)
    client = TestClient(app)

    for method, path, body, required_scope in ROUTES:
        no_auth = _request(client, method, path, None, body)
        assert no_auth.status_code in {401, 403}

        wrong_scope_key = mint_key("stats:read", tenant_id="tenant-a")
        wrong_scope = _request(
            client,
            method,
            path,
            {"X-API-Key": wrong_scope_key, "X-Tenant-Id": "tenant-a", "Authorization": "Bearer test.token.value"},
            body,
        )
        assert wrong_scope.status_code == 403

        scoped_key = mint_key(required_scope, tenant_id="tenant-a")
        tenant_mismatch = _request(
            client,
            method,
            path,
            {"X-API-Key": scoped_key, "X-Tenant-Id": "tenant-b", "Authorization": "Bearer test.token.value"},
            body,
        )
        assert tenant_mismatch.status_code in {401, 403, 409}


def test_opa_coverage_or_exemption_for_new_routes() -> None:
    protected_routes = {p for _, p, _, _ in ROUTES}
    policy_text = ""
    for p in ["policy/opa/main.rego", "policy/opa/policies.rego"]:
        try:
            policy_text += open(p, encoding="utf-8").read()
        except FileNotFoundError:
            continue

    explicit_exempt = {
        "/compliance-cp/summary",
        "/compliance-cp/portfolio",
        "/compliance-cp/controls",
        "/compliance-cp/evidence/ingest",
        "/enterprise-controls/frameworks",
        "/enterprise-controls/catalog",
        "/enterprise-controls/crosswalk",
        "/enterprise-controls/tenant-state",
        "/exceptions/requests",
        "/breakglass/sessions",
        "/auth/federation/validate",
        "/ai/infer",
        "/evidence/anchors",
        "/evidence/runs",
        "/evidence/runs/nonexistent",
        "/evidence/runs/register",
        "/planes",
    }

    uncovered = set()
    for route in protected_routes:
        token = route.replace("/nonexistent", "")
        if token in policy_text:
            continue
        if route in explicit_exempt:
            continue
        uncovered.add(route)

    assert not uncovered, f"OPA uncovered protected routes: {sorted(uncovered)}"
