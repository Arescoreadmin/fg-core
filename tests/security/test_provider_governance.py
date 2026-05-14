from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def _auth_headers(raw_key: str) -> dict[str, str]:
    return {"X-API-Key": raw_key}


def _insert_governance_record(
    db_path: str,
    *,
    tenant_id: str,
    provider_id: str,
    operational_state: str = "healthy",
    governance_state: str = "approved",
    trust_classification: str = "unknown",
    routing_eligible: int = 1,
    failover_eligible: int = 0,
    restrictions_json: str = "[]",
    block_reason: str | None = None,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT OR REPLACE INTO provider_governance_records
                (tenant_id, provider_id, operational_state, governance_state,
                 trust_classification, routing_eligible, failover_eligible,
                 restrictions_json, block_reason, policy_version, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                provider_id,
                operational_state,
                governance_state,
                trust_classification,
                routing_eligible,
                failover_eligible,
                restrictions_json,
                block_reason,
                1,
                now,
                now,
            ),
        )
        con.commit()
    finally:
        con.close()


def _insert_baa_record(
    db_path: str,
    *,
    tenant_id: str,
    provider_id: str,
    baa_status: str = "active",
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT OR REPLACE INTO provider_baa_records
                (tenant_id, provider_id, baa_status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (tenant_id, provider_id, baa_status, now, now),
        )
        con.commit()
    finally:
        con.close()


def _insert_eval_run(
    db_path: str,
    *,
    tenant_id: str,
    run_ref: str | None = None,
    corpus_id: str | None = None,
    status: str = "completed",
    query_count: int = 10,
) -> str:
    run_ref = run_ref or str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT OR REPLACE INTO retrieval_evaluation_runs
                (tenant_id, run_ref, corpus_id, status, query_count,
                 relevance_indicators_json, coverage_indicators_json,
                 correctness_indicators_json, evaluation_metadata_json,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                run_ref,
                corpus_id,
                status,
                query_count,
                "{}",
                "{}",
                "{}",
                "{}",
                now,
                now,
            ),
        )
        con.commit()
    finally:
        con.close()
    return run_ref


@pytest.fixture
def tenant_a_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def tenant_b_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def app(build_app, fresh_db: str):
    return build_app(sqlite_path=fresh_db)


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def tenant_a_key(tenant_a_id: str, fresh_db: str) -> str:
    try:
        return mint_key("ui:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        return mint_key("ui:read", ttl_seconds=86400)


# ─── Auth required ────────────────────────────────────────────────────────────


def test_governance_list_requires_auth(client: TestClient) -> None:
    r = client.get("/ui/provider/governance")
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


def test_routing_requires_auth(client: TestClient) -> None:
    r = client.get("/ui/provider/routing")
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


def test_failover_requires_auth(client: TestClient) -> None:
    r = client.get("/ui/provider/failover")
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


def test_evaluation_runs_requires_auth(client: TestClient) -> None:
    r = client.get("/ui/evaluation/runs")
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


def test_evaluation_quality_requires_auth(client: TestClient) -> None:
    r = client.get("/ui/evaluation/quality")
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


# ─── Scope enforcement ────────────────────────────────────────────────────────


def test_governance_wrong_scope_rejected(
    client: TestClient,
    tenant_a_id: str,
) -> None:
    try:
        wrong_key = mint_key("forensics:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        wrong_key = mint_key("forensics:read", ttl_seconds=86400)

    r = client.get("/ui/provider/governance", headers=_auth_headers(wrong_key))
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


def test_evaluation_wrong_scope_rejected(
    client: TestClient,
    tenant_a_id: str,
) -> None:
    try:
        wrong_key = mint_key("forensics:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        wrong_key = mint_key("forensics:read", ttl_seconds=86400)

    r = client.get("/ui/evaluation/runs", headers=_auth_headers(wrong_key))
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


# ─── Tenant isolation: governance ─────────────────────────────────────────────


def test_governance_list_tenant_isolation(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_b_id: str,
    tenant_a_key: str,
) -> None:
    """Tenant A cannot see tenant B governance records."""
    _insert_governance_record(fresh_db, tenant_id=tenant_b_id, provider_id="openai")
    _insert_governance_record(fresh_db, tenant_id=tenant_a_id, provider_id="anthropic")

    r = client.get("/ui/provider/governance", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    providers = [p["provider_id"] for p in body["providers"]]
    assert "anthropic" in providers
    assert "openai" not in providers, f"Tenant A saw tenant B provider: {body}"


def test_governance_detail_tenant_isolation(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_b_id: str,
    tenant_a_key: str,
) -> None:
    """Tenant A cannot see tenant B provider detail."""
    _insert_governance_record(fresh_db, tenant_id=tenant_b_id, provider_id="openai")

    r = client.get(
        "/ui/provider/governance/openai",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["governance"] is None, f"Tenant A saw tenant B governance: {body}"
    assert body["baa"] is None


def test_routing_tenant_isolation(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_b_id: str,
    tenant_a_key: str,
) -> None:
    """Routing policy only returns tenant A's providers."""
    _insert_governance_record(fresh_db, tenant_id=tenant_b_id, provider_id="openai")
    _insert_governance_record(fresh_db, tenant_id=tenant_a_id, provider_id="anthropic")

    r = client.get("/ui/provider/routing", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    all_ids = (
        [p["provider_id"] for p in body["allowed_providers"]]
        + [p["provider_id"] for p in body["blocked_providers"]]
        + [p["provider_id"] for p in body["restricted_providers"]]
        + [p["provider_id"] for p in body["failover_providers"]]
    )
    assert "openai" not in all_ids, f"Tenant A saw tenant B provider in routing: {body}"


def test_failover_tenant_isolation(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_b_id: str,
    tenant_a_key: str,
) -> None:
    """Failover state only returns tenant A's degraded providers."""
    _insert_governance_record(
        fresh_db,
        tenant_id=tenant_b_id,
        provider_id="openai",
        operational_state="degraded",
    )
    _insert_governance_record(
        fresh_db,
        tenant_id=tenant_a_id,
        provider_id="anthropic",
        operational_state="healthy",
    )

    r = client.get("/ui/provider/failover", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    degraded_ids = [p["provider_id"] for p in body["degraded_providers"]]
    assert "openai" not in degraded_ids, (
        f"Tenant A saw tenant B degraded provider: {body}"
    )


# ─── Tenant isolation: evaluation ─────────────────────────────────────────────


def test_evaluation_runs_tenant_isolation(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_b_id: str,
    tenant_a_key: str,
) -> None:
    """Tenant A cannot see tenant B evaluation runs."""
    b_run = _insert_eval_run(fresh_db, tenant_id=tenant_b_id)
    a_run = _insert_eval_run(fresh_db, tenant_id=tenant_a_id)

    r = client.get("/ui/evaluation/runs", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    run_refs = [r["run_ref"] for r in body["runs"]]
    assert a_run in run_refs
    assert b_run not in run_refs, f"Tenant A saw tenant B eval run: {body}"


def test_evaluation_run_detail_tenant_isolation(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_b_id: str,
    tenant_a_key: str,
) -> None:
    """GET /ui/evaluation/runs/{run_ref} returns 404 for another tenant's run."""
    b_run = _insert_eval_run(fresh_db, tenant_id=tenant_b_id)

    r = client.get(
        f"/ui/evaluation/runs/{b_run}",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 404, f"Expected 404, got {r.status_code}: {r.text}"


def test_evaluation_quality_tenant_isolation(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_b_id: str,
    tenant_a_key: str,
) -> None:
    """Quality summary only counts tenant A's completed runs."""
    for _ in range(3):
        _insert_eval_run(fresh_db, tenant_id=tenant_b_id, status="completed")
    for _ in range(2):
        _insert_eval_run(fresh_db, tenant_id=tenant_a_id, status="completed")

    r = client.get("/ui/evaluation/quality", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["completed_run_count"] == 2, (
        f"Quality summary counted tenant B runs: {body}"
    )


# ─── Export-safe serialization ────────────────────────────────────────────────


def test_governance_list_no_secrets_in_response(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Governance list response must not contain secret fields."""
    _insert_governance_record(fresh_db, tenant_id=tenant_a_id, provider_id="openai")

    r = client.get("/ui/provider/governance", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    raw = r.text
    for forbidden in ("api_key", "secret", "credential", "token", "password"):
        assert forbidden not in raw.lower(), (
            f"Governance response contains forbidden field '{forbidden}': {raw[:200]}"
        )


def test_routing_response_no_raw_config(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Routing policy must not expose raw provider configuration or credentials."""
    _insert_governance_record(fresh_db, tenant_id=tenant_a_id, provider_id="openai")

    r = client.get("/ui/provider/routing", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    raw = r.text
    for forbidden in ("api_key", "endpoint", "credential", "token"):
        assert forbidden not in raw.lower(), (
            f"Routing response contains forbidden field '{forbidden}': {raw[:200]}"
        )


# ─── Deterministic state rendering ───────────────────────────────────────────


def test_blocked_provider_renders_deterministically(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Blocked provider is deterministically surfaced in routing and governance."""
    _insert_governance_record(
        fresh_db,
        tenant_id=tenant_a_id,
        provider_id="openai",
        governance_state="blocked",
        routing_eligible=0,
        block_reason="policy_violation",
    )

    r_gov = client.get("/ui/provider/governance", headers=_auth_headers(tenant_a_key))
    assert r_gov.status_code == 200, r_gov.text
    provider = r_gov.json()["providers"][0]
    assert provider["governance_state"] == "blocked"
    assert provider["routing_eligible"] is False
    assert provider["block_reason"] == "policy_violation"

    r_routing = client.get("/ui/provider/routing", headers=_auth_headers(tenant_a_key))
    assert r_routing.status_code == 200, r_routing.text
    routing_body = r_routing.json()
    blocked_ids = [p["provider_id"] for p in routing_body["blocked_providers"]]
    assert "openai" in blocked_ids, (
        f"Blocked provider not in blocked list: {routing_body}"
    )


def test_degraded_provider_renders_in_failover(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Degraded provider appears in failover degraded list."""
    _insert_governance_record(
        fresh_db,
        tenant_id=tenant_a_id,
        provider_id="openai",
        operational_state="degraded",
    )

    r = client.get("/ui/provider/failover", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    degraded_ids = [p["provider_id"] for p in body["degraded_providers"]]
    assert "openai" in degraded_ids, f"Degraded provider not in degraded list: {body}"


def test_unknown_provider_safe_render(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Provider detail returns governance_available=False for unknown provider."""
    r = client.get(
        "/ui/provider/governance/nonexistent-provider",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["governance_available"] is False
    assert body["baa_available"] is False
    assert body["governance"] is None
    assert body["baa"] is None


# ─── Pagination ───────────────────────────────────────────────────────────────


def test_governance_pagination(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Governance list pagination returns correct counts."""
    for i in range(5):
        _insert_governance_record(
            fresh_db,
            tenant_id=tenant_a_id,
            provider_id=f"provider-{i}",
        )

    r = client.get(
        "/ui/provider/governance?limit=2&offset=0",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 5
    assert len(body["providers"]) == 2


# ─── Evaluation run validation ────────────────────────────────────────────────


def test_eval_run_ref_too_long(
    client: TestClient,
    tenant_a_key: str,
) -> None:
    """run_ref exceeding 128 chars returns 422."""
    too_long = "x" * 129
    r = client.get(
        f"/ui/evaluation/runs/{too_long}",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"


def test_provider_id_too_long(
    client: TestClient,
    tenant_a_key: str,
) -> None:
    """provider_id exceeding 64 chars returns 422."""
    too_long = "x" * 65
    r = client.get(
        f"/ui/provider/governance/{too_long}",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 422, f"Expected 422, got {r.status_code}: {r.text}"


# ─── BAA status rendering ─────────────────────────────────────────────────────


def test_baa_status_in_governance_detail(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """BAA status is included in governance detail when record exists."""
    _insert_governance_record(fresh_db, tenant_id=tenant_a_id, provider_id="openai")
    _insert_baa_record(
        fresh_db, tenant_id=tenant_a_id, provider_id="openai", baa_status="active"
    )

    r = client.get(
        "/ui/provider/governance/openai",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["baa_available"] is True
    assert body["baa"]["baa_status"] == "active"


def test_missing_baa_surfaced_correctly(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Provider without BAA record shows baa_available=False."""
    _insert_governance_record(fresh_db, tenant_id=tenant_a_id, provider_id="openai")

    r = client.get(
        "/ui/provider/governance/openai",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["baa_available"] is False
    assert body["baa"] is None


# ─── Evaluation run status/filter ─────────────────────────────────────────────


def test_evaluation_runs_empty_state(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Empty state returns zero runs without error."""
    r = client.get("/ui/evaluation/runs", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 0
    assert body["runs"] == []


def test_evaluation_quality_no_fabricated_algorithms(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Quality summary explicitly marks evaluation algorithms as unavailable."""
    r = client.get("/ui/evaluation/quality", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["evaluation_algorithms_available"] is False


def test_failover_no_fabricated_telemetry(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Failover state explicitly marks telemetry as unavailable."""
    r = client.get("/ui/provider/failover", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["telemetry_available"] is False


# ─── BAA-aware routing classification ────────────────────────────────────────


def test_expired_baa_provider_not_in_allowed_routing(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Provider with an expired BAA record must appear in restricted, not allowed."""
    _insert_governance_record(
        fresh_db,
        tenant_id=tenant_a_id,
        provider_id="openai",
        governance_state="approved",
        routing_eligible=1,
    )
    _insert_baa_record(
        fresh_db, tenant_id=tenant_a_id, provider_id="openai", baa_status="expired"
    )

    r = client.get("/ui/provider/routing", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    allowed_ids = [p["provider_id"] for p in body["allowed_providers"]]
    restricted_ids = [p["provider_id"] for p in body["restricted_providers"]]
    assert "openai" not in allowed_ids, (
        f"Expired-BAA provider appeared in allowed_providers: {body}"
    )
    assert "openai" in restricted_ids, (
        f"Expired-BAA provider not in restricted_providers: {body}"
    )


def test_revoked_baa_provider_not_in_allowed_routing(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Provider with a revoked BAA must appear in restricted, not allowed."""
    _insert_governance_record(
        fresh_db,
        tenant_id=tenant_a_id,
        provider_id="anthropic",
        governance_state="approved",
        routing_eligible=1,
    )
    _insert_baa_record(
        fresh_db, tenant_id=tenant_a_id, provider_id="anthropic", baa_status="revoked"
    )

    r = client.get("/ui/provider/routing", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    allowed_ids = [p["provider_id"] for p in body["allowed_providers"]]
    restricted_ids = [p["provider_id"] for p in body["restricted_providers"]]
    assert "anthropic" not in allowed_ids
    assert "anthropic" in restricted_ids


def test_pending_baa_provider_not_in_allowed_routing(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Provider with a pending BAA must appear in restricted, not allowed."""
    _insert_governance_record(
        fresh_db,
        tenant_id=tenant_a_id,
        provider_id="azure_openai",
        governance_state="approved",
        routing_eligible=1,
    )
    _insert_baa_record(
        fresh_db,
        tenant_id=tenant_a_id,
        provider_id="azure_openai",
        baa_status="pending",
    )

    r = client.get("/ui/provider/routing", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    allowed_ids = [p["provider_id"] for p in body["allowed_providers"]]
    restricted_ids = [p["provider_id"] for p in body["restricted_providers"]]
    assert "azure_openai" not in allowed_ids
    assert "azure_openai" in restricted_ids


def test_active_baa_provider_in_allowed_routing(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Provider with an active BAA and approved governance appears in allowed_providers."""
    _insert_governance_record(
        fresh_db,
        tenant_id=tenant_a_id,
        provider_id="openai",
        governance_state="approved",
        routing_eligible=1,
    )
    _insert_baa_record(
        fresh_db, tenant_id=tenant_a_id, provider_id="openai", baa_status="active"
    )

    r = client.get("/ui/provider/routing", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    allowed_ids = [p["provider_id"] for p in body["allowed_providers"]]
    assert "openai" in allowed_ids, (
        f"Active-BAA provider missing from allowed_providers: {body}"
    )


def test_no_baa_record_provider_classification(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_a_key: str,
) -> None:
    """Provider with no BAA record (synthesized 'missing') is not forced into restricted
    by the routing endpoint — only explicit non-active BAA records trigger restriction."""
    _insert_governance_record(
        fresh_db,
        tenant_id=tenant_a_id,
        provider_id="unregulated_provider",
        governance_state="approved",
        routing_eligible=1,
    )
    # No BAA record inserted — baa_status will be synthesized as 'missing'

    r = client.get("/ui/provider/routing", headers=_auth_headers(tenant_a_key))
    assert r.status_code == 200, r.text
    body = r.json()
    # Should appear in allowed (no explicit non-active BAA record)
    allowed_ids = [p["provider_id"] for p in body["allowed_providers"]]
    assert "unregulated_provider" in allowed_ids, (
        f"Provider without BAA record should be in allowed, got: {body}"
    )
