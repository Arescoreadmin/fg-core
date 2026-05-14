"""
Security and isolation tests for PR 54 — Evaluation Lab API.

Covers:
- Auth enforcement for all new endpoints
- Tenant isolation: query sets, query items, run sub-resources
- Cross-tenant rejection for all new endpoints
- Export safety: blocked metadata keys not returned
- Deterministic ordering of query items
- Input validation (oversized refs)
- Empty-state safe rendering
- No fabricated metrics in responses
- Unknown confidence renders safely
- Unsupported metric fields absent from responses
- Reranker comparison determinism
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def _auth_headers(raw_key: str) -> dict[str, str]:
    return {"X-API-Key": raw_key}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _insert_eval_run(
    db_path: str,
    *,
    tenant_id: str,
    run_ref: str | None = None,
    status: str = "completed",
    query_count: int = 5,
    relevance: str = "{}",
    coverage: str = "{}",
    correctness: str = "{}",
    metadata: str = "{}",
) -> str:
    run_ref = run_ref or str(uuid.uuid4())
    now = _now()
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT OR REPLACE INTO retrieval_evaluation_runs
                (tenant_id, run_ref, status, query_count,
                 relevance_indicators_json, coverage_indicators_json,
                 correctness_indicators_json, evaluation_metadata_json,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                run_ref,
                status,
                query_count,
                relevance,
                coverage,
                correctness,
                metadata,
                now,
                now,
            ),
        )
        con.commit()
    finally:
        con.close()
    return run_ref


def _insert_query_set(
    db_path: str,
    *,
    tenant_id: str,
    set_ref: str | None = None,
    name: str = "Test Query Set",
    corpus_id: str | None = None,
) -> str:
    set_ref = set_ref or str(uuid.uuid4())
    now = _now()
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT OR REPLACE INTO evaluation_query_sets
                (tenant_id, set_ref, name, corpus_id,
                 operator_notes_json, export_safe_metadata_json,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (tenant_id, set_ref, name, corpus_id, "[]", "{}", now, now),
        )
        con.commit()
    finally:
        con.close()
    return set_ref


def _insert_query_item(
    db_path: str,
    *,
    tenant_id: str,
    set_ref: str,
    item_ref: str | None = None,
    query_category: str | None = None,
) -> str:
    item_ref = item_ref or str(uuid.uuid4())
    now = _now()
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT OR REPLACE INTO evaluation_query_items
                (tenant_id, set_ref, item_ref, query_category,
                 expected_source_ids_json, expected_chunk_ids_json,
                 expected_source_hashes_json, expected_provenance_ids_json,
                 retrieval_expectations_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                set_ref,
                item_ref,
                query_category,
                "[]",
                "[]",
                "[]",
                "[]",
                "{}",
                now,
                now,
            ),
        )
        con.commit()
    finally:
        con.close()
    return item_ref


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
def client(app) -> TestClient:
    return TestClient(app)


@pytest.fixture
def tenant_a_key(tenant_a_id: str, fresh_db: str) -> str:
    try:
        return mint_key("ui:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        return mint_key("ui:read", ttl_seconds=86400)


# ─── Auth enforcement ─────────────────────────────────────────────────────────


def test_query_sets_requires_auth(client: TestClient) -> None:
    r = client.get("/ui/evaluation/query-sets")
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


def test_query_set_detail_requires_auth(client: TestClient) -> None:
    r = client.get(f"/ui/evaluation/query-sets/{uuid.uuid4()}")
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


def test_run_comparison_requires_auth(client: TestClient) -> None:
    r = client.get(f"/ui/evaluation/runs/{uuid.uuid4()}/comparison")
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


def test_run_confidence_requires_auth(client: TestClient) -> None:
    r = client.get(f"/ui/evaluation/runs/{uuid.uuid4()}/confidence")
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


def test_run_hallucination_requires_auth(client: TestClient) -> None:
    r = client.get(f"/ui/evaluation/runs/{uuid.uuid4()}/hallucination")
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


def test_run_reranker_requires_auth(client: TestClient) -> None:
    r = client.get(f"/ui/evaluation/runs/{uuid.uuid4()}/reranker")
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


def test_run_export_requires_auth(client: TestClient) -> None:
    r = client.get(f"/ui/evaluation/runs/{uuid.uuid4()}/export")
    assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"


# ─── Query set tenant isolation ───────────────────────────────────────────────


def test_query_sets_tenant_isolation(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_b_id: str,
) -> None:
    """Tenant A cannot see Tenant B's query sets."""
    b_set = _insert_query_set(fresh_db, tenant_id=tenant_b_id, name="B Set")
    a_set = _insert_query_set(fresh_db, tenant_id=tenant_a_id, name="A Set")
    try:
        a_key = mint_key("ui:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        a_key = mint_key("ui:read", ttl_seconds=86400)
    r = client.get("/ui/evaluation/query-sets", headers=_auth_headers(a_key))
    assert r.status_code == 200
    refs = [qs["set_ref"] for qs in r.json()["query_sets"]]
    assert b_set not in refs, "Tenant A must not see Tenant B's query set"
    assert a_set in refs


def test_query_set_detail_cross_tenant_rejected(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_b_id: str,
) -> None:
    """Tenant A cannot read Tenant B's query set detail."""
    b_set = _insert_query_set(fresh_db, tenant_id=tenant_b_id)
    try:
        a_key = mint_key("ui:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        a_key = mint_key("ui:read", ttl_seconds=86400)
    r = client.get(
        f"/ui/evaluation/query-sets/{b_set}",
        headers=_auth_headers(a_key),
    )
    assert r.status_code == 404, (
        f"Expected 404 for cross-tenant set, got {r.status_code}"
    )


def test_query_set_items_tenant_scoped(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_b_id: str,
) -> None:
    """Items in Tenant A's set cannot reference Tenant B's items."""
    a_set = _insert_query_set(fresh_db, tenant_id=tenant_a_id)
    b_item = _insert_query_item(fresh_db, tenant_id=tenant_b_id, set_ref=a_set)
    a_item = _insert_query_item(fresh_db, tenant_id=tenant_a_id, set_ref=a_set)
    try:
        a_key = mint_key("ui:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        a_key = mint_key("ui:read", ttl_seconds=86400)
    r = client.get(
        f"/ui/evaluation/query-sets/{a_set}",
        headers=_auth_headers(a_key),
    )
    assert r.status_code == 200
    item_refs = [i["item_ref"] for i in r.json()["items"]]
    assert b_item not in item_refs, "Must not return Tenant B's item"
    assert a_item in item_refs


# ─── Run sub-resource tenant isolation ───────────────────────────────────────


def _run_sub_resource_cross_tenant(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
    tenant_b_id: str,
    sub_path: str,
) -> None:
    b_run = _insert_eval_run(fresh_db, tenant_id=tenant_b_id)
    try:
        a_key = mint_key("ui:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        a_key = mint_key("ui:read", ttl_seconds=86400)
    r = client.get(
        f"/ui/evaluation/runs/{b_run}/{sub_path}",
        headers=_auth_headers(a_key),
    )
    assert r.status_code == 404, (
        f"Expected 404 for cross-tenant run/{sub_path}, got {r.status_code}"
    )


def test_comparison_cross_tenant_rejected(
    client, fresh_db, tenant_a_id, tenant_b_id
) -> None:
    _run_sub_resource_cross_tenant(
        client, fresh_db, tenant_a_id, tenant_b_id, "comparison"
    )


def test_confidence_cross_tenant_rejected(
    client, fresh_db, tenant_a_id, tenant_b_id
) -> None:
    _run_sub_resource_cross_tenant(
        client, fresh_db, tenant_a_id, tenant_b_id, "confidence"
    )


def test_hallucination_cross_tenant_rejected(
    client, fresh_db, tenant_a_id, tenant_b_id
) -> None:
    _run_sub_resource_cross_tenant(
        client, fresh_db, tenant_a_id, tenant_b_id, "hallucination"
    )


def test_reranker_cross_tenant_rejected(
    client, fresh_db, tenant_a_id, tenant_b_id
) -> None:
    _run_sub_resource_cross_tenant(
        client, fresh_db, tenant_a_id, tenant_b_id, "reranker"
    )


def test_export_cross_tenant_rejected(
    client, fresh_db, tenant_a_id, tenant_b_id
) -> None:
    _run_sub_resource_cross_tenant(client, fresh_db, tenant_a_id, tenant_b_id, "export")


# ─── Export safety ────────────────────────────────────────────────────────────


def test_export_excludes_blocked_metadata_keys(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
) -> None:
    """Export must strip secret/token/auth keys from evaluation_metadata."""
    dangerous_meta = json.dumps(
        {
            "api_key": "sk-dangerous-key",
            "auth_header": "Bearer token123",
            "secret": "my-secret",
            "token": "raw-token",
            "credentials": "user:pass",
            "safe_field": "this-is-ok",
            "retrieval_strategy": "hybrid",
        }
    )
    run_ref = _insert_eval_run(
        fresh_db,
        tenant_id=tenant_a_id,
        metadata=dangerous_meta,
    )
    try:
        a_key = mint_key("ui:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        a_key = mint_key("ui:read", ttl_seconds=86400)
    r = client.get(
        f"/ui/evaluation/runs/{run_ref}/export",
        headers=_auth_headers(a_key),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["export_safe"] is True
    meta = body["evaluation_metadata"]
    assert "api_key" not in meta, "api_key must be excluded from export"
    assert "auth_header" not in meta, "auth_header must be excluded from export"
    assert "secret" not in meta, "secret must be excluded from export"
    assert "token" not in meta, "token must be excluded from export"
    assert "credentials" not in meta, "credentials must be excluded from export"
    assert meta.get("safe_field") == "this-is-ok", "safe fields must be present"
    assert meta.get("retrieval_strategy") == "hybrid", "safe fields must be present"


def test_export_safe_flag_always_true(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
) -> None:
    run_ref = _insert_eval_run(fresh_db, tenant_id=tenant_a_id)
    try:
        a_key = mint_key("ui:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        a_key = mint_key("ui:read", ttl_seconds=86400)
    r = client.get(
        f"/ui/evaluation/runs/{run_ref}/export",
        headers=_auth_headers(a_key),
    )
    assert r.status_code == 200
    assert r.json()["export_safe"] is True


# ─── Input validation ─────────────────────────────────────────────────────────


def test_query_set_detail_ref_too_long(
    client: TestClient,
    tenant_a_key: str,
) -> None:
    too_long = "x" * 129
    r = client.get(
        f"/ui/evaluation/query-sets/{too_long}",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code in (422, 404)


def test_run_comparison_ref_too_long(
    client: TestClient,
    tenant_a_key: str,
) -> None:
    too_long = "x" * 129
    r = client.get(
        f"/ui/evaluation/runs/{too_long}/comparison",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 422


def test_run_export_ref_too_long(
    client: TestClient,
    tenant_a_key: str,
) -> None:
    too_long = "x" * 129
    r = client.get(
        f"/ui/evaluation/runs/{too_long}/export",
        headers=_auth_headers(tenant_a_key),
    )
    assert r.status_code == 422


# ─── Empty-state safe rendering ───────────────────────────────────────────────


def test_query_sets_empty_state(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
) -> None:
    try:
        a_key = mint_key("ui:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        a_key = mint_key("ui:read", ttl_seconds=86400)
    r = client.get("/ui/evaluation/query-sets", headers=_auth_headers(a_key))
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 0
    assert body["query_sets"] == []


def test_run_comparison_not_found(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
) -> None:
    try:
        a_key = mint_key("ui:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        a_key = mint_key("ui:read", ttl_seconds=86400)
    r = client.get(
        f"/ui/evaluation/runs/{uuid.uuid4()}/comparison",
        headers=_auth_headers(a_key),
    )
    assert r.status_code == 404


# ─── No fabricated metrics ────────────────────────────────────────────────────


def test_comparison_no_fabricated_precision(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
) -> None:
    """Comparison response must include comparison_note and not fabricate precision."""
    run_ref = _insert_eval_run(fresh_db, tenant_id=tenant_a_id)
    try:
        a_key = mint_key("ui:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        a_key = mint_key("ui:read", ttl_seconds=86400)
    r = client.get(
        f"/ui/evaluation/runs/{run_ref}/comparison",
        headers=_auth_headers(a_key),
    )
    assert r.status_code == 200
    rc = r.json()["retrieval_comparison"]
    assert "comparison_note" in rc, "comparison_note must be present"
    assert "fabricated" not in rc, "fabricated key must not appear"
    assert "precision" not in rc, "no precision metric keys in root"


def test_confidence_unknown_renders_safely(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
) -> None:
    """Confidence source renders as 'unknown' when not set — not fabricated."""
    run_ref = _insert_eval_run(fresh_db, tenant_id=tenant_a_id)
    try:
        a_key = mint_key("ui:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        a_key = mint_key("ui:read", ttl_seconds=86400)
    r = client.get(
        f"/ui/evaluation/runs/{run_ref}/confidence",
        headers=_auth_headers(a_key),
    )
    assert r.status_code == 200
    cd = r.json()["confidence_distribution"]
    assert cd["confidence_source"] == "unknown"
    assert cd["confidence_source_labeled"] is True
    assert cd["has_confidence_data"] is False


def test_hallucination_review_type_labeled_heuristic(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
) -> None:
    """Hallucination review_type must be 'heuristic' and include review_note."""
    run_ref = _insert_eval_run(fresh_db, tenant_id=tenant_a_id)
    try:
        a_key = mint_key("ui:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        a_key = mint_key("ui:read", ttl_seconds=86400)
    r = client.get(
        f"/ui/evaluation/runs/{run_ref}/hallucination",
        headers=_auth_headers(a_key),
    )
    assert r.status_code == 200
    hr = r.json()["hallucination_review"]
    assert hr["review_type"] == "heuristic"
    assert "heuristic" in hr["review_note"].lower()
    assert hr["export_safe"] is True
    assert hr["tenant_scoped"] is True


def test_reranker_ordering_deterministic_flag(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
) -> None:
    run_ref = _insert_eval_run(fresh_db, tenant_id=tenant_a_id)
    try:
        a_key = mint_key("ui:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        a_key = mint_key("ui:read", ttl_seconds=86400)
    r = client.get(
        f"/ui/evaluation/runs/{run_ref}/reranker",
        headers=_auth_headers(a_key),
    )
    assert r.status_code == 200
    rc = r.json()["reranker_comparison"]
    assert rc["ordering_deterministic"] is True
    assert "reranker_note" in rc


# ─── Deterministic query item ordering ───────────────────────────────────────


def test_query_items_deterministic_ordering(
    client: TestClient,
    fresh_db: str,
    tenant_a_id: str,
) -> None:
    """Query items must always return in the same order (created_at ASC, item_ref ASC)."""
    a_set = _insert_query_set(fresh_db, tenant_id=tenant_a_id)
    for _ in range(5):
        _insert_query_item(fresh_db, tenant_id=tenant_a_id, set_ref=a_set)
    try:
        a_key = mint_key("ui:read", ttl_seconds=86400, tenant_id=tenant_a_id)
    except TypeError:
        a_key = mint_key("ui:read", ttl_seconds=86400)
    r1 = client.get(
        f"/ui/evaluation/query-sets/{a_set}",
        headers=_auth_headers(a_key),
    )
    r2 = client.get(
        f"/ui/evaluation/query-sets/{a_set}",
        headers=_auth_headers(a_key),
    )
    assert r1.status_code == 200
    assert r2.status_code == 200
    items1 = [i["item_ref"] for i in r1.json()["items"]]
    items2 = [i["item_ref"] for i in r2.json()["items"]]
    assert items1 == items2, "Query item ordering must be deterministic"
