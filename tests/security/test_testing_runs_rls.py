from __future__ import annotations

import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def _sign(payload: dict[str, object], secret: str) -> str:
    return "sha256=" + hmac.new(
        secret.encode("utf-8"),
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _client(build_app, monkeypatch):
    monkeypatch.setenv("FG_TESTING_CONTROL_TOWER_ENABLED", "1")
    monkeypatch.setenv("FG_INTERNAL_TOKEN", "internal-test-token")
    monkeypatch.setenv("FG_CONTROL_TOWER_SIGNING_SECRET", "ct-secret")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "999")
    monkeypatch.setenv("GITHUB_SHA", "abcdef1234567")
    return TestClient(build_app(auth_enabled=True))


def _payload() -> dict[str, object]:
    return {
        "lane": "fg-fast",
        "status": "passed",
        "started_at": "2026-02-26T00:00:00Z",
        "finished_at": "2026-02-26T00:01:00Z",
        "duration_ms": 60000,
        "commit_sha": "abcdef1234567",
        "ref": "refs/heads/main",
        "triggered_by": "ci",
        "triage_schema_version": "2.0",
        "triage_category_counts": {},
        "artifact_hashes": {},
        "artifact_paths": [],
        "summary_md": "ok",
    }


def _canonical(payload: dict[str, object], tenant: str) -> dict[str, object]:
    seed = {
        "tenant_id": tenant,
        "lane": payload["lane"],
        "commit_sha": payload["commit_sha"],
        "started_at": payload["started_at"],
        "artifact_hashes": payload["artifact_hashes"],
    }
    run_id = hashlib.sha256(json.dumps(seed, sort_keys=True).encode("utf-8")).hexdigest()[:32]
    c = dict(payload)
    c["tenant_id"] = tenant
    c["status"] = str(payload["status"]).lower()
    c["run_id"] = run_id
    return c


def _register(client: TestClient, key: str, tenant: str) -> str:
    payload = _payload()
    canonical = _canonical(payload, tenant)
    r = client.post(
        "/control/testing/runs/register",
        json=payload,
        headers={
            "X-API-Key": key,
            "x-fg-internal-token": "internal-test-token",
            "x-github-run-id": "999",
            "x-fg-signature": _sign(canonical, "ct-secret"),
        },
    )
    assert r.status_code == 200
    return r.json()["run_id"]


def test_tenant_cannot_read_other_tenant_runs(build_app, monkeypatch) -> None:
    client = _client(build_app, monkeypatch)
    key_a = mint_key("control-plane:admin", "control-plane:read", tenant_id="tenant-a")
    key_b = mint_key("control-plane:admin", "control-plane:read", tenant_id="tenant-b")
    run_id = _register(client, key_a, "tenant-a")

    resp = client.get("/control/testing/runs", headers={"X-API-Key": key_b})
    assert resp.status_code == 200
    ids = [row["run_id"] for row in resp.json()["runs"]]
    assert run_id not in ids


def test_rls_policy_rejects_unbound_reads(build_app, monkeypatch) -> None:
    client = _client(build_app, monkeypatch)
    resp = client.get("/control/testing/runs", headers={"X-API-Key": "ci-test-key-00000000000000000000000000000000"})
    assert resp.status_code == 400
