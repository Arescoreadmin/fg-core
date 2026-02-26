from __future__ import annotations

import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


def _sign(payload: dict[str, object], secret: str) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256=" + hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def _client(build_app, monkeypatch):
    monkeypatch.setenv("FG_TESTING_CONTROL_TOWER_ENABLED", "1")
    monkeypatch.setenv("FG_INTERNAL_TOKEN", "internal-test-token")
    monkeypatch.setenv("FG_CONTROL_TOWER_SIGNING_SECRET", "ct-secret")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "999")
    monkeypatch.setenv("GITHUB_SHA", "abcdef1234567")
    app = build_app(auth_enabled=True)
    return TestClient(app)


def _payload() -> dict[str, object]:
    return {
        "lane": "fg-fast",
        "status": "passed",
        "started_at": "2026-02-26T00:00:00Z",
        "finished_at": "2026-02-26T00:02:00Z",
        "duration_ms": 120000,
        "commit_sha": "abcdef1234567",
        "ref": "refs/heads/main",
        "triggered_by": "ci",
        "triage_schema_version": "2.0",
        "triage_category_counts": {"UNKNOWN": 0},
        "artifact_hashes": {"lane.log": "a" * 64},
        "artifact_paths": ["artifacts/testing/lane.log"],
        "summary_md": "ok",
    }


def _canonical_for_signing(payload: dict[str, object], tenant_id: str) -> dict[str, object]:
    seed = {
        "tenant_id": tenant_id,
        "lane": payload["lane"],
        "commit_sha": payload["commit_sha"],
        "started_at": payload["started_at"],
        "artifact_hashes": payload["artifact_hashes"],
    }
    run_id = hashlib.sha256(json.dumps(seed, sort_keys=True).encode("utf-8")).hexdigest()[:32]
    c = dict(payload)
    c["tenant_id"] = tenant_id
    c["status"] = str(payload["status"]).lower()
    c["run_id"] = run_id
    return c


def test_register_and_list_runs(build_app, monkeypatch) -> None:
    client = _client(build_app, monkeypatch)
    key = mint_key("control-plane:admin", "control-plane:read", tenant_id="tenant-a")
    payload = _payload()
    canonical = _canonical_for_signing(payload, "tenant-a")

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
    run_id = r.json()["run_id"]

    listed = client.get("/control/testing/runs", headers={"X-API-Key": key})
    assert listed.status_code == 200
    body = listed.json()
    assert body["runs"] and body["runs"][0]["run_id"] == run_id

    detail = client.get(f"/control/testing/runs/{run_id}", headers={"X-API-Key": key})
    assert detail.status_code == 200
    assert detail.json()["lane"] == "fg-fast"

    health = client.get("/control/testing/health", headers={"X-API-Key": key})
    assert health.status_code == 200
    assert health.json()["snapshots"]


def test_register_rejects_bad_signature(build_app, monkeypatch) -> None:
    client = _client(build_app, monkeypatch)
    key = mint_key("control-plane:admin", tenant_id="tenant-a")
    payload = _payload()
    r = client.post(
        "/control/testing/runs/register",
        json=payload,
        headers={
            "X-API-Key": key,
            "x-fg-internal-token": "internal-test-token",
            "x-github-run-id": "999",
            "x-fg-signature": "sha256=deadbeef",
        },
    )
    assert r.status_code == 403
