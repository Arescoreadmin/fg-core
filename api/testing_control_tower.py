from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from api.auth_scopes import bind_tenant_id, require_scopes
from services.testing_control_tower_store import get_run, latest_health, list_runs, register_run

router = APIRouter(prefix="/control/testing", tags=["testing-control-tower"])

_ALLOWLISTED_LANES = {"fg-fast", "fg-contract", "fg-security", "fg-full", "fg-flake-detect"}
_ALLOWED_STATUS = {"passed", "failed", "running", "queued", "canceled", "flaky"}
_REQUIRED_FIELDS = {
    "lane",
    "status",
    "started_at",
    "finished_at",
    "duration_ms",
    "commit_sha",
    "ref",
    "triggered_by",
    "triage_schema_version",
    "triage_category_counts",
    "artifact_hashes",
    "artifact_paths",
    "summary_md",
}


def _internal_guard(request: Request) -> None:
    expected = (os.getenv("FG_INTERNAL_TOKEN") or "").strip()
    provided = (request.headers.get("x-fg-internal-token") or "").strip()
    if not expected or provided != expected:
        raise HTTPException(status_code=403, detail="forbidden")

    if (os.getenv("GITHUB_ACTIONS") or "").strip().lower() != "true":
        raise HTTPException(status_code=403, detail="ci_context_required")

    expected_run_id = (os.getenv("GITHUB_RUN_ID") or "").strip()
    if expected_run_id:
        supplied_run_id = (request.headers.get("x-github-run-id") or "").strip()
        if supplied_run_id != expected_run_id:
            raise HTTPException(status_code=403, detail="ci_attestation_mismatch")


def _canonical_payload(body: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    unknown = sorted(set(body) - _REQUIRED_FIELDS)
    missing = sorted(_REQUIRED_FIELDS - set(body))
    if unknown or missing:
        raise HTTPException(status_code=400, detail={"missing": missing, "unknown": unknown})

    lane = str(body["lane"])
    if lane not in _ALLOWLISTED_LANES:
        raise HTTPException(status_code=400, detail="lane_not_allowlisted")

    status_val = str(body["status"]).lower()
    if status_val not in _ALLOWED_STATUS:
        raise HTTPException(status_code=400, detail="invalid_status")

    expected_sha = (os.getenv("GITHUB_SHA") or "").strip().lower()
    provided_sha = str(body["commit_sha"]).strip().lower()
    if expected_sha and provided_sha != expected_sha:
        raise HTTPException(status_code=400, detail="commit_sha_mismatch")

    canonical = dict(body)
    canonical["tenant_id"] = tenant_id
    canonical["status"] = status_val

    # server-side deterministic run id (client-supplied run_id ignored)
    seed = {
        "tenant_id": tenant_id,
        "lane": canonical["lane"],
        "commit_sha": canonical["commit_sha"],
        "started_at": canonical["started_at"],
        "artifact_hashes": canonical["artifact_hashes"],
    }
    canonical["run_id"] = hashlib.sha256(json.dumps(seed, sort_keys=True).encode("utf-8")).hexdigest()[:32]
    return canonical


def _verify_signature(request: Request, canonical: dict[str, Any]) -> None:
    secret = (os.getenv("FG_CONTROL_TOWER_SIGNING_SECRET") or "").encode("utf-8")
    if not secret:
        raise HTTPException(status_code=503, detail="signing_not_configured")

    provided = (request.headers.get("x-fg-signature") or "").strip().lower()
    if not provided.startswith("sha256="):
        raise HTTPException(status_code=403, detail="signature_missing")

    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected = "sha256=" + hmac.new(secret, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=403, detail="signature_invalid")


@router.post("/runs/register", dependencies=[Depends(require_scopes("control-plane:admin"))])
def register_run_summary(request: Request, body: dict[str, Any]) -> dict[str, str]:
    _internal_guard(request)
    tenant_id = bind_tenant_id(request, None)
    canonical = _canonical_payload(body, tenant_id)
    _verify_signature(request, canonical)

    actor = str(getattr(getattr(request, "state", None), "auth", None).key_prefix or "ci")
    policy_change_event = bool(body.get("policy_change_event", False))
    register_run(canonical, actor=actor, policy_change_event=policy_change_event)
    return {"status": "registered", "run_id": str(canonical["run_id"])}


@router.get("/runs", dependencies=[Depends(require_scopes("control-plane:read"))])
def get_runs(request: Request, limit: int = Query(default=50, ge=1, le=50)) -> dict[str, object]:
    tenant_id = bind_tenant_id(request, None)
    return {"runs": list_runs(tenant_id, limit=limit)}


@router.get("/runs/{run_id}", dependencies=[Depends(require_scopes("control-plane:read"))])
def get_run_detail(run_id: str, request: Request) -> dict[str, object]:
    tenant_id = bind_tenant_id(request, None)
    run = get_run(tenant_id, run_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return run


@router.get("/health", dependencies=[Depends(require_scopes("control-plane:read"))])
def get_health(request: Request, lane: str | None = Query(default=None)) -> dict[str, object]:
    tenant_id = bind_tenant_id(request, None)
    return {"snapshots": latest_health(tenant_id, lane=lane)}
