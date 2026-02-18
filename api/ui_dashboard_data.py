from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass
import hashlib
import json
import logging
import os
import time
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from api.auth_scopes import bind_tenant_id, require_scopes
from api.config.env import is_production_env
from api.dashboard_context import DashboardContext, DEFAULT_DASHBOARD_CONTEXT
from api.db import get_engine
from api.security_audit import audit_admin_action
from api.ui_dashboards import _verify_chain
from services.dashboard_runtime_policy import policy_hash, widget_allowed
from services.ui_widgets.registry import get_widget_contract

router = APIRouter(prefix="/ui/dashboard-data", tags=["ui-dashboard-data"])
log = logging.getLogger("frostgate.ui_dashboard")

_WIDGET_TIMEOUT_MS = int(os.getenv("FG_DASH_WIDGET_TIMEOUT_MS", "250"))
_WIDGET_MAX_PAYLOAD_BYTES = int(os.getenv("FG_DASH_WIDGET_MAX_PAYLOAD_BYTES", str(64 * 1024)))
_WIDGET_MAX_ERRORS = int(os.getenv("FG_DASH_WIDGET_MAX_ERRORS", "3"))
_CACHE_TTL_SECONDS = float(os.getenv("FG_DASH_SNAPSHOT_CACHE_TTL_SECONDS", "2"))

_CACHE: dict[str, tuple[float, str, dict[str, Any]]] = {}


class SnapshotRequest(BaseModel):
    dashboard_id: str = Field(min_length=1, max_length=128)
    widget_ids: list[str] = Field(default_factory=list)
    context: DashboardContext = Field(default_factory=lambda: DEFAULT_DASHBOARD_CONTEXT)
    tenant_id: str | None = Field(default=None, max_length=128)


@dataclass
class ProviderResult:
    ok: bool
    data: Any
    error: str | None = None


def _provider_system_health(*, tenant_id: str, context: DashboardContext) -> dict[str, Any]:
    _ = context
    return {"tenant_id": tenant_id, "status": "ok"}


def _provider_recent_decisions(*, tenant_id: str, context: DashboardContext) -> dict[str, Any]:
    from sqlalchemy import desc, select
    from sqlalchemy.orm import Session

    from api.db_models import DecisionRecord

    with Session(get_engine()) as session:
        stmt = (
            select(DecisionRecord)
            .where(DecisionRecord.tenant_id == tenant_id)
            .order_by(desc(DecisionRecord.created_at), desc(DecisionRecord.id))
            .limit(10)
        )
        rows = session.execute(stmt).scalars().all()
    return {
        "count": len(rows),
        "items": [
            {
                "id": int(r.id),
                "event_type": r.event_type,
                "threat_level": r.threat_level,
                "source": r.source,
            }
            for r in rows
        ],
        "q": context.q,
    }


def _provider_drift_status(*, tenant_id: str, context: DashboardContext) -> dict[str, Any]:
    from sqlalchemy.orm import Session

    with Session(get_engine()) as session:
        res = _verify_chain(session, tenant_id)
    return {"status": res.status, "checked": res.checked, "time_range": context.time_range}


_PROVIDERS = {
    "system_health": _provider_system_health,
    "recent_decisions": _provider_recent_decisions,
    "drift_status": _provider_drift_status,
}


def _resolve_persona(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    scopes = set(getattr(auth, "scopes", set()) or set())
    if "admin:read" in scopes:
        return "admin"
    if "forensics:read" in scopes:
        return "forensics"
    if "controls:read" in scopes:
        return "controls"
    return "analyst"


def _request_correlation_id(request: Request) -> str:
    return str(getattr(getattr(request, "state", None), "request_id", "-") or "-")


def _theme_hash(tenant_id: str) -> str:
    from pathlib import Path

    import json as _json

    theme_root = Path("contracts/dashboard/themes")
    path = theme_root / f"{tenant_id}.json"
    if not path.exists():
        path = theme_root / "default.json"
    try:
        payload = _json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        payload = {}
    blob = _json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _run_widget(widget_id: str, tenant_id: str, context: DashboardContext) -> ProviderResult:
    contract = get_widget_contract(widget_id)
    if not contract:
        return ProviderResult(ok=False, data=None, error="unknown_widget")
    provider_key = contract.get("data_provider")
    fn = _PROVIDERS.get(provider_key)
    if not fn:
        return ProviderResult(ok=False, data=None, error="unknown_provider")
    try:
        data = fn(tenant_id=tenant_id, context=context)
        payload_bytes = len(json.dumps(data, sort_keys=True).encode("utf-8"))
        if payload_bytes > _WIDGET_MAX_PAYLOAD_BYTES:
            return ProviderResult(ok=False, data=None, error="payload_too_large")
        return ProviderResult(ok=True, data=data)
    except Exception:
        return ProviderResult(ok=False, data=None, error="provider_failed")


def _override_enabled() -> bool:
    if is_production_env() or (os.getenv("FG_ENV", "").lower() == "staging"):
        return False
    return os.getenv("FG_UI_ADMIN_OVERRIDE_ENABLED", "0").lower() in {"1", "true", "yes", "on"}


def _override_scope_and_reason(request: Request, reason: str | None) -> tuple[str, str]:
    auth = getattr(getattr(request, "state", None), "auth", None)
    scopes = set(getattr(auth, "scopes", set()) or set())
    if "admin:tenant_override" not in scopes:
        raise HTTPException(status_code=403, detail="admin_override_scope_required")
    r = (reason or "").strip()
    if len(r) < 8:
        raise HTTPException(status_code=400, detail="admin_override_reason_required")
    return str(getattr(auth, "key_prefix", "unknown")), r


def _params_hash(payload: SnapshotRequest, *, override: bool) -> str:
    blob = json.dumps(
        {
            "dashboard_id": payload.dashboard_id,
            "widget_ids": sorted(payload.widget_ids),
            "context": payload.context.model_dump(),
            "override": override,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _etag_key(
    *,
    tenant_id: str,
    persona: str,
    dashboard_id: str,
    widgets: list[str],
    context: DashboardContext,
    override_flag: bool,
) -> str:
    versions = {wid: (get_widget_contract(wid) or {}).get("version", "na") for wid in widgets}
    filter_hash = hashlib.sha256(
        json.dumps(context.model_dump(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    blob = json.dumps(
        {
            "tenant_id": tenant_id,
            "persona": persona,
            "dashboard_id": dashboard_id,
            "canonical_filter_hash": filter_hash,
            "widget_subset": sorted(widgets),
            "override_flag": override_flag,
            "policy_hash": policy_hash(),
            "theme_hash": _theme_hash(tenant_id),
            "versions": versions,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _cached_response(cache_key: str) -> tuple[str, dict[str, Any]] | None:
    item = _CACHE.get(cache_key)
    if not item:
        return None
    created_at, etag, payload = item
    if (time.time() - created_at) > _CACHE_TTL_SECONDS:
        _CACHE.pop(cache_key, None)
        return None
    return etag, payload


@router.post(
    "/snapshot",
    dependencies=[Depends(require_scopes("ui:read"))],
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def snapshot(
    payload: SnapshotRequest,
    request: Request,
    if_none_match: str | None = Header(default=None, alias="If-None-Match"),
    x_fg_admin_override_tenant: str | None = Header(default=None, alias="X-FG-Admin-Override-Tenant"),
    x_fg_override_reason: str | None = Header(default=None, alias="X-FG-Override-Reason"),
) -> Response:
    tenant_id = bind_tenant_id(request, payload.tenant_id, require_explicit_for_unscoped=True)
    target_tenant = tenant_id
    override_flag = bool(x_fg_admin_override_tenant)
    if x_fg_admin_override_tenant:
        if not _override_enabled():
            raise HTTPException(status_code=403, detail="admin_override_disabled")
        key_prefix, reason = _override_scope_and_reason(request, x_fg_override_reason)
        target_tenant = x_fg_admin_override_tenant.strip()
        params_hash = _params_hash(payload, override=True)
        audit_admin_action(
            action="ui_dashboard_snapshot_admin_override",
            tenant_id=tenant_id,
            request=request,
            details={
                "actor_key_prefix": key_prefix,
                "source_tenant_id": tenant_id,
                "target_tenant_id": target_tenant,
                "reason": reason,
                "route": "/ui/dashboard-data/snapshot",
                "parameters_hash": params_hash,
            },
        )

    persona = _resolve_persona(request)
    cache_key = _etag_key(
        tenant_id=target_tenant,
        persona=persona,
        dashboard_id=payload.dashboard_id,
        widgets=payload.widget_ids,
        context=payload.context,
        override_flag=override_flag,
    )
    cached = _cached_response(cache_key)
    if cached:
        etag, cached_payload = cached
        if if_none_match == etag:
            return Response(status_code=304, headers={"ETag": etag})
        return JSONResponse(cached_payload, headers={"ETag": etag})

    widget_data: dict[str, Any] = {}
    errors: dict[str, str] = {}
    error_count = 0
    correlation_id = _request_correlation_id(request)
    filter_hash = hashlib.sha256(
        json.dumps(payload.context.model_dump(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    for wid in payload.widget_ids:
        allowed, deny_reason = widget_allowed(tenant_id=target_tenant, persona=persona, widget_id=wid)
        outcome = "allowed" if allowed else "denied"
        log.info(
            "ui_widget_load_attempt",
            extra={
                "tenant_id": target_tenant,
                "persona": persona,
                "widget_id": wid,
                "correlation_id": correlation_id,
                "outcome": outcome,
                "policy_reason": deny_reason,
                "filter_hash": filter_hash,
            },
        )
        if not allowed:
            errors[wid] = str(deny_reason or "WIDGET_DISABLED_BY_POLICY")
            continue

        contract = get_widget_contract(wid)
        degrade_ok = bool((contract or {}).get("degrade_ok", False))
        with ThreadPoolExecutor(max_workers=1) as pool:
            fut = pool.submit(_run_widget, wid, target_tenant, payload.context)
            try:
                result = fut.result(timeout=_WIDGET_TIMEOUT_MS / 1000.0)
            except TimeoutError:
                result = ProviderResult(ok=False, data=None, error="timeout")

        if result.ok:
            widget_data[wid] = result.data
            log.info("ui_widget_load_result", extra={"tenant_id": target_tenant, "persona": persona, "widget_id": wid, "correlation_id": correlation_id, "outcome": "allowed", "filter_hash": filter_hash})
            continue

        error_count += 1
        if error_count > _WIDGET_MAX_ERRORS:
            raise HTTPException(status_code=400, detail="widget_error_budget_exceeded")
        if not degrade_ok:
            raise HTTPException(status_code=400, detail=f"widget_failed:{wid}")
        err = str(result.error or "widget_failed")
        errors[wid] = err
        degraded_outcome = "timeout" if err == "timeout" else "degraded"
        log.info("ui_widget_load_result", extra={"tenant_id": target_tenant, "persona": persona, "widget_id": wid, "correlation_id": correlation_id, "outcome": degraded_outcome, "filter_hash": filter_hash})

    body = {
        "dashboard_id": payload.dashboard_id,
        "tenant_id": target_tenant,
        "context": payload.context.model_dump(),
        "widget_data": widget_data,
        "errors": errors,
    }
    etag = cache_key
    if not errors:
        _CACHE[cache_key] = (time.time(), etag, body)
    return JSONResponse(body, headers={"ETag": etag})
