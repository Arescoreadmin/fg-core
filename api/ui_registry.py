from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from api.auth_scopes import bind_tenant_id, require_scopes
from api.dashboard_context import DEFAULT_DASHBOARD_CONTEXT
from services.dashboard_contracts import load_json_contract, validate_views_contract
from services.dashboard_runtime_policy import widget_allowed
from services.ui_widgets.registry import load_widget_contracts

router = APIRouter(prefix="/ui/registry", tags=["ui-registry"])

_DASHBOARD_ROOT = Path("contracts/dashboard").resolve()
_VIEWS_PATH = _DASHBOARD_ROOT / "views.json"
_VIEWS_SCHEMA_PATH = _DASHBOARD_ROOT / "schema" / "views.schema.json"


@lru_cache(maxsize=1)
def _views_contract() -> dict[str, Any]:
    _ = load_json_contract(_VIEWS_SCHEMA_PATH, root=_DASHBOARD_ROOT)
    payload = load_json_contract(_VIEWS_PATH, root=_DASHBOARD_ROOT)
    errs = validate_views_contract(payload)
    if errs:
        raise RuntimeError("invalid dashboard views contract")
    return payload


def _resolve_persona(scopes: set[str]) -> str:
    if "admin:read" in scopes:
        return "admin"
    if "forensics:read" in scopes:
        return "forensics"
    if "controls:read" in scopes:
        return "controls"
    return "analyst"


def _auth_scopes(request: Request) -> set[str]:
    auth = getattr(getattr(request, "state", None), "auth", None)
    return set(getattr(auth, "scopes", set()) or set())


def _filtered_dashboard(
    dashboard: dict[str, Any], scopes: set[str], *, tenant_id: str, persona: str
) -> dict[str, Any]:
    contracts = load_widget_contracts()
    kept_widgets: list[dict[str, Any]] = []
    for widget_id in dashboard.get("widgets", []):
        contract = contracts.get(widget_id)
        if not contract:
            continue
        required = set(contract.get("permissions", {}).get("scopes", []))
        if required and not required.issubset(scopes):
            continue
        allowed, reason = widget_allowed(
            tenant_id=tenant_id, persona=persona, widget_id=widget_id
        )
        if not allowed:
            continue
        kept_widgets.append(
            {"id": widget_id, "contract": contract, "policy_reason": reason}
        )
    return {
        "id": dashboard.get("id"),
        "title": dashboard.get("title"),
        "context_default": dashboard.get(
            "context_default", DEFAULT_DASHBOARD_CONTEXT.model_dump()
        ),
        "widgets": kept_widgets,
    }


@router.get(
    "/persona",
    dependencies=[Depends(require_scopes("ui:read"))],
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def get_persona(request: Request) -> dict[str, Any]:
    _ = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    scopes = _auth_scopes(request)
    return {"persona": _resolve_persona(scopes)}


@router.get(
    "/dashboards",
    dependencies=[Depends(require_scopes("ui:read"))],
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def get_dashboards(request: Request) -> dict[str, Any]:
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    scopes = _auth_scopes(request)
    persona = _resolve_persona(scopes)
    views = _views_contract()
    dashboards = []
    for d in views.get("dashboards", []):
        allowed = set(d.get("persona", {}).get("allowed", []))
        if allowed and persona not in allowed:
            continue
        dashboards.append(
            _filtered_dashboard(d, scopes, tenant_id=tenant_id, persona=persona)
        )
    return {"persona": persona, "dashboards": dashboards}


@router.get(
    "/dashboards/{dashboard_id}",
    dependencies=[Depends(require_scopes("ui:read"))],
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def get_dashboard(dashboard_id: str, request: Request) -> dict[str, Any]:
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    scopes = _auth_scopes(request)
    persona = _resolve_persona(scopes)
    views = _views_contract()
    for d in views.get("dashboards", []):
        if d.get("id") != dashboard_id:
            continue
        allowed = set(d.get("persona", {}).get("allowed", []))
        if allowed and persona not in allowed:
            raise HTTPException(status_code=403, detail="persona_not_authorized")
        return _filtered_dashboard(d, scopes, tenant_id=tenant_id, persona=persona)
    raise HTTPException(status_code=404, detail="dashboard_not_found")
