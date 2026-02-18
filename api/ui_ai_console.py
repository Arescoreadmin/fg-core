from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import os
from threading import Lock
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from api.auth_scopes import bind_tenant_id, require_scopes

router = APIRouter(prefix="/ui/ai", tags=["ui-ai-console"])
legacy_router = APIRouter(tags=["ui-ai-console-legacy"])


@dataclass
class _TenantAIState:
    device_id: str
    enabled: bool
    day_key: str
    tokens_used: int


class _AIConsoleStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._state: dict[str, _TenantAIState] = {}

    def _today(self) -> str:
        return datetime.now(UTC).strftime("%Y-%m-%d")

    def _ensure(self, tenant_id: str) -> _TenantAIState:
        with self._lock:
            state = self._state.get(tenant_id)
            if state is None:
                state = _TenantAIState(
                    device_id=f"device-{tenant_id}",
                    enabled=False,
                    day_key=self._today(),
                    tokens_used=0,
                )
                self._state[tenant_id] = state
            elif state.day_key != self._today():
                state.day_key = self._today()
                state.tokens_used = 0
            return state

    def snapshot(self, tenant_id: str) -> _TenantAIState:
        return self._ensure(tenant_id)

    def set_enabled(self, tenant_id: str, *, enabled: bool) -> _TenantAIState:
        state = self._ensure(tenant_id)
        with self._lock:
            state.enabled = enabled
        return state

    def add_tokens(self, tenant_id: str, tokens: int) -> _TenantAIState:
        state = self._ensure(tenant_id)
        with self._lock:
            if state.day_key != self._today():
                state.day_key = self._today()
                state.tokens_used = 0
            state.tokens_used += max(0, tokens)
        return state


_STORE = _AIConsoleStore()


class ToggleRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=128)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    device_id: str = Field(min_length=1, max_length=128)
    provider: str | None = Field(default="simulated", max_length=64)
    tenant_id: str | None = Field(default=None, max_length=128)


def _allowed_providers() -> set[str]:
    raw_env = os.getenv("FG_AI_ALLOWED_PROVIDERS")
    if raw_env is None:
        raw = "simulated"
    else:
        raw = raw_env.strip()
    if not raw:
        return set()
    return {x.strip() for x in raw.split(",") if x.strip()}


def _request_cap() -> int:
    return int(os.getenv("FG_AI_REQUEST_TOKEN_CAP", "512"))


def _daily_quota() -> int:
    return int(os.getenv("FG_AI_DAILY_TOKEN_QUOTA", "4000"))


def _token_estimate(text: str) -> int:
    return max(1, len(text) // 4)


def _enforce_tenant_match(bound: str, supplied: str | None) -> None:
    if supplied and supplied.strip() and supplied.strip() != bound:
        raise HTTPException(status_code=403, detail="tenant_mismatch")


@router.get(
    "/experience",
    dependencies=[Depends(require_scopes("ui:read", "ai:chat"))],
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def ui_ai_experience(request: Request, tenant_id: str | None = None) -> dict[str, Any]:
    bound_tenant = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    _enforce_tenant_match(bound_tenant, tenant_id)
    state = _STORE.snapshot(bound_tenant)
    allowed = sorted(_allowed_providers())
    return {
        "tenant_id": bound_tenant,
        "device": {"device_id": state.device_id, "enabled": state.enabled},
        "providers": {"allowed": allowed, "default": "simulated"},
        "usage": {
            "day": state.day_key,
            "tokens_used": state.tokens_used,
            "daily_quota": _daily_quota(),
            "request_token_cap": _request_cap(),
        },
    }


@router.post(
    "/device/enable",
    dependencies=[Depends(require_scopes("ui:read", "ai:chat", "admin:write"))],
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def ui_ai_device_enable(payload: ToggleRequest, request: Request) -> dict[str, Any]:
    bound_tenant = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    state = _STORE.snapshot(bound_tenant)
    if payload.device_id != state.device_id:
        raise HTTPException(status_code=403, detail="unknown_device")
    state = _STORE.set_enabled(bound_tenant, enabled=True)
    return {"ok": True, "device": {"device_id": state.device_id, "enabled": True}}


@router.post(
    "/device/disable",
    dependencies=[Depends(require_scopes("ui:read", "ai:chat", "admin:write"))],
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def ui_ai_device_disable(payload: ToggleRequest, request: Request) -> dict[str, Any]:
    bound_tenant = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    state = _STORE.snapshot(bound_tenant)
    if payload.device_id != state.device_id:
        raise HTTPException(status_code=403, detail="unknown_device")
    state = _STORE.set_enabled(bound_tenant, enabled=False)
    return {"ok": True, "device": {"device_id": state.device_id, "enabled": False}}


@router.post(
    "/chat",
    dependencies=[Depends(require_scopes("ui:read", "ai:chat"))],
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def ui_ai_chat(payload: ChatRequest, request: Request) -> dict[str, Any]:
    bound_tenant = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    _enforce_tenant_match(bound_tenant, payload.tenant_id)
    state = _STORE.snapshot(bound_tenant)
    if payload.device_id != state.device_id:
        raise HTTPException(status_code=403, detail="unknown_device")
    if not state.enabled:
        raise HTTPException(status_code=403, detail="device_not_enabled")

    provider = (payload.provider or "simulated").strip()
    if provider not in _allowed_providers():
        raise HTTPException(status_code=403, detail="provider_not_allowed")

    req_tokens = _token_estimate(payload.message)
    if req_tokens > _request_cap():
        raise HTTPException(status_code=400, detail="request_token_cap_exceeded")

    if state.tokens_used + req_tokens > _daily_quota():
        raise HTTPException(status_code=429, detail="daily_quota_exceeded")

    updated = _STORE.add_tokens(bound_tenant, req_tokens)
    return {
        "reply": f"simulated:{payload.message[:120]}",
        "device_id": state.device_id,
        "provider": provider,
        "usage": {
            "tokens_used": updated.tokens_used,
            "daily_quota": _daily_quota(),
            "request_tokens": req_tokens,
        },
    }


@legacy_router.get(
    "/admin/devices",
    dependencies=[Depends(require_scopes("admin:write"))],
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def admin_devices(request: Request) -> dict[str, Any]:
    bound_tenant = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    state = _STORE.snapshot(bound_tenant)
    return {
        "tenant_id": bound_tenant,
        "devices": [
            {
                "device_id": state.device_id,
                "enabled": state.enabled,
                "tokens_used": state.tokens_used,
                "day": state.day_key,
            }
        ],
    }


@legacy_router.post(
    "/admin/devices/{device_id}/enable",
    dependencies=[Depends(require_scopes("admin:write"))],
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def admin_device_enable(device_id: str, request: Request) -> dict[str, Any]:
    bound_tenant = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    state = _STORE.snapshot(bound_tenant)
    if state.device_id != device_id:
        raise HTTPException(status_code=403, detail="unknown_device")
    state = _STORE.set_enabled(bound_tenant, enabled=True)
    return {
        "ok": True,
        "device": {"device_id": state.device_id, "enabled": state.enabled},
    }


@legacy_router.post(
    "/admin/devices/{device_id}/disable",
    dependencies=[Depends(require_scopes("admin:write"))],
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def admin_device_disable(device_id: str, request: Request) -> dict[str, Any]:
    bound_tenant = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    state = _STORE.snapshot(bound_tenant)
    if state.device_id != device_id:
        raise HTTPException(status_code=403, detail="unknown_device")
    state = _STORE.set_enabled(bound_tenant, enabled=False)
    return {
        "ok": True,
        "device": {"device_id": state.device_id, "enabled": state.enabled},
    }


@legacy_router.post(
    "/ui/devices/{device_id}/enable",
    dependencies=[Depends(require_scopes("ui:read", "ai:chat", "admin:write"))],
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def ui_device_enable_legacy(device_id: str, request: Request) -> dict[str, Any]:
    return admin_device_enable(device_id, request)


@legacy_router.post(
    "/ui/devices/{device_id}/disable",
    dependencies=[Depends(require_scopes("ui:read", "ai:chat", "admin:write"))],
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def ui_device_disable_legacy(device_id: str, request: Request) -> dict[str, Any]:
    return admin_device_disable(device_id, request)
