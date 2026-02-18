from __future__ import annotations

import hashlib
import os
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from api.db_models import AgentDeviceKey, AgentDeviceRegistry, AgentEnrollmentToken
from api.security_audit import audit_admin_action

router = APIRouter(
    prefix="/admin/agent",
    tags=["agent-admin"],
    dependencies=[Depends(require_scopes("keys:admin"))],
)


@dataclass
class _Bucket:
    tokens: float
    updated_at: float


class _RateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = {}
        self._lock = Lock()

    def allow(self, key: str, *, rate_per_sec: float, burst: int) -> bool:
        if (os.getenv("FG_ENV") or "").strip().lower() == "test":
            return True
        now = time.time()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                self._buckets[key] = _Bucket(tokens=float(burst - 1), updated_at=now)
                return True
            elapsed = max(0.0, now - bucket.updated_at)
            bucket.tokens = min(float(burst), bucket.tokens + elapsed * rate_per_sec)
            bucket.updated_at = now
            if bucket.tokens < 1.0:
                return False
            bucket.tokens -= 1.0
            return True


_TOKEN_ISSUE_LIMITER = _RateLimiter()


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _token_hash(raw: str) -> str:
    pepper = (os.getenv("FG_AGENT_TOKEN_PEPPER") or os.getenv("FG_KEY_PEPPER") or "").strip()
    if not pepper:
        raise RuntimeError("FG_AGENT_TOKEN_PEPPER or FG_KEY_PEPPER is required")
    return hashlib.sha256(f"{pepper}:{raw}".encode("utf-8")).hexdigest()


class EnrollmentTokenCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ttl_minutes: int = Field(default=15, ge=1, le=1440)
    max_uses: int = Field(default=1, ge=1, le=10)
    reason: str = Field(min_length=4, max_length=256)
    ticket: str = Field(min_length=2, max_length=128)


class EnrollmentTokenCreateResponse(BaseModel):
    token: str
    expires_at: str
    max_uses: int


class DeviceInfo(BaseModel):
    device_id: str
    tenant_id: str
    status: str
    suspicious: bool
    last_seen_at: str | None
    last_ip: str | None
    last_version: str | None


@router.post("/enrollment-tokens", response_model=EnrollmentTokenCreateResponse, responses={429: {"description": "Too Many Requests"}})
def create_enrollment_token(
    body: EnrollmentTokenCreateRequest,
    request: Request,
) -> EnrollmentTokenCreateResponse:
    tenant_id = require_bound_tenant(request)
    auth_ctx = getattr(request.state, "auth", None)
    actor_id = getattr(auth_ctx, "key_prefix", None) or "admin"

    if not _TOKEN_ISSUE_LIMITER.allow(f"tenant:{tenant_id}", rate_per_sec=1 / 30.0, burst=3):
        raise HTTPException(status_code=429, detail="tenant token issuance rate limited")
    if not _TOKEN_ISSUE_LIMITER.allow(f"actor:{actor_id}", rate_per_sec=1 / 60.0, burst=2):
        raise HTTPException(status_code=429, detail="admin token issuance rate limited")

    raw = f"agt_{secrets.token_urlsafe(24)}"
    expires_at = _utcnow() + timedelta(minutes=body.ttl_minutes)
    max_active_per_tenant = int(os.getenv("FG_AGENT_MAX_ACTIVE_TOKENS_PER_TENANT", "10"))

    engine = get_engine()
    with Session(engine) as session:
        active_count = (
            session.query(func.count(AgentEnrollmentToken.id))
            .filter(
                AgentEnrollmentToken.tenant_id == tenant_id,
                AgentEnrollmentToken.expires_at > _utcnow(),
                AgentEnrollmentToken.used_count < AgentEnrollmentToken.max_uses,
            )
            .scalar()
        )
        if int(active_count or 0) >= max_active_per_tenant:
            raise HTTPException(status_code=429, detail="too many active enrollment tokens for tenant")

        session.add(
            AgentEnrollmentToken(
                token_hash=_token_hash(raw),
                tenant_id=tenant_id,
                created_by=actor_id,
                reason=body.reason,
                ticket=body.ticket,
                expires_at=expires_at,
                max_uses=body.max_uses,
                used_count=0,
            )
        )
        session.commit()

    audit_admin_action(
        action="agent-enrollment-token-created",
        tenant_id=tenant_id,
        request=request,
        details={
            "reason": body.reason,
            "ticket": body.ticket,
            "max_uses": body.max_uses,
            "expires_at": expires_at.isoformat(),
            "actor_id": actor_id,
        },
    )
    return EnrollmentTokenCreateResponse(
        token=raw,
        expires_at=expires_at.isoformat(),
        max_uses=body.max_uses,
    )


@router.get("/devices")
def list_devices(
    request: Request,
    status: str | None = Query(default=None),
) -> dict[str, list[DeviceInfo]]:
    tenant_id = require_bound_tenant(request)

    engine = get_engine()
    with Session(engine) as session:
        query = session.query(AgentDeviceRegistry).filter(
            AgentDeviceRegistry.tenant_id == tenant_id
        )
        if status:
            query = query.filter(AgentDeviceRegistry.status == status)

        rows = query.order_by(AgentDeviceRegistry.created_at.desc()).all()
        return {
            "devices": [
                DeviceInfo(
                    device_id=row.device_id,
                    tenant_id=row.tenant_id,
                    status=row.status,
                    suspicious=bool(row.suspicious),
                    last_seen_at=(row.last_seen_at.isoformat() if row.last_seen_at else None),
                    last_ip=row.last_ip,
                    last_version=row.last_version,
                )
                for row in rows
            ]
        }


@router.post("/devices/{device_id}/revoke")
def revoke_device(device_id: str, request: Request) -> dict[str, bool]:
    tenant_id = require_bound_tenant(request)

    engine = get_engine()
    with Session(engine) as session:
        device = (
            session.query(AgentDeviceRegistry)
            .filter(
                AgentDeviceRegistry.device_id == device_id,
                AgentDeviceRegistry.tenant_id == tenant_id,
            )
            .first()
        )
        if device is None:
            raise HTTPException(status_code=404, detail="device not found")
        device.status = "revoked"
        device.suspicious = True
        session.query(AgentDeviceKey).filter(
            AgentDeviceKey.device_id == device_id,
            AgentDeviceKey.tenant_id == tenant_id,
        ).update({"enabled": False})
        session.commit()

    audit_admin_action(
        action=f"agent-revoke:{device_id}",
        tenant_id=tenant_id,
        request=request,
        details={"device_id": device_id},
    )
    return {"revoked": True}
