from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock

from packaging.version import InvalidVersion
from packaging.version import Version as _Version

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from api.db_models import (
    AgentCollectorStatus,
    AgentDeviceKey,
    AgentDeviceRegistry,
    AgentEnrollmentToken,
    AgentTenantConfig,
)
from api.security_audit import audit_admin_action

log = logging.getLogger("frostgate.agent.admin")

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
    pepper = (
        os.getenv("FG_AGENT_TOKEN_PEPPER") or os.getenv("FG_KEY_PEPPER") or ""
    ).strip()
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


@router.post(
    "/enrollment-tokens",
    response_model=EnrollmentTokenCreateResponse,
    responses={429: {"description": "Too Many Requests"}},
)
def create_enrollment_token(
    body: EnrollmentTokenCreateRequest,
    request: Request,
) -> EnrollmentTokenCreateResponse:
    tenant_id = require_bound_tenant(request)
    auth_ctx = getattr(request.state, "auth", None)
    actor_id = getattr(auth_ctx, "key_prefix", None) or "admin"

    if not _TOKEN_ISSUE_LIMITER.allow(
        f"tenant:{tenant_id}", rate_per_sec=1 / 30.0, burst=3
    ):
        raise HTTPException(
            status_code=429, detail="tenant token issuance rate limited"
        )
    if not _TOKEN_ISSUE_LIMITER.allow(
        f"actor:{actor_id}", rate_per_sec=1 / 60.0, burst=2
    ):
        raise HTTPException(status_code=429, detail="admin token issuance rate limited")

    raw = f"agt_{secrets.token_urlsafe(24)}"
    expires_at = _utcnow() + timedelta(minutes=body.ttl_minutes)
    max_active_per_tenant = int(
        os.getenv("FG_AGENT_MAX_ACTIVE_TOKENS_PER_TENANT", "10")
    )

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
            raise HTTPException(
                status_code=429, detail="too many active enrollment tokens for tenant"
            )

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
                    last_seen_at=(
                        row.last_seen_at.isoformat() if row.last_seen_at else None
                    ),
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


@router.post("/devices/{device_id}/disable")
def disable_device(device_id: str, request: Request) -> dict[str, bool]:
    """
    Soft-disable a device.  Reversible via /enable.  All device keys are
    disabled so the agent cannot authenticate.  Revoked devices cannot be
    disabled (they are already permanently blocked).
    """
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
        if device.status == "revoked":
            raise HTTPException(
                status_code=409, detail="revoked device cannot be disabled"
            )
        device.status = "disabled"
        session.query(AgentDeviceKey).filter(
            AgentDeviceKey.device_id == device_id,
            AgentDeviceKey.tenant_id == tenant_id,
        ).update({"enabled": False})
        session.commit()

    audit_admin_action(
        action=f"agent-disable:{device_id}",
        tenant_id=tenant_id,
        request=request,
        details={"device_id": device_id},
    )
    return {"disabled": True}


@router.post("/devices/{device_id}/enable")
def enable_device(device_id: str, request: Request) -> dict[str, bool]:
    """
    Re-enable a previously disabled device.  Only the most recently created
    device key is re-activated; older rotated keys remain inactive.
    Revoked devices cannot be re-enabled.
    """
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
        if device.status == "revoked":
            raise HTTPException(
                status_code=409, detail="revoked device cannot be re-enabled"
            )
        if device.status != "disabled":
            raise HTTPException(status_code=409, detail="device is not disabled")
        device.status = "active"
        # Re-enable only the most recently created key to avoid activating
        # stale rotated keys that were intentionally disabled before the
        # disable action.
        latest_key = (
            session.query(AgentDeviceKey)
            .filter(
                AgentDeviceKey.device_id == device_id,
                AgentDeviceKey.tenant_id == tenant_id,
            )
            .order_by(AgentDeviceKey.created_at.desc())
            .first()
        )
        if latest_key is not None:
            latest_key.enabled = True
        session.commit()

    audit_admin_action(
        action=f"agent-enable:{device_id}",
        tenant_id=tenant_id,
        request=request,
        details={"device_id": device_id},
    )
    return {"enabled": True}


class VersionFloorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version_floor: str | None = Field(default=None, max_length=64)


class VersionFloorResponse(BaseModel):
    version_floor: str | None = None


@router.get("/version-floor", response_model=VersionFloorResponse)
def get_version_floor(request: Request) -> VersionFloorResponse:
    """Return the per-tenant agent version floor, or null if unset."""
    tenant_id = require_bound_tenant(request)

    engine = get_engine()
    with Session(engine) as session:
        tc = session.get(AgentTenantConfig, tenant_id)
        return VersionFloorResponse(
            version_floor=(tc.version_floor or None) if tc else None
        )


@router.put("/version-floor", response_model=VersionFloorResponse)
def set_version_floor(
    body: VersionFloorRequest, request: Request
) -> VersionFloorResponse:
    """
    Set (or clear) the per-tenant minimum agent version.
    Agents below this floor will receive action='shutdown' on heartbeat and
    config fetch.  Set version_floor=null to remove the per-tenant floor
    (global FG_AGENT_MIN_VERSION env var still applies).
    """
    tenant_id = require_bound_tenant(request)
    auth_ctx = getattr(request.state, "auth", None)
    actor_id = getattr(auth_ctx, "key_prefix", None) or "admin"

    engine = get_engine()
    with Session(engine) as session:
        tc = session.get(AgentTenantConfig, tenant_id)
        if tc is None:
            tc = AgentTenantConfig(
                tenant_id=tenant_id,
                version_floor=body.version_floor,
                updated_at=_utcnow(),
                updated_by=actor_id,
            )
            session.add(tc)
        else:
            tc.version_floor = body.version_floor
            tc.updated_at = _utcnow()
            tc.updated_by = actor_id
        session.commit()

    audit_admin_action(
        action="agent-version-floor-set",
        tenant_id=tenant_id,
        request=request,
        details={
            "version_floor": body.version_floor,
            "actor_id": actor_id,
        },
    )
    return VersionFloorResponse(version_floor=body.version_floor)


# ---------------------------------------------------------------------------
# Observability — task 17.5
# ---------------------------------------------------------------------------


def _no_heartbeat_threshold() -> int:
    """Read threshold at request time so tests can override via env."""
    return int(os.getenv("FG_AGENT_NO_HEARTBEAT_SECONDS", "3600"))


# Health status values (deterministic, not collapsed into generic blobs).
_HEALTH_REVOKED = "revoked"
_HEALTH_DISABLED = "disabled"
_HEALTH_OUTDATED = "outdated"
_HEALTH_NO_HEARTBEAT = "no_heartbeat"
_HEALTH_DEGRADED = "degraded"
_HEALTH_HEALTHY = "healthy"
_HEALTH_UNKNOWN = "unknown"


class CollectorStatusItem(BaseModel):
    collector_name: str
    last_outcome: str  # "ran" | "failed" | "skipped"
    last_run_at: str
    last_error: str | None = None


class AgentObservabilityResponse(BaseModel):
    device_id: str
    tenant_id: str
    health_status: str
    lifecycle_status: str
    last_seen_at: str | None
    version: str | None
    version_floor: str | None
    effective_min_version: str | None
    collector_statuses: list[CollectorStatusItem]
    backlog_state: str
    backlog_reason: str
    reasons: list[str]


def _version_below_floor(version: str, floor: str) -> bool:
    """
    Return True if version is semantically below floor.

    Uses packaging.version.Version for PEP 440 / semver-aware comparison so
    that 10.0.0 > 2.0.0 (lexicographic comparison would invert this).
    If either string is not parseable as a valid version, falls back to True
    (fail-closed: treat unparseable agent version as below floor).
    """
    try:
        return _Version(version) < _Version(floor)
    except InvalidVersion:
        log.warning(
            "version_floor_compare_failed version=%r floor=%r; treating as below floor",
            version,
            floor,
        )
        return True


def _derive_health(
    *,
    lifecycle_status: str,
    last_seen_at: datetime | None,
    version: str | None,
    effective_floor: str,
    collector_statuses: list[AgentCollectorStatus],
    now: datetime,
) -> tuple[str, list[str]]:
    """
    Derive a deterministic health_status and list of actionable reasons.

    Priority (highest first):
      revoked → disabled → outdated → no_heartbeat → degraded → healthy
    """
    reasons: list[str] = []

    if lifecycle_status == "revoked":
        reasons.append("DEVICE_REVOKED")
        return _HEALTH_REVOKED, reasons

    if lifecycle_status == "disabled":
        reasons.append("DEVICE_DISABLED")
        return _HEALTH_DISABLED, reasons

    if effective_floor and version and _version_below_floor(version, effective_floor):
        reasons.append(f"VERSION_BELOW_FLOOR:{version}<{effective_floor}")
        return _HEALTH_OUTDATED, reasons

    if last_seen_at is None:
        reasons.append("NO_HEARTBEAT_RECORDED")
        return _HEALTH_NO_HEARTBEAT, reasons

    # SQLite stores datetimes as naive; normalise to UTC-aware for comparison.
    last_seen_aware = (
        last_seen_at.replace(tzinfo=UTC)
        if last_seen_at.tzinfo is None
        else last_seen_at
    )
    elapsed = (now - last_seen_aware).total_seconds()
    if elapsed > _no_heartbeat_threshold():
        reasons.append(f"HEARTBEAT_STALE:{int(elapsed)}s_since_last_seen")
        return _HEALTH_NO_HEARTBEAT, reasons

    # Degraded if lifecycle is suspicious or quarantined.
    if lifecycle_status in {"suspicious", "quarantined"}:
        reasons.append(f"DEVICE_{lifecycle_status.upper()}")

    # Collector failures are visible and actionable.
    for cs in collector_statuses:
        if cs.last_outcome == "failed":
            reasons.append(
                f"COLLECTOR_FAILED:{cs.collector_name}:{cs.last_error or 'unknown'}"
            )

    if reasons:
        return _HEALTH_DEGRADED, reasons

    return _HEALTH_HEALTHY, reasons


@router.get(
    "/devices/{device_id}/status",
    response_model=AgentObservabilityResponse,
    responses={
        404: {"description": "Device not found"},
    },
    summary="Get agent observability status",
    description=(
        "Returns health, last_seen, lifecycle state, collector statuses, and backlog "
        "state for a specific device scoped to the caller's tenant."
    ),
)
def get_device_status(
    device_id: str,
    request: Request,
) -> AgentObservabilityResponse:
    """
    Operator observability endpoint — returns deterministic health status.

    Health derivation priority (highest wins):
      revoked → disabled → outdated → no_heartbeat → degraded → healthy

    Tenant isolation: device_id is verified against caller's tenant_id.
    """
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

        # Load per-tenant version floor.
        tc = session.get(AgentTenantConfig, tenant_id)
        tenant_floor = (tc.version_floor or "").strip() if tc else ""
        global_floor = (os.getenv("FG_AGENT_MIN_VERSION") or "").strip()
        effective_floor = tenant_floor or global_floor

        # Load collector statuses for this device (sorted by name for determinism).
        collector_rows = (
            session.query(AgentCollectorStatus)
            .filter(AgentCollectorStatus.device_id == device_id)
            .order_by(AgentCollectorStatus.collector_name)
            .all()
        )

        now = _utcnow()
        health_status, reasons = _derive_health(
            lifecycle_status=device.status,
            last_seen_at=device.last_seen_at,
            version=device.last_version,
            effective_floor=effective_floor,
            collector_statuses=collector_rows,
            now=now,
        )

        collector_items = [
            CollectorStatusItem(
                collector_name=cs.collector_name,
                last_outcome=cs.last_outcome,
                last_run_at=cs.last_run_at.isoformat(),
                last_error=cs.last_error,
            )
            for cs in collector_rows
        ]

        return AgentObservabilityResponse(
            device_id=device.device_id,
            tenant_id=device.tenant_id,
            health_status=health_status,
            lifecycle_status=device.status,
            last_seen_at=(
                device.last_seen_at.isoformat() if device.last_seen_at else None
            ),
            version=device.last_version,
            version_floor=tenant_floor or None,
            effective_min_version=effective_floor or None,
            collector_statuses=collector_items,
            backlog_state="not_tracked",
            backlog_reason="backlog_tracking_not_implemented",
            reasons=reasons,
        )
