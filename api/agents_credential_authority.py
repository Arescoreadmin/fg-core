# api/agents_credential_authority.py
"""R4.10 — Agent and Device Credential Authority API.

Canonical lifecycle management for agent and device credentials.
All authentication flows resolve through the credential authority;
no independent credential validation exists in this module.

Routes (admin plane — requires admin:write):
  POST   /admin/agents/bootstrap             Issue one-time bootstrap token
  POST   /admin/agents/{agent_id}/rotate     Rotate credential by slot
  POST   /admin/agents/{agent_id}/revoke     Revoke credential
  POST   /admin/agents/{agent_id}/suspend    Suspend credential
  POST   /admin/agents/{agent_id}/resume     Resume credential
  GET    /admin/agents/{agent_id}/credential Get current credential record
  GET    /admin/devices/{device_id}/credential Get credential record by device_id

Routes (agent plane — requires agent bootstrap token exchange):
  POST   /agents/enroll                      Exchange bootstrap token for credential
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

import api.credential_authority as ca
from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from api.deps import tenant_db_required

log = logging.getLogger("frostgate.agents_credential_authority")

admin_router = APIRouter(
    prefix="/admin/agents",
    tags=["agent-credential-authority"],
    dependencies=[Depends(require_scopes("admin:write"))],
)

agent_router = APIRouter(
    prefix="/agents",
    tags=["agent-enrollment"],
)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class BootstrapTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="agent_bootstrap", max_length=256)
    ttl_seconds: int = Field(
        default=ca.DEFAULT_BOOTSTRAP_TOKEN_TTL_SECONDS, ge=60, le=86400
    )
    max_uses: int = Field(default=1, ge=1, le=10)


class BootstrapTokenResponse(BaseModel):
    token: str
    tenant_id: str
    expires_at: str
    enrollment_id: int


class EnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bootstrap_token: str = Field(min_length=8, max_length=256)
    agent_id: str = Field(min_length=1, max_length=122)
    device_id: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = Field(min_length=1, max_length=64)
    architecture: str = Field(min_length=1, max_length=32)
    os_version: str = Field(min_length=1, max_length=128)
    agent_version: str = Field(min_length=1, max_length=64)
    hardware_fingerprint: str = Field(min_length=1, max_length=512)
    deployment_environment: str = Field(default="prod", max_length=32)
    trust_level: str = Field(default="full", max_length=32)


class EnrollResponse(BaseModel):
    credential_id: str
    agent_secret: str  # shown exactly once
    credential_slot: str
    expires_at: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


class RotateResponse(BaseModel):
    credential_id: str
    agent_secret: str
    credential_slot: str
    expires_at: Optional[str] = None
    generation: int


class CredentialInfoResponse(BaseModel):
    credential_id: str
    credential_type: str
    credential_slot: str
    status: str
    generation: int
    expires_at: Optional[str] = None
    issued_at: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


class SuspendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="admin_suspend", max_length=256)


class RevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="admin_revoke", max_length=256)


class StatusResponse(BaseModel):
    ok: bool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _actor(request: Request) -> str:
    return str(getattr(getattr(request.state, "auth", None), "key_prefix", "unknown"))


def _dt_iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def _record_to_info(rec: ca.CredentialRecord) -> CredentialInfoResponse:
    return CredentialInfoResponse(
        credential_id=rec.credential_id,
        credential_type=rec.credential_type,
        credential_slot=rec.credential_slot,
        status=rec.status,
        generation=rec.generation,
        expires_at=_dt_iso(rec.expires_at),
        issued_at=_dt_iso(rec.issued_at),
        metadata=rec.metadata,
    )


def _get_credential_by_slot(
    engine: object, tenant_id: str, slot: str
) -> ca.CredentialRecord:
    """Return the most-recent (highest generation) credential for a slot.

    Raises HTTPException(404) when the slot has never been issued.
    """
    from sqlalchemy.engine import Engine

    assert isinstance(engine, Engine)
    try:
        rec = ca.get_active_credential_for_slot(
            engine,
            tenant_id=tenant_id,
            credential_type="agent_device",
            credential_slot=slot,
        )
    except ca.CredentialNotFoundError as exc:
        if not exc.absent:
            # Slot exists but credential is revoked/suspended — still return info
            pass
        raise HTTPException(status_code=404, detail="CREDENTIAL_NOT_FOUND") from exc

    if rec is None:
        raise HTTPException(status_code=404, detail="CREDENTIAL_NOT_FOUND")
    return rec


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------


@admin_router.post("/bootstrap")
def bootstrap(
    body: BootstrapTokenRequest,
    request: Request,
) -> BootstrapTokenResponse:
    """Issue a one-time bootstrap token for an agent to enroll with."""
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    engine = get_engine()

    try:
        result = ca.issue_bootstrap_token(
            engine,
            tenant_id=tenant_id,
            actor_id=actor,
            ttl_seconds=body.ttl_seconds,
            reason=body.reason,
            max_uses=body.max_uses,
        )
    except ca.TenantLifecycleError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ca.TenantNotFoundError as exc:
        raise HTTPException(status_code=404, detail="TENANT_NOT_FOUND") from exc

    return BootstrapTokenResponse(
        token=result.raw_token,
        tenant_id=result.tenant_id,
        expires_at=result.expires_at.isoformat(),
        enrollment_id=result.enrollment_id,
    )


@admin_router.get("/{agent_id}/credential")
def get_agent_credential(
    agent_id: str,
    request: Request,
) -> CredentialInfoResponse:
    """Get the current credential record for an agent."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    slot = f"agent:{agent_id}"

    try:
        rec = ca.get_active_credential_for_slot(
            engine,
            tenant_id=tenant_id,
            credential_type="agent_device",
            credential_slot=slot,
        )
    except ca.CredentialNotFoundError as exc:
        if not exc.absent:
            # Slot exists but credential is in terminal/suspended state — look up by slot
            raise HTTPException(
                status_code=404, detail="AGENT_CREDENTIAL_REVOKED_OR_EXPIRED"
            ) from exc
        raise HTTPException(status_code=404, detail="CREDENTIAL_NOT_FOUND") from exc

    if rec is None:
        raise HTTPException(status_code=404, detail="CREDENTIAL_NOT_FOUND")

    return _record_to_info(rec)


@admin_router.post("/{agent_id}/rotate")
def rotate_agent_credential(
    agent_id: str,
    request: Request,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
) -> RotateResponse:
    """Rotate the canonical credential for an agent."""
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    engine = get_engine()
    slot = f"agent:{agent_id}"

    try:
        result = ca.rotate_credential(
            engine,
            tenant_id=tenant_id,
            credential_type="agent_device",
            credential_slot=slot,
            actor_id=actor,
            idempotency_key=idempotency_key,
        )
    except ca.CredentialSlotNotFoundError as exc:
        raise HTTPException(status_code=404, detail="CREDENTIAL_NOT_FOUND") from exc
    except ca.CredentialStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ca.TenantLifecycleError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    if result.plaintext_secret is None:
        raise HTTPException(
            status_code=409,
            detail="ROTATE_IDEMPOTENCY_REPLAY_NO_SECRET",
        )

    return RotateResponse(
        credential_id=result.record.credential_id,
        agent_secret=result.plaintext_secret,
        credential_slot=result.record.credential_slot,
        expires_at=_dt_iso(result.record.expires_at),
        generation=result.record.generation,
    )


@admin_router.post("/{agent_id}/revoke")
def revoke_agent_credential(
    agent_id: str,
    body: RevokeRequest,
    request: Request,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    db: Session = Depends(tenant_db_required),
) -> StatusResponse:
    """Revoke the canonical credential for an agent."""
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    engine = get_engine()
    slot = f"agent:{agent_id}"

    # Resolve credential_id from slot.
    try:
        rec = ca.get_active_credential_for_slot(
            engine,
            tenant_id=tenant_id,
            credential_type="agent_device",
            credential_slot=slot,
        )
    except ca.CredentialNotFoundError as exc:
        if exc.absent:
            raise HTTPException(status_code=404, detail="CREDENTIAL_NOT_FOUND") from exc
        # Already revoked/expired — treat as idempotent success.
        return StatusResponse(ok=True)

    if rec is None:
        raise HTTPException(status_code=404, detail="CREDENTIAL_NOT_FOUND")

    try:
        ca.revoke_credential(
            engine,
            credential_id=rec.credential_id,
            tenant_id=tenant_id,
            actor_id=actor,
            reason=body.reason,
            request_id=idempotency_key,
        )
    except ca.CredentialStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return StatusResponse(ok=True)


@admin_router.post("/{agent_id}/suspend")
def suspend_agent_credential(
    agent_id: str,
    body: SuspendRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> StatusResponse:
    """Suspend the active credential for an agent (reversible)."""
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    engine = get_engine()
    slot = f"agent:{agent_id}"

    try:
        rec = ca.get_active_credential_for_slot(
            engine,
            tenant_id=tenant_id,
            credential_type="agent_device",
            credential_slot=slot,
        )
    except ca.CredentialNotFoundError as exc:
        raise HTTPException(status_code=404, detail="CREDENTIAL_NOT_FOUND") from exc

    if rec is None:
        raise HTTPException(status_code=404, detail="CREDENTIAL_NOT_FOUND")

    try:
        ca.suspend_credential(
            engine,
            credential_id=rec.credential_id,
            tenant_id=tenant_id,
            actor_id=actor,
            reason=body.reason,
        )
    except ca.CredentialStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return StatusResponse(ok=True)


@admin_router.post("/{agent_id}/resume")
def resume_agent_credential(
    agent_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> StatusResponse:
    """Resume a suspended agent credential."""
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    engine = get_engine()
    slot = f"agent:{agent_id}"

    # For resume we need to find the credential even when suspended.
    # Query tenant_credentials directly since get_active_credential_for_slot
    # raises absent=False for suspended creds (correct fail-closed behavior).
    with engine.begin() as conn:
        row = conn.execute(
            text(
                "SELECT credential_id FROM tenant_credentials "
                "WHERE tenant_id = :tid AND credential_type = 'agent_device' "
                "  AND credential_slot = :slot AND status = 'suspended' "
                "ORDER BY generation DESC LIMIT 1"
            ),
            {"tid": tenant_id, "slot": slot},
        ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="NO_SUSPENDED_CREDENTIAL_FOR_AGENT",
        )

    try:
        ca.resume_credential(
            engine,
            credential_id=row[0],
            tenant_id=tenant_id,
            actor_id=actor,
        )
    except ca.CredentialStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return StatusResponse(ok=True)


# ---------------------------------------------------------------------------
# Device routes (by device_id from metadata)
# ---------------------------------------------------------------------------

device_router = APIRouter(
    prefix="/admin/devices",
    tags=["device-credential-authority"],
    dependencies=[Depends(require_scopes("admin:write"))],
)


@device_router.get("/{device_id}/credential")
def get_device_credential(
    device_id: str,
    request: Request,
) -> CredentialInfoResponse:
    """Get the credential record associated with a device_id (metadata lookup)."""
    tenant_id = require_bound_tenant(request)
    engine = get_engine()

    is_postgres = engine.dialect.name == "postgresql"
    json_filter = (
        "metadata ->> 'device_id'"
        if is_postgres
        else "JSON_EXTRACT(metadata, '$.device_id')"
    )

    with engine.begin() as conn:
        row = conn.execute(
            text(
                "SELECT credential_id FROM tenant_credentials "
                "WHERE tenant_id = :tid AND credential_type = 'agent_device' "
                f"  AND {json_filter} = :did "
                "ORDER BY generation DESC LIMIT 1"
            ),
            {"tid": tenant_id, "did": device_id},
        ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="CREDENTIAL_NOT_FOUND")

    try:
        rec = ca.get_credential(engine, row[0], tenant_id)
    except ca.CredentialNotFoundError as exc:
        raise HTTPException(status_code=404, detail="CREDENTIAL_NOT_FOUND") from exc

    return _record_to_info(rec)


@device_router.post("/{device_id}/suspend")
def suspend_device_credential(
    device_id: str,
    body: SuspendRequest,
    request: Request,
) -> StatusResponse:
    """Suspend the credential for a device (reversible)."""
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    engine = get_engine()

    is_postgres = engine.dialect.name == "postgresql"
    json_filter = (
        "metadata ->> 'device_id'"
        if is_postgres
        else "JSON_EXTRACT(metadata, '$.device_id')"
    )

    with engine.begin() as conn:
        row = conn.execute(
            text(
                "SELECT credential_id FROM tenant_credentials "
                "WHERE tenant_id = :tid AND credential_type = 'agent_device' "
                f"  AND {json_filter} = :did "
                "  AND status = 'active' "
                "ORDER BY generation DESC LIMIT 1"
            ),
            {"tid": tenant_id, "did": device_id},
        ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="NO_ACTIVE_CREDENTIAL_FOR_DEVICE")

    try:
        ca.suspend_credential(
            engine,
            credential_id=row[0],
            tenant_id=tenant_id,
            actor_id=actor,
            reason=body.reason,
        )
    except ca.CredentialStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return StatusResponse(ok=True)


@device_router.post("/{device_id}/resume")
def resume_device_credential(
    device_id: str,
    request: Request,
) -> StatusResponse:
    """Resume a suspended device credential."""
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    engine = get_engine()

    is_postgres = engine.dialect.name == "postgresql"
    json_filter = (
        "metadata ->> 'device_id'"
        if is_postgres
        else "JSON_EXTRACT(metadata, '$.device_id')"
    )

    with engine.begin() as conn:
        row = conn.execute(
            text(
                "SELECT credential_id FROM tenant_credentials "
                "WHERE tenant_id = :tid AND credential_type = 'agent_device' "
                f"  AND {json_filter} = :did "
                "  AND status = 'suspended' "
                "ORDER BY generation DESC LIMIT 1"
            ),
            {"tid": tenant_id, "did": device_id},
        ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=404, detail="NO_SUSPENDED_CREDENTIAL_FOR_DEVICE"
        )

    try:
        ca.resume_credential(
            engine,
            credential_id=row[0],
            tenant_id=tenant_id,
            actor_id=actor,
        )
    except ca.CredentialStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return StatusResponse(ok=True)


# ---------------------------------------------------------------------------
# Agent enrollment route (unauthenticated — bootstrap token is the credential)
# ---------------------------------------------------------------------------


@agent_router.post("/enroll")
def enroll_agent(body: EnrollRequest, request: Request) -> EnrollResponse:
    """Exchange a bootstrap token for a canonical agent_device credential.

    The bootstrap token is consumed atomically. The returned agent_secret is
    shown exactly once and must be stored securely by the agent.
    """
    # Tenant is resolved from a special header on this unauthenticated route.
    tenant_id = request.headers.get("x-tenant-id", "").strip()
    if not tenant_id:
        raise HTTPException(status_code=400, detail="X-Tenant-Id header required")

    engine = get_engine()

    try:
        result = ca.exchange_bootstrap_token(
            engine,
            tenant_id=tenant_id,
            raw_token=body.bootstrap_token,
            agent_id=body.agent_id,
            device_id=body.device_id,
            hostname=body.hostname,
            platform=body.platform,
            architecture=body.architecture,
            os_version=body.os_version,
            agent_version=body.agent_version,
            hardware_fingerprint=body.hardware_fingerprint,
            deployment_environment=body.deployment_environment,
            trust_level=body.trust_level,
            actor_id="agent_self_enrollment",
        )
    except ca.CredentialNotFoundError as exc:
        raise HTTPException(status_code=401, detail="INVALID_BOOTSTRAP_TOKEN") from exc
    except ca.CredentialStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ca.TenantLifecycleError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ca.TenantNotFoundError as exc:
        raise HTTPException(status_code=404, detail="TENANT_NOT_FOUND") from exc

    rec = result.record
    return EnrollResponse(
        credential_id=rec.credential_id,
        agent_secret=result.plaintext_secret or "",
        credential_slot=rec.credential_slot,
        expires_at=rec.expires_at.isoformat() if rec.expires_at else None,
        metadata=rec.metadata,
    )
