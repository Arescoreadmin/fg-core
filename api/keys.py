"""
API Key Management Router for FrostGate Core.

Provides endpoints for:
- Listing API keys (admin)
- Creating new API keys (admin)
- Revoking API keys (admin)
- Rotating API keys (self-service)
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from api.auth_scopes import (
    mint_key,
    revoke_api_key,
    list_api_keys,
    verify_api_key,
    require_scopes,
    _validate_tenant_id,
    DEFAULT_TTL_SECONDS,
)

log = logging.getLogger("frostgate.keys")

router = APIRouter(
    prefix="/keys",
    tags=["keys"],
    dependencies=[
        Depends(verify_api_key),
        Depends(require_scopes("keys:admin")),
    ],
)


class CreateKeyRequest(BaseModel):
    """Request to create a new API key."""

    name: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Human-readable name for the key",
    )
    scopes: list[str] = Field(
        default_factory=list,
        description="List of scopes to grant to the key",
    )
    tenant_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Tenant ID to associate with the key",
    )
    ttl_seconds: int = Field(
        default=DEFAULT_TTL_SECONDS,
        ge=60,
        le=365 * 24 * 3600,  # Max 1 year
        description="Time-to-live in seconds (default 24 hours)",
    )

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, v):
        if not v:
            return v
        # Validate scope format
        valid_scopes = []
        for scope in v:
            scope = str(scope).strip()
            if not scope:
                continue
            # Scope should be alphanumeric with : and * allowed
            if not all(c.isalnum() or c in ":*_-" for c in scope):
                raise ValueError(f"Invalid scope format: {scope}")
            if len(scope) > 64:
                raise ValueError(f"Scope too long: {scope}")
            valid_scopes.append(scope)
        return valid_scopes

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id(cls, v):
        if v is None:
            return v
        is_valid, error = _validate_tenant_id(v)
        if not is_valid:
            raise ValueError(error)
        return v


class CreateKeyResponse(BaseModel):
    """Response containing the newly created API key."""

    key: str = Field(description="The full API key (only shown once)")
    prefix: str = Field(description="Key prefix for identification")
    scopes: list[str] = Field(description="Scopes granted to the key")
    tenant_id: Optional[str] = Field(description="Associated tenant ID")
    ttl_seconds: int = Field(description="Time-to-live in seconds")
    expires_at: int = Field(description="Unix timestamp when key expires")


class KeyInfo(BaseModel):
    """Information about an API key (without the secret)."""

    prefix: str
    name: Optional[str] = None
    scopes: list[str] = Field(default_factory=list)
    enabled: bool = True
    tenant_id: Optional[str] = None
    created_at: Optional[str] = None


class ListKeysResponse(BaseModel):
    """Response containing list of API keys."""

    keys: list[KeyInfo]
    total: int


class RevokeKeyRequest(BaseModel):
    """Request to revoke an API key."""

    prefix: str = Field(
        min_length=1,
        max_length=64,
        description="Key prefix to revoke",
    )


class RevokeKeyResponse(BaseModel):
    """Response after revoking an API key."""

    revoked: bool
    prefix: str
    message: str


@router.post("", response_model=CreateKeyResponse)
def create_key(req: CreateKeyRequest) -> CreateKeyResponse:
    """
    Create a new API key.

    Requires `keys:admin` scope.
    """
    import time

    try:
        key = mint_key(
            *req.scopes,
            ttl_seconds=req.ttl_seconds,
            tenant_id=req.tenant_id,
        )

        # Extract prefix from key
        parts = key.split(".")
        prefix = parts[0] if parts else "fgk"

        now = int(time.time())
        expires_at = now + req.ttl_seconds

        log.info(
            "API key created",
            extra={
                "prefix": prefix,
                "scopes": req.scopes,
                "tenant_id": req.tenant_id,
                "ttl_seconds": req.ttl_seconds,
            },
        )

        return CreateKeyResponse(
            key=key,
            prefix=prefix,
            scopes=req.scopes,
            tenant_id=req.tenant_id,
            ttl_seconds=req.ttl_seconds,
            expires_at=expires_at,
        )
    except Exception as e:
        log.exception("Failed to create API key")
        raise HTTPException(status_code=500, detail=f"Failed to create key: {e}")


@router.get("", response_model=ListKeysResponse)
def get_keys(
    tenant_id: Optional[str] = Query(default=None, max_length=128),
    include_disabled: bool = Query(default=False),
) -> ListKeysResponse:
    """
    List API keys.

    Requires `keys:admin` scope.
    Does not return the actual key secrets.
    """
    # Validate tenant_id if provided
    if tenant_id:
        is_valid, error = _validate_tenant_id(tenant_id)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error)

    try:
        keys = list_api_keys(tenant_id=tenant_id, include_disabled=include_disabled)
        key_infos = [KeyInfo(**k) for k in keys]
        return ListKeysResponse(keys=key_infos, total=len(key_infos))
    except Exception as e:
        log.exception("Failed to list API keys")
        raise HTTPException(status_code=500, detail=f"Failed to list keys: {e}")


@router.post("/revoke", response_model=RevokeKeyResponse)
def revoke_key(req: RevokeKeyRequest) -> RevokeKeyResponse:
    """
    Revoke (disable) an API key by prefix.

    Requires `keys:admin` scope.
    """
    try:
        revoked = revoke_api_key(req.prefix)

        if revoked:
            log.info("API key revoked", extra={"prefix": req.prefix})
            return RevokeKeyResponse(
                revoked=True,
                prefix=req.prefix,
                message="Key successfully revoked",
            )
        else:
            return RevokeKeyResponse(
                revoked=False,
                prefix=req.prefix,
                message="Key not found or already revoked",
            )
    except Exception as e:
        log.exception("Failed to revoke API key")
        raise HTTPException(status_code=500, detail=f"Failed to revoke key: {e}")


@router.delete("/{prefix}", response_model=RevokeKeyResponse)
def delete_key(prefix: str) -> RevokeKeyResponse:
    """
    Delete (revoke) an API key by prefix.

    Requires `keys:admin` scope.
    This is an alias for POST /keys/revoke for REST compliance.
    """
    if not prefix or len(prefix) > 64:
        raise HTTPException(status_code=400, detail="Invalid prefix")

    return revoke_key(RevokeKeyRequest(prefix=prefix))
