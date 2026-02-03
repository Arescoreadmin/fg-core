"""
API Key Management Router for FrostGate Core.

Provides endpoints for:
- Listing API keys (admin)
- Creating new API keys (admin)
- Revoking API keys (admin)
- Rotating API keys (self-service)
- Key lifecycle management
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator

from api.auth_scopes import (
    bind_tenant_id,
    mint_key,
    revoke_api_key,
    list_api_keys,
    verify_api_key,
    require_scopes,
    _validate_tenant_id,
    DEFAULT_TTL_SECONDS,
)
from api.security_audit import audit_key_created, audit_key_revoked, audit_key_rotated

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
    expires_at: Optional[str] = None
    last_used_at: Optional[str] = None
    use_count: Optional[int] = None


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
def create_key(req: CreateKeyRequest, request: Request) -> CreateKeyResponse:
    """
    Create a new API key.

    Requires `keys:admin` scope.
    """
    try:
        bound_tenant = bind_tenant_id(
            request,
            req.tenant_id,
            require_explicit_for_unscoped=True,
        )
        key = mint_key(
            *req.scopes,
            ttl_seconds=req.ttl_seconds,
            tenant_id=bound_tenant,
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
                "tenant_id": bound_tenant,
                "ttl_seconds": req.ttl_seconds,
            },
        )

        # Audit log the key creation
        audit_key_created(
            key_prefix=prefix,
            scopes=req.scopes,
            tenant_id=bound_tenant,
            request=request,
            ttl_seconds=req.ttl_seconds,
        )

        return CreateKeyResponse(
            key=key,
            prefix=prefix,
            scopes=req.scopes,
            tenant_id=bound_tenant,
            ttl_seconds=req.ttl_seconds,
            expires_at=expires_at,
        )
    except HTTPException:
        raise
    except Exception as e:
        log.exception("Failed to create API key")
        raise HTTPException(status_code=500, detail=f"Failed to create key: {e}")


@router.get("", response_model=ListKeysResponse)
def get_keys(
    request: Request,
    tenant_id: Optional[str] = Query(default=None, max_length=128),
    include_disabled: bool = Query(default=False),
) -> ListKeysResponse:
    """
    List API keys.

    Requires `keys:admin` scope.
    Does not return the actual key secrets.
    """
    # Validate tenant_id if provided
    try:
        bound_tenant = bind_tenant_id(
            request,
            tenant_id,
            require_explicit_for_unscoped=True,
        )
        keys = list_api_keys(
            tenant_id=bound_tenant,
            include_disabled=include_disabled,
        )
        key_infos = [KeyInfo(**k) for k in keys]
        return ListKeysResponse(keys=key_infos, total=len(key_infos))
    except HTTPException:
        raise
    except Exception as e:
        log.exception("Failed to list API keys")
        raise HTTPException(status_code=500, detail=f"Failed to list keys: {e}")


@router.post("/revoke", response_model=RevokeKeyResponse)
def revoke_key(
    req: RevokeKeyRequest,
    request: Request,
    tenant_id: Optional[str] = Query(default=None, max_length=128),
) -> RevokeKeyResponse:
    """
    Revoke (disable) an API key by prefix.

    Requires `keys:admin` scope.
    """
    try:
        bound_tenant = bind_tenant_id(
            request,
            tenant_id,
            require_explicit_for_unscoped=True,
        )
        revoked = revoke_api_key(req.prefix, tenant_id=bound_tenant)

        if revoked:
            log.info("API key revoked", extra={"prefix": req.prefix})
            # Audit log the revocation
            audit_key_revoked(key_prefix=req.prefix, request=request)
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
    except HTTPException:
        raise
    except Exception as e:
        log.exception("Failed to revoke API key")
        raise HTTPException(status_code=500, detail=f"Failed to revoke key: {e}")


@router.delete("/{prefix}", response_model=RevokeKeyResponse)
def delete_key(
    prefix: str,
    request: Request,
    tenant_id: Optional[str] = Query(default=None, max_length=128),
) -> RevokeKeyResponse:
    """
    Delete (revoke) an API key by prefix.

    Requires `keys:admin` scope.
    This is an alias for POST /keys/revoke for REST compliance.
    """
    if not prefix or len(prefix) > 64:
        raise HTTPException(status_code=400, detail="Invalid prefix")

    return revoke_key(RevokeKeyRequest(prefix=prefix), request, tenant_id=tenant_id)


# =============================================================================
# Key Rotation
# =============================================================================


class RotateKeyRequest(BaseModel):
    """Request to rotate an API key."""

    current_key: str = Field(
        min_length=10,
        max_length=256,
        description="The current API key to rotate",
    )
    ttl_seconds: int = Field(
        default=DEFAULT_TTL_SECONDS,
        ge=60,
        le=365 * 24 * 3600,
        description="TTL for the new key (default 24 hours)",
    )
    revoke_old: bool = Field(
        default=True,
        description="Whether to immediately revoke the old key",
    )


class RotateKeyResponse(BaseModel):
    """Response containing the rotated API key."""

    new_key: str = Field(description="The new API key (only shown once)")
    new_prefix: str = Field(description="New key prefix for identification")
    old_prefix: str = Field(description="Old key prefix (for reference)")
    scopes: list[str] = Field(description="Scopes inherited from old key")
    tenant_id: Optional[str] = Field(description="Associated tenant ID")
    expires_at: int = Field(description="Unix timestamp when new key expires")
    old_key_revoked: bool = Field(description="Whether the old key was revoked")


@router.post("/rotate", response_model=RotateKeyResponse)
def rotate_key(
    req: RotateKeyRequest,
    request: Request,
    tenant_id: Optional[str] = Query(default=None, max_length=128),
) -> RotateKeyResponse:
    """
    Rotate an API key, creating a new key with the same scopes.

    This endpoint allows key rotation for security best practices:
    - Creates a new key with the same scopes as the old key
    - Optionally revokes the old key immediately
    - Links the new key to the old key for audit trail

    Requires the current key to be valid and active.
    """
    import sqlite3
    import os
    from api.db import _resolve_sqlite_path
    from api.auth_scopes import _sha256_hex, _parse_scopes_csv

    current_key = req.current_key.strip()
    if not current_key:
        raise HTTPException(status_code=400, detail="Current key is required")

    # Validate the current key exists and is active
    sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
    if not sqlite_path:
        sqlite_path = str(_resolve_sqlite_path())

    # Parse the current key to extract components
    parts = current_key.split(".")
    if len(parts) < 3:
        raise HTTPException(status_code=400, detail="Invalid key format")

    old_prefix = parts[0]
    secret_val = parts[-1]
    old_key_hash = _sha256_hex(secret_val)

    try:
        bound_tenant = bind_tenant_id(
            request,
            tenant_id,
            require_explicit_for_unscoped=True,
        )
        con = sqlite3.connect(sqlite_path)
        try:
            row = con.execute(
                "SELECT id, scopes_csv, enabled, tenant_id FROM api_keys WHERE prefix=? AND key_hash=? LIMIT 1",
                (old_prefix, old_key_hash),
            ).fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="Key not found")

            key_id, scopes_csv, enabled, db_tenant_id = row

            if not enabled:
                raise HTTPException(status_code=400, detail="Key is already disabled")

            if not db_tenant_id or db_tenant_id != bound_tenant:
                raise HTTPException(status_code=403, detail="Tenant mismatch")

            # Parse scopes from old key
            scopes = list(_parse_scopes_csv(scopes_csv))

            # Create new key with same scopes
            new_key = mint_key(
                *scopes,
                ttl_seconds=req.ttl_seconds,
                tenant_id=db_tenant_id,
            )

            new_parts = new_key.split(".")
            new_prefix = new_parts[0] if new_parts else "fgk"

            # Link the new key to the old key for audit trail
            new_secret = new_parts[-1]
            new_key_hash = _sha256_hex(new_secret)
            con.execute(
                "UPDATE api_keys SET rotated_from=? WHERE key_hash=?",
                (old_key_hash, new_key_hash),
            )

            # Revoke old key if requested
            old_key_revoked = False
            if req.revoke_old:
                con.execute(
                    "UPDATE api_keys SET enabled=0 WHERE id=?",
                    (key_id,),
                )
                old_key_revoked = True

            con.commit()

            now = int(time.time())
            expires_at = now + req.ttl_seconds

            log.info(
                "API key rotated",
                extra={
                    "old_prefix": old_prefix,
                    "new_prefix": new_prefix,
                    "tenant_id": db_tenant_id,
                    "old_key_revoked": old_key_revoked,
                },
            )

            # Audit log the rotation
            audit_key_rotated(
                old_prefix=old_prefix,
                new_prefix=new_prefix,
                tenant_id=db_tenant_id,
                request=request,
                old_key_revoked=old_key_revoked,
            )

            return RotateKeyResponse(
                new_key=new_key,
                new_prefix=new_prefix,
                old_prefix=old_prefix,
                scopes=scopes,
                tenant_id=db_tenant_id,
                expires_at=expires_at,
                old_key_revoked=old_key_revoked,
            )

        finally:
            con.close()

    except HTTPException:
        raise
    except Exception as e:
        log.exception("Failed to rotate API key")
        raise HTTPException(status_code=500, detail=f"Failed to rotate key: {e}")
