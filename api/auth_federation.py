from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from api.auth_scopes import require_bound_tenant, require_scopes
from services.federation_extension import FederationService

router = APIRouter(tags=["auth-federation"])
service = FederationService()


@router.post(
    "/auth/federation/validate",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def validate_federated_identity(request: Request) -> dict[str, object]:
    bound_tenant = require_bound_tenant(request)
    bearer = (request.headers.get("Authorization") or "").strip()
    if not bearer.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "federation_missing_bearer",
                "reason": "missing bearer token",
            },
        )
    token = bearer.split(" ", 1)[1].strip()
    try:
        claims = service.validate_token(token)
    except ValueError as exc:
        raise HTTPException(
            status_code=401,
            detail={"error_code": str(exc), "reason": "token validation failed"},
        ) from exc

    tenant_id = str(claims.get("tenant_id") or claims.get("tid") or "")
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "federation_missing_tenant_claim",
                "reason": "tenant claim required",
            },
        )

    if tenant_id != bound_tenant:
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "federation_tenant_mismatch",
                "reason": "token tenant mismatch",
            },
        )

    groups = claims.get("groups") if isinstance(claims.get("groups"), list) else []
    mapped_roles = service.map_roles([str(g) for g in groups])
    return {
        "tenant_id": tenant_id,
        "subject": claims.get("sub"),
        "issuer": claims.get("iss"),
        "roles": mapped_roles,
        "privileged_session": bool(mapped_roles),
    }
