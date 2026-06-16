from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from api.auth_scopes import require_bound_tenant, require_scopes
from services.federation_extension import FederationService
from services.federation_extension.service import FederationValidationError

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
        principal = service.validate_token(token)
    except FederationValidationError as exc:
        raise HTTPException(
            status_code=401,
            detail={"error_code": exc.error_code, "reason": exc.reason},
        ) from exc

    if principal.tenant_id != bound_tenant:
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "federation_tenant_mismatch",
                "reason": "token tenant mismatch",
            },
        )

    mapped_roles = service.map_roles(principal.groups)
    return {
        "tenant_id": principal.tenant_id,
        "subject": principal.subject,
        "issuer": principal.issuer,
        "roles": mapped_roles,
        "privileged_session": bool(mapped_roles),
    }
