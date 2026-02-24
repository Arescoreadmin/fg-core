from fastapi import APIRouter, Depends, Header, Request

from api.auth_scopes.resolution import bind_tenant_id, require_scopes

router = APIRouter()


@router.get("/planes", dependencies=[Depends(require_scopes("admin:write"))])
def get_planes(
    request: Request,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
) -> dict[str, object]:
    _ = bind_tenant_id(request, x_tenant_id, require_explicit_for_unscoped=True)
    return {"planes": list_planes()}


def get_planes(
    request: Request,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id"),
) -> dict[str, object]:
    # This will raise 400/403 with redact_detail() behavior.
    _ = bind_tenant_id(request, x_tenant_id, require_explicit_for_unscoped=True)
    return {"planes": list_planes()}
