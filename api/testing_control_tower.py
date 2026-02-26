from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status

from api.auth_scopes import require_bound_tenant, require_scopes

router = APIRouter(prefix="/control-plane/v2/testing", tags=["testing-control-tower"])


@router.get("/lanes", dependencies=[Depends(require_scopes("control-plane:read"))])
def list_lanes(request: Request) -> dict[str, object]:
    _ = require_bound_tenant(request)
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "error": {
                "code": "FG-TESTING-501",
                "message": "Testing Control Tower backend not implemented yet",
            }
        },
    )


@router.post("/runs", dependencies=[Depends(require_scopes("control-plane:admin"))])
def start_run(request: Request) -> dict[str, object]:
    _ = require_bound_tenant(request)
    trace_id = request.headers.get("x-request-id") or ""
    return {
        "status": "not_implemented",
        "trace_id": trace_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


@router.get("/runs/{run_id}/artifacts", dependencies=[Depends(require_scopes("control-plane:read"))])
def run_artifacts(run_id: str, request: Request) -> dict[str, object]:
    _ = require_bound_tenant(request)
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={
            "error": {
                "code": "FG-TESTING-502",
                "message": f"Artifacts for run {run_id} not implemented",
            }
        },
    )
