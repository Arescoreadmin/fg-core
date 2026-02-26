from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from api.auth_scopes import require_bound_tenant, require_scopes
from api.ui_guard import ui_enabled_guard

router = APIRouter(
    prefix="/ui/dash",
    tags=["ui-testing-control-tower"],
    dependencies=[Depends(ui_enabled_guard), Depends(require_scopes("ui:read"))],
)


@router.get("/testing-control-tower", response_class=HTMLResponse)
def testing_control_tower_ui(request: Request) -> str:
    _ = require_bound_tenant(request)
    return """
<!doctype html>
<html><head><title>Testing Control Tower (Preview)</title></head>
<body>
  <h1>Testing Control Tower</h1>
  <p>Feature flag enabled, implementation pending (Phase 3+).</p>
</body></html>
"""
