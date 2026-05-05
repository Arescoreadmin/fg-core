"""
admin_gateway/routers/core_proxy.py — Public passthrough proxy for fg-core.

Forwards /core/{path} → fg-core without auth, serving the customer-facing
assessment and report flow. The assessment UUID itself is the access token
on these endpoints (UUID is unguessable; see api/assessments.py).

Only assessment/* and webhooks/* paths are reachable this way; all other
fg-core admin/governance endpoints remain gated behind the /admin router.
"""
from __future__ import annotations

import logging
import os

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

log = logging.getLogger("admin-gateway.core-proxy")

router = APIRouter(tags=["core-proxy"])

# Paths under /core that this passthrough allows. Any prefix not in this list
# returns 403 — prevents accidental exposure of internal fg-core admin routes.
_ALLOWED_PREFIXES = (
    "assessment/",
)


def _core_base_url() -> str:
    url = os.environ.get("AG_CORE_BASE_URL", "http://frostgate-core:8080")
    return url.rstrip("/")


@router.api_route("/core/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def core_passthrough(path: str, request: Request) -> Response:
    """
    Proxy /core/{path} to fg-core at /{path} with no auth headers.
    Only paths matching _ALLOWED_PREFIXES are forwarded.
    """
    if not any(path.startswith(p) for p in _ALLOWED_PREFIXES):
        raise HTTPException(
            status_code=403,
            detail=f"Path /core/{path} is not accessible through this proxy.",
        )

    base_url = _core_base_url()
    target_url = f"{base_url}/{path}"
    params = dict(request.query_params)

    # Pass through a minimal set of headers — no internal auth tokens
    forward_headers = {
        "Content-Type": request.headers.get("Content-Type", "application/json"),
    }
    # Forward Stripe-Signature for webhook verification
    if "stripe-signature" in request.headers:
        forward_headers["stripe-signature"] = request.headers["stripe-signature"]

    body = await request.body()

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            upstream = await client.request(
                method=request.method,
                url=target_url,
                params=params,
                content=body,
                headers=forward_headers,
            )
    except httpx.RequestError as exc:
        log.error("core_proxy.request_failed path=%s error=%s", path, exc)
        raise HTTPException(status_code=502, detail="fg-core unreachable")

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers={"Content-Type": upstream.headers.get("Content-Type", "application/json")},
    )
