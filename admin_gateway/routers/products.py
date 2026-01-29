"""Products Registry API Router.

Provides tenant-scoped CRUD operations for products and their endpoints.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_gateway.auth import Scope, get_current_session, require_scope_dependency
from admin_gateway.auth.session import Session
from admin_gateway.auth.tenant import get_allowed_tenants, validate_tenant_access
from admin_gateway.db import Product, ProductEndpoint, get_db

log = logging.getLogger("admin-gateway.products")

router = APIRouter(prefix="/admin/products", tags=["products"])


# ==============================================================================
# Request/Response Models
# ==============================================================================


class EndpointCreate(BaseModel):
    """Request model for creating a product endpoint."""

    kind: str = Field(..., pattern="^(rest|grpc|nats)$", description="Endpoint type")
    url: Optional[str] = Field(None, max_length=1024, description="URL for REST/gRPC")
    target: Optional[str] = Field(None, max_length=1024, description="Target for NATS")
    meta: Optional[dict[str, Any]] = Field(
        None,
        description="Additional metadata",
        json_schema_extra={"additionalProperties": True},
    )

    @field_validator("kind")
    @classmethod
    def validate_kind(cls, v: str) -> str:
        v = v.lower()
        if v not in ("rest", "grpc", "nats"):
            raise ValueError("kind must be rest, grpc, or nats")
        return v


class ProductCreate(BaseModel):
    """Request model for creating a product."""

    slug: str = Field(..., min_length=1, max_length=128, pattern="^[a-z0-9][a-z0-9-]*$")
    name: str = Field(..., min_length=1, max_length=256)
    env: str = Field(default="production", max_length=64)
    owner: Optional[str] = Field(None, max_length=256)
    enabled: bool = Field(default=True)
    endpoints: list[EndpointCreate] = Field(default_factory=list)


class ProductUpdate(BaseModel):
    """Request model for updating a product."""

    name: Optional[str] = Field(None, min_length=1, max_length=256)
    env: Optional[str] = Field(None, max_length=64)
    owner: Optional[str] = Field(None, max_length=256)
    enabled: Optional[bool] = None
    endpoints: Optional[list[EndpointCreate]] = None


class EndpointResponse(BaseModel):
    """Response model for a product endpoint."""

    id: int
    product_id: int
    kind: str
    url: Optional[str]
    target: Optional[str]
    meta: Optional[dict[str, Any]] = Field(
        None,
        json_schema_extra={"additionalProperties": True},
    )
    created_at: str


class ProductResponse(BaseModel):
    """Response model for a product."""

    id: int
    slug: str
    name: str
    env: str
    owner: Optional[str]
    enabled: bool
    tenant_id: str
    created_at: str
    updated_at: str
    endpoints: list[EndpointResponse]


class ProductListResponse(BaseModel):
    """Response model for product list."""

    products: list[ProductResponse]
    total: int


class TestConnectionResult(BaseModel):
    """Response model for connection test."""

    product_id: int
    product_name: str
    endpoint_id: Optional[int]
    endpoint_kind: str
    endpoint_url: Optional[str]
    success: bool
    status_code: Optional[int]
    latency_ms: Optional[float]
    error: Optional[str]
    tested_at: str


# ==============================================================================
# Helpers
# ==============================================================================


def _get_tenant_id(request: Request, session: Session, is_write: bool = False) -> str:
    """Extract and validate tenant ID from request."""
    tenant_id = request.headers.get("X-Tenant-ID")
    if not tenant_id and not is_write:
        tenant_id = session.tenant_id
    if not tenant_id:
        if not is_write:
            allowed = sorted(get_allowed_tenants(session))
            tenant_id = allowed[0] if allowed else None
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tenant ID required (X-Tenant-ID header or user tenants)",
        )
    validate_tenant_access(session, tenant_id, is_write=is_write)
    return tenant_id


def _product_to_response(product: Product) -> ProductResponse:
    """Convert Product model to response."""
    endpoints = []
    for ep in product.endpoints or []:
        meta = None
        if ep.meta_json:
            try:
                meta = json.loads(ep.meta_json)
            except (json.JSONDecodeError, TypeError):
                pass
        endpoints.append(
            EndpointResponse(
                id=ep.id,
                product_id=ep.product_id,
                kind=ep.kind,
                url=ep.url,
                target=ep.target,
                meta=meta,
                created_at=ep.created_at.isoformat() if ep.created_at else "",
            )
        )

    return ProductResponse(
        id=product.id,
        slug=product.slug,
        name=product.name,
        env=product.env,
        owner=product.owner,
        enabled=product.enabled,
        tenant_id=product.tenant_id,
        created_at=product.created_at.isoformat() if product.created_at else "",
        updated_at=product.updated_at.isoformat() if product.updated_at else "",
        endpoints=endpoints,
    )


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _resolve_host_ips(hostname: str) -> list[ipaddress._BaseAddress]:
    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    ips: set[ipaddress._BaseAddress] = set()
    for entry in results:
        addr = entry[4][0]
        try:
            ips.add(ipaddress.ip_address(addr))
        except ValueError:
            continue
    return list(ips)


def _validate_health_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only http/https URLs are allowed",
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid endpoint URL",
        )

    host_l = hostname.lower()
    if host_l in {"localhost"} or host_l.endswith(".localhost"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Blocked endpoint host",
        )

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None

    if ip:
        if _is_blocked_ip(ip):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Blocked endpoint host",
            )
        return

    resolved = _resolve_host_ips(hostname)
    if not resolved:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to resolve endpoint host",
        )

    if any(_is_blocked_ip(ip_addr) for ip_addr in resolved):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Blocked endpoint host",
        )


async def _audit_action(
    request: Request,
    action: str,
    resource_id: Optional[str],
    outcome: str,
    details: Optional[dict] = None,
    user: Optional[Session] = None,
) -> None:
    """Log an audit event."""
    audit_logger = getattr(request.app.state, "audit_logger", None)
    if audit_logger:
        await audit_logger.log(
            request_id=getattr(request.state, "request_id", "unknown"),
            action=action,
            resource="products",
            resource_id=resource_id,
            outcome=outcome,
            actor=user.user_id if user else None,
            details=details,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )


# ==============================================================================
# Endpoints
# ==============================================================================


@router.get(
    "",
    response_model=ProductListResponse,
    dependencies=[Depends(require_scope_dependency(Scope.PRODUCT_READ))],
)
async def list_products(
    request: Request,
    db: AsyncSession = Depends(get_db),
    session: Session = Depends(get_current_session),
) -> ProductListResponse:
    """List all products for the authenticated tenant.

    Requires: product:read scope
    """
    tenant_id = _get_tenant_id(request, session)

    # Query products for tenant
    stmt = select(Product).where(Product.tenant_id == tenant_id).order_by(Product.name)
    result = await db.execute(stmt)
    products = result.scalars().all()

    await _audit_action(
        request,
        "list_products",
        None,
        "success",
        {"count": len(products)},
        session,
    )

    return ProductListResponse(
        products=[_product_to_response(p) for p in products],
        total=len(products),
    )


@router.post(
    "",
    response_model=ProductResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope_dependency(Scope.PRODUCT_WRITE))],
)
async def create_product(
    request: Request,
    data: ProductCreate,
    db: AsyncSession = Depends(get_db),
    session: Session = Depends(get_current_session),
) -> ProductResponse:
    """Create a new product.

    Requires: product:write scope
    """
    tenant_id = _get_tenant_id(request, session, is_write=True)

    # Check for duplicate slug within tenant
    stmt = select(Product).where(
        Product.tenant_id == tenant_id, Product.slug == data.slug
    )
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Product with slug '{data.slug}' already exists",
        )

    # Create product
    product = Product(
        slug=data.slug,
        name=data.name,
        env=data.env,
        owner=data.owner,
        enabled=data.enabled,
        tenant_id=tenant_id,
    )
    db.add(product)
    await db.flush()  # Get the product ID

    # Create endpoints
    for ep_data in data.endpoints:
        endpoint = ProductEndpoint(
            product_id=product.id,
            kind=ep_data.kind,
            url=ep_data.url,
            target=ep_data.target,
            meta_json=json.dumps(ep_data.meta) if ep_data.meta else None,
        )
        db.add(endpoint)

    await db.commit()
    await db.refresh(product)

    await _audit_action(
        request,
        "create_product",
        str(product.id),
        "success",
        {"slug": data.slug, "name": data.name},
        session,
    )

    return _product_to_response(product)


@router.get(
    "/{product_id}",
    response_model=ProductResponse,
    dependencies=[Depends(require_scope_dependency(Scope.PRODUCT_READ))],
)
async def get_product(
    request: Request,
    product_id: int,
    db: AsyncSession = Depends(get_db),
    session: Session = Depends(get_current_session),
) -> ProductResponse:
    """Get a product by ID.

    Requires: product:read scope
    """
    tenant_id = _get_tenant_id(request, session)

    # Query product
    stmt = select(Product).where(
        Product.id == product_id, Product.tenant_id == tenant_id
    )
    result = await db.execute(stmt)
    product = result.scalar_one_or_none()

    if not product:
        await _audit_action(
            request,
            "get_product",
            str(product_id),
            "failure",
            {"reason": "not_found"},
            session,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Product not found",
        )

    await _audit_action(
        request, "get_product", str(product_id), "success", None, session
    )

    return _product_to_response(product)


@router.patch(
    "/{product_id}",
    response_model=ProductResponse,
    dependencies=[Depends(require_scope_dependency(Scope.PRODUCT_WRITE))],
)
async def update_product(
    request: Request,
    product_id: int,
    data: ProductUpdate,
    db: AsyncSession = Depends(get_db),
    session: Session = Depends(get_current_session),
) -> ProductResponse:
    """Update a product.

    Requires: product:write scope
    """
    tenant_id = _get_tenant_id(request, session, is_write=True)

    # Query product
    stmt = select(Product).where(
        Product.id == product_id, Product.tenant_id == tenant_id
    )
    result = await db.execute(stmt)
    product = result.scalar_one_or_none()

    if not product:
        await _audit_action(
            request,
            "update_product",
            str(product_id),
            "failure",
            {"reason": "not_found"},
            session,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Product not found",
        )

    # Update fields
    changes = {}
    if data.name is not None:
        changes["name"] = (product.name, data.name)
        product.name = data.name
    if data.env is not None:
        changes["env"] = (product.env, data.env)
        product.env = data.env
    if data.owner is not None:
        changes["owner"] = (product.owner, data.owner)
        product.owner = data.owner
    if data.enabled is not None:
        changes["enabled"] = (product.enabled, data.enabled)
        product.enabled = data.enabled

    # Update endpoints if provided
    if data.endpoints is not None:
        # Delete existing endpoints
        for ep in list(product.endpoints):
            await db.delete(ep)

        # Create new endpoints
        for ep_data in data.endpoints:
            endpoint = ProductEndpoint(
                product_id=product.id,
                kind=ep_data.kind,
                url=ep_data.url,
                target=ep_data.target,
                meta_json=json.dumps(ep_data.meta) if ep_data.meta else None,
            )
            db.add(endpoint)
        changes["endpoints"] = f"replaced with {len(data.endpoints)} endpoints"

    product.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(product)

    await _audit_action(
        request,
        "update_product",
        str(product_id),
        "success",
        {"changes": {k: str(v) for k, v in changes.items()}},
        session,
    )

    return _product_to_response(product)


@router.post(
    "/{product_id}/test-connection",
    response_model=TestConnectionResult,
    dependencies=[Depends(require_scope_dependency(Scope.PRODUCT_READ))],
)
async def test_connection(
    request: Request,
    product_id: int,
    db: AsyncSession = Depends(get_db),
    session: Session = Depends(get_current_session),
) -> TestConnectionResult:
    """Test connection to a product's endpoint.

    Attempts to reach the product's health endpoint.
    For REST endpoints, performs GET {base_url}/health.
    For gRPC, attempts a reflection call.
    For NATS, attempts to connect to the target.

    Requires: product:read scope
    """
    import time

    tenant_id = _get_tenant_id(request, session)

    # Query product
    stmt = select(Product).where(
        Product.id == product_id, Product.tenant_id == tenant_id
    )
    result = await db.execute(stmt)
    product = result.scalar_one_or_none()

    if not product:
        await _audit_action(
            request,
            "test_connection",
            str(product_id),
            "failure",
            {"reason": "not_found"},
            session,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Product not found",
        )

    # Find REST endpoint (primary for health checks)
    rest_endpoint = None
    for ep in product.endpoints:
        if ep.kind == "rest" and ep.url:
            rest_endpoint = ep
            break

    # If no REST endpoint, try any endpoint with URL
    if not rest_endpoint:
        for ep in product.endpoints:
            if ep.url:
                rest_endpoint = ep
                break

    if not rest_endpoint or not rest_endpoint.url:
        await _audit_action(
            request,
            "test_connection",
            str(product_id),
            "failure",
            {"reason": "no_endpoint"},
            session,
        )
        return TestConnectionResult(
            product_id=product.id,
            product_name=product.name,
            endpoint_id=None,
            endpoint_kind="none",
            endpoint_url=None,
            success=False,
            status_code=None,
            latency_ms=None,
            error="No REST endpoint configured for this product",
            tested_at=datetime.now(timezone.utc).isoformat(),
        )

    # Build health check URL
    base_url = rest_endpoint.url.rstrip("/")
    health_url = f"{base_url}/health"

    # Perform health check
    start_time = time.time()
    try:
        _validate_health_url(health_url)
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(health_url)
            latency_ms = (time.time() - start_time) * 1000

            if 300 <= response.status_code < 400 and response.headers.get("location"):
                await _audit_action(
                    request,
                    "test_connection",
                    str(product_id),
                    "failure",
                    {"endpoint_url": health_url, "error": "redirect_blocked"},
                    session,
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Redirects are not allowed",
                )

            success = response.status_code < 400

            await _audit_action(
                request,
                "test_connection",
                str(product_id),
                "success" if success else "failure",
                {
                    "endpoint_url": health_url,
                    "status_code": response.status_code,
                    "latency_ms": round(latency_ms, 2),
                },
                session,
            )

            return TestConnectionResult(
                product_id=product.id,
                product_name=product.name,
                endpoint_id=rest_endpoint.id,
                endpoint_kind=rest_endpoint.kind,
                endpoint_url=health_url,
                success=success,
                status_code=response.status_code,
                latency_ms=round(latency_ms, 2),
                error=None if success else f"HTTP {response.status_code}",
                tested_at=datetime.now(timezone.utc).isoformat(),
            )

    except httpx.TimeoutException:
        latency_ms = (time.time() - start_time) * 1000
        await _audit_action(
            request,
            "test_connection",
            str(product_id),
            "failure",
            {"endpoint_url": health_url, "error": "timeout"},
            session,
        )
        return TestConnectionResult(
            product_id=product.id,
            product_name=product.name,
            endpoint_id=rest_endpoint.id,
            endpoint_kind=rest_endpoint.kind,
            endpoint_url=health_url,
            success=False,
            status_code=None,
            latency_ms=round(latency_ms, 2),
            error="Connection timeout",
            tested_at=datetime.now(timezone.utc).isoformat(),
        )

    except httpx.ConnectError as e:
        latency_ms = (time.time() - start_time) * 1000
        await _audit_action(
            request,
            "test_connection",
            str(product_id),
            "failure",
            {"endpoint_url": health_url, "error": str(e)},
            session,
        )
        return TestConnectionResult(
            product_id=product.id,
            product_name=product.name,
            endpoint_id=rest_endpoint.id,
            endpoint_kind=rest_endpoint.kind,
            endpoint_url=health_url,
            success=False,
            status_code=None,
            latency_ms=round(latency_ms, 2),
            error=f"Connection failed: {e}",
            tested_at=datetime.now(timezone.utc).isoformat(),
        )

    except HTTPException as exc:
        latency_ms = (time.time() - start_time) * 1000
        await _audit_action(
            request,
            "test_connection",
            str(product_id),
            "failure",
            {"endpoint_url": health_url, "error": exc.detail},
            session,
        )
        raise
    except Exception as e:
        latency_ms = (time.time() - start_time) * 1000
        log.exception("Unexpected error testing connection")
        await _audit_action(
            request,
            "test_connection",
            str(product_id),
            "error",
            {"endpoint_url": health_url, "error": str(e)},
            session,
        )
        return TestConnectionResult(
            product_id=product.id,
            product_name=product.name,
            endpoint_id=rest_endpoint.id,
            endpoint_kind=rest_endpoint.kind,
            endpoint_url=health_url,
            success=False,
            status_code=None,
            latency_ms=round(latency_ms, 2),
            error=f"Unexpected error: {e}",
            tested_at=datetime.now(timezone.utc).isoformat(),
        )
