"""Admin Gateway Database Models.

Products Registry data models for tenant-scoped product management.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, relationship


def utcnow() -> datetime:
    """Return current UTC timestamp."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


class EndpointKind(str, Enum):
    """Endpoint connection types."""

    REST = "rest"
    GRPC = "grpc"
    NATS = "nats"


class Product(Base):
    """Product model for Products Registry.

    Represents a registered product/service that FrostGate protects.
    Products are tenant-scoped for multi-tenant isolation.
    """

    __tablename__ = "products"
    __table_args__ = (
        Index("ix_products_tenant_slug", "tenant_id", "slug", unique=True),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    slug = Column(String(128), nullable=False, index=True)
    name = Column(String(256), nullable=False)
    env = Column(String(64), nullable=False, default="production")
    owner = Column(String(256), nullable=True)
    enabled = Column(Boolean, nullable=False, default=True)

    # Tenant scoping for multi-tenant isolation
    tenant_id = Column(String(128), nullable=False, index=True)

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
    )

    # Relationships
    endpoints = relationship(
        "ProductEndpoint",
        back_populates="product",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "slug": self.slug,
            "name": self.name,
            "env": self.env,
            "owner": self.owner,
            "enabled": self.enabled,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "endpoints": [ep.to_dict() for ep in (self.endpoints or [])],
        }


class ProductEndpoint(Base):
    """Product Endpoint model.

    Represents connection endpoints for a product (REST, gRPC, NATS).
    """

    __tablename__ = "product_endpoints"
    __table_args__ = (Index("ix_product_endpoints_product_kind", "product_id", "kind"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    product_id = Column(
        Integer,
        ForeignKey("products.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind = Column(String(32), nullable=False)  # rest, grpc, nats
    url = Column(String(1024), nullable=True)  # For REST/gRPC
    target = Column(String(1024), nullable=True)  # For NATS subject
    meta_json = Column(Text, nullable=True)  # JSON string for additional metadata

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )

    # Relationships
    product = relationship("Product", back_populates="endpoints")

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        import json

        meta = None
        if self.meta_json:
            try:
                meta = json.loads(self.meta_json)
            except (json.JSONDecodeError, TypeError):
                meta = self.meta_json

        return {
            "id": self.id,
            "product_id": self.product_id,
            "kind": self.kind,
            "url": self.url,
            "target": self.target,
            "meta": meta,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
