"""Create products tables

Revision ID: 20250128_000001
Revises:
Create Date: 2025-01-28 00:00:01.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "20250128_000001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create products table
    op.create_table(
        "products",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("slug", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column(
            "env", sa.String(length=64), nullable=False, server_default="production"
        ),
        sa.Column("owner", sa.String(length=256), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_products_slug", "products", ["slug"], unique=False)
    op.create_index("ix_products_tenant_id", "products", ["tenant_id"], unique=False)
    op.create_index(
        "ix_products_tenant_slug", "products", ["tenant_id", "slug"], unique=True
    )

    # Create product_endpoints table
    op.create_table(
        "product_endpoints",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("product_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("url", sa.String(length=1024), nullable=True),
        sa.Column("target", sa.String(length=1024), nullable=True),
        sa.Column("meta_json", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(
            ["product_id"],
            ["products.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_product_endpoints_product_id",
        "product_endpoints",
        ["product_id"],
        unique=False,
    )
    op.create_index(
        "ix_product_endpoints_product_kind",
        "product_endpoints",
        ["product_id", "kind"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_product_endpoints_product_kind", table_name="product_endpoints")
    op.drop_index("ix_product_endpoints_product_id", table_name="product_endpoints")
    op.drop_table("product_endpoints")
    op.drop_index("ix_products_tenant_slug", table_name="products")
    op.drop_index("ix_products_tenant_id", table_name="products")
    op.drop_index("ix_products_slug", table_name="products")
    op.drop_table("products")
