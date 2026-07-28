"""Tenant authority classification foundation tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from api.tenant_authority import (
    TENANT_KINDS,
    TENANT_KIND_POLICIES,
    ensure_billing_eligible,
    ensure_portal_enabled,
    policy_for_tenant_kind,
)
from api.tenant_repository import TenantRepository

MIGRATION = Path("migrations/postgres/0166_tenant_authority_classification.sql")

_CREATE_SQL = """
CREATE TABLE tenants (
    tenant_id VARCHAR(128) PRIMARY KEY,
    display_name TEXT NOT NULL,
    lifecycle_state VARCHAR(32) NOT NULL DEFAULT 'active',
    tenant_kind VARCHAR(32) NOT NULL DEFAULT 'customer'
        CHECK (tenant_kind IN ('customer', 'internal_platform', 'validation', 'demo')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_by TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    canonical_version INTEGER NOT NULL DEFAULT 1,
    last_reconciled_at TEXT,
    archived_at TEXT,
    migration_source VARCHAR(32),
    migration_version VARCHAR(32)
)
"""


@pytest.fixture
def engine():
    eng = create_engine("sqlite+pysqlite:///:memory:", future=True)
    with eng.begin() as conn:
        conn.execute(text(_CREATE_SQL))
    yield eng
    eng.dispose()


def test_policy_matrix_is_explicit_and_non_contradictory():
    assert set(TENANT_KIND_POLICIES) == {
        "customer",
        "internal_platform",
        "validation",
        "demo",
    }
    assert policy_for_tenant_kind("customer").customer_visible is True
    assert policy_for_tenant_kind("customer").portal_enabled is True
    assert policy_for_tenant_kind("customer").billing_eligible is True
    assert policy_for_tenant_kind("customer").operator_authority_allowed is False

    internal = policy_for_tenant_kind("internal_platform")
    assert internal.customer_visible is False
    assert internal.portal_enabled is False
    assert internal.billing_eligible is False
    assert internal.operator_authority_allowed is True

    for kind in ["validation", "demo"]:
        policy = policy_for_tenant_kind(kind)
        assert policy.billing_eligible is False
        assert policy.operator_authority_allowed is False


def test_every_tenant_kind_has_policy():
    assert set(TENANT_KIND_POLICIES.keys()) == set(TENANT_KINDS)


def test_every_tenant_kind_policy_has_complete_boolean_flags():
    for kind in TENANT_KINDS:
        policy = policy_for_tenant_kind(kind)
        assert isinstance(policy.customer_visible, bool)
        assert isinstance(policy.portal_enabled, bool)
        assert isinstance(policy.billing_eligible, bool)
        assert isinstance(policy.operator_authority_allowed, bool)


def test_migration_adds_non_null_constrained_tenant_kind_with_safe_defaults():
    sql = MIGRATION.read_text(encoding="utf-8")
    assert "ADD COLUMN IF NOT EXISTS tenant_kind" in sql
    assert "NOT NULL DEFAULT 'customer'" in sql
    assert "chk_tenants_tenant_kind" in sql
    assert "'internal_platform'" in sql
    assert "'validation'" in sql
    assert "'demo'" in sql
    assert "frostgate-e2e-validation" in sql
    assert "frostgate-provisioning-validation" in sql
    assert "frostgate-internal" not in sql
    assert "LIKE" not in sql.upper()


def test_existing_tenant_defaults_to_customer_in_schema(engine):
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, display_name) VALUES ('legacy-customer', 'Legacy')"
            )
        )
        row = conn.execute(
            text("SELECT tenant_kind FROM tenants WHERE tenant_id='legacy-customer'")
        ).fetchone()
    assert row[0] == "customer"


def test_invalid_tenant_kind_rejected_by_schema(engine):
    with pytest.raises(Exception):
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenants (tenant_id, display_name, tenant_kind) VALUES ('bad', 'Bad', 'operator')"
                )
            )


def test_repository_round_trips_tenant_kind(engine):
    repo = TenantRepository(engine)
    row = repo.create("validation-a", "Validation A", tenant_kind="validation")
    assert row.tenant_kind == "validation"
    fetched = repo.get("validation-a")
    assert fetched is not None
    assert fetched.tenant_kind == "validation"


def test_generic_customer_flow_cannot_create_internal_platform(engine):
    repo = TenantRepository(engine)
    with pytest.raises(ValueError, match="internal_platform"):
        repo.create("internal-a", "Internal A", tenant_kind="internal_platform")


def test_privileged_path_can_create_internal_platform_for_future_pr(engine):
    repo = TenantRepository(engine)
    row = repo.create(
        "internal-a",
        "Internal A",
        tenant_kind="internal_platform",
        allow_internal_platform=True,
    )
    assert row.tenant_kind == "internal_platform"


def test_portal_and_billing_policy_blocks_internal_validation_and_demo(engine):
    repo = TenantRepository(engine)
    repo.create("customer-a", "Customer A")
    repo.create(
        "internal-a",
        "Internal A",
        tenant_kind="internal_platform",
        allow_internal_platform=True,
    )
    repo.create("validation-a", "Validation A", tenant_kind="validation")
    repo.create("demo-a", "Demo A", tenant_kind="demo")

    from sqlalchemy.orm import Session

    with Session(engine) as db:
        ensure_portal_enabled(db, "customer-a")
        ensure_billing_eligible(db, "customer-a")
        for tenant_id in ["internal-a", "validation-a"]:
            with pytest.raises(ValueError):
                ensure_portal_enabled(db, tenant_id)
        for tenant_id in ["internal-a", "validation-a", "demo-a"]:
            with pytest.raises(ValueError):
                ensure_billing_eligible(db, tenant_id)


def test_customer_and_validation_are_not_operator_authority(engine):
    repo = TenantRepository(engine)
    repo.create("lace-money-group", "Lace Money Group")
    repo.create("validation-a", "Validation A", tenant_kind="validation")
    repo.create("demo-a", "Demo A", tenant_kind="demo")
    internal = repo.create(
        "internal-a",
        "Internal A",
        tenant_kind="internal_platform",
        allow_internal_platform=True,
    )
    suspended = repo.create(
        "internal-suspended",
        "Internal Suspended",
        tenant_kind="internal_platform",
        allow_internal_platform=True,
    )
    repo.set_lifecycle_state(suspended.tenant_id, "suspended")

    assert (
        policy_for_tenant_kind(
            repo.get("lace-money-group").tenant_kind
        ).operator_authority_allowed
        is False
    )
    assert (
        policy_for_tenant_kind(
            repo.get("validation-a").tenant_kind
        ).operator_authority_allowed
        is False
    )
    assert (
        policy_for_tenant_kind(
            repo.get("demo-a").tenant_kind
        ).operator_authority_allowed
        is False
    )
    assert (
        policy_for_tenant_kind(internal.tenant_kind).operator_authority_allowed is True
    )
    assert repo.get("internal-suspended").lifecycle_state == "suspended"
