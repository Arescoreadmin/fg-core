"""tests/identity_governance/test_delegated_admin.py — Delegated admin tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from api.identity_governance.delegated_admin import (
    ADMIN_LEVEL_ORDER,
    DelegatedAdminAuthority,
)
from api.identity_governance.models import (
    DelegatedAdminLevel,
    DelegatedAdminRecord,
    DelegatedAdminScope,
)


@pytest.fixture
def authority() -> DelegatedAdminAuthority:
    return DelegatedAdminAuthority()


def _record(
    level: DelegatedAdminLevel,
    tenant_id: str = "tenant-a",
    **scope_kwargs,
) -> DelegatedAdminRecord:
    scope = DelegatedAdminScope(tenant_id=tenant_id, **scope_kwargs)
    return DelegatedAdminRecord(
        record_id="rec-1",
        tenant_id=tenant_id,
        subject="admin@fg",
        level=level,
        scope=scope,
        granted_by="platform",
        granted_at=datetime.now(tz=timezone.utc),
    )


def test_level_order_platform_is_zero() -> None:
    assert ADMIN_LEVEL_ORDER[DelegatedAdminLevel.PLATFORM_ADMIN] == 0
    assert ADMIN_LEVEL_ORDER[DelegatedAdminLevel.TENANT_ADMIN] == 1
    assert ADMIN_LEVEL_ORDER[DelegatedAdminLevel.ENGAGEMENT_ADMIN] == 6


def test_can_grant_downward_ok(authority: DelegatedAdminAuthority) -> None:
    assert authority.can_grant(
        DelegatedAdminLevel.PLATFORM_ADMIN,
        DelegatedAdminLevel.TENANT_ADMIN,
    )


def test_cannot_grant_same_level(authority: DelegatedAdminAuthority) -> None:
    assert not authority.can_grant(
        DelegatedAdminLevel.TENANT_ADMIN,
        DelegatedAdminLevel.TENANT_ADMIN,
    )


def test_cannot_grant_upward(authority: DelegatedAdminAuthority) -> None:
    assert not authority.can_grant(
        DelegatedAdminLevel.DEPARTMENT_ADMIN,
        DelegatedAdminLevel.PLATFORM_ADMIN,
    )


def test_validate_scope_matching(authority: DelegatedAdminAuthority) -> None:
    r = _record(
        DelegatedAdminLevel.BUSINESS_UNIT_ADMIN,
        organization_id="org-1",
        business_unit_id="bu-a",
    )
    target = DelegatedAdminScope(
        tenant_id="tenant-a",
        organization_id="org-1",
        business_unit_id="bu-a",
        department_id="dept-x",
    )
    assert authority.validate_scope(r, target)


def test_validate_scope_wrong_tenant(authority: DelegatedAdminAuthority) -> None:
    r = _record(DelegatedAdminLevel.TENANT_ADMIN)
    other = DelegatedAdminScope(tenant_id="tenant-b")
    assert not authority.validate_scope(r, other)


def test_validate_scope_widening_denied(
    authority: DelegatedAdminAuthority,
) -> None:
    r = _record(
        DelegatedAdminLevel.BUSINESS_UNIT_ADMIN,
        business_unit_id="bu-a",
    )
    target = DelegatedAdminScope(
        tenant_id="tenant-a",
        business_unit_id="bu-b",  # different bu — widening
    )
    assert not authority.validate_scope(r, target)


def test_platform_admin_can_grant_any(
    authority: DelegatedAdminAuthority,
) -> None:
    for lvl in DelegatedAdminLevel:
        if lvl == DelegatedAdminLevel.PLATFORM_ADMIN:
            continue
        assert authority.can_grant(DelegatedAdminLevel.PLATFORM_ADMIN, lvl)


def test_assert_no_escalation_ok(authority: DelegatedAdminAuthority) -> None:
    grantor = _record(DelegatedAdminLevel.TENANT_ADMIN)
    target = DelegatedAdminScope(tenant_id="tenant-a", organization_id="org-1")
    # Should not raise
    authority.assert_no_escalation(
        grantor, DelegatedAdminLevel.DEPARTMENT_ADMIN, target
    )


def test_assert_no_escalation_upward_blocked(
    authority: DelegatedAdminAuthority,
) -> None:
    grantor = _record(DelegatedAdminLevel.DEPARTMENT_ADMIN)
    target = DelegatedAdminScope(tenant_id="tenant-a")
    with pytest.raises(ValueError, match="escalation blocked"):
        authority.assert_no_escalation(
            grantor, DelegatedAdminLevel.TENANT_ADMIN, target
        )


def test_assert_no_escalation_cross_tenant_blocked(
    authority: DelegatedAdminAuthority,
) -> None:
    grantor = _record(DelegatedAdminLevel.TENANT_ADMIN, tenant_id="tenant-a")
    target = DelegatedAdminScope(tenant_id="tenant-b")
    with pytest.raises(ValueError, match="escalation blocked"):
        authority.assert_no_escalation(
            grantor, DelegatedAdminLevel.DEPARTMENT_ADMIN, target
        )


def test_regional_admin_cannot_grant_tenant_admin(
    authority: DelegatedAdminAuthority,
) -> None:
    assert not authority.can_grant(
        DelegatedAdminLevel.REGIONAL_ADMIN,
        DelegatedAdminLevel.TENANT_ADMIN,
    )


def test_scope_narrowing_allowed(authority: DelegatedAdminAuthority) -> None:
    grantor = _record(DelegatedAdminLevel.TENANT_ADMIN)  # no bu set
    target = DelegatedAdminScope(tenant_id="tenant-a", business_unit_id="bu-x")
    assert authority.validate_scope(grantor, target)


def test_deterministic_can_grant(authority: DelegatedAdminAuthority) -> None:
    for a in DelegatedAdminLevel:
        for b in DelegatedAdminLevel:
            r1 = authority.can_grant(a, b)
            r2 = authority.can_grant(a, b)
            assert r1 == r2
