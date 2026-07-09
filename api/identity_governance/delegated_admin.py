"""api/identity_governance/delegated_admin.py — Delegated admin boundaries.

Enforces two invariants:

1. **No upward escalation.** A grantor may only grant an admin level
   strictly less powerful than their own (higher numeric value in
   :data:`ADMIN_LEVEL_ORDER`). Same-level or higher-level grants raise
   ``ValueError``.
2. **Scope containment.** A grantor's scope must contain the target scope
   for every scope dimension the grantor has set — the target may narrow,
   but never broaden.
"""

from __future__ import annotations

from api.identity_governance.models import (
    DelegatedAdminLevel,
    DelegatedAdminRecord,
    DelegatedAdminScope,
)

ADMIN_LEVEL_ORDER: dict[DelegatedAdminLevel, int] = {
    DelegatedAdminLevel.PLATFORM_ADMIN: 0,
    DelegatedAdminLevel.TENANT_ADMIN: 1,
    DelegatedAdminLevel.REGIONAL_ADMIN: 2,
    DelegatedAdminLevel.BUSINESS_UNIT_ADMIN: 3,
    DelegatedAdminLevel.DEPARTMENT_ADMIN: 4,
    DelegatedAdminLevel.PROJECT_ADMIN: 5,
    DelegatedAdminLevel.ENGAGEMENT_ADMIN: 6,
}


class DelegatedAdminAuthority:
    """Delegated administration boundary checks."""

    def can_grant(
        self,
        grantor_level: DelegatedAdminLevel,
        target_level: DelegatedAdminLevel,
    ) -> bool:
        """Return True iff ``grantor_level`` is strictly more powerful.

        More powerful == lower value in :data:`ADMIN_LEVEL_ORDER`.
        """
        return ADMIN_LEVEL_ORDER[grantor_level] < ADMIN_LEVEL_ORDER[target_level]

    def validate_scope(
        self,
        admin_record: DelegatedAdminRecord,
        target_scope: DelegatedAdminScope,
    ) -> bool:
        """Return True iff ``target_scope`` is contained in the grantor's scope.

        Scope containment rules:
        - ``tenant_id`` must match exactly.
        - For every optional dimension the grantor has SET (non-None), the
          target must either match exactly or be strictly narrower (i.e. the
          grantor did not set it and the target did — this widens; disallowed).
          When the grantor has NOT set a dimension, the target may set it
          freely (narrower is fine).
        """
        grantor_scope = admin_record.scope
        if grantor_scope.tenant_id != target_scope.tenant_id:
            return False

        dimensions = (
            "organization_id",
            "business_unit_id",
            "department_id",
            "project_id",
            "engagement_id",
        )
        for dim in dimensions:
            grantor_val = getattr(grantor_scope, dim)
            target_val = getattr(target_scope, dim)
            if grantor_val is None:
                # Grantor did not scope this dimension — target may set it
                # to any value (narrower).
                continue
            if target_val != grantor_val:
                # Grantor scoped this dimension — target must match exactly.
                return False
        return True

    def assert_no_escalation(
        self,
        grantor: DelegatedAdminRecord,
        target_level: DelegatedAdminLevel,
        target_scope: DelegatedAdminScope,
    ) -> None:
        """Raise ``ValueError`` if the grant would escalate power or scope."""
        if not self.can_grant(grantor.level, target_level):
            raise ValueError(
                "delegated admin escalation blocked: grantor level "
                f"{grantor.level.value!r} cannot grant "
                f"{target_level.value!r} (grantor must be strictly higher)"
            )
        if not self.validate_scope(grantor, target_scope):
            raise ValueError(
                "delegated admin escalation blocked: target scope not contained "
                "in grantor's scope"
            )
