"""services/identity_resolver/versioning.py — Authoritative membership_version bumper.

Call bump_version() whenever an authorization-affecting field changes on tenant_users:
  active, role, identity_binding_status, identity_provider, identity_issuer,
  identity_subject, identity_type, identity_risk_state, identity_verification_level.

Do NOT call for: display_name, last_active_at, or any cosmetic metadata.
"""

from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.orm import Session

log = logging.getLogger("frostgate.identity_resolver.versioning")

_BUMP_SQL = text(
    """
    UPDATE tenant_users
    SET membership_version = membership_version + 1
    WHERE id        = :membership_id
      AND tenant_id = :tenant_id
    RETURNING membership_version
    """
)


class MembershipVersionService:
    """Single source of truth for incrementing membership_version on tenant_users.

    Thread-safe and stateless; a single instance can be shared across requests.
    """

    def bump_version(
        self,
        db: Session,
        *,
        membership_id: str,
        tenant_id: str,
        reason: str,
    ) -> int:
        """Increment membership_version and return the new value.

        Raises:
            ValueError — no matching row found (wrong id or tenant_id)
        """
        row = db.execute(
            _BUMP_SQL,
            {"membership_id": membership_id, "tenant_id": tenant_id},
        ).one_or_none()

        if row is None:
            raise ValueError(
                f"membership_version bump failed: no row for "
                f"membership_id={membership_id!r} tenant_id={tenant_id!r}"
            )

        new_version = int(row.membership_version)
        log.info(
            "membership_version.bumped",
            extra={
                "membership_id": membership_id,
                "tenant_id": tenant_id,
                "new_version": new_version,
                "reason": reason,
            },
        )
        return new_version


membership_version_svc = MembershipVersionService()
