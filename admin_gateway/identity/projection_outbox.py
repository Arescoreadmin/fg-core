"""AUTH-ROLE-001B: Outbox enqueue helper for identity projection.

Call ``enqueue_projection`` within the same DB transaction as the authoritative
mutation (first-bind or role/active change).  Do NOT open a new transaction or
session; the INSERT is committed atomically with the authoritative write.

Auth0 tokens and credentials are never stored in the outbox.
"""

from __future__ import annotations

import json
import logging
import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session

log = logging.getLogger("admin-gateway.identity.projection_outbox")

_INSERT_SQL = text(
    """
    INSERT INTO identity_projection_outbox
        (id, principal_id, membership_id, tenant_id, provider,
         provider_subject, roles, projection_revision)
    VALUES
        (:id, :principal_id, :membership_id, :tenant_id, :provider,
         :provider_subject, :roles, :projection_revision)
    """
)


def enqueue_projection(
    db: Session,
    *,
    membership_id: str,
    principal_id: str,
    tenant_id: str,
    provider: str,
    provider_subject: str,
    roles: list[str],
    projection_revision: int,
) -> None:
    """Insert a pending projection event into ``identity_projection_outbox``.

    Must be called within the same DB transaction as the authoritative mutation
    so the outbox row is committed atomically.  Do not call ``db.commit()``
    here; the caller owns the transaction.

    Args:
        db: Active SQLAlchemy session (transaction already open).
        membership_id: tenant_users.id of the affected membership.
        principal_id: fg_principals.id (UUID string) for the bound principal.
        tenant_id: Tenant identifier.
        provider: Identity provider name (e.g. ``"auth0"``).
        provider_subject: Provider-side user subject (e.g. ``"auth0|abc123"``).
        roles: List of role strings to project into Auth0 app_metadata.
        projection_revision: membership_version at the time of this mutation;
            used for stale-write safety in the worker.
    """
    row_id = str(uuid.uuid4())
    db.execute(
        _INSERT_SQL,
        {
            "id": row_id,
            "principal_id": principal_id,
            "membership_id": membership_id,
            "tenant_id": tenant_id,
            "provider": provider,
            "provider_subject": provider_subject,
            "roles": json.dumps(roles),
            "projection_revision": projection_revision,
        },
    )
    log.info(
        "identity_projection_outbox.enqueued outbox_id=%s membership_id=%s revision=%d",
        row_id,
        membership_id,
        projection_revision,
    )
