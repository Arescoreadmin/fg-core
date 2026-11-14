"""api/msp_portfolio.py — MSP-002 read-only portfolio composition.

NOT an authority. Which customers appear, and which permissions apply to
each, is decided only by ``api/msp_authority.py`` (``list_actor_customers``:
DB role ∩ customer-approved capabilities ∩ ``MSP_DELEGABLE_PERMISSIONS``).
This module turns an already-authorized page of customers into summaries.

Per customer and per section:

* A section is read only when its capability is in that customer's effective
  set; otherwise it is ``not_authorized`` and carries no data.
* Data comes from the sanctioned field-assessment data-access layer
  (``services/field_assessment/store.py``), queried under that customer's
  RLS tenant context; the caller's context is restored afterwards. There are
  no cross-tenant queries, no joins across customers and no cache.
* A failure in one section of one customer yields ``unavailable`` for that
  section only. The error is never echoed.
* Absent data is ``not_configured``, never a zero score. No synthetic score
  is computed. Governance posture is deliberately absent: no canonical,
  absent-safe governance summary exists yet (docs/msp/MSP_002_ARCHITECTURE.md).
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable

from sqlalchemy import text
from sqlalchemy.orm import Session

from api.db import set_tenant_context
from services.field_assessment import store as fa_store

log = logging.getLogger("frostgate.msp.portfolio")

PORTFOLIO_DEFAULT_PAGE = 25
PORTFOLIO_MAX_PAGE = 50
# Bound each summary query on Postgres; a slow customer cannot stall the page.
SECTION_STATEMENT_TIMEOUT_MS = 5000

# FindingStatus values that still need action (services/field_assessment/models.py).
OUTSTANDING_FINDING_STATUSES = frozenset({"open", "acknowledged"})

SectionReader = Callable[[Session, str], dict[str, Any]]


@dataclass(frozen=True)
class PortfolioEntry:
    """An authorized customer, snapshotted as plain values before any read."""

    customer_tenant_id: str
    display_name: str
    relationship_id: str
    expires_at: str | None
    effective_permissions: frozenset[str]


def _assessment_summary(db: Session, tenant_id: str) -> dict[str, Any]:
    rows = fa_store.list_engagements(
        db,
        tenant_id=tenant_id,
        status_filter=None,
        limit=fa_store.MAX_PAGE_SIZE,
        cursor=None,
    )
    if not rows:
        return {"state": "not_configured"}
    by_status = Counter(str(r.status) for r in rows)
    return {
        "state": "available",
        "engagements_by_status": dict(sorted(by_status.items())),
        "observed": len(rows),
        "truncated": len(rows) >= fa_store.MAX_PAGE_SIZE,
        "last_activity_at": max(str(r.updated_at) for r in rows),
    }


def _findings_summary(db: Session, tenant_id: str) -> dict[str, Any]:
    rows = fa_store.list_findings_for_tenant(
        db, tenant_id=tenant_id, limit=fa_store.MAX_PAGE_SIZE
    )
    if not rows:
        return {"state": "not_configured"}
    outstanding = Counter(
        str(r.severity) for r in rows if str(r.status) in OUTSTANDING_FINDING_STATUSES
    )
    return {
        "state": "available",
        "outstanding_by_severity": dict(sorted(outstanding.items())),
        "outstanding_total": sum(outstanding.values()),
        "observed": len(rows),
        "truncated": len(rows) >= fa_store.MAX_PAGE_SIZE,
        "last_activity_at": max(str(r.updated_at) for r in rows),
    }


# (response key, required delegated permission, reader)
SECTIONS: tuple[tuple[str, str, SectionReader], ...] = (
    ("assessment", "assessment.read", _assessment_summary),
    ("findings", "finding.read", _findings_summary),
)


def _bound_statement_time(db: Session) -> None:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT set_config('statement_timeout', :ms, true)"),
            {"ms": str(SECTION_STATEMENT_TIMEOUT_MS)},
        )


def build_portfolio_items(
    db: Session, *, entries: list[PortfolioEntry], restore_tenant: str
) -> tuple[list[dict[str, Any]], list[tuple[PortfolioEntry, list[str]]]]:
    """Summaries for one page of authorized customers.

    Returns the response items and, per customer, the permissions whose data
    was actually read (for the customer-chain audit event).
    """
    items: list[dict[str, Any]] = []
    reads: list[tuple[PortfolioEntry, list[str]]] = []
    for entry in entries:
        item: dict[str, Any] = {
            "customer_tenant_id": entry.customer_tenant_id,
            "display_name": entry.display_name,
            "relationship_id": entry.relationship_id,
            "relationship_status": "active",
            "effective_permissions": sorted(entry.effective_permissions),
            "expires_at": entry.expires_at,
        }
        used: list[str] = []
        for key, permission, reader in SECTIONS:
            if permission not in entry.effective_permissions:
                item[key] = {"state": "not_authorized"}
                continue
            try:
                set_tenant_context(db, entry.customer_tenant_id)
                _bound_statement_time(db)
                item[key] = reader(db, entry.customer_tenant_id)
                used.append(permission)
            except Exception:
                # Nothing has been written yet, so a rollback only discards
                # this failed read. Never echo the error to the caller.
                db.rollback()
                log.warning(
                    "msp.portfolio.section_unavailable",
                    extra={"section": key, "relationship_id": entry.relationship_id},
                )
                item[key] = {"state": "unavailable"}
            finally:
                set_tenant_context(db, restore_tenant)
        items.append(item)
        if used:
            reads.append((entry, used))
    return items, reads
