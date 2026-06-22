"""services/billing/reconciliation.py — Billing reconciliation service (P1.5).

Retries pending usage events and failed subscription links against the provider.
Used by scheduled jobs or admin-triggered reconciliation runs.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from sqlalchemy import update

from api.db_models_billing import BillingSubscriptionLink, UsageEvent
from api.observability.metrics import (
    BILLING_RECONCILIATION_FAILURES_TOTAL,
    BILLING_RECONCILIATION_RUNS_TOTAL,
)
from services.billing.metering import _append_ledger_entry

log = logging.getLogger("frostgate.billing.reconciliation")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class BillingReconciler:
    """Retries provider reporting for pending/failed billing records."""

    def reconcile_pending_usage(
        self,
        db: Session,
        provider,
        *,
        tenant_id: str | None = None,
        limit: int = 100,
    ) -> dict:
        """Find pending UsageEvents, attempt to report to provider, update status."""
        query = db.query(UsageEvent).filter(UsageEvent.billing_status == "pending")
        if tenant_id is not None:
            query = query.filter(UsageEvent.tenant_id == tenant_id)
        events = query.limit(limit).all()

        reported = 0
        failed = 0
        for evt in events:
            try:
                result = provider.report_usage(
                    "",
                    evt.meter_code,
                    evt.quantity,
                    evt.idempotency_key,
                )
                now = _utcnow()
                provider_event_id = result.get("id")
                # Use core SQL to bypass the ORM append-only guard for authorized transitions
                db.execute(
                    update(UsageEvent)
                    .where(UsageEvent.id == evt.id)
                    .values(
                        billing_status="reported",
                        reported_at=now,
                        provider_event_id=provider_event_id,
                    )
                )
                db.expire(evt)
                _append_ledger_entry(
                    db,
                    tenant_id=evt.tenant_id,
                    event_type="usage_reported",
                    entity_type="usage_event",
                    entity_id=evt.id,
                    old_state="pending",
                    new_state="reported",
                )
                reported += 1
            except Exception as exc:
                log.warning(
                    "billing.reconcile_usage_failed event_id=%s error=%s",
                    evt.id,
                    exc,
                )
                BILLING_RECONCILIATION_FAILURES_TOTAL.inc()
                failed += 1

        return {"reported": reported, "failed": failed, "total": len(events)}

    def reconcile_subscription_links(
        self,
        db: Session,
        provider,
        *,
        tenant_id: str | None = None,
    ) -> dict:
        """Retry sync for BillingSubscriptionLinks with sync_status='failed'."""
        query = db.query(BillingSubscriptionLink).filter(
            BillingSubscriptionLink.sync_status == "failed"
        )
        if tenant_id is not None:
            query = query.filter(BillingSubscriptionLink.tenant_id == tenant_id)
        links = query.all()

        synced = 0
        failed = 0
        for link in links:
            try:
                if link.provider_subscription_id:
                    provider.retrieve_invoice(link.provider_subscription_id)
                link.sync_status = "synced"
                link.last_synced_at = _utcnow()
                db.flush()
                synced += 1
            except Exception as exc:
                log.warning(
                    "billing.reconcile_link_failed link_id=%s error=%s",
                    link.id,
                    exc,
                )
                BILLING_RECONCILIATION_FAILURES_TOTAL.inc()
                failed += 1

        return {"synced": synced, "failed": failed, "total": len(links)}

    def run_full_reconciliation(
        self,
        db: Session,
        provider,
        *,
        tenant_id: str | None = None,
    ) -> dict:
        """Run both usage and subscription link reconciliation."""
        BILLING_RECONCILIATION_RUNS_TOTAL.inc()
        usage_stats = self.reconcile_pending_usage(db, provider, tenant_id=tenant_id)
        link_stats = self.reconcile_subscription_links(
            db, provider, tenant_id=tenant_id
        )
        return {"usage": usage_stats, "subscription_links": link_stats}
