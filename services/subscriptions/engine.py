"""services/subscriptions/engine.py — Subscription Assignment Engine (P1.4).

Governs the commercial authority layer:
  SubscriptionContract  → contains one or more SubscriptionItems
  SubscriptionItem      → links a contract to a policy bundle with lifecycle state
  SubscriptionEventLedger → immutable, append-only event log

When a SubscriptionItem is created or activated, the engine automatically syncs a
TenantBundleAssignment so that the existing capability resolver (P1.2) picks it up
without any duplication of capability logic.

Resolution priority (unchanged, P1.4 only adds the subscription sync mechanism):
  Explicit Grant → Bundle Assignment (via subscription) → Tier Default
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from api.db_models import (
    PolicyBundle,
    TenantBundleAssignment,
)
from api.db_models_subscriptions import (
    SubscriptionContract,
    SubscriptionEventLedger,
    SubscriptionItem,
)
from services.subscriptions.models import (
    ContractResponse,
    ExplainCapabilityResponse,
    ItemResponse,
    LedgerEntryResponse,
    ResolutionLayer,
)

log = logging.getLogger("frostgate.subscriptions.engine")

_VALID_CONTRACT_STATUSES = frozenset(
    {"draft", "active", "suspended", "canceled", "expired"}
)
_VALID_ITEM_STATUSES = frozenset({"active", "suspended", "canceled", "expired"})

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _compute_entry_hash(
    prev_hash: str,
    item_id: str,
    event_type: str,
    event_at: datetime,
    actor: str,
    reason: str | None,
) -> str:
    payload = f"{prev_hash}|{item_id}|{event_type}|{event_at.isoformat()}|{actor}|{reason or ''}"
    return hashlib.sha256(payload.encode()).hexdigest()


def _to_contract_response(c: SubscriptionContract) -> ContractResponse:
    return ContractResponse(
        id=c.id,
        tenant_id=c.tenant_id,
        contract_ref=c.contract_ref,
        sku_package=c.sku_package,
        sku_metadata=c.sku_metadata or {},
        status=c.status,
        starts_at=c.starts_at,
        ends_at=c.ends_at,
        created_by=c.created_by,
        created_at=c.created_at,
        updated_at=c.updated_at,
        notes=c.notes,
    )


def _to_item_response(item: SubscriptionItem) -> ItemResponse:
    return ItemResponse(
        id=item.id,
        contract_id=item.contract_id,
        tenant_id=item.tenant_id,
        bundle_id=item.bundle_id,
        sku_code=item.sku_code,
        meter_code=item.meter_code,
        status=item.status,
        starts_at=item.starts_at,
        ends_at=item.ends_at,
        parent_item_id=item.parent_item_id,
        bundle_assignment_id=item.bundle_assignment_id,
        created_at=item.created_at,
        updated_at=item.updated_at,
    )


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


def _append_ledger_event(
    db: Session,
    item_id: str,
    tenant_id: str,
    event_type: str,
    actor: str,
    reason: str | None,
    metadata: dict[str, Any] | None = None,
) -> SubscriptionEventLedger:
    """Append an immutable event to the ledger for the given subscription item.

    Computes the hash chain: prev_hash = last entry's entry_hash (or GENESIS).
    """
    last = (
        db.query(SubscriptionEventLedger)
        .filter(SubscriptionEventLedger.subscription_item_id == item_id)
        .order_by(SubscriptionEventLedger.event_at.desc())
        .first()
    )
    prev_hash = last.entry_hash if last is not None else "GENESIS"
    now = _utcnow()
    entry_hash = _compute_entry_hash(prev_hash, item_id, event_type, now, actor, reason)

    entry = SubscriptionEventLedger(
        id=str(uuid.uuid4()),
        subscription_item_id=item_id,
        tenant_id=tenant_id,
        event_type=event_type,
        event_at=now,
        actor=actor,
        reason=reason,
        metadata_json=metadata or {},
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    db.add(entry)
    db.flush()

    try:
        from api.observability.metrics import SUBSCRIPTION_EVENT_LEDGER_ENTRIES_TOTAL

        SUBSCRIPTION_EVENT_LEDGER_ENTRIES_TOTAL.labels(event_type=event_type).inc()
    except Exception:
        pass

    return entry


# ---------------------------------------------------------------------------
# Bundle assignment sync
# ---------------------------------------------------------------------------


def _sync_bundle_assignment(
    db: Session,
    item: SubscriptionItem,
    *,
    activate: bool,
) -> str | None:
    """Create or expire the TenantBundleAssignment that backs this subscription item.

    activate=True  → create/refresh assignment (active item)
    activate=False → expire assignment (suspended/canceled/expired item)

    Returns the assignment ID when activating, None when deactivating.
    """
    now = _utcnow()

    if activate:
        # First check if an assignment already exists for this tenant+bundle (unique constraint)
        existing = (
            db.query(TenantBundleAssignment)
            .filter(
                TenantBundleAssignment.tenant_id == item.tenant_id,
                TenantBundleAssignment.bundle_id == item.bundle_id,
            )
            .first()
        )

        if existing is not None:
            # Refresh: clear any prior expiry, update subscription_id
            existing.expires_at = item.ends_at
            existing.subscription_id = item.id
            db.flush()
            return existing.id
        else:
            assignment = TenantBundleAssignment(
                id=str(uuid.uuid4()),
                tenant_id=item.tenant_id,
                bundle_id=item.bundle_id,
                subscription_id=item.id,
                assigned_at=now,
                expires_at=item.ends_at,
                assigned_by="subscription_engine",
            )
            db.add(assignment)
            db.flush()
            return assignment.id
    else:
        # Deactivate: expire immediately
        if item.bundle_assignment_id:
            assignment = (
                db.query(TenantBundleAssignment)
                .filter(TenantBundleAssignment.id == item.bundle_assignment_id)
                .first()
            )
            if assignment is not None:
                assignment.expires_at = now
                db.flush()
        return None


def _invalidate(tenant_id: str) -> None:
    try:
        from services.capability_bundles.resolver import invalidate_cache

        invalidate_cache(tenant_id)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# SubscriptionEngine
# ---------------------------------------------------------------------------


class SubscriptionEngine:
    """Core engine for P1.4 Subscription Assignment Engine.

    All methods take a live SQLAlchemy Session. Callers own the transaction
    boundary (commit/rollback).
    """

    # --- Contracts ----------------------------------------------------------

    def create_contract(
        self,
        db: Session,
        tenant_id: str,
        contract_ref: str,
        sku_package: str,
        starts_at: datetime,
        *,
        sku_metadata: dict[str, Any] | None = None,
        ends_at: datetime | None = None,
        status: str = "draft",
        created_by: str = "system",
        notes: str | None = None,
    ) -> ContractResponse:
        if status not in _VALID_CONTRACT_STATUSES:
            raise ValueError(f"invalid contract status: {status!r}")

        contract = SubscriptionContract(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            contract_ref=contract_ref,
            sku_package=sku_package,
            sku_metadata=sku_metadata or {},
            status=status,
            starts_at=starts_at,
            ends_at=ends_at,
            created_by=created_by,
            created_at=_utcnow(),
            updated_at=_utcnow(),
            notes=notes,
        )
        db.add(contract)
        db.flush()

        try:
            from api.observability.metrics import SUBSCRIPTION_CONTRACTS_CREATED_TOTAL

            SUBSCRIPTION_CONTRACTS_CREATED_TOTAL.labels(sku_package=sku_package).inc()
        except Exception:
            pass

        log.info(
            "subscription_engine.contract_created tenant_id=%s id=%s ref=%s sku=%s",
            tenant_id,
            contract.id,
            contract_ref,
            sku_package,
        )
        return _to_contract_response(contract)

    def get_contract(
        self, db: Session, contract_id: str, tenant_id: str
    ) -> ContractResponse | None:
        contract = (
            db.query(SubscriptionContract)
            .filter(
                SubscriptionContract.id == contract_id,
                SubscriptionContract.tenant_id == tenant_id,
            )
            .first()
        )
        return _to_contract_response(contract) if contract is not None else None

    def list_contracts(self, db: Session, tenant_id: str) -> list[ContractResponse]:
        contracts = (
            db.query(SubscriptionContract)
            .filter(SubscriptionContract.tenant_id == tenant_id)
            .order_by(SubscriptionContract.created_at.desc())
            .all()
        )
        return [_to_contract_response(c) for c in contracts]

    def update_contract_status(
        self,
        db: Session,
        contract_id: str,
        tenant_id: str,
        status: str,
        actor: str,
        reason: str | None = None,
    ) -> ContractResponse | None:
        if status not in _VALID_CONTRACT_STATUSES:
            raise ValueError(f"invalid contract status: {status!r}")
        contract = (
            db.query(SubscriptionContract)
            .filter(
                SubscriptionContract.id == contract_id,
                SubscriptionContract.tenant_id == tenant_id,
            )
            .first()
        )
        if contract is None:
            return None
        contract.status = status
        contract.updated_at = _utcnow()
        db.flush()
        log.info(
            "subscription_engine.contract_status_changed id=%s status=%s actor=%s",
            contract_id,
            status,
            actor,
        )
        return _to_contract_response(contract)

    # --- SubscriptionItems --------------------------------------------------

    def create_item(
        self,
        db: Session,
        contract_id: str,
        tenant_id: str,
        bundle_id: str,
        sku_code: str,
        starts_at: datetime,
        *,
        meter_code: str | None = None,
        ends_at: datetime | None = None,
        status: str = "active",
        parent_item_id: str | None = None,
        actor: str = "system",
    ) -> ItemResponse:
        if status not in _VALID_ITEM_STATUSES:
            raise ValueError(f"invalid item status: {status!r}")

        # Verify bundle exists
        bundle = db.query(PolicyBundle).filter(PolicyBundle.id == bundle_id).first()
        if bundle is None:
            raise ValueError(f"unknown bundle_id: {bundle_id!r}")

        item = SubscriptionItem(
            id=str(uuid.uuid4()),
            contract_id=contract_id,
            tenant_id=tenant_id,
            bundle_id=bundle_id,
            sku_code=sku_code,
            meter_code=meter_code,
            status=status,
            starts_at=starts_at,
            ends_at=ends_at,
            parent_item_id=parent_item_id,
            bundle_assignment_id=None,
            created_at=_utcnow(),
            updated_at=_utcnow(),
        )
        db.add(item)
        db.flush()

        # Sync bundle assignment for active items
        if status == "active":
            assignment_id = _sync_bundle_assignment(db, item, activate=True)
            item.bundle_assignment_id = assignment_id
            item.updated_at = _utcnow()
            db.flush()
            _invalidate(tenant_id)

        # Write ledger event
        _append_ledger_event(
            db,
            item.id,
            tenant_id,
            "created",
            actor,
            None,
            {"sku_code": sku_code, "bundle_id": bundle_id, "status": status},
        )

        try:
            from api.observability.metrics import SUBSCRIPTION_ITEMS_CREATED_TOTAL

            SUBSCRIPTION_ITEMS_CREATED_TOTAL.labels(sku_code=sku_code).inc()
        except Exception:
            pass

        log.info(
            "subscription_engine.item_created tenant_id=%s id=%s bundle=%s sku=%s status=%s",
            tenant_id,
            item.id,
            bundle_id,
            sku_code,
            status,
        )
        return _to_item_response(item)

    def get_item(
        self, db: Session, item_id: str, tenant_id: str
    ) -> ItemResponse | None:
        item = (
            db.query(SubscriptionItem)
            .filter(
                SubscriptionItem.id == item_id,
                SubscriptionItem.tenant_id == tenant_id,
            )
            .first()
        )
        return _to_item_response(item) if item is not None else None

    def list_items(self, db: Session, tenant_id: str) -> list[ItemResponse]:
        items = (
            db.query(SubscriptionItem)
            .filter(SubscriptionItem.tenant_id == tenant_id)
            .order_by(SubscriptionItem.created_at.desc())
            .all()
        )
        return [_to_item_response(i) for i in items]

    def update_item_status(
        self,
        db: Session,
        item_id: str,
        tenant_id: str,
        status: str,
        actor: str,
        reason: str | None = None,
    ) -> ItemResponse | None:
        if status not in _VALID_ITEM_STATUSES:
            raise ValueError(f"invalid item status: {status!r}")
        item = (
            db.query(SubscriptionItem)
            .filter(
                SubscriptionItem.id == item_id,
                SubscriptionItem.tenant_id == tenant_id,
            )
            .first()
        )
        if item is None:
            return None

        prev_status = item.status
        item.status = status
        item.updated_at = _utcnow()
        db.flush()

        # Sync bundle assignment to match new status
        if status == "active":
            assignment_id = _sync_bundle_assignment(db, item, activate=True)
            item.bundle_assignment_id = assignment_id
            item.updated_at = _utcnow()
            db.flush()
        else:
            _sync_bundle_assignment(db, item, activate=False)

        _invalidate(tenant_id)

        # Write ledger event
        event_type = "reactivated" if status == "active" else status
        _append_ledger_event(
            db,
            item.id,
            tenant_id,
            event_type,
            actor,
            reason,
            {"from_status": prev_status, "to_status": status},
        )

        try:
            from api.observability.metrics import (
                SUBSCRIPTION_ITEMS_STATUS_CHANGES_TOTAL,
            )

            SUBSCRIPTION_ITEMS_STATUS_CHANGES_TOTAL.labels(
                from_status=prev_status, to_status=status
            ).inc()
        except Exception:
            pass

        log.info(
            "subscription_engine.item_status_changed id=%s %s→%s actor=%s",
            item_id,
            prev_status,
            status,
            actor,
        )
        return _to_item_response(item)

    def list_ledger(
        self, db: Session, item_id: str, tenant_id: str
    ) -> list[LedgerEntryResponse]:
        entries = (
            db.query(SubscriptionEventLedger)
            .filter(
                SubscriptionEventLedger.subscription_item_id == item_id,
                SubscriptionEventLedger.tenant_id == tenant_id,
            )
            .order_by(SubscriptionEventLedger.event_at.asc())
            .all()
        )
        return [
            LedgerEntryResponse(
                id=e.id,
                subscription_item_id=e.subscription_item_id,
                tenant_id=e.tenant_id,
                event_type=e.event_type,
                event_at=e.event_at,
                actor=e.actor,
                reason=e.reason,
                metadata_json=e.metadata_json or {},
                prev_hash=e.prev_hash,
                entry_hash=e.entry_hash,
            )
            for e in entries
        ]

    # --- explain-capability -------------------------------------------------

    def explain_capability(
        self, db: Session, tenant_id: str, capability: str
    ) -> ExplainCapabilityResponse:
        """Trace the full capability resolution chain for a tenant and capability.

        Returns a structured explanation showing which layer granted/denied access
        and the state of all dependency capabilities.
        """
        from api.entitlements import (
            CAPABILITY_REGISTRY,
            _get_tenant_tier,
            _tier_capabilities,
        )
        from api.db import set_tenant_context
        from api.db_models import TenantEntitlement
        from sqlalchemy import or_

        chain: list[ResolutionLayer] = []
        now = datetime.now(timezone.utc)

        # Layer 1: Registry
        if capability not in CAPABILITY_REGISTRY:
            chain.append(ResolutionLayer(layer="registry", result="miss"))
            return ExplainCapabilityResponse(
                tenant_id=tenant_id,
                capability=capability,
                decision="denied",
                source="registry_miss",
                resolution_chain=chain,
            )
        chain.append(ResolutionLayer(layer="registry", result="found"))

        # Layer 2: Explicit DB grant
        set_tenant_context(db, tenant_id)
        explicit = (
            db.query(TenantEntitlement)
            .filter(
                TenantEntitlement.tenant_id == tenant_id,
                TenantEntitlement.capability == capability,
                or_(
                    TenantEntitlement.expires_at.is_(None),
                    TenantEntitlement.expires_at > now,
                ),
            )
            .first()
        )
        if explicit is not None:
            chain.append(
                ResolutionLayer(
                    layer="explicit_grant",
                    result="granted",
                    detail={
                        "entitlement_id": explicit.id,
                        "granted_by": explicit.granted_by,
                    },
                )
            )
            dep_checks = self._check_dependencies(db, tenant_id, capability)
            return ExplainCapabilityResponse(
                tenant_id=tenant_id,
                capability=capability,
                decision="granted",
                source="explicit",
                resolution_chain=chain,
                dependency_checks=dep_checks,
            )
        chain.append(ResolutionLayer(layer="explicit_grant", result="miss"))

        # Layer 3: Subscription-backed bundle assignment
        from services.capability_bundles.resolver import resolve_tenant_capabilities

        bundle_caps = resolve_tenant_capabilities(db, tenant_id)
        if capability in bundle_caps:
            # Find which active subscription item provides this capability
            sub_detail = self._find_subscription_source(db, tenant_id, capability)
            chain.append(
                ResolutionLayer(
                    layer="bundle_assignment",
                    result="granted",
                    detail=sub_detail,
                )
            )
            dep_checks = self._check_dependencies(db, tenant_id, capability)
            return ExplainCapabilityResponse(
                tenant_id=tenant_id,
                capability=capability,
                decision="granted",
                source="subscription"
                if sub_detail.get("via_subscription")
                else "bundle",
                resolution_chain=chain,
                dependency_checks=dep_checks,
            )
        chain.append(ResolutionLayer(layer="bundle_assignment", result="miss"))

        # Layer 4: Tier default
        tier = _get_tenant_tier(tenant_id)
        tier_caps = _tier_capabilities().get(tier, frozenset())
        if capability in tier_caps:
            chain.append(
                ResolutionLayer(
                    layer="tier_default",
                    result="granted",
                    detail={"tier": tier},
                )
            )
            dep_checks = self._check_dependencies(db, tenant_id, capability)
            return ExplainCapabilityResponse(
                tenant_id=tenant_id,
                capability=capability,
                decision="granted",
                source="tier",
                resolution_chain=chain,
                dependency_checks=dep_checks,
            )
        chain.append(
            ResolutionLayer(
                layer="tier_default", result="denied", detail={"tier": tier}
            )
        )

        return ExplainCapabilityResponse(
            tenant_id=tenant_id,
            capability=capability,
            decision="denied",
            source="tier",
            resolution_chain=chain,
            dependency_checks={},
        )

    def _check_dependencies(
        self, db: Session, tenant_id: str, capability: str
    ) -> dict[str, str]:
        """Return granted/denied for each transitive dependency."""
        from api.entitlements import check_capability
        from services.capability_enforcement.graph import get_required_capabilities

        deps = get_required_capabilities(capability)
        result: dict[str, str] = {}
        for dep in deps:
            dep_result = check_capability(db, tenant_id, dep)
            result[dep] = "granted" if dep_result.allowed else "denied"
        return result

    def _find_subscription_source(
        self, db: Session, tenant_id: str, capability: str
    ) -> dict[str, Any]:
        """Find which active subscription item provides a capability (best effort)."""
        from api.db_models import Capability, PolicyBundleCapability

        cap_row = (
            db.query(Capability).filter(Capability.capability_key == capability).first()
        )
        if cap_row is None:
            return {}

        # Find active subscription items for this tenant that include this capability
        items = (
            db.query(SubscriptionItem)
            .filter(
                SubscriptionItem.tenant_id == tenant_id,
                SubscriptionItem.status == "active",
            )
            .all()
        )
        for item in items:
            bundle_cap = (
                db.query(PolicyBundleCapability)
                .filter(
                    PolicyBundleCapability.bundle_id == item.bundle_id,
                    PolicyBundleCapability.capability_id == cap_row.id,
                )
                .first()
            )
            if bundle_cap is not None:
                return {
                    "via_subscription": True,
                    "subscription_item_id": item.id,
                    "contract_id": item.contract_id,
                    "sku_code": item.sku_code,
                    "bundle_id": item.bundle_id,
                }
        return {"via_subscription": False}
