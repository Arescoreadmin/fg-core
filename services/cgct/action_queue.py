"""P0-11: CGCT Action Queue Computation Service.

Generates deterministic action items from authoritative source tables only.
No AI recommendations — rules-based detection from existing data.

Authority sources:
  - CLM: FaClmCert (renewal_due, expired, in_review, pending_*)
  - TIM: FaTimDriftEvent (open drift events)
  - Verification: FaVerificationBundle (partial, missing_evidence, tampered)

Entry points:
  compute_actions(db, *, tenant_id, engagement_id) -> list[dict]
  store_actions(db, *, tenant_id, engagement_id, actions) -> int
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("frostgate.cgct.action_queue")

_SCHEMA_VERSION = "1.0"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id() -> str:
    return uuid.uuid4().hex


def _clm_actions(db: Any, *, tenant_id: str, engagement_id: str) -> list[dict]:
    """Generate actions from CLM cert lifecycle statuses."""
    actions: list[dict] = []
    try:
        from api.db_models_clm import FaClmCert  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        q = select(FaClmCert).where(
            FaClmCert.tenant_id == tenant_id,
            FaClmCert.engagement_id == engagement_id,
        )
        certs = db.execute(q).scalars().all()
        for cert in certs:
            status = cert.lifecycle_status or ""

            if status in ("renewal_due", "expired"):
                actions.append(
                    {
                        "action_type": "renew_certification",
                        "action_title": f"Renew certification: {cert.cert_name or cert.id}",
                        "action_description": (
                            f"Certification '{cert.cert_name}' has lifecycle status "
                            f"'{status}' and requires renewal."
                        ),
                        "priority": "high",
                        "source_system": "clm",
                        "source_id": cert.id,
                        "evidence_refs_json": "[]",
                    }
                )
            elif status in ("in_review", "pending_evidence", "pending_approval"):
                actions.append(
                    {
                        "action_type": "review_certification",
                        "action_title": f"Review certification: {cert.cert_name or cert.id}",
                        "action_description": (
                            f"Certification '{cert.cert_name}' is in status "
                            f"'{status}' and requires review."
                        ),
                        "priority": "medium",
                        "source_system": "clm",
                        "source_id": cert.id,
                        "evidence_refs_json": "[]",
                    }
                )
    except Exception:
        log.debug("cgct.action_queue: CLM certs unavailable", exc_info=True)
    return actions


def _tim_drift_actions(db: Any, *, tenant_id: str, engagement_id: str) -> list[dict]:
    """Generate actions from open TIM drift events."""
    actions: list[dict] = []
    try:
        from api.db_models_tim import FaTimDriftEvent  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        q = select(FaTimDriftEvent).where(
            FaTimDriftEvent.tenant_id == tenant_id,
            FaTimDriftEvent.engagement_id == engagement_id,
            FaTimDriftEvent.status == "open",
            FaTimDriftEvent.resolved_at.is_(None),
        )
        events = db.execute(q).scalars().all()
        for event in events:
            actions.append(
                {
                    "action_type": "investigate_drift",
                    "action_title": f"Investigate drift: {event.drift_rule}",
                    "action_description": (
                        f"Open drift event '{event.drift_rule}' detected with "
                        f"severity '{event.severity}' requires investigation."
                    ),
                    "priority": "high",
                    "source_system": "tim",
                    "source_id": event.id,
                    "evidence_refs_json": "[]",
                }
            )
    except Exception:
        log.debug("cgct.action_queue: TIM drift events unavailable", exc_info=True)
    return actions


def _bundle_actions(db: Any, *, tenant_id: str, engagement_id: str) -> list[dict]:
    """Generate actions from verification bundle coverage status."""
    actions: list[dict] = []
    try:
        from api.db_models_verification_bundle import FaVerificationBundle  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        q = (
            select(FaVerificationBundle)
            .where(
                FaVerificationBundle.tenant_id == tenant_id,
                FaVerificationBundle.engagement_id == engagement_id,
            )
            .order_by(FaVerificationBundle.generated_at.desc())
            .limit(20)
        )
        bundles = db.execute(q).scalars().all()
        for bundle in bundles:
            coverage = bundle.coverage_status or ""
            if coverage == "tampered":
                actions.append(
                    {
                        "action_type": "validate_evidence",
                        "action_title": f"Tampered evidence bundle: {bundle.id[:12]}",
                        "action_description": (
                            f"Verification bundle {bundle.id} has coverage_status "
                            f"'tampered' — immediate evidence integrity investigation required."
                        ),
                        "priority": "critical",
                        "source_system": "verification_bundle",
                        "source_id": bundle.id,
                        "evidence_refs_json": "[]",
                    }
                )
            elif coverage in ("partial", "missing_evidence"):
                actions.append(
                    {
                        "action_type": "validate_evidence",
                        "action_title": f"Incomplete evidence bundle: {bundle.id[:12]}",
                        "action_description": (
                            f"Verification bundle {bundle.id} has coverage_status "
                            f"'{coverage}' — evidence needs to be completed."
                        ),
                        "priority": "medium",
                        "source_system": "verification_bundle",
                        "source_id": bundle.id,
                        "evidence_refs_json": "[]",
                    }
                )
    except Exception:
        log.debug("cgct.action_queue: verification bundles unavailable", exc_info=True)
    return actions


def compute_actions(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
) -> list[dict]:
    """Compute deterministic action items for (tenant_id, engagement_id).

    Aggregates actions from CLM certs, TIM drift events, and verification bundles.
    Returns a list of action dicts (not persisted — call store_actions to persist).
    """
    actions: list[dict] = []
    actions.extend(_clm_actions(db, tenant_id=tenant_id, engagement_id=engagement_id))
    actions.extend(
        _tim_drift_actions(db, tenant_id=tenant_id, engagement_id=engagement_id)
    )
    actions.extend(
        _bundle_actions(db, tenant_id=tenant_id, engagement_id=engagement_id)
    )
    return actions


def store_actions(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    actions: list[dict],
) -> int:
    """Persist computed actions to fg_cgct_action_queue. Returns count stored.

    Each call appends new rows (append-only table).
    Caller must commit the session.
    """
    if not actions:
        return 0

    stored = 0
    try:
        from api.db_models_cgct import FaCgctActionItem  # noqa: PLC0415

        now = _now_iso()
        for action in actions:
            row = FaCgctActionItem(
                id=_new_id(),
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                action_type=action.get("action_type", ""),
                action_title=action.get("action_title", ""),
                action_description=action.get("action_description"),
                priority=action.get("priority", "medium"),
                status="open",
                source_system=action.get("source_system", ""),
                source_id=action.get("source_id"),
                evidence_refs_json=action.get("evidence_refs_json", "[]"),
                actor_type="system",
                created_at=now,
                schema_version=_SCHEMA_VERSION,
            )
            db.add(row)
            stored += 1
    except Exception:
        log.warning("cgct.action_queue: store_actions failed", exc_info=True)
        return 0

    return stored
