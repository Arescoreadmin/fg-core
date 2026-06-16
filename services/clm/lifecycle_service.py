"""P0-10: Certification Lifecycle Management (CLM) service.

Manages the full lifecycle of certifications: creation, status transitions,
reviews, attestations, renewals, health scoring, lineage traversal, and
trust impact computation.

No new trust engines. All data sourced from existing P0-6A/B, P0-7 tables.

Entry points (all return plain dict; empty dict on fatal error; caller commits):
  create_certification()    — create cert record + manifest + lifecycle event
  transition_lifecycle()    — validated status transition
  add_review()              — append review record + lifecycle event
  add_attestation()         — append attestation record + lifecycle event
  initiate_renewal()        — append renewal record + lifecycle event
  get_certification_health() — health scoring with renewal_recommended flag
  get_lineage()             — parent chain + family tree
  compute_trust_impact()    — certification impact on trust posture
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("frostgate.clm")

_GENERATION_VERSION = "clm-1.0"
_AUTHORITY_VERSION = "v1"
_SCHEMA_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Valid lifecycle state machine
# ---------------------------------------------------------------------------

_VALID_TRANSITIONS: dict[str, set[str]] = {
    "draft": {"in_review", "pending_evidence", "archived"},
    "in_review": {"pending_evidence", "pending_approval", "revoked", "archived"},
    "pending_evidence": {"in_review", "revoked", "archived"},
    "pending_approval": {"approved", "in_review", "revoked", "archived"},
    "approved": {"certified", "revoked", "archived"},
    "certified": {"renewal_due", "expired", "revoked", "superseded", "archived"},
    "renewal_due": {"in_review", "revoked", "expired", "archived"},
    "expired": {"in_review", "archived"},
    "revoked": {"archived"},
    "superseded": {"archived"},
    "archived": set(),
}

# Certification level → trust weight
_CERT_LEVEL_WEIGHT: dict[str, int] = {
    "bronze": 10,
    "silver": 20,
    "gold": 30,
    "platinum": 40,
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _new_id() -> str:
    return uuid.uuid4().hex


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(data: Any) -> str:
    raw = json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def _days_until(valid_until: str | None) -> int | None:
    if not valid_until:
        return None
    try:
        until_dt = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        delta = (until_dt - now).days
        return delta
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Platform data fetchers (graceful degradation on import/query errors)
# ---------------------------------------------------------------------------


def _fetch_trust_arc_cert(db: Any, *, trust_arc_cert_id: str | None) -> Any:
    if not trust_arc_cert_id:
        return None
    try:
        from api.db_models_trust_arc import FaTrustCertification  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        return db.execute(
            select(FaTrustCertification).where(
                FaTrustCertification.id == trust_arc_cert_id
            )
        ).scalar_one_or_none()
    except Exception:
        return None


def _fetch_recent_snapshots(
    db: Any, *, tenant_id: str, engagement_id: str, limit: int = 10
) -> list[Any]:
    try:
        from api.db_models_tim import FaTimTrustSnapshot  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        return (
            db.execute(
                select(FaTimTrustSnapshot)
                .where(
                    FaTimTrustSnapshot.tenant_id == tenant_id,
                    FaTimTrustSnapshot.engagement_id == engagement_id,
                )
                .order_by(FaTimTrustSnapshot.evaluated_at.desc())
                .limit(limit)
            )
            .scalars()
            .all()
        )
    except Exception:
        return []


def _fetch_recent_drift_events(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    since_iso: str | None = None,
    limit: int = 50,
) -> list[Any]:
    try:
        from api.db_models_tim import FaTimDriftEvent  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        q = select(FaTimDriftEvent).where(
            FaTimDriftEvent.tenant_id == tenant_id,
            FaTimDriftEvent.engagement_id == engagement_id,
        )
        if since_iso:
            q = q.where(FaTimDriftEvent.detected_at >= since_iso)
        q = q.order_by(FaTimDriftEvent.detected_at.desc()).limit(limit)
        return db.execute(q).scalars().all()
    except Exception:
        return []


def _fetch_recent_bundles(
    db: Any, *, tenant_id: str, engagement_id: str, limit: int = 10
) -> list[Any]:
    try:
        from api.db_models_verification_bundle import FaVerificationBundle  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        return (
            db.execute(
                select(FaVerificationBundle)
                .where(
                    FaVerificationBundle.tenant_id == tenant_id,
                    FaVerificationBundle.engagement_id == engagement_id,
                )
                .order_by(FaVerificationBundle.generated_at.desc())
                .limit(limit)
            )
            .scalars()
            .all()
        )
    except Exception:
        return []


def _fetch_recent_decisions(
    db: Any, *, tenant_id: str, engagement_id: str, limit: int = 10
) -> list[Any]:
    try:
        from api.db_models_trust_arc import FaTrustDecisionMemory  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        return (
            db.execute(
                select(FaTrustDecisionMemory)
                .where(
                    FaTrustDecisionMemory.tenant_id == tenant_id,
                    FaTrustDecisionMemory.engagement_id == engagement_id,
                )
                .order_by(FaTrustDecisionMemory.created_at.desc())
                .limit(limit)
            )
            .scalars()
            .all()
        )
    except Exception:
        return []


def _fetch_recent_timeline(
    db: Any, *, tenant_id: str, engagement_id: str, limit: int = 20
) -> list[Any]:
    try:
        from api.db_models_timeline import TimelineEventRecord  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        return (
            db.execute(
                select(TimelineEventRecord)
                .where(TimelineEventRecord.tenant_id == tenant_id)
                .filter(
                    TimelineEventRecord.payload["engagement_id"].as_string()
                    == engagement_id
                )
                .order_by(TimelineEventRecord.occurred_at.desc())
                .limit(limit)
            )
            .scalars()
            .all()
        )
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------


def create_certification(
    db: Any,
    *,
    tenant_id: str,
    engagement_id: str,
    trust_arc_cert_id: str | None = None,
    cert_name: str = "",
    cert_type: str = "standard",
    framework: str | None = None,
    certification_level: str | None = None,
    valid_from: str | None = None,
    valid_until: str | None = None,
    created_by: str = "system",
    parent_cert_id: str | None = None,
    family_id: str | None = None,
    actor_type: str = "human",
    framework_version: str | None = None,
    certification_profile: str | None = None,
) -> dict[str, Any]:
    """Create a new CLM certification record with manifest and initial event.

    Fetches existing platform data to populate the manifest.
    Returns assembled dict on success; empty dict on fatal error.
    Caller owns the DB session and must commit.
    """
    try:
        from api.db_models_clm import (  # noqa: PLC0415
            FaClmCert,
            FaClmCertManifest,
            FaClmLifecycleEvent,
        )

        now = _now_iso()
        cert_id = _new_id()

        # Gather platform evidence for manifest
        snapshots = _fetch_recent_snapshots(
            db, tenant_id=tenant_id, engagement_id=engagement_id, limit=10
        )
        bundles = _fetch_recent_bundles(
            db, tenant_id=tenant_id, engagement_id=engagement_id, limit=10
        )
        decisions = _fetch_recent_decisions(
            db, tenant_id=tenant_id, engagement_id=engagement_id, limit=10
        )
        timeline = _fetch_recent_timeline(
            db, tenant_id=tenant_id, engagement_id=engagement_id, limit=20
        )

        snapshot_ids = [s.id for s in snapshots]
        bundle_ids = [b.id for b in bundles]
        decision_refs = [d.id for d in decisions]
        timeline_refs = [t.id for t in timeline]
        evidence_refs: list[str] = []

        if trust_arc_cert_id:
            evidence_refs.append(trust_arc_cert_id)

        # Compute cert_hash (no ephemeral timestamps in hash)
        cert_hash = _sha256(
            {
                "tenant_id": tenant_id,
                "engagement_id": engagement_id,
                "trust_arc_cert_id": trust_arc_cert_id,
                "cert_name": cert_name,
                "cert_type": cert_type,
                "certification_level": certification_level,
                "valid_from": valid_from,
                "valid_until": valid_until,
                "created_at": now,
            }
        )

        # Compute manifest_hash
        manifest_hash = _sha256(
            {
                "trust_arc_cert_id": trust_arc_cert_id,
                "snapshot_ids": sorted(snapshot_ids),
                "bundle_ids": sorted(bundle_ids),
                "timeline_refs": sorted(timeline_refs),
                "decision_refs": sorted(decision_refs),
                "evidence_refs": sorted(evidence_refs),
            }
        )

        # Persist: FaClmCert
        cert = FaClmCert(
            id=cert_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            trust_arc_cert_id=trust_arc_cert_id,
            cert_name=cert_name,
            cert_type=cert_type,
            framework=framework,
            certification_level=certification_level,
            lifecycle_status="draft",
            parent_cert_id=parent_cert_id,
            family_id=family_id,
            valid_from=valid_from,
            valid_until=valid_until,
            created_by=created_by,
            created_at=now,
            cert_hash=cert_hash,
            actor_type=actor_type,
            framework_version=framework_version,
            certification_profile=certification_profile,
            generation_version=_GENERATION_VERSION,
            authority_version=_AUTHORITY_VERSION,
            schema_version=_SCHEMA_VERSION,
        )
        db.add(cert)

        # Persist: FaClmCertManifest
        manifest = FaClmCertManifest(
            id=_new_id(),
            cert_id=cert_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            trust_arc_cert_id=trust_arc_cert_id,
            snapshot_ids=json.dumps(snapshot_ids),
            bundle_ids=json.dumps(bundle_ids),
            timeline_refs=json.dumps(timeline_refs),
            decision_refs=json.dumps(decision_refs),
            evidence_refs=json.dumps(evidence_refs),
            manifest_hash=manifest_hash,
            generated_at=now,
            schema_version=_SCHEMA_VERSION,
        )
        db.add(manifest)

        # Persist: FaClmLifecycleEvent (created)
        event = FaClmLifecycleEvent(
            id=_new_id(),
            cert_id=cert_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type="created",
            from_status=None,
            to_status="draft",
            actor=created_by,
            actor_type=actor_type,
            notes=None,
            event_data=json.dumps({"cert_name": cert_name, "cert_type": cert_type}),
            occurred_at=now,
            schema_version=_SCHEMA_VERSION,
        )
        db.add(event)

        db.flush()

        return {
            "cert_id": cert_id,
            "tenant_id": tenant_id,
            "engagement_id": engagement_id,
            "trust_arc_cert_id": trust_arc_cert_id,
            "cert_name": cert_name,
            "cert_type": cert_type,
            "framework": framework,
            "certification_level": certification_level,
            "lifecycle_status": "draft",
            "parent_cert_id": parent_cert_id,
            "family_id": family_id,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "created_by": created_by,
            "created_at": now,
            "cert_hash": cert_hash,
            "actor_type": actor_type,
            "framework_version": framework_version,
            "certification_profile": certification_profile,
            "generation_version": _GENERATION_VERSION,
            "schema_version": _SCHEMA_VERSION,
            "manifest": {
                "manifest_hash": manifest_hash,
                "snapshot_ids": snapshot_ids,
                "bundle_ids": bundle_ids,
                "timeline_refs": timeline_refs,
                "decision_refs": decision_refs,
                "evidence_refs": evidence_refs,
                "generated_at": now,
                "schema_version": _SCHEMA_VERSION,
            },
        }

    except Exception:
        log.exception("clm.create_certification error")
        return {}


def transition_lifecycle(
    db: Any,
    *,
    cert_id: str,
    tenant_id: str,
    to_status: str,
    actor: str = "system",
    actor_type: str = "human",
    notes: str | None = None,
) -> dict[str, Any]:
    """Validate and apply a lifecycle status transition.

    Raises ValueError on invalid transition or missing cert.
    Returns transition summary dict on success.
    Caller commits.
    """
    from api.db_models_clm import FaClmCert, FaClmLifecycleEvent  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    cert = db.execute(
        select(FaClmCert).where(
            FaClmCert.id == cert_id,
            FaClmCert.tenant_id == tenant_id,
        )
    ).scalar_one_or_none()

    if cert is None:
        raise ValueError(f"cert_id={cert_id} not found for tenant={tenant_id}")

    from_status = cert.lifecycle_status
    allowed = _VALID_TRANSITIONS.get(from_status, set())
    if to_status not in allowed:
        raise ValueError(
            f"Invalid transition {from_status!r} → {to_status!r}. "
            f"Allowed: {sorted(allowed)}"
        )

    now = _now_iso()
    cert.lifecycle_status = to_status
    cert.status_updated_by = actor
    cert.status_updated_at = now

    event = FaClmLifecycleEvent(
        id=_new_id(),
        cert_id=cert_id,
        tenant_id=tenant_id,
        engagement_id=cert.engagement_id,
        event_type="status_transition",
        from_status=from_status,
        to_status=to_status,
        actor=actor,
        actor_type=actor_type,
        notes=notes,
        event_data=json.dumps({}),
        occurred_at=now,
        schema_version=_SCHEMA_VERSION,
    )
    db.add(event)
    db.flush()

    return {
        "cert_id": cert_id,
        "from_status": from_status,
        "to_status": to_status,
        "actor": actor,
        "actor_type": actor_type,
        "occurred_at": now,
    }


def add_review(
    db: Any,
    *,
    cert_id: str,
    tenant_id: str,
    reviewer: str,
    reviewer_type: str = "human",
    review_outcome: str,
    notes: str | None = None,
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    """Append a review record and lifecycle event.

    Returns empty dict if cert not found.
    Caller commits.
    """
    try:
        from api.db_models_clm import (  # noqa: PLC0415
            FaClmCertReview,
            FaClmLifecycleEvent,
        )
        from sqlalchemy import select  # noqa: PLC0415
        from api.db_models_clm import FaClmCert  # noqa: PLC0415

        cert = db.execute(
            select(FaClmCert).where(
                FaClmCert.id == cert_id,
                FaClmCert.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        if cert is None:
            return {}

        now = _now_iso()
        refs = evidence_refs or []
        review_id = _new_id()

        review = FaClmCertReview(
            id=review_id,
            cert_id=cert_id,
            tenant_id=tenant_id,
            engagement_id=cert.engagement_id,
            reviewer=reviewer,
            reviewer_type=reviewer_type,
            review_outcome=review_outcome,
            notes=notes,
            evidence_refs=json.dumps(refs),
            reviewed_at=now,
            schema_version=_SCHEMA_VERSION,
        )
        db.add(review)

        event = FaClmLifecycleEvent(
            id=_new_id(),
            cert_id=cert_id,
            tenant_id=tenant_id,
            engagement_id=cert.engagement_id,
            event_type="review_completed",
            from_status=cert.lifecycle_status,
            to_status=cert.lifecycle_status,
            actor=reviewer,
            actor_type=reviewer_type,
            notes=notes,
            event_data=json.dumps({"review_outcome": review_outcome}),
            occurred_at=now,
            schema_version=_SCHEMA_VERSION,
        )
        db.add(event)
        db.flush()

        return {
            "review_id": review_id,
            "cert_id": cert_id,
            "reviewer": reviewer,
            "reviewer_type": reviewer_type,
            "review_outcome": review_outcome,
            "notes": notes,
            "evidence_refs": refs,
            "reviewed_at": now,
            "schema_version": _SCHEMA_VERSION,
        }

    except Exception:
        log.exception("clm.add_review error")
        return {}


def add_attestation(
    db: Any,
    *,
    cert_id: str,
    tenant_id: str,
    attestation_type: str,
    attester: str,
    attester_type: str = "human",
    attestation_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append an attestation record and lifecycle event.

    Returns empty dict if cert not found.
    Caller commits.
    """
    try:
        from api.db_models_clm import (  # noqa: PLC0415
            FaClmCert,
            FaClmCertAttestation,
            FaClmLifecycleEvent,
        )
        from sqlalchemy import select  # noqa: PLC0415

        cert = db.execute(
            select(FaClmCert).where(
                FaClmCert.id == cert_id,
                FaClmCert.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        if cert is None:
            return {}

        data = attestation_data or {}
        attestation_hash = _sha256(data)

        now = _now_iso()
        attestation_id = _new_id()

        attestation = FaClmCertAttestation(
            id=attestation_id,
            cert_id=cert_id,
            tenant_id=tenant_id,
            engagement_id=cert.engagement_id,
            attestation_type=attestation_type,
            attester=attester,
            attester_type=attester_type,
            attestation_data=json.dumps(data),
            attestation_hash=attestation_hash,
            attested_at=now,
            schema_version=_SCHEMA_VERSION,
        )
        db.add(attestation)

        event = FaClmLifecycleEvent(
            id=_new_id(),
            cert_id=cert_id,
            tenant_id=tenant_id,
            engagement_id=cert.engagement_id,
            event_type="attestation_added",
            from_status=cert.lifecycle_status,
            to_status=cert.lifecycle_status,
            actor=attester,
            actor_type=attester_type,
            notes=None,
            event_data=json.dumps({"attestation_type": attestation_type}),
            occurred_at=now,
            schema_version=_SCHEMA_VERSION,
        )
        db.add(event)
        db.flush()

        return {
            "attestation_id": attestation_id,
            "cert_id": cert_id,
            "attestation_type": attestation_type,
            "attester": attester,
            "attester_type": attester_type,
            "attestation_data": data,
            "attestation_hash": attestation_hash,
            "attested_at": now,
            "schema_version": _SCHEMA_VERSION,
        }

    except Exception:
        log.exception("clm.add_attestation error")
        return {}


def initiate_renewal(
    db: Any,
    *,
    cert_id: str,
    tenant_id: str,
    renewal_type: str = "routine",
    initiated_by: str = "system",
) -> dict[str, Any]:
    """Append a renewal record and lifecycle event.

    Computes renewal_readiness from platform health data.
    Returns empty dict if cert not found.
    Caller commits.
    """
    try:
        from api.db_models_clm import (  # noqa: PLC0415
            FaClmCert,
            FaClmCertRenewal,
            FaClmLifecycleEvent,
        )
        from sqlalchemy import select  # noqa: PLC0415

        cert = db.execute(
            select(FaClmCert).where(
                FaClmCert.id == cert_id,
                FaClmCert.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        if cert is None:
            return {}

        now = _now_iso()

        # Compute renewal_readiness
        snapshots = _fetch_recent_snapshots(
            db,
            tenant_id=tenant_id,
            engagement_id=cert.engagement_id,
            limit=5,
        )
        from datetime import timedelta  # noqa: PLC0415

        thirty_ago = (datetime.now(timezone.utc) - timedelta(days=30)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        drift_events = _fetch_recent_drift_events(
            db,
            tenant_id=tenant_id,
            engagement_id=cert.engagement_id,
            since_iso=thirty_ago,
            limit=50,
        )

        days_until_expiry = _days_until(cert.valid_until)
        avg_posture = None
        if snapshots:
            scores = [s.posture_score for s in snapshots]
            avg_posture = round(sum(scores) / len(scores), 1)

        open_drift = [e for e in drift_events if e.status == "open"]
        readiness: dict[str, Any] = {
            "days_until_expiry": days_until_expiry,
            "avg_posture_score": avg_posture,
            "open_drift_events": len(open_drift),
            "recent_snapshots": len(snapshots),
            "renewal_risk": "high"
            if (days_until_expiry or 999) < 30
            else "medium"
            if (days_until_expiry or 999) < 90
            else "low",
        }

        renewal_id = _new_id()
        renewal = FaClmCertRenewal(
            id=renewal_id,
            cert_id=cert_id,
            tenant_id=tenant_id,
            engagement_id=cert.engagement_id,
            renewal_type=renewal_type,
            renewal_status="initiated",
            initiated_by=initiated_by,
            initiated_at=now,
            renewal_readiness=json.dumps(readiness),
            schema_version=_SCHEMA_VERSION,
        )
        db.add(renewal)

        event = FaClmLifecycleEvent(
            id=_new_id(),
            cert_id=cert_id,
            tenant_id=tenant_id,
            engagement_id=cert.engagement_id,
            event_type="renewal_initiated",
            from_status=cert.lifecycle_status,
            to_status=cert.lifecycle_status,
            actor=initiated_by,
            actor_type="human",
            notes=None,
            event_data=json.dumps({"renewal_type": renewal_type}),
            occurred_at=now,
            schema_version=_SCHEMA_VERSION,
        )
        db.add(event)
        db.flush()

        return {
            "renewal_id": renewal_id,
            "cert_id": cert_id,
            "renewal_type": renewal_type,
            "renewal_status": "initiated",
            "initiated_by": initiated_by,
            "initiated_at": now,
            "renewal_readiness": readiness,
            "schema_version": _SCHEMA_VERSION,
        }

    except Exception:
        log.exception("clm.initiate_renewal error")
        return {}


def get_certification_health(
    db: Any,
    *,
    cert_id: str,
    tenant_id: str,
) -> dict[str, Any]:
    """Compute health summary for a certification.

    Returns health dict with renewal_recommended flag.
    Returns empty dict if cert not found.
    """
    try:
        from api.db_models_clm import FaClmCert  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415
        from datetime import timedelta  # noqa: PLC0415

        cert = db.execute(
            select(FaClmCert).where(
                FaClmCert.id == cert_id,
                FaClmCert.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        if cert is None:
            return {}

        snapshots = _fetch_recent_snapshots(
            db,
            tenant_id=tenant_id,
            engagement_id=cert.engagement_id,
            limit=5,
        )

        thirty_ago = (datetime.now(timezone.utc) - timedelta(days=30)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        drift_events = _fetch_recent_drift_events(
            db,
            tenant_id=tenant_id,
            engagement_id=cert.engagement_id,
            since_iso=thirty_ago,
            limit=50,
        )

        days_until_expiry = _days_until(cert.valid_until)
        avg_posture = None
        if snapshots:
            scores = [s.posture_score for s in snapshots]
            avg_posture = round(sum(scores) / len(scores), 1)

        open_drift = [e for e in drift_events if e.status == "open"]
        high_sev = [e for e in open_drift if e.severity in ("high", "critical")]

        # Drift risk score: 0–100, higher = riskier
        drift_risk_score = min(100, len(open_drift) * 5 + len(high_sev) * 10)

        renewal_recommended = False
        if days_until_expiry is not None and days_until_expiry <= 90:
            renewal_recommended = True
        if cert.lifecycle_status in ("renewal_due", "expired"):
            renewal_recommended = True

        return {
            "cert_id": cert_id,
            "lifecycle_status": cert.lifecycle_status,
            "certification_level": cert.certification_level,
            "valid_until": cert.valid_until,
            "days_until_expiry": days_until_expiry,
            "avg_posture_score": avg_posture,
            "open_drift_events": len(open_drift),
            "drift_risk_score": drift_risk_score,
            "renewal_recommended": renewal_recommended,
            "snapshot_count": len(snapshots),
        }

    except Exception:
        log.exception("clm.get_certification_health error")
        return {}


def get_lineage(
    db: Any,
    *,
    cert_id: str,
    tenant_id: str,
) -> dict[str, Any]:
    """Walk parent chain and family tree for a certification.

    Returns {"root": {...}, "chain": [...], "total": int}
    Returns empty dict if cert not found.
    """
    try:
        from api.db_models_clm import FaClmCert  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415

        def _load_cert(cid: str) -> Any:
            return db.execute(
                select(FaClmCert).where(
                    FaClmCert.id == cid,
                    FaClmCert.tenant_id == tenant_id,
                )
            ).scalar_one_or_none()

        def _cert_summary(c: Any) -> dict[str, Any]:
            return {
                "cert_id": c.id,
                "cert_name": c.cert_name,
                "cert_type": c.cert_type,
                "lifecycle_status": c.lifecycle_status,
                "certification_level": c.certification_level,
                "valid_from": c.valid_from,
                "valid_until": c.valid_until,
                "parent_cert_id": c.parent_cert_id,
                "family_id": c.family_id,
                "created_at": c.created_at,
            }

        start_cert = _load_cert(cert_id)
        if start_cert is None:
            return {}

        # Walk upward through parent_cert_id chain (max depth 50)
        chain: list[dict[str, Any]] = [_cert_summary(start_cert)]
        visited: set[str] = {cert_id}
        current = start_cert

        for _ in range(50):
            if not current.parent_cert_id:
                break
            if current.parent_cert_id in visited:
                break  # circular guard
            parent = _load_cert(current.parent_cert_id)
            if parent is None:
                break
            visited.add(parent.id)
            chain.append(_cert_summary(parent))
            current = parent

        # Root is the last item (top of ancestry chain)
        root = chain[-1]
        # Reverse so chain[0] = root, chain[-1] = start_cert
        chain = list(reversed(chain))

        return {
            "root": root,
            "chain": chain,
            "total": len(chain),
        }

    except Exception:
        log.exception("clm.get_lineage error")
        return {}


def compute_trust_impact(
    db: Any,
    *,
    cert_id: str,
    tenant_id: str,
    engagement_id: str,
) -> dict[str, Any]:
    """Compute certification trust impact on overall posture.

    Returns impact dict with trust_contribution, risk_reduction,
    monitoring_coverage, certification_impact.
    Returns empty dict if cert not found.
    """
    try:
        from api.db_models_clm import FaClmCert  # noqa: PLC0415
        from sqlalchemy import select  # noqa: PLC0415
        from datetime import timedelta  # noqa: PLC0415

        cert = db.execute(
            select(FaClmCert).where(
                FaClmCert.id == cert_id,
                FaClmCert.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        if cert is None:
            return {}

        snapshots = _fetch_recent_snapshots(
            db, tenant_id=tenant_id, engagement_id=engagement_id, limit=10
        )

        thirty_ago = (datetime.now(timezone.utc) - timedelta(days=30)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        drift_events = _fetch_recent_drift_events(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            since_iso=thirty_ago,
            limit=50,
        )

        cert_level_weight = _CERT_LEVEL_WEIGHT.get(cert.certification_level or "", 15)

        # Compute impact metrics
        avg_posture = None
        if snapshots:
            scores = [s.posture_score for s in snapshots]
            avg_posture = sum(scores) / len(scores)

        open_drift = [e for e in drift_events if e.status == "open"]

        # Trust contribution: cert weight as % of 100
        trust_contribution = cert_level_weight

        # Risk reduction: higher weight + lower open drift = more reduction
        risk_reduction = max(0, cert_level_weight - len(open_drift) * 2)

        # Monitoring coverage: based on snapshot density
        monitoring_coverage = min(100, len(snapshots) * 10)

        return {
            "cert_id": cert_id,
            "certification_level": cert.certification_level,
            "certification_impact": cert_level_weight,
            "trust_contribution": trust_contribution,
            "risk_reduction": risk_reduction,
            "monitoring_coverage": monitoring_coverage,
            "avg_posture_score": round(avg_posture, 1) if avg_posture else None,
            "open_drift_events": len(open_drift),
            "snapshot_count": len(snapshots),
        }

    except Exception:
        log.exception("clm.compute_trust_impact error")
        return {}
