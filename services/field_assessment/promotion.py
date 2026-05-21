"""Promotion service — bridges a delivered Field Assessment engagement to governance.

This module is NOT standalone.
It is a tenant-scoped component of the Field Assessment Engagement Substrate.

promote_engagement_to_governance() is the single entry point. It fires inline
when an engagement transitions to 'delivered' and is also callable from the
admin retry route (POST /field-assessment/engagements/{id}/promote).

Failure semantics:
  Promotion failure NEVER raises to the caller. The engagement stays 'delivered'.
  The GovernancePromotion record is marked status='failed' and the admin retry
  route can re-run the promotion. This preserves the QA-approved assessment
  delivery regardless of governance bootstrap success.

Transaction boundaries:
  Workflows and assets are written inside a savepoint. If the savepoint fails,
  only those writes are rolled back — the outer transaction (engagement status,
  audit event, timeline event, promotion record) still commits.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.db_models_governance_asset_candidates import GaAssetCandidate
from api.db_models_governance_assets import GaAsset
from api.db_models_governance_promotion import GovernancePromotion
from api.rag.ingest import CorpusDocument, IngestRequest, IngestStatus, ingest_corpus
from services.canonical import utc_iso8601_z_now
from services.field_assessment.models import PromotionAlreadyExists
from services.field_assessment.promotion_store import (
    complete_promotion,
    create_promotion,
    fail_promotion,
    get_promotion,
    reset_promotion_for_retry,
    update_corpus_count,
)
from services.field_assessment.store import list_findings
from services.field_assessment.timeline import emit_fa_timeline_event
from services.governance_workflows.engine import create_workflow

log = logging.getLogger("frostgate.fa.promotion")

_MAX_FINDINGS = 100  # mirrors store.MAX_PAGE_SIZE


def promote_engagement_to_governance(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    gate_snapshot: dict[str, Any],
    baseline_readiness_score: int,
) -> GovernancePromotion:
    """Promote a delivered engagement into continuous governance.

    Idempotent: returns the existing completed record without side effects.
    Retry-safe: resets a failed record to pending and re-runs all steps.
    Failure-safe: promotion failure is logged and recorded but never re-raised.
    """
    existing = get_promotion(db, tenant_id=tenant_id, engagement_id=engagement_id)

    if existing is not None:
        if existing.status == "completed":
            return existing
        if existing.status == "failed":
            promotion = reset_promotion_for_retry(
                db,
                promotion=existing,
                gate_snapshot=gate_snapshot,
                baseline_readiness_score=baseline_readiness_score,
            )
        else:
            # pending — in-flight (only possible in a concurrent retry race)
            return existing
    else:
        try:
            promotion = create_promotion(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                gate_snapshot=gate_snapshot,
                baseline_readiness_score=baseline_readiness_score,
            )
        except PromotionAlreadyExists:
            # Lost a creation race — another concurrent caller inserted first.
            # Return whatever exists for this tenant/engagement; never re-raise.
            refetch = get_promotion(
                db, tenant_id=tenant_id, engagement_id=engagement_id
            )
            if refetch is not None:
                return refetch
            raise

    try:
        with db.begin_nested():
            workflow_count = _promote_findings_to_workflows(
                db, tenant_id=tenant_id, engagement_id=engagement_id
            )
            asset_count = _promote_asset_candidates(
                db, tenant_id=tenant_id, engagement_id=engagement_id
            )
        complete_promotion(
            db,
            promotion=promotion,
            asset_count=asset_count,
            workflow_count=workflow_count,
        )
    except Exception as exc:  # noqa: BLE001
        log.error(
            "Promotion failed for engagement %s (tenant %s): %s",
            engagement_id,
            tenant_id,
            exc,
        )
        try:
            fail_promotion(db, promotion=promotion, error_detail=str(exc)[:2000])
        except Exception as fail_exc:  # noqa: BLE001
            log.error(
                "Failed to record promotion failure for engagement %s: %s",
                engagement_id,
                fail_exc,
            )

    if promotion.status == "completed":
        _emit_promotion_timeline(
            db, tenant_id=tenant_id, engagement_id=engagement_id, promotion=promotion
        )
        _feed_findings_to_corpus(
            db, tenant_id=tenant_id, engagement_id=engagement_id, promotion=promotion
        )

    return promotion


def _promote_findings_to_workflows(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
) -> int:
    findings = list_findings(
        db,
        engagement_id=engagement_id,
        tenant_id=tenant_id,
        severity_filter=None,
        status_filter=None,
        limit=_MAX_FINDINGS,
    )
    if len(findings) == _MAX_FINDINGS:
        log.warning(
            "Promotion hit _MAX_FINDINGS=%d for engagement %s — some findings "
            "may not have corresponding workflows.",
            _MAX_FINDINGS,
            engagement_id,
        )

    count = 0
    for finding in findings:
        wf = create_workflow(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            template_name="finding_remediation",
            context_ref_type="finding",
            context_ref_id=finding.id,
            created_by="system:promotion",
            severity=finding.severity,
            title=finding.title,
        )
        # finding_id is not a create_workflow parameter — set directly on the record.
        wf.finding_id = finding.id
        db.flush()
        count += 1

    return count


def _promote_asset_candidates(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
) -> int:
    stmt = select(GaAssetCandidate).where(
        GaAssetCandidate.tenant_id == tenant_id,
        GaAssetCandidate.engagement_id == engagement_id,
        GaAssetCandidate.status == "detected",
        GaAssetCandidate.promoted_asset_id.is_(None),
    )
    candidates = list(db.execute(stmt).scalars().all())

    now = utc_iso8601_z_now()
    count = 0
    for candidate in candidates:
        asset = GaAsset(
            asset_id=candidate.candidate_id,
            tenant_id=tenant_id,
            asset_type=candidate.suggested_asset_type,
            name=candidate.suggested_name,
            status="active",
            risk_tier="unclassified",
            risk_score=0,
            discovery_source="discovered",
            external_id=candidate.candidate_id,
            metadata_json={},
            schema_version="1.0",
            created_at=now,
            updated_at=now,
            created_by_email="system:promotion",
            source_scan_result_id=candidate.scan_result_id,
            source_engagement_id=engagement_id,
        )
        try:
            with db.begin_nested():
                db.add(asset)
                db.flush()
        except IntegrityError:
            # Duplicate candidate_id — asset already promoted in a prior attempt.
            log.debug("Asset %s already exists, skipping.", candidate.candidate_id)
            continue

        candidate.status = "promoted"
        candidate.promoted_asset_id = candidate.candidate_id
        candidate.promoted_at = now
        candidate.auto_promoted = True
        db.flush()
        count += 1

    return count


def _emit_promotion_timeline(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    promotion: GovernancePromotion,
) -> None:
    """Emit promotion timeline event. Failure-safe: never raises."""
    try:
        emit_fa_timeline_event(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type="field_assessment.engagement.promoted",
            payload={
                "promotion_id": promotion.id,
                "workflow_count": promotion.workflow_count,
                "asset_count": promotion.asset_count,
                "baseline_readiness_score": promotion.baseline_readiness_score,
            },
            replay_eligible=True,
        )
    except Exception as exc:  # noqa: BLE001
        log.error(
            "Failed to emit promotion timeline event for engagement %s: %s",
            engagement_id,
            exc,
        )


def _feed_findings_to_corpus(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    promotion: GovernancePromotion,
) -> None:
    """Feed all engagement findings into the RAG corpus. Failure-safe: never raises.

    Paginates through findings in stable (created_at ASC, id ASC) order until
    exhausted, so corpus_entries_added always reflects the true finding count.
    """
    try:
        docs: list[CorpusDocument] = []
        offset = 0
        while True:
            page = list_findings(
                db,
                engagement_id=engagement_id,
                tenant_id=tenant_id,
                severity_filter=None,
                status_filter=None,
                limit=_MAX_FINDINGS,
                offset=offset,
            )
            for f in page:
                docs.append(
                    CorpusDocument(
                        source_id=f"fa:{engagement_id}:finding:{f.id}",
                        content=f"{f.title}\n\n{f.description}".strip(),
                        metadata={
                            "finding_id": f.id,
                            "engagement_id": engagement_id,
                            "severity": f.severity,
                            "finding_type": f.finding_type,
                        },
                    )
                )
            if len(page) < _MAX_FINDINGS:
                break
            offset += len(page)

        if not docs:
            return

        result = ingest_corpus(
            IngestRequest(documents=docs),
            trusted_tenant_id=tenant_id,
        )
        count = sum(1 for r in result.records if r.status == IngestStatus.SUCCESS)
        update_corpus_count(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            corpus_entries_added=count,
        )
        log.info(
            "Corpus feed completed for engagement %s: %d documents ingested",
            engagement_id,
            count,
        )
    except Exception as exc:  # noqa: BLE001
        log.error(
            "Corpus feed failed for engagement %s (tenant %s): %s",
            engagement_id,
            tenant_id,
            exc,
        )
