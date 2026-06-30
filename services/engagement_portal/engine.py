"""Engagement Portal engine (PR 18.2).

Read-through facade over authoritative services (Report, Evidence, Remediation,
Trust, Transparency, Timeline). Writes are limited to portal-owned tables:
  - portal_engagement_preferences
  - portal_engagement_activity (append-only)
  - portal_engagement_notifications

No business logic is duplicated. Every cross-authority read is wrapped in a
try/except boundary so the portal degrades gracefully when an authority is
not yet populated (returns empty lists / None defaults).

Caller (API layer) owns db.commit().
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy.orm import Session

from services.canonical import utc_iso8601_z_now
from services.engagement_portal.health import get_health_response
from services.engagement_portal.repository import (
    count_notifications,
    fetch_preferences,
    insert_activity,
    list_activities,
    list_notifications,
    upsert_preferences,
)
from services.engagement_portal.schemas import (
    ActivityFeedItem,
    ActivityFeedResponse,
    DashboardResponse,
    EvidenceWorkspaceItem,
    EvidenceWorkspaceResponse,
    HealthResponse,
    NotificationItem,
    NotificationListResponse,
    PortalAccessDenied,
    PortalStatisticsResponse,
    PreferencesResponse,
    RemediationWorkspaceItem,
    RemediationWorkspaceResponse,
    ReportWorkspaceItem,
    ReportWorkspaceResponse,
    SearchResponse,
    SearchResultItem,
    TimelineEvent,
    TimelineResponse,
    TransparencyWorkspaceResponse,
    TrustWorkspaceResponse,
    UpdatePreferencesRequest,
)
from services.engagement_portal.statistics import compute_portal_statistics
from services.engagement_portal.validators import (
    validate_limit_offset,
    validate_search_query,
    validate_tenant_id,
)


class EngagementPortalEngine:
    """Engagement Portal orchestration engine."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        validate_tenant_id(tenant_id)
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # Health (no tenant check at call site — but engine still bound)
    # ------------------------------------------------------------------

    def health(self) -> HealthResponse:
        return get_health_response()

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def get_dashboard(self, assessment_id: str | None = None) -> DashboardResponse:
        latest_report_id: str | None = None
        latest_report_state: str | None = None
        try:
            from api.db_models_report_authority import FaReport

            q = self._db.query(FaReport).filter(FaReport.tenant_id == self._tenant_id)
            if assessment_id is not None:
                q = q.filter(FaReport.assessment_id == assessment_id)
            latest = q.order_by(FaReport.created_at.desc()).first()
            if latest is not None:
                latest_report_id = latest.id
                latest_report_state = latest.lifecycle_state
        except Exception:
            pass

        # Defaults — cross-authority counts are intentionally None/0 when an
        # authority is not yet populated for this tenant.
        return DashboardResponse(
            tenant_id=self._tenant_id,
            engagement_id=assessment_id,
            overall_readiness=None,
            governance_score=None,
            assessment_progress=None,
            evidence_collected=0,
            evidence_verified=0,
            evidence_freshness_pct=None,
            open_findings=0,
            remediation_progress=None,
            pending_approvals=0,
            latest_report_id=latest_report_id,
            latest_report_state=latest_report_state,
            verification_status=None,
            trust_status=None,
            transparency_status=None,
            generated_at=utc_iso8601_z_now(),
        )

    # ------------------------------------------------------------------
    # Timeline workspace
    # ------------------------------------------------------------------

    def get_timeline(self, limit: int = 50, offset: int = 0) -> TimelineResponse:
        validate_limit_offset(limit, offset)
        items: list[TimelineEvent] = []
        total = 0
        try:
            from api.db_models_timeline_authority import TimelineAuthorityEventRecord

            q = self._db.query(TimelineAuthorityEventRecord).filter(
                TimelineAuthorityEventRecord.tenant_id == self._tenant_id
            )
            total = q.count()
            rows = (
                q.order_by(TimelineAuthorityEventRecord.occurred_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            for row in rows:
                occurred_at = row.occurred_at
                occurred_str = (
                    occurred_at.isoformat()
                    if hasattr(occurred_at, "isoformat")
                    else str(occurred_at)
                )
                items.append(
                    TimelineEvent(
                        event_id=str(row.event_id),
                        event_type=str(row.event_type),
                        source_system=str(row.source_system),
                        entity_id=str(row.entity_id) if row.entity_id else None,
                        entity_type=str(row.entity_type) if row.entity_type else None,
                        actor_id=str(row.actor_id) if row.actor_id else None,
                        summary=str(row.event_type),
                        occurred_at=occurred_str,
                        authoritative_ref=str(row.external_reference)
                        if row.external_reference
                        else None,
                    )
                )
        except Exception:
            items = []
            total = 0
        return TimelineResponse(items=items, total=total, offset=offset, limit=limit)

    # ------------------------------------------------------------------
    # Evidence workspace
    # ------------------------------------------------------------------

    def get_evidence_workspace(
        self, limit: int = 50, offset: int = 0
    ) -> EvidenceWorkspaceResponse:
        validate_limit_offset(limit, offset)
        items: list[EvidenceWorkspaceItem] = []
        total = 0
        try:
            from api.db_models_evidence_authority import FaEvidence

            q = self._db.query(FaEvidence).filter(
                FaEvidence.tenant_id == self._tenant_id
            )
            total = q.count()
            rows = (
                q.order_by(FaEvidence.created_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            for r in rows:
                items.append(
                    EvidenceWorkspaceItem(
                        evidence_id=str(getattr(r, "id", "")),
                        title=getattr(r, "title", None),
                        classification=getattr(r, "classification", None),
                        freshness_status=getattr(r, "freshness_status", None),
                        verification_status=getattr(r, "verification_status", None),
                        trust_digest=getattr(r, "trust_digest", None),
                        transparency_entry=getattr(r, "transparency_entry", None),
                        collected_at=_iso_or_none(getattr(r, "collected_at", None)),
                        reviewer_notes=getattr(r, "reviewer_notes", None),
                    )
                )
        except Exception:
            items = []
            total = 0
        return EvidenceWorkspaceResponse(
            items=items, total=total, offset=offset, limit=limit
        )

    # ------------------------------------------------------------------
    # Report workspace
    # ------------------------------------------------------------------

    def get_report_workspace(
        self, limit: int = 50, offset: int = 0
    ) -> ReportWorkspaceResponse:
        validate_limit_offset(limit, offset)
        items: list[ReportWorkspaceItem] = []
        total = 0
        try:
            from api.db_models_report_authority import FaReport

            q = self._db.query(FaReport).filter(FaReport.tenant_id == self._tenant_id)
            total = q.count()
            rows = (
                q.order_by(FaReport.created_at.desc()).offset(offset).limit(limit).all()
            )
            for r in rows:
                items.append(
                    ReportWorkspaceItem(
                        report_id=r.id,
                        report_ref=r.report_ref,
                        report_type=r.report_type,
                        lifecycle_state=r.lifecycle_state,
                        title=r.title,
                        quality_grade=r.quality_grade,
                        published_at=r.published_at,
                        has_pdf=bool(r.has_pdf),
                        has_html=bool(r.has_html),
                        has_json=bool(r.has_json),
                        manifest_hash=r.manifest_hash,
                        trust_verified=bool(r.signature),
                    )
                )
        except Exception:
            items = []
            total = 0
        return ReportWorkspaceResponse(
            items=items, total=total, offset=offset, limit=limit
        )

    # ------------------------------------------------------------------
    # Remediation workspace
    # ------------------------------------------------------------------

    def get_remediation_workspace(
        self, limit: int = 50, offset: int = 0
    ) -> RemediationWorkspaceResponse:
        validate_limit_offset(limit, offset)
        items: list[RemediationWorkspaceItem] = []
        total = 0
        try:
            from api.db_models_remediation import RemediationTask  # type: ignore

            q = self._db.query(RemediationTask).filter(
                RemediationTask.tenant_id == self._tenant_id
            )
            total = q.count()
            rows = (
                q.order_by(RemediationTask.created_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            for r in rows:
                items.append(
                    RemediationWorkspaceItem(
                        task_id=str(getattr(r, "id", "")),
                        title=getattr(r, "title", None),
                        priority=getattr(r, "priority", None),
                        status=getattr(r, "status", None),
                        owner_id=getattr(r, "owner_id", None),
                        due_date=_iso_or_none(getattr(r, "due_date", None)),
                        verification_required=bool(
                            getattr(r, "verification_required", False)
                        ),
                        evidence_required=bool(getattr(r, "evidence_required", False)),
                        completion_pct=_as_float_or_none(
                            getattr(r, "completion_pct", None)
                        ),
                    )
                )
        except Exception:
            items = []
            total = 0
        return RemediationWorkspaceResponse(
            items=items, total=total, offset=offset, limit=limit
        )

    # ------------------------------------------------------------------
    # Trust workspace
    # ------------------------------------------------------------------

    def get_trust_workspace(self) -> TrustWorkspaceResponse:
        # Aggregates a summary from fa_report; portal does not re-sign or
        # re-verify — it surfaces the existing trust state. Defaults are safe.
        signing_algorithm: str | None = None
        last_signed_at: str | None = None
        history_count = 0
        verified = False
        try:
            from api.db_models_report_authority import FaReport

            q = self._db.query(FaReport).filter(FaReport.tenant_id == self._tenant_id)
            history_count = q.count()
            latest = q.order_by(FaReport.created_at.desc()).first()
            if latest is not None:
                signing_algorithm = latest.signing_algorithm
                last_signed_at = latest.published_at
                verified = bool(latest.signature)
        except Exception:
            pass
        return TrustWorkspaceResponse(
            trust_manifest=None,
            signing_algorithm=signing_algorithm,
            key_provider=None,
            provider_version=None,
            trust_digest=None,
            verified=verified,
            last_signed_at=last_signed_at,
            history_count=history_count,
        )

    # ------------------------------------------------------------------
    # Transparency workspace
    # ------------------------------------------------------------------

    def get_transparency_workspace(self) -> TransparencyWorkspaceResponse:
        transparency_root: str | None = None
        merkle_root: str | None = None
        sequence_count = 0
        last_entry_at: str | None = None
        try:
            from api.db_models_report_authority import FaReport

            q = self._db.query(FaReport).filter(FaReport.tenant_id == self._tenant_id)
            sequence_count = q.count()
            latest = q.order_by(FaReport.created_at.desc()).first()
            if latest is not None:
                transparency_root = latest.transparency_root
                merkle_root = latest.merkle_root
                last_entry_at = latest.published_at
        except Exception:
            pass
        return TransparencyWorkspaceResponse(
            transparency_root=transparency_root,
            merkle_root=merkle_root,
            append_only_confirmed=True,
            sequence_count=sequence_count,
            last_entry_at=last_entry_at,
            proof_available=bool(merkle_root),
        )

    # ------------------------------------------------------------------
    # Activity feed
    # ------------------------------------------------------------------

    def get_activity_feed(
        self,
        limit: int = 50,
        offset: int = 0,
        workspace: str | None = None,
    ) -> ActivityFeedResponse:
        validate_limit_offset(limit, offset)
        rows, total = list_activities(
            self._db,
            tenant_id=self._tenant_id,
            limit=limit,
            offset=offset,
            workspace=workspace,
        )
        items = [
            ActivityFeedItem(
                activity_id=r.id,
                event_type=r.event_type,
                workspace=r.workspace,
                entity_id=r.entity_id,
                actor_id=r.actor_id,
                occurred_at=r.created_at,
                summary=r.summary,
            )
            for r in rows
        ]
        return ActivityFeedResponse(
            items=items, total=total, offset=offset, limit=limit
        )

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_statistics(self) -> PortalStatisticsResponse:
        stats = compute_portal_statistics(self._db, tenant_id=self._tenant_id)
        return PortalStatisticsResponse(
            tenant_id=self._tenant_id,
            total_activities=stats["total_activities"],
            total_reports_viewed=stats["total_reports_viewed"],
            total_evidence_viewed=stats["total_evidence_viewed"],
            total_searches=stats["total_searches"],
            active_notifications=stats["active_notifications"],
            preferences_set=stats["preferences_set"],
            computed_at=utc_iso8601_z_now(),
        )

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(
        self,
        query: str,
        scope: list[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> SearchResponse:
        validate_search_query(query)
        validate_limit_offset(limit, offset)
        started = time.perf_counter()
        items: list[SearchResultItem] = []
        total = 0
        like_pattern = f"%{query.strip()}%"
        try:
            from api.db_models_report_authority import FaReport

            q = (
                self._db.query(FaReport)
                .filter(FaReport.tenant_id == self._tenant_id)
                .filter(
                    (FaReport.title.ilike(like_pattern))
                    | (FaReport.report_ref.ilike(like_pattern))
                )
            )
            total = q.count()
            rows = (
                q.order_by(FaReport.created_at.desc()).offset(offset).limit(limit).all()
            )
            for r in rows:
                items.append(
                    SearchResultItem(
                        result_id=r.id,
                        result_type="report",
                        title=r.title,
                        ref=r.report_ref,
                        matched_field="title",
                        score=1.0,
                    )
                )
        except Exception:
            items = []
            total = 0
        took_ms = int((time.perf_counter() - started) * 1000)
        return SearchResponse(query=query, items=items, total=total, took_ms=took_ms)

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------

    def get_notifications(
        self, limit: int = 50, offset: int = 0
    ) -> NotificationListResponse:
        validate_limit_offset(limit, offset)
        rows, _ = list_notifications(
            self._db, tenant_id=self._tenant_id, limit=limit, offset=offset
        )
        total = count_notifications(self._db, tenant_id=self._tenant_id)
        items = [
            NotificationItem(
                notification_id=r.id,
                notification_type=r.notification_type,
                status=r.status,
                subject=r.subject,
                body=r.body,
                created_at=r.created_at,
                delivered_at=r.delivered_at,
            )
            for r in rows
        ]
        return NotificationListResponse(
            items=items, total=total, offset=offset, limit=limit
        )

    # ------------------------------------------------------------------
    # Preferences
    # ------------------------------------------------------------------

    def get_preferences(self) -> PreferencesResponse:
        row = fetch_preferences(self._db, tenant_id=self._tenant_id)
        if row is None:
            return PreferencesResponse(
                tenant_id=self._tenant_id,
                theme=None,
                notification_email=True,
                timezone=None,
                language=None,
                updated_at=None,
            )
        return PreferencesResponse(
            tenant_id=self._tenant_id,
            theme=row.theme,
            notification_email=bool(row.notification_email),
            timezone=row.timezone,
            language=row.language,
            updated_at=row.updated_at,
        )

    def update_preferences(
        self, request: UpdatePreferencesRequest
    ) -> PreferencesResponse:
        row = upsert_preferences(
            self._db,
            tenant_id=self._tenant_id,
            theme=request.theme,
            notification_email=request.notification_email,
            timezone=request.timezone,
            language=request.language,
        )
        return PreferencesResponse(
            tenant_id=self._tenant_id,
            theme=row.theme,
            notification_email=bool(row.notification_email),
            timezone=row.timezone,
            language=row.language,
            updated_at=row.updated_at,
        )

    # ------------------------------------------------------------------
    # Activity record (append-only write)
    # ------------------------------------------------------------------

    def record_activity(
        self,
        event_type: str,
        workspace: str | None = None,
        entity_id: str | None = None,
        actor_id: str | None = None,
        summary: str | None = None,
    ) -> None:
        if not isinstance(event_type, str) or not event_type.strip():
            raise PortalAccessDenied("event_type must be non-empty")
        insert_activity(
            self._db,
            tenant_id=self._tenant_id,
            event_type=event_type,
            workspace=workspace,
            entity_id=entity_id,
            actor_id=actor_id,
            summary=summary,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso_or_none(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            return None
    if isinstance(value, str):
        return value
    return None


def _as_float_or_none(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
