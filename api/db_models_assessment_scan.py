"""ORM model for Microsoft Graph assessment scan sessions."""

from __future__ import annotations

from sqlalchemy import Index, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


class AssessmentScanSession(Base):
    """Tracks a single Microsoft Graph scan session tied to an assessment.

    Lifecycle: pending_acknowledgment → acknowledged → running → completed | failed

    manifest_json   — JSON array of ScanAction dicts (declared before execution)
    ack_token       — HMAC token the client provides to authorise execution
    action_log_json — HMAC-chained log of executed actions (summaries only, no raw data)
    findings_json   — structured findings derived from scan results
    methodology_md  — human-readable leave-behind generated after completion
    """

    __tablename__ = "assessment_scan_sessions"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(Text, nullable=False)
    tenant_id: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        Text, nullable=False, default="pending_acknowledgment"
    )
    manifest_id: Mapped[str] = mapped_column(Text, nullable=False)
    manifest_json: Mapped[str] = mapped_column(Text, nullable=False)
    ack_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    acknowledged_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    completed_at: Mapped[str | None] = mapped_column(Text, nullable=True)
    action_log_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    findings_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    methodology_md: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        Index("ix_scan_sessions_assessment_id", "assessment_id"),
        Index("ix_scan_sessions_tenant_id", "tenant_id"),
    )
