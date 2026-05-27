# api/db_models_questionnaire.py
"""SQLAlchemy ORM models for the NIST AI RMF Questionnaire.

PR 26: Structured per-control manual evidence capture.

Tables:
  fa_questionnaires           — one per engagement+framework; lifecycle status
  fa_questionnaire_responses  — one row per control, pre-seeded on creation

Status lifecycle: draft → submitted → finalized
Response statuses: not_assessed | implemented | partial | not_implemented | not_applicable

Tenant isolation:
  All queries must include tenant_id.
  No DEFAULT on tenant_id — store layer always provides an explicit value.
"""

from __future__ import annotations

from sqlalchemy import Float, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


class FaQuestionnaire(Base):
    """One questionnaire per engagement per framework."""

    __tablename__ = "fa_questionnaires"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    framework: Mapped[str] = mapped_column(
        String(64), nullable=False, default="nist_ai_rmf"
    )
    framework_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0"
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    submitted_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    submitted_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "engagement_id",
            "framework",
            name="uq_fa_questionnaire_engagement_framework",
        ),
        Index("ix_fa_questionnaires_engagement_tenant", "engagement_id", "tenant_id"),
    )


class FaQuestionnaireResponse(Base):
    """One response row per NIST AI RMF control per questionnaire."""

    __tablename__ = "fa_questionnaire_responses"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    questionnaire_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    control_name: Mapped[str] = mapped_column(Text, nullable=False)
    response_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="not_assessed"
    )
    evidence_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    assessor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "questionnaire_id",
            "control_id",
            name="uq_fa_questionnaire_response_control",
        ),
        Index("ix_fa_qresponses_engagement_tenant", "engagement_id", "tenant_id"),
        Index("ix_fa_qresponses_control_id", "control_id"),
    )
