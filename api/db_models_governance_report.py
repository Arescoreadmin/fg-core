# api/db_models_governance_report.py
"""SQLAlchemy ORM model for deterministic governance report records.

Infrastructure note (PR 98):
  This file extends Base.metadata with governance_reports table.
  Imported by api.db._ensure_models_imported() so init_db() creates the table.

Immutability contract:
  Once is_finalized=True, report_json and manifest_hash are treated as immutable.
  This is enforced at the manager layer (governance_report_manager.py), not via
  a DB trigger, to maintain portability across SQLite (dev) and PostgreSQL (prod).

Tenant isolation:
  All queries must include a tenant_id predicate.
  No DEFAULT 'public' on tenant_id — manager always provides an explicit value.

Schema:
  governance_reports(
    id TEXT PK,
    assessment_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    version INTEGER DEFAULT 1,
    schema_version TEXT DEFAULT '1.0',
    manifest_hash TEXT NOT NULL,
    report_json JSONB NOT NULL,
    generated_at TEXT NOT NULL,
    is_finalized BOOLEAN DEFAULT FALSE
  )
"""

from __future__ import annotations

from sqlalchemy import Boolean, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:  # pragma: no cover
    from sqlalchemy import JSON  # type: ignore[assignment]

from api.db_models import Base


class GovernanceReportRecord(Base):
    """Deterministic governance report record.

    report_json stores the canonical serialized GovernanceReport dict.
    manifest_hash is the SHA-256 over all deterministic fields (excluding itself).
    is_finalized=True marks the record as immutable — manager layer enforces this.
    """

    __tablename__ = "governance_reports"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    schema_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0"
    )
    manifest_hash: Mapped[str] = mapped_column(Text, nullable=False)
    report_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    generated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    is_finalized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        Index(
            "ix_governance_reports_assessment",
            "assessment_id",
            "tenant_id",
        ),
        Index("ix_governance_reports_tenant", "tenant_id"),
    )
