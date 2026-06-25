# api/db_models_control_effectiveness_explainability.py
"""SQLAlchemy ORM models for PR 16.5.1 — Explainability & Governance Action Engine.

Tables:
  fa_control_ranking — pre-computed ranking snapshots per rank_type

Design:
  - Rankings are stored and refreshed by recalculate_all().
  - Rankings can be deleted and replaced on refresh (not append-only).
  - Contributions, root causes, actions, narrative, and priority are derived
    on-the-fly from fa_control_effectiveness and are not persisted.

PR 16.5.1 — Control Effectiveness Explainability & Governance Action Engine
"""

from __future__ import annotations

from sqlalchemy import Float, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


class FaControlRanking(Base):
    """Pre-computed ranking position per rank_type per control."""

    __tablename__ = "fa_control_ranking"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rank_type: Mapped[str] = mapped_column(String(32), nullable=False)
    rank_position: Mapped[int] = mapped_column(Integer, nullable=False)
    effectiveness_score: Mapped[float] = mapped_column(Float, nullable=False)
    effectiveness_level: Mapped[str] = mapped_column(String(32), nullable=False)
    effectiveness_risk: Mapped[str] = mapped_column(String(16), nullable=False)
    generated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "idx_fa_control_ranking_tenant_type",
            "tenant_id",
            "rank_type",
        ),
        Index(
            "idx_fa_control_ranking_tenant_control",
            "tenant_id",
            "control_id",
        ),
    )
