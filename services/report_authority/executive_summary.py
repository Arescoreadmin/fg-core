"""services/report_authority/executive_summary.py

Deterministic executive summary builder.
"""
from __future__ import annotations

from typing import Any


def build_executive_summary(
    *,
    organization: str,
    assessment_date: str,
    overall_readiness: str,
    overall_governance_score: float,
    risk_summary: dict[str, int],
    executive_recommendations: list[str],
    assessor_id: str,
    reviewer_id: str | None,
    report_id: str,
) -> dict[str, Any]:
    """Build a deterministic executive summary dict.

    All collections are sorted to guarantee identical output for logically
    identical inputs regardless of call-site insertion order.
    """
    return {
        "organization": organization,
        "assessment_date": assessment_date,
        "overall_readiness": overall_readiness,
        "overall_governance_score": round(overall_governance_score, 4),
        "risk_summary": dict(sorted(risk_summary.items())),
        "executive_recommendations": sorted(executive_recommendations),
        "assessor_id": assessor_id,
        "reviewer_id": reviewer_id or "",
        "report_id": report_id,
    }
