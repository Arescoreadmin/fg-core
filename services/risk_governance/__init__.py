# services/risk_governance/__init__.py
"""Risk Governance Engine — PR 14.2.

Bounded context for formal governance workflows over risk acceptances:
approval lifecycle, multi-approver quorum, review scheduling, escalation,
and governance intelligence. Separate from services/risk_acceptance/ which
owns governance records; this context owns governance workflows.
"""
