"""Continuous Governance Orchestration Authority (PR 18.4).

New bounded context — owns the `fa_gov_orch_*` tables and provides the
write authority for governance orchestration policies, playbooks,
workflows, reassessments, triggers, simulations, approvals, maintenance
windows, and change-detection records.

This authority sits above the individual authorities (evidence, remediation,
verification, trust, transparency, learning) and coordinates their
continuous evaluation, reassessment, and triggered execution.
"""

GOVERNANCE_ORCHESTRATION_SCHEMA_VERSION: str = "1.0"
