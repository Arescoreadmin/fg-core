"""Enterprise Remediation Authority (PR 18.3).

New bounded context — separate from `services/remediation/`. Owns the
`fa_rem_*` tables and provides the write authority for remediation plans,
tasks, assignments, dependencies, verification, and evidence linkage.
"""

REMEDIATION_AUTHORITY_SCHEMA_VERSION: str = "1.0"
