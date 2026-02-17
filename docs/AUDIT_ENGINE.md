# Regulatory Audit Spine + Bank Exam Mode

## Runtime engine

`services/audit_engine` runs deterministic checks and writes append-only hash-chain records.

Cadence classes:
- light: every 5 minutes
- full: hourly
- reproducibility simulation: daily

Each ledger row includes:
- invariant id + decision
- config/policy hash
- git commit + runtime version + host id
- engine code hash
- previous record hash + self hash + HMAC signature

## Compliance registry

`services/compliance_registry` stores append-only requirement and finding records.

Tables:
- `compliance_requirements`
- `compliance_findings`
- `compliance_snapshots`

No updates/deletes are allowed (DB trigger + ORM guards).

## APIs

Audit:
- `GET /audit/sessions`
- `GET /audit/export`
- `POST /audit/reproduce`
- `GET /audit/exam-snapshot`
- `GET /audit/exams`
- `POST /audit/exams/run`
- `GET /audit/exams/{id}/export`
- `POST /audit/exams/{id}/reproduce`

Compliance:
- `POST /compliance/requirements/import`
- `GET /compliance/requirements/diff`
- `POST /compliance/findings/import`
- `POST /compliance/requirements/updates/available`
- `GET /compliance/requirements/updates`
- `POST /compliance/requirements/updates/{update_id}/apply`

UI summaries:
- `GET /ui/audit/overview`
- `GET /ui/audit/status`
- `GET /ui/audit/chain-integrity`
- `GET /ui/audit/export-link`
- `GET /ui/compliance/overview`
- `GET /ui/compliance/requirements/status`
- `GET /ui/compliance/findings`
- `GET /ui/compliance/exam-readiness`

## Local checks

- `make audit-chain-verify`
- `make compliance-chain-verify`
- `make compliance-registry-test`
- `make audit-export-test`
- `make audit-repro-test`
- `make exam-export-test`
- `make exam-reproduce-test`
- `make contract-authority-refresh`


Freshness SLA fields are emitted in compliance snapshots:
- `requirements_freshness_max_age_days`
- `requirements_stale`
- `stale_requirement_sources`

Canonicalization guard is enforced for signed/chain-sensitive paths via `make canonicalization-guard` (AST-based).
