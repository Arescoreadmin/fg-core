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

## Export storage

- `start`/`end` (and exam `window_start_utc`/`window_end_utc`) must be ISO-8601 UTC timestamps ending in `Z`, at most 32 characters, with `start <= end`. Anything else returns 400 `AUDIT_EXPORT_WINDOW_INVALID`.
- Bundles are written to `<FG_AUDIT_EXPORT_DIR>/t-<sha256(tenant_id)[:32]>/audit_export_<start>_<end>.json`, where the name is built from the parsed timestamps. A tenant directory or file that resolves outside that namespace is refused (409 `AUDIT_EXPORT_STORAGE_INVALID`).
- Writes are atomic, and a failed write leaves no temporary file.
- Exam export archives the bundle it just built, never a re-read of the file.
- The tenant directory is a namespace, not an access control: no route serves export files by path.

## Local checks

- `python tools/seed/run_seed.py` (canonical local tester bootstrap)
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
