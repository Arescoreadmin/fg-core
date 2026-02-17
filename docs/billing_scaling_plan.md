# Billing Scaling Plan (Partitioning, Retention, and Query Paths)

## Scope
This document defines the baseline scale model for billing coverage and invoice generation.

## Canonical time contract

- `coverage_day` is computed in **UTC**.
- Invoice periods use **inclusive start, exclusive end** boundaries: `[period_start, period_end)`.
- The same boundary contract is used for coverage ingestion, daily count aggregation, invoice build, and evidence export.

## Data model strategy

### Partition candidates
For PostgreSQL deployments at large scale, partition these write-heavy tables by month:

- `billing_coverage_daily_state` by `coverage_day`
- `billing_daily_counts` by `day`
- `device_coverage_ledger` by `created_at`
- `billing_invoices` by `period_start`
- `billing_runs` by `period_start`

Recommended secondary key for routing and maintenance: `tenant_id`.

### Indexed query paths
Invoice generation path must read pre-aggregated counts and avoid full ledger scans:

- `billing_daily_counts (tenant_id, day)`
- `billing_coverage_daily_state (tenant_id, coverage_day, coverage_state)`
- `billing_coverage_daily_state (tenant_id, device_id, coverage_day)`
- `billing_identity_claims (tenant_id, device_id)`
- `billing_invoices (tenant_id, period_start, period_end)`
- `billing_runs (tenant_id, period_start, period_end)`
- `billing_count_sync_checkpoints (tenant_id, self_hash)`

## Retention policy (explicit)

- `billing_invoices`, `billing_runs`, `billing_identity_claim_events`, `billing_count_sync_checkpoint_events`: **7 years**.
- `billing_daily_counts`: **24 months** minimum.
- `billing_coverage_daily_state`: **180 days** rolling retention after invoice finalization, provided evidence bundle cryptographic proof exists.
- `device_coverage_ledger`: **24 months** minimum (or 7 years in regulated contracts).

## Billing run model

A billing run is represented by `billing_runs`:

- `run_id`: deterministic run identifier
- `replay_id`: replay/audit correlation ID
- `idempotency_key`: deterministic key derived from tenant + period + pricing + contract hash
- `status`: scheduled/completed/failed
- `invoice_id`: linked invoice output (if completed)
- `export_path`: evidence bundle location

This supports reproducibility and batch orchestration.

## Operational notes

- Daily count sync is checkpointed with tamper-evident chain hashes.
- Checkpoint replay should be monitored by CI (`billing-daily-sync`) and production alerts.
- Disputed identity claims should be escalated when unresolved beyond SLA threshold.
- Finalized invoices freeze evidence regeneration to avoid silent artifact drift.
