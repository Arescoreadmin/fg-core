-- Migration 0084: H12 Durable Job Infrastructure.
--
-- Adds five columns to fa_scan_jobs to support the full DurableJobService
-- lease model, retry/backoff policy, idempotency, and dead-letter routing:
--
--   idempotency_key   — caller-supplied dedup key; partial UNIQUE index enforces
--                       at most one non-null duplicate
--   max_retries       — how many times the worker may retry before dead_letter
--   next_retry_at     — ISO-8601 UTC timestamp; NULL until first failure
--   lease_acquired_at — when the current lease was taken (companion to lease_owner)
--   metadata          — JSON blob for scanner-specific params (e.g. domain lists)
--
-- Status values now include 'dead_letter' and 'cancelled' in addition to the
-- existing 'queued' / 'running' / 'complete' / 'failed'.  No DB CHECK constraint
-- is added — the application layer (DurableJobService) is the enforcer so that
-- adding new statuses later requires no migration.
--
-- All blocks are idempotent via to_regclass() / column-existence checks.

-- ---------------------------------------------------------------------------
-- 1. New columns on fa_scan_jobs
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_scan_jobs') IS NOT NULL THEN

        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_name = 'fa_scan_jobs' AND column_name = 'idempotency_key'
        ) THEN
            ALTER TABLE fa_scan_jobs ADD COLUMN idempotency_key VARCHAR(255);
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_name = 'fa_scan_jobs' AND column_name = 'max_retries'
        ) THEN
            ALTER TABLE fa_scan_jobs ADD COLUMN max_retries INTEGER NOT NULL DEFAULT 3;
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_name = 'fa_scan_jobs' AND column_name = 'next_retry_at'
        ) THEN
            ALTER TABLE fa_scan_jobs ADD COLUMN next_retry_at VARCHAR(64);
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_name = 'fa_scan_jobs' AND column_name = 'lease_acquired_at'
        ) THEN
            ALTER TABLE fa_scan_jobs ADD COLUMN lease_acquired_at VARCHAR(64);
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_name = 'fa_scan_jobs' AND column_name = 'scan_metadata'
        ) THEN
            ALTER TABLE fa_scan_jobs ADD COLUMN scan_metadata TEXT;
        END IF;

    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Partial unique index for idempotency_key (NULL values excluded)
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_scan_jobs') IS NOT NULL
       AND NOT EXISTS (
           SELECT 1 FROM pg_indexes
            WHERE tablename = 'fa_scan_jobs'
              AND indexname  = 'ix_fa_scan_jobs_idempotency_key'
       )
    THEN
        CREATE UNIQUE INDEX ix_fa_scan_jobs_idempotency_key
            ON fa_scan_jobs (idempotency_key)
            WHERE idempotency_key IS NOT NULL;
    END IF;
END $$;
