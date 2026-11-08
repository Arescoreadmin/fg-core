-- Migration 0202: Scanner collection status and coverage transparency
-- L14-SCAN-COMPLETENESS-001
--
-- Adds collection_status columns to scan-related tables so that the
-- canonical CollectionStatus enum value is persisted alongside scan results.
-- All columns are nullable to support legacy rows and mixed-version rollout.
--
-- New type: fa_collection_status_enum (additive — does not affect existing rows)
-- New columns:
--   fa_scan_jobs.collection_status
--   fa_normalized_findings.collection_status
--
-- Safety:
-- - All changes are additive (no DROP, no NOT NULL without DEFAULT).
-- - Legacy null = CollectionStatus.UNKNOWN (fail-closed interpretation).
-- - No existing data is modified.
-- - Compatible with Postgres 14+ row-level security and existing RLS policies.

-- -------------------------------------------------------------------------
-- 1. Collection status enum type
-- -------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'fa_collection_status_enum') THEN
        CREATE TYPE fa_collection_status_enum AS ENUM (
            'COMPLETE',
            'PARTIAL',
            'DENIED',
            'TIMEOUT',
            'TRUNCATED',
            'FAILED',
            'CANCELLED',
            'NOT_ASSESSED',
            'UNKNOWN'
        );
    END IF;
END
$$;

-- -------------------------------------------------------------------------
-- 2. fa_scan_jobs — add collection_status
-- -------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'fa_scan_jobs'
          AND column_name = 'collection_status'
    ) THEN
        ALTER TABLE fa_scan_jobs
            ADD COLUMN collection_status fa_collection_status_enum;

        COMMENT ON COLUMN fa_scan_jobs.collection_status IS
            'Canonical CollectionStatus for the completed scan. '
            'NULL = legacy row; treat as UNKNOWN (fail-closed). '
            'L14-SCAN-COMPLETENESS-001.';
    END IF;
END
$$;

-- -------------------------------------------------------------------------
-- 3. fa_scan_jobs — add collection_summary JSONB for machine-readable output
-- -------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'fa_scan_jobs'
          AND column_name = 'collection_summary'
    ) THEN
        ALTER TABLE fa_scan_jobs
            ADD COLUMN collection_summary jsonb;

        COMMENT ON COLUMN fa_scan_jobs.collection_summary IS
            'Machine-readable AssessmentCoverageSummary JSON. '
            'Consumed by L14-SCAN-REPORT-PROOF-001 report renderer. '
            'NULL = legacy row or summary not yet generated.';
    END IF;
END
$$;

-- -------------------------------------------------------------------------
-- 4. fa_normalized_findings — add collection_status per finding
-- -------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'fa_normalized_findings'
          AND column_name = 'collection_status'
    ) THEN
        ALTER TABLE fa_normalized_findings
            ADD COLUMN collection_status fa_collection_status_enum;

        COMMENT ON COLUMN fa_normalized_findings.collection_status IS
            'CollectionStatus of the scan that produced this finding. '
            'A finding from a PARTIAL or DENIED scan cannot be claimed CONFIRMED. '
            'NULL = legacy row; treat as UNKNOWN.';
    END IF;
END
$$;

-- -------------------------------------------------------------------------
-- 5. Indexes for coverage queries (tenant-scoped, non-unique)
--
-- NOTE: CREATE INDEX CONCURRENTLY cannot run inside a transaction block and
-- is therefore incompatible with the migration executor (engine.begin()).
-- Plain CREATE INDEX IF NOT EXISTS is correct here: the columns are new
-- (all NULL), so the partial index scan is a no-op and completes instantly.
-- -------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS
    idx_fa_scan_jobs_collection_status
    ON fa_scan_jobs (tenant_id, collection_status)
    WHERE collection_status IS NOT NULL;

CREATE INDEX IF NOT EXISTS
    idx_fa_normalized_findings_collection_status
    ON fa_normalized_findings (engagement_id, collection_status)
    WHERE collection_status IS NOT NULL;
