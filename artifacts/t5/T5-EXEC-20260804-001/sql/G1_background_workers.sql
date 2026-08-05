-- T5-EXEC-20260804-001 / G1 Background Worker State Queries
-- Execution: 2026-08-04T10:53:00Z
-- Captured via: railway run --service api python3 (DATABASE_URL proxy)

-- Job-related tables discovered
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
AND table_name ILIKE ANY(ARRAY['%job%','%task%','%queue%','%worker%','%scan%'])
ORDER BY table_name;

-- fa_scan_jobs status breakdown
SELECT status, COUNT(*) FROM fa_scan_jobs GROUP BY status ORDER BY status;

-- Any pending/running/queued scan jobs
SELECT id, scanner_type, status, created_at, lease_expires_at
FROM fa_scan_jobs
WHERE status NOT IN ('complete', 'failed', 'cancelled')
LIMIT 10;

-- Oldest non-complete scan job
SELECT MIN(created_at) FROM fa_scan_jobs WHERE status NOT IN ('complete', 'failed');

-- fa_rem_task state breakdown
SELECT task_state, COUNT(*) FROM fa_rem_task GROUP BY task_state ORDER BY task_state;

-- fg_cgct_action_queue count
SELECT COUNT(*) FROM fg_cgct_action_queue;

-- fa_quarantined_scans count
SELECT COUNT(*) FROM fa_quarantined_scans;

-- DB timestamp reference
SELECT NOW() AT TIME ZONE 'UTC';
