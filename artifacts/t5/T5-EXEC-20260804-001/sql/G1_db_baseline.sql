-- T5-EXEC-20260804-001 / G1 DB Baseline Queries
-- Execution: 2026-08-04T10:42:15Z
-- Captured via: railway run --service api python3 (DATABASE_URL proxy)

-- Migration version
SELECT version, applied_at FROM schema_migrations ORDER BY applied_at DESC LIMIT 5;

-- Connection counts
SELECT count(*) AS total_connections FROM pg_stat_activity WHERE datname = current_database();
SELECT count(*) AS active_connections FROM pg_stat_activity WHERE datname = current_database() AND state = 'active';
SELECT count(*) AS idle_connections FROM pg_stat_activity WHERE datname = current_database() AND state = 'idle';
SELECT count(*) AS waiting_locks FROM pg_stat_activity WHERE wait_event_type = 'Lock';

-- Longest query
SELECT COALESCE(max(extract(epoch from now() - query_start)::int), 0) AS longest_query_sec
FROM pg_stat_activity WHERE state = 'active' AND query NOT LIKE '%pg_stat_activity%';

-- Limits and health
SELECT setting::int AS max_connections FROM pg_settings WHERE name = 'max_connections';
SELECT deadlocks AS deadlocks_total FROM pg_stat_database WHERE datname = current_database();
SELECT pg_size_pretty(pg_database_size(current_database())) AS db_size;

-- Runtime role
SELECT current_user;
SELECT usename FROM pg_stat_activity WHERE datname = current_database();
