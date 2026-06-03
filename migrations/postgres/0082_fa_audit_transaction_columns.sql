-- Migration 0082: Add H13 transaction correlation columns to fa_engagement_audit_events.
--
-- These columns support the AuditAtomicityService forensic audit trail.
-- All columns are nullable so existing schema v1.0 rows remain valid.
-- New events emitted by AuditAtomicityService use schema_version='2.0' and
-- populate all correlation columns.
--
-- transaction_id  — immutable UUID per business operation linking audit to mutation
-- correlation_id  — optional cross-service correlation (e.g. X-Request-ID)
-- before_hash     — SHA-256 of canonical entity state before mutation
-- after_hash      — SHA-256 of canonical entity state after mutation
-- entity_type     — standardised entity class (engagement, finding, observation, …)
-- entity_id       — primary key of the mutated entity
-- actor_type      — actor classification: human_operator | portal_client | api_key | system
--
-- Uses to_regclass() guard and column existence check so the block is safe to
-- replay against a schema that already has these columns.

DO $$
BEGIN
    IF to_regclass('public.fa_engagement_audit_events') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_name  = 'fa_engagement_audit_events'
               AND column_name = 'transaction_id'
        ) THEN
            ALTER TABLE fa_engagement_audit_events
                ADD COLUMN transaction_id  VARCHAR(64),
                ADD COLUMN correlation_id  VARCHAR(128),
                ADD COLUMN before_hash     VARCHAR(64),
                ADD COLUMN after_hash      VARCHAR(64),
                ADD COLUMN entity_type     VARCHAR(64),
                ADD COLUMN entity_id       VARCHAR(64),
                ADD COLUMN actor_type      VARCHAR(32);

            CREATE INDEX ix_fa_audit_events_transaction_id
                ON fa_engagement_audit_events (transaction_id)
                WHERE transaction_id IS NOT NULL;

            CREATE INDEX ix_fa_audit_events_entity
                ON fa_engagement_audit_events (entity_type, entity_id)
                WHERE entity_type IS NOT NULL;
        END IF;
    END IF;
END $$;
