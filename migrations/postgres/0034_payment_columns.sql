-- 0034_payment_columns.sql
-- Add Stripe payment tracking to assessments and org_profiles.
-- Also adds stripe_events audit table for webhook idempotency.

ALTER TABLE org_profiles
    ADD COLUMN IF NOT EXISTS email TEXT;

ALTER TABLE assessments
    ADD COLUMN IF NOT EXISTS email          TEXT,
    ADD COLUMN IF NOT EXISTS stripe_session_id TEXT,
    ADD COLUMN IF NOT EXISTS payment_status TEXT NOT NULL DEFAULT 'unpaid',
    ADD COLUMN IF NOT EXISTS tier           TEXT;

CREATE INDEX IF NOT EXISTS ix_assessments_stripe_session
    ON assessments(stripe_session_id) WHERE stripe_session_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_assessments_payment_status
    ON assessments(payment_status);

-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS stripe_events (
    id              BIGSERIAL    PRIMARY KEY,
    stripe_event_id TEXT         NOT NULL UNIQUE,
    event_type      TEXT         NOT NULL,
    payload         JSONB        NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_stripe_events_type ON stripe_events(event_type);
