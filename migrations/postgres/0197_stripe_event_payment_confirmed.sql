-- Migration 0197: Add payment_confirmed_at to stripe_events
--
-- payment_confirmed_at is set atomically with AssessmentRecord.payment_status
-- transitioning to 'paid'. A non-NULL value is the durable payment audit
-- anchor; it and payment_status are committed in a single transaction.
--
-- Additive / non-breaking: existing rows get NULL (no payment confirmed).

ALTER TABLE stripe_events
    ADD COLUMN IF NOT EXISTS payment_confirmed_at TIMESTAMPTZ DEFAULT NULL;

CREATE INDEX IF NOT EXISTS ix_stripe_events_payment_confirmed_at
    ON stripe_events (payment_confirmed_at)
    WHERE payment_confirmed_at IS NOT NULL;
