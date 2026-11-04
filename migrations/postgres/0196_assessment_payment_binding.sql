-- 0196_assessment_payment_binding.sql
-- L14-STRIPE-TEST-001: Add server-side payment binding columns to assessments.
--
-- Adds three columns required to validate Stripe Checkout Sessions server-side:
--   expected_amount_cents  — the authoritative amount recorded at session creation
--   payment_purpose        — 'assessment_initial' or 'assessment_delivery'
--   checkout_idempotency_key — idempotency key used when creating the session
--
-- These are written by the API at checkout session creation time and verified
-- by the webhook handler against Stripe's reported amount/currency.
-- Stripe metadata is never trusted alone to establish payment authorization.

ALTER TABLE assessments
    ADD COLUMN IF NOT EXISTS expected_amount_cents     INTEGER,
    ADD COLUMN IF NOT EXISTS payment_purpose           TEXT,
    ADD COLUMN IF NOT EXISTS checkout_idempotency_key  TEXT;

CREATE INDEX IF NOT EXISTS ix_assessments_payment_purpose
    ON assessments(payment_purpose)
    WHERE payment_purpose IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ix_assessments_checkout_idempotency_key
    ON assessments(checkout_idempotency_key)
    WHERE checkout_idempotency_key IS NOT NULL;
