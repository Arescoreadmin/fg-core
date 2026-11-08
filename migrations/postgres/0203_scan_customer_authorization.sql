-- Migration 0203: L14-SCAN-AUTH-HARDENING-001 — customer scan authorization receipts,
-- scope-to-receipt binding, and scan audit/job constraint repair.
--
-- Adds:
--   fa_customer_authorization_receipts — authenticated customer approval of explicit
--       targets, operations and time window for one tenant + engagement (AUTH-GAP-001).
--       Material fields are immutable once decided (trigger below). Rows are never
--       deleted; revoked/rejected receipts remain for audit.
--   fa_scan_authorizations.customer_receipt_id — nullable binding of an operator scope
--       to the customer receipt that authorizes it. NULL = legacy operator-asserted
--       scope; never grandfathered as verified customer consent.
--
-- Repairs (pre-existing defects found during the AUTH-HARDENING audit):
--   1. fa_scan_audit_events.event_type CHECK (migration 0079) only allowed six values,
--      so the scan.authorization.* / scan.cancel.* events written since migration 0200
--      would be rejected by Postgres. The constraint is replaced with the full set.
--   2. fa_scan_jobs_status_check (migration 0200) omitted 'dead_letter', which
--      DurableJobService.mark_failed() writes for non-retryable failures.
--
-- Safety:
--   - Additive only: no column dropped, no data rewritten, no row fabricated.
--   - Existing scope rows keep customer_receipt_id = NULL (explicit legacy state).
--   - Constraint replacements only WIDEN the accepted value sets.
--   - No CREATE INDEX CONCURRENTLY (api/db_migrations.py runs in one transaction).
--   - No key material is stored: attestation_value is an HMAC output, attestation_kid
--     is an identifier; keys live only in the runtime key ring.
--   - Tenant isolation is enforced by mandatory tenant_id + engagement_id predicates
--     in every application query (same model as 0200/0201).

-- ---------------------------------------------------------------------------
-- 1. Customer authorization receipts
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_customer_authorization_receipts (
    id                           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    receipt_group_id             UUID NOT NULL,
    receipt_version              INTEGER NOT NULL DEFAULT 1 CHECK (receipt_version >= 1),
    schema_version               TEXT NOT NULL,

    tenant_id                    TEXT NOT NULL,
    engagement_id                VARCHAR(64) NOT NULL REFERENCES fa_engagements(id),
    customer_org_name            TEXT NOT NULL,
    assessment_purpose           TEXT NOT NULL,
    rules_of_engagement_ref      TEXT NOT NULL,
    consent_statement_version    TEXT NOT NULL,
    target_normalization_version TEXT NOT NULL,

    -- [{"target","type","operations":[...],"allow_subdomains"}] — normalized, sorted
    approved_targets             JSONB NOT NULL,
    authorized_operations        JSONB NOT NULL,
    window_start                 TIMESTAMPTZ NOT NULL,
    window_end                   TIMESTAMPTZ NOT NULL,

    -- Stored lifecycle; 'expired' is derived (now >= window_end), never stored.
    status                       TEXT NOT NULL DEFAULT 'pending_approval'
                                     CHECK (status IN ('pending_approval', 'approved',
                                                       'rejected', 'revoked')),

    requested_by_subject         TEXT NOT NULL,
    requested_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Approver identity — derived server-side from authenticated ActorContext.
    approver_subject             TEXT,
    approver_email               TEXT,
    approver_auth_source         TEXT,
    approver_authority_basis     TEXT,
    approver_membership_id       TEXT,
    approver_also_assessor       BOOLEAN,
    approved_at                  TIMESTAMPTZ,

    -- Integrity: canonical SHA-256 digest of every material approval field, plus
    -- optional server attestation (HMAC-SHA256 under a trusted key id).
    payload_digest               TEXT,
    digest_algorithm             TEXT,
    attestation_kid              TEXT,
    attestation_alg              TEXT,
    attestation_value            TEXT,
    proof_level                  TEXT,

    rejected_at                  TIMESTAMPTZ,
    rejected_by_subject          TEXT,
    rejection_reason             TEXT,
    revoked_at                   TIMESTAMPTZ,
    revoked_by_subject           TEXT,
    revocation_reason            TEXT,

    created_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fa_car_window_order CHECK (window_end > window_start),
    CONSTRAINT fa_car_group_version_uniq UNIQUE (receipt_group_id, receipt_version),
    -- An approved receipt always carries its approver, digest and proof level
    -- (the trigger keeps them unchanged when it is later revoked).
    CONSTRAINT fa_car_approved_complete CHECK (
        status <> 'approved'
        OR (approver_subject IS NOT NULL AND approved_at IS NOT NULL
            AND payload_digest IS NOT NULL AND proof_level IS NOT NULL)
    ),
    CONSTRAINT fa_car_revoked_complete CHECK (
        status <> 'revoked' OR revoked_at IS NOT NULL
    ),
    CONSTRAINT fa_car_attestation_pairing CHECK (
        (attestation_kid IS NULL AND attestation_value IS NULL AND attestation_alg IS NULL)
        OR (attestation_kid IS NOT NULL AND attestation_value IS NOT NULL
            AND attestation_alg IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS fa_car_tenant_engagement_idx
    ON fa_customer_authorization_receipts (tenant_id, engagement_id, status);
CREATE INDEX IF NOT EXISTS fa_car_group_idx
    ON fa_customer_authorization_receipts (tenant_id, receipt_group_id);

-- ---------------------------------------------------------------------------
-- 2. Immutability: decided receipts cannot be altered; nothing can be deleted.
--    Permitted transitions: pending_approval -> approved | rejected | revoked,
--    approved -> revoked. Request fields never change after insert; approval
--    fields never change after approval.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION fa_customer_authorization_receipts_guard()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'fa_customer_authorization_receipts is append-only: DELETE is not permitted';
    END IF;

    IF ROW(NEW.id, NEW.receipt_group_id, NEW.receipt_version, NEW.schema_version,
           NEW.tenant_id, NEW.engagement_id, NEW.customer_org_name,
           NEW.assessment_purpose, NEW.rules_of_engagement_ref,
           NEW.consent_statement_version, NEW.target_normalization_version,
           NEW.approved_targets, NEW.authorized_operations, NEW.window_start,
           NEW.window_end, NEW.requested_by_subject, NEW.requested_at,
           NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.receipt_group_id, OLD.receipt_version, OLD.schema_version,
           OLD.tenant_id, OLD.engagement_id, OLD.customer_org_name,
           OLD.assessment_purpose, OLD.rules_of_engagement_ref,
           OLD.consent_statement_version, OLD.target_normalization_version,
           OLD.approved_targets, OLD.authorized_operations, OLD.window_start,
           OLD.window_end, OLD.requested_by_subject, OLD.requested_at,
           OLD.created_at)
    THEN
        RAISE EXCEPTION 'fa_customer_authorization_receipts: request fields are immutable';
    END IF;

    IF OLD.status = 'pending_approval'
       AND NEW.status IN ('approved', 'rejected', 'revoked') THEN
        RETURN NEW;
    END IF;

    IF OLD.status = 'approved' AND NEW.status = 'revoked'
       AND ROW(NEW.approver_subject, NEW.approver_email, NEW.approver_auth_source,
               NEW.approver_authority_basis, NEW.approver_membership_id,
               NEW.approver_also_assessor, NEW.approved_at, NEW.payload_digest,
               NEW.digest_algorithm, NEW.attestation_kid, NEW.attestation_alg,
               NEW.attestation_value, NEW.proof_level)
           IS NOT DISTINCT FROM
           ROW(OLD.approver_subject, OLD.approver_email, OLD.approver_auth_source,
               OLD.approver_authority_basis, OLD.approver_membership_id,
               OLD.approver_also_assessor, OLD.approved_at, OLD.payload_digest,
               OLD.digest_algorithm, OLD.attestation_kid, OLD.attestation_alg,
               OLD.attestation_value, OLD.proof_level)
    THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'fa_customer_authorization_receipts: illegal state change after decision';
END;
$$;

DROP TRIGGER IF EXISTS fa_customer_authorization_receipts_guard_trigger
    ON fa_customer_authorization_receipts;

CREATE TRIGGER fa_customer_authorization_receipts_guard_trigger
    BEFORE UPDATE OR DELETE ON fa_customer_authorization_receipts
    FOR EACH ROW EXECUTE FUNCTION fa_customer_authorization_receipts_guard();

-- ---------------------------------------------------------------------------
-- 3. Scope-to-receipt binding
-- ---------------------------------------------------------------------------

ALTER TABLE fa_scan_authorizations
    ADD COLUMN IF NOT EXISTS customer_receipt_id UUID
        REFERENCES fa_customer_authorization_receipts(id);

CREATE INDEX IF NOT EXISTS fa_scan_auth_customer_receipt_idx
    ON fa_scan_authorizations (tenant_id, customer_receipt_id)
    WHERE customer_receipt_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 4. Repair: scan audit event types (widen only)
-- ---------------------------------------------------------------------------

ALTER TABLE fa_scan_audit_events
    DROP CONSTRAINT IF EXISTS fa_scan_audit_events_event_type_check;

ALTER TABLE fa_scan_audit_events
    ADD CONSTRAINT fa_scan_audit_events_event_type_check
    CHECK (event_type IN (
        -- migration 0079
        'scan.initiated',
        'scan.validation_rejected',
        'scan.running',
        'scan.completed',
        'scan.failed',
        'scan.rate_limited',
        -- L14-SCAN-SAFETY-001 (written since migration 0200)
        'scan.authorization.created',
        'scan.authorization.activated',
        'scan.authorization.revoked',
        'scan.authorization.denied',
        'scan.cancel.requested',
        'scan.cancel.denied',
        -- L14-SCAN-AUTH-HARDENING-001
        'scan.authorization.activation_denied',
        'scan.authorization.dispatch_authorized',
        'scan.authorization.worker_start_authorized',
        'scan.authorization.worker_start_denied',
        'scan.authorization.target_denied',
        'scan.authorization.lost',
        'scan.cancelled',
        'scan.late_completion_rejected',
        'scan.consent.requested',
        'scan.consent.approved',
        'scan.consent.approval_denied',
        'scan.consent.rejected',
        'scan.consent.revoked'
    ));

-- ---------------------------------------------------------------------------
-- 5. Repair: job status set includes dead_letter (widen only)
-- ---------------------------------------------------------------------------

ALTER TABLE fa_scan_jobs
    DROP CONSTRAINT IF EXISTS fa_scan_jobs_status_check;

ALTER TABLE fa_scan_jobs
    ADD CONSTRAINT fa_scan_jobs_status_check
    CHECK (status IN ('queued', 'running', 'complete', 'failed',
                      'cancel_requested', 'cancelled', 'dead_letter'));
