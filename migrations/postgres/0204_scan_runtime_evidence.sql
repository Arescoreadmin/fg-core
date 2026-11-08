-- Migration 0204: L14-SCAN-RUNNER-INTEGRITY-001 — runtime scanner evidence capture.
--
-- Wires fa_scan_evidence_envelopes (0201) into real scanner execution:
--   1. collection_status CHECK widened to the canonical CollectionStatus vocabulary
--      (0202 / PR #811).  The original lowercase values stay valid for legacy rows.
--   2. Runtime capture metadata: observation_path (location of the digested
--      sub-payload inside fa_scan_results.raw_payload), customer_receipt_id and
--      authorization_proof_level (PR #812 provenance as of worker start),
--      payload_size_bytes (bounded-capture accounting).
--   3. Idempotency: one envelope per (tenant, scan result, source_type, source_id).
--      Retries and duplicate worker deliveries reuse, never duplicate.
--   4. Immutability: captured identity, digest and authorization provenance cannot
--      be rewritten.  provenance_status may only move one way to INVALID (tamper
--      detected); scan_result_id may only become NULL (FK ON DELETE SET NULL).
--   5. fa_scan_audit_events.event_type gains scan.evidence.captured and
--      scan.evidence.capture_failed.
--
-- Safety: additive only.  No envelope is fabricated for historical scan results;
-- no row is rewritten.  Legacy rows have NULL source_id and are unaffected by the
-- unique index (NULLs are distinct).  No CREATE INDEX CONCURRENTLY (the migration
-- executor runs in one transaction).  No payload is duplicated (digests only).

-- ---------------------------------------------------------------------------
-- 1. Canonical collection status on envelopes
-- ---------------------------------------------------------------------------

ALTER TABLE fa_scan_evidence_envelopes
    DROP CONSTRAINT IF EXISTS fa_scan_evidence_envelopes_collection_status_check;

ALTER TABLE fa_scan_evidence_envelopes
    ADD CONSTRAINT fa_scan_evidence_envelopes_collection_status_check
    CHECK (collection_status IN (
        'complete', 'partial', 'failed',
        'COMPLETE', 'PARTIAL', 'DENIED', 'TIMEOUT', 'TRUNCATED', 'FAILED',
        'CANCELLED', 'NOT_ASSESSED', 'UNKNOWN'
    ));

-- ---------------------------------------------------------------------------
-- 2. Runtime capture metadata
-- ---------------------------------------------------------------------------

ALTER TABLE fa_scan_evidence_envelopes
    ADD COLUMN IF NOT EXISTS observation_path          TEXT,
    ADD COLUMN IF NOT EXISTS customer_receipt_id       UUID
        REFERENCES fa_customer_authorization_receipts(id),
    ADD COLUMN IF NOT EXISTS authorization_proof_level TEXT,
    ADD COLUMN IF NOT EXISTS payload_size_bytes        INTEGER
        CHECK (payload_size_bytes IS NULL OR payload_size_bytes >= 0);

-- ---------------------------------------------------------------------------
-- 3. Idempotent capture identity
-- ---------------------------------------------------------------------------

CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_scan_evidence_env_observation
    ON fa_scan_evidence_envelopes (tenant_id, scan_result_id, source_type, source_id);

CREATE INDEX IF NOT EXISTS fa_evidence_custody_normalized_reason
    ON fa_evidence_custody_events (tenant_id, evidence_id, reason)
    WHERE event_type = 'NORMALIZED';

-- ---------------------------------------------------------------------------
-- 4. Immutability of captured evidence identity and digest
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION fa_scan_evidence_envelopes_guard()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id, NEW.tenant_id, NEW.engagement_id, NEW.scan_job_id, NEW.scanner_id,
           NEW.scanner_version, NEW.source_type, NEW.source_id, NEW.observation_path,
           NEW.payload_digest, NEW.canonicalization_ver, NEW.schema_version,
           NEW.collected_at, NEW.collection_status, NEW.authorization_ref,
           NEW.authorization_version, NEW.customer_receipt_id,
           NEW.authorization_proof_level, NEW.payload_size_bytes, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_id, OLD.engagement_id, OLD.scan_job_id, OLD.scanner_id,
           OLD.scanner_version, OLD.source_type, OLD.source_id, OLD.observation_path,
           OLD.payload_digest, OLD.canonicalization_ver, OLD.schema_version,
           OLD.collected_at, OLD.collection_status, OLD.authorization_ref,
           OLD.authorization_version, OLD.customer_receipt_id,
           OLD.authorization_proof_level, OLD.payload_size_bytes, OLD.created_at)
    THEN
        RAISE EXCEPTION 'fa_scan_evidence_envelopes: captured evidence is immutable';
    END IF;

    IF NEW.provenance_status IS DISTINCT FROM OLD.provenance_status
       AND (NEW.provenance_status <> 'INVALID' OR OLD.provenance_status = 'INVALID')
    THEN
        RAISE EXCEPTION 'fa_scan_evidence_envelopes: provenance_status may only move to INVALID';
    END IF;

    IF NEW.scan_result_id IS DISTINCT FROM OLD.scan_result_id
       AND NEW.scan_result_id IS NOT NULL
    THEN
        RAISE EXCEPTION 'fa_scan_evidence_envelopes: scan_result_id is immutable';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS fa_scan_evidence_envelopes_guard_trigger
    ON fa_scan_evidence_envelopes;

CREATE TRIGGER fa_scan_evidence_envelopes_guard_trigger
    BEFORE UPDATE ON fa_scan_evidence_envelopes
    FOR EACH ROW EXECUTE FUNCTION fa_scan_evidence_envelopes_guard();

-- ---------------------------------------------------------------------------
-- 5. Scan audit event types (widen only)
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
        'scan.consent.revoked',
        -- L14-SCAN-RUNNER-INTEGRITY-001
        'scan.evidence.captured',
        'scan.evidence.capture_failed'
    ));
