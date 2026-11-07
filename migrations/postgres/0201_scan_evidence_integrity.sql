-- Migration 0201: L14-SCAN-INTEGRITY-001 — canonical scanner evidence envelopes,
--                 confidence fields on findings, and append-only chain-of-custody
--
-- Adds:
--   fa_scan_evidence_envelopes    — canonical evidence envelope with SHA-256 payload digest
--   fa_evidence_custody_events    — append-only chain-of-custody event log
--   ALTER fa_normalized_findings  — confidence_level, verification_method,
--                                   confidence_justification, evidence_envelope_id
--
-- Design notes:
--   - All changes are ADDITIVE. No existing column, table, or index is modified
--     or dropped. This migration is safe to replay (IF NOT EXISTS throughout).
--   - fa_scan_evidence_envelopes.payload_digest stores "sha256:<hex>" — the
--     "sha256:" prefix is mandatory; callers must not store bare hex values.
--   - fa_evidence_custody_events is enforced append-only by a PL/pgSQL trigger.
--     This is in addition to the application-level EvidenceCustodyService
--     constraint (defence in depth).
--   - fa_normalized_findings may predate this migration. The ALTER is guarded
--     with ADD COLUMN IF NOT EXISTS so it is safe to run against an existing table.
--   - scan_job_id references fa_scan_jobs via soft reference (UUID only, no FK)
--     because scan job rows may be pruned after completion. Evidence envelopes
--     must outlive the jobs that produced them.

-- ---------------------------------------------------------------------------
-- Canonical scanner evidence envelopes
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_scan_evidence_envelopes (
    id                      VARCHAR(64) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id               TEXT NOT NULL,
    engagement_id           VARCHAR(64) NOT NULL REFERENCES fa_engagements(id) ON DELETE CASCADE,
    scan_result_id          VARCHAR(64) REFERENCES fa_scan_results(id) ON DELETE SET NULL,
    scan_job_id             UUID,  -- soft ref; no FK (jobs may be pruned)

    schema_version          TEXT NOT NULL DEFAULT '1.0',
    scanner_id              TEXT NOT NULL,
    scanner_version         TEXT,
    authorization_ref       UUID REFERENCES fa_scan_authorizations(id) ON DELETE SET NULL,
    authorization_version   INTEGER,

    collected_at            TIMESTAMPTZ NOT NULL,
    collection_status       TEXT NOT NULL DEFAULT 'complete'
                                CHECK (collection_status IN ('complete', 'partial', 'failed')),
    source_type             TEXT NOT NULL,
    source_id               TEXT,

    payload_digest          TEXT NOT NULL,       -- "sha256:<hex>"
    canonicalization_ver    TEXT NOT NULL DEFAULT '1.0',
    provenance_status       TEXT NOT NULL DEFAULT 'UNVERIFIED'
                                CHECK (provenance_status IN (
                                    'VERIFIED_AUTHENTIC',
                                    'VERIFIED_INTEGRITY_ONLY',
                                    'UNVERIFIED',
                                    'MISSING',
                                    'INVALID',
                                    'INDETERMINATE'
                                )),
    signature_ref           TEXT,                -- vault key ref if signed; NULL otherwise

    data_sensitivity        TEXT NOT NULL DEFAULT 'internal'
                                CHECK (data_sensitivity IN ('internal', 'confidential', 'restricted')),
    correlation_id          TEXT,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS fa_scan_evidence_env_tenant_eng
    ON fa_scan_evidence_envelopes(tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS fa_scan_evidence_env_scan_result
    ON fa_scan_evidence_envelopes(scan_result_id)
    WHERE scan_result_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS fa_scan_evidence_env_provenance
    ON fa_scan_evidence_envelopes(provenance_status);

CREATE INDEX IF NOT EXISTS fa_scan_evidence_env_scanner
    ON fa_scan_evidence_envelopes(tenant_id, scanner_id);

-- ---------------------------------------------------------------------------
-- Confidence fields on fa_normalized_findings
--
-- fa_normalized_findings was created in migration 0097. The ADD COLUMN IF NOT
-- EXISTS guard makes this safe to replay and safe against out-of-order runs.
-- ---------------------------------------------------------------------------

ALTER TABLE fa_normalized_findings
    ADD COLUMN IF NOT EXISTS confidence_level          TEXT,
    ADD COLUMN IF NOT EXISTS verification_method       TEXT,
    ADD COLUMN IF NOT EXISTS confidence_justification  TEXT,
    ADD COLUMN IF NOT EXISTS evidence_envelope_id      VARCHAR(64)
        REFERENCES fa_scan_evidence_envelopes(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS fa_findings_confidence_level
    ON fa_normalized_findings(tenant_id, confidence_level)
    WHERE confidence_level IS NOT NULL;

CREATE INDEX IF NOT EXISTS fa_findings_evidence_envelope
    ON fa_normalized_findings(evidence_envelope_id)
    WHERE evidence_envelope_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Append-only chain-of-custody event log
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_evidence_custody_events (
    id              VARCHAR(64) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    evidence_id     VARCHAR(64) NOT NULL REFERENCES fa_scan_evidence_envelopes(id) ON DELETE CASCADE,
    tenant_id       TEXT NOT NULL,
    engagement_id   VARCHAR(64) NOT NULL,
    event_type      TEXT NOT NULL
                        CHECK (event_type IN (
                            'COLLECTED', 'INGESTED', 'NORMALIZED', 'VERIFIED',
                            'LOCKED', 'REVIEWED', 'REFERENCED_IN_REPORT',
                            'EXPORTED', 'RETAINED', 'LEGAL_HOLD', 'SUPERSEDED'
                        )),
    actor           TEXT NOT NULL,
    actor_type      TEXT NOT NULL DEFAULT 'system',
    from_state      TEXT,
    to_state        TEXT,
    reason          TEXT,
    correlation_id  TEXT,
    digest_ref      TEXT,  -- digest at time of custody event
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS fa_evidence_custody_tenant
    ON fa_evidence_custody_events(tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS fa_evidence_custody_evidence
    ON fa_evidence_custody_events(evidence_id);

CREATE INDEX IF NOT EXISTS fa_evidence_custody_event_type
    ON fa_evidence_custody_events(event_type, tenant_id);

-- ---------------------------------------------------------------------------
-- Append-only trigger on fa_evidence_custody_events
--
-- Defence-in-depth: the application layer (EvidenceCustodyService) also
-- enforces append-only semantics, but a database-level trigger ensures that
-- even direct SQL access cannot corrupt the custody trail.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION fa_evidence_custody_append_only()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' OR TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'fa_evidence_custody_events is append-only: %% is not permitted',
            TG_OP;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS fa_evidence_custody_append_only_trigger
    ON fa_evidence_custody_events;

CREATE TRIGGER fa_evidence_custody_append_only_trigger
    BEFORE UPDATE OR DELETE ON fa_evidence_custody_events
    FOR EACH ROW EXECUTE FUNCTION fa_evidence_custody_append_only();
