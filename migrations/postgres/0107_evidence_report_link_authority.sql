-- Migration 0107: Evidence-to-Report Link Authority (PR 1.4)
-- SCHEMA CHANGE — new table fa_evidence_report_links
--
-- Creates an append-only join table for evidence-to-report cryptographic linkage.
-- Each row proves: which evidence supported which report, signed by FrostGate authority.
--
-- Append-only: no UPDATE or DELETE. Link amendments create new rows.
-- Authority version: evidence-report-authority-v1
-- Link version: report-link-v1

-- ---------------------------------------------------------------------------
-- 1. Table
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_evidence_report_links (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL,
    engagement_id        TEXT NOT NULL,
    evidence_id          TEXT NOT NULL,
    provenance_record_id TEXT,
    report_id            TEXT NOT NULL,
    report_hash          TEXT,
    report_signature     TEXT,
    linked_at            TEXT NOT NULL,
    linked_by            TEXT,
    authority_version    TEXT,
    link_version         TEXT,
    event_hash           TEXT NOT NULL,
    previous_hash        TEXT,
    signature            TEXT,
    signing_key_id       TEXT,
    signed_at            TEXT,
    signature_version    TEXT,
    schema_version       TEXT NOT NULL DEFAULT '1.0',
    created_at           TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- 2. Indexes
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_evidence_report_links_tenant_id
    ON fa_evidence_report_links (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_evidence_report_links_engagement
    ON fa_evidence_report_links (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_evidence_report_links_evidence
    ON fa_evidence_report_links (tenant_id, evidence_id);

CREATE INDEX IF NOT EXISTS ix_fa_evidence_report_links_report
    ON fa_evidence_report_links (tenant_id, report_id);

CREATE INDEX IF NOT EXISTS ix_fa_evidence_report_links_provenance
    ON fa_evidence_report_links (provenance_record_id)
    WHERE provenance_record_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_fa_evidence_report_links_event_hash
    ON fa_evidence_report_links (event_hash);

CREATE INDEX IF NOT EXISTS ix_fa_evidence_report_links_signing_key_id
    ON fa_evidence_report_links (signing_key_id)
    WHERE signing_key_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 3. Row-level security — tenant isolation
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_evidence_report_links') IS NOT NULL THEN
        ALTER TABLE fa_evidence_report_links ENABLE ROW LEVEL SECURITY;
        ALTER TABLE fa_evidence_report_links FORCE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS fa_evidence_report_links_tenant_isolation
            ON fa_evidence_report_links;
        CREATE POLICY fa_evidence_report_links_tenant_isolation
            ON fa_evidence_report_links
            USING (
                tenant_id = current_setting('app.current_tenant_id', true)
                OR current_setting('app.current_tenant_id', true) = ''
            );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 4. Append-only enforcement
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_evidence_report_links') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_evidence_report_links_append_only_update
            ON fa_evidence_report_links;
        CREATE TRIGGER fa_evidence_report_links_append_only_update
            BEFORE UPDATE ON fa_evidence_report_links
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS fa_evidence_report_links_append_only_delete
            ON fa_evidence_report_links;
        CREATE TRIGGER fa_evidence_report_links_append_only_delete
            BEFORE DELETE ON fa_evidence_report_links
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;
