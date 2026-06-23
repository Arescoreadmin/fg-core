-- 0126_timeline_authority_p1.sql
-- PR 14.6.2 P1 — Timeline Authority: authority level, signature reservation,
--               external references, federation hooks

-- Authority level: who/what authorised this event
ALTER TABLE fa_timeline_events
    ADD COLUMN IF NOT EXISTS authority_level TEXT NOT NULL DEFAULT 'SYSTEM';

ALTER TABLE fa_timeline_events
    DROP CONSTRAINT IF EXISTS chk_fa_timeline_authority_level;
ALTER TABLE fa_timeline_events
    ADD CONSTRAINT chk_fa_timeline_authority_level CHECK (
        authority_level IN (
            'SYSTEM','HUMAN','REVIEWER','COMMITTEE',
            'AUTONOMOUS_AGENT','AUTONOMOUS_SYSTEM','AGI_SYSTEM'
        )
    );

-- Signature reservation (unused until Notary / cryptographic approval chains)
ALTER TABLE fa_timeline_events
    ADD COLUMN IF NOT EXISTS signature_algorithm TEXT NOT NULL DEFAULT '';
ALTER TABLE fa_timeline_events
    ADD COLUMN IF NOT EXISTS signature_value     TEXT NOT NULL DEFAULT '';
ALTER TABLE fa_timeline_events
    ADD COLUMN IF NOT EXISTS signed_at           TIMESTAMPTZ;

-- External references (Jira, ServiceNow, Azure DevOps, legal hold, etc.)
ALTER TABLE fa_timeline_events
    ADD COLUMN IF NOT EXISTS external_reference      TEXT NOT NULL DEFAULT '';
ALTER TABLE fa_timeline_events
    ADD COLUMN IF NOT EXISTS external_reference_type TEXT NOT NULL DEFAULT '';

-- Federation hooks (CGIN / cross-tenant anonymised governance analytics)
ALTER TABLE fa_timeline_events
    ADD COLUMN IF NOT EXISTS origin_system   TEXT NOT NULL DEFAULT '';
ALTER TABLE fa_timeline_events
    ADD COLUMN IF NOT EXISTS origin_tenant   TEXT NOT NULL DEFAULT '';
ALTER TABLE fa_timeline_events
    ADD COLUMN IF NOT EXISTS origin_event_id TEXT NOT NULL DEFAULT '';

-- Index: authority level queries within a tenant
CREATE INDEX IF NOT EXISTS ix_fa_timeline_authority_level
    ON fa_timeline_events (tenant_id, authority_level);

-- Index: external reference lookups
CREATE INDEX IF NOT EXISTS ix_fa_timeline_external_ref
    ON fa_timeline_events (tenant_id, external_reference_type, external_reference)
    WHERE external_reference != '';
