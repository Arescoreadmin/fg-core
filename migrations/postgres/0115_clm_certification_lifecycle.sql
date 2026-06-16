-- Migration: 0115_clm_certification_lifecycle
-- Creates Certification Lifecycle Management (CLM) persistence tables for P0-10.
--
-- Tables:
--   fa_clm_certs                — one row per managed cert (lifecycle_status mutable)
--   fa_clm_lifecycle_events     — append-only status transitions + lifecycle events
--   fa_clm_cert_reviews         — append-only review records
--   fa_clm_cert_attestations    — append-only attestation records
--   fa_clm_cert_renewals        — append-only renewal records
--   fa_clm_cert_manifests       — append-only deterministic audit manifest (unique cert_id)
--
-- Design:
--   fa_clm_certs: NOT append-only — lifecycle_status, status_updated_by,
--     status_updated_at mutate during lifecycle progression.
--   All other tables: append-only (guarded by append_only_guard() triggers).
--   All tables: tenant-scoped + RLS enforced (ENABLE + FORCE, app.tenant_id GUC).
--
-- Governance Readiness:
--   actor_type: human | agent | system | workflow
--   cert_type: standard | renewal | exception | interim
--   framework: NIST | ISO | SOC | HIPAA | CMMC | internal
--   certification_level: bronze | silver | gold | platinum | custom
--
-- Lifecycle states (fa_clm_certs.lifecycle_status):
--   draft → in_review → pending_evidence → pending_approval → approved →
--   certified → renewal_due → expired → revoked → superseded → archived
--
-- Rollback:
--   DROP TABLE IF EXISTS fa_clm_cert_manifests;
--   DROP TABLE IF EXISTS fa_clm_cert_renewals;
--   DROP TABLE IF EXISTS fa_clm_cert_attestations;
--   DROP TABLE IF EXISTS fa_clm_cert_reviews;
--   DROP TABLE IF EXISTS fa_clm_lifecycle_events;
--   DROP TABLE IF EXISTS fa_clm_certs;

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. CLM Certs (main record — lifecycle_status mutable)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_clm_certs (
    id                      TEXT        NOT NULL PRIMARY KEY,
    tenant_id               TEXT        NOT NULL,
    engagement_id           TEXT        NOT NULL,

    -- Link to static Trust Arc cert record (optional)
    trust_arc_cert_id       TEXT,

    -- Classification
    cert_name               TEXT        NOT NULL DEFAULT '',
    cert_type               TEXT        NOT NULL DEFAULT 'standard',      -- standard|renewal|exception|interim
    framework               TEXT,                                          -- NIST|ISO|SOC|HIPAA|CMMC|internal
    certification_level     TEXT,                                          -- bronze|silver|gold|platinum|custom

    -- Lifecycle (only mutable fields after creation)
    lifecycle_status        TEXT        NOT NULL DEFAULT 'draft',

    -- Lineage
    parent_cert_id          TEXT,                                          -- nullable; lineage pointer
    family_id               TEXT,                                          -- groups renewal chains

    -- Validity window
    valid_from              TEXT,
    valid_until             TEXT,

    -- Provenance
    created_by              TEXT        NOT NULL DEFAULT 'system',
    created_at              TEXT        NOT NULL,
    status_updated_by       TEXT,
    status_updated_at       TEXT,

    -- Integrity
    cert_hash               TEXT,

    -- Governance readiness
    actor_type              TEXT        NOT NULL DEFAULT 'human',          -- human|agent|system|workflow

    -- Marketplace readiness
    framework_version       TEXT,
    certification_profile   TEXT,

    -- Versioning
    generation_version      TEXT        NOT NULL DEFAULT 'clm-1.0',
    authority_version       TEXT        NOT NULL DEFAULT 'v1',
    schema_version          TEXT        NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 2. Indexes — fa_clm_certs
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_clm_certs_tenant_id
    ON fa_clm_certs (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_clm_certs_tenant_engagement
    ON fa_clm_certs (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_clm_certs_tenant_status
    ON fa_clm_certs (tenant_id, lifecycle_status);

CREATE INDEX IF NOT EXISTS ix_fa_clm_certs_tenant_family
    ON fa_clm_certs (tenant_id, family_id);

-- ---------------------------------------------------------------------------
-- 3. RLS — fa_clm_certs
-- ---------------------------------------------------------------------------

ALTER TABLE fa_clm_certs ENABLE ROW LEVEL SECURITY;
ALTER TABLE fa_clm_certs FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fa_clm_certs_tenant_isolation ON fa_clm_certs;
CREATE POLICY fa_clm_certs_tenant_isolation
    ON fa_clm_certs
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- ---------------------------------------------------------------------------
-- 4. CLM Lifecycle Events (append-only)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_clm_lifecycle_events (
    id              TEXT        NOT NULL PRIMARY KEY,
    cert_id         TEXT        NOT NULL,
    tenant_id       TEXT        NOT NULL,
    engagement_id   TEXT        NOT NULL,

    -- Event classification
    event_type      TEXT        NOT NULL,  -- status_transition|review_requested|review_completed|attestation_added|renewal_initiated|evidence_linked|exception_granted|revoked|archived
    from_status     TEXT,
    to_status       TEXT,

    -- Actor
    actor           TEXT        NOT NULL DEFAULT 'system',
    actor_type      TEXT        NOT NULL DEFAULT 'human',

    -- Payload
    notes           TEXT,
    event_data      TEXT        NOT NULL DEFAULT '{}',

    occurred_at     TEXT        NOT NULL,
    schema_version  TEXT        NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 5. Indexes — fa_clm_lifecycle_events
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_clm_lifecycle_events_cert_id
    ON fa_clm_lifecycle_events (cert_id);

CREATE INDEX IF NOT EXISTS ix_fa_clm_lifecycle_events_tenant_id
    ON fa_clm_lifecycle_events (tenant_id);

-- ---------------------------------------------------------------------------
-- 6. RLS — fa_clm_lifecycle_events
-- ---------------------------------------------------------------------------

ALTER TABLE fa_clm_lifecycle_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE fa_clm_lifecycle_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fa_clm_lifecycle_events_tenant_isolation ON fa_clm_lifecycle_events;
CREATE POLICY fa_clm_lifecycle_events_tenant_isolation
    ON fa_clm_lifecycle_events
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- Append-only guards
DROP TRIGGER IF EXISTS fa_clm_le_append_only_update ON fa_clm_lifecycle_events;
CREATE TRIGGER fa_clm_le_append_only_update
    BEFORE UPDATE ON fa_clm_lifecycle_events
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

DROP TRIGGER IF EXISTS fa_clm_le_append_only_delete ON fa_clm_lifecycle_events;
CREATE TRIGGER fa_clm_le_append_only_delete
    BEFORE DELETE ON fa_clm_lifecycle_events
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

-- ---------------------------------------------------------------------------
-- 7. CLM Cert Reviews (append-only)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_clm_cert_reviews (
    id              TEXT        NOT NULL PRIMARY KEY,
    cert_id         TEXT        NOT NULL,
    tenant_id       TEXT        NOT NULL,
    engagement_id   TEXT        NOT NULL,

    reviewer        TEXT        NOT NULL,
    reviewer_type   TEXT        NOT NULL DEFAULT 'human',
    review_outcome  TEXT        NOT NULL,  -- approved|rejected|pending_evidence|exception_requested

    notes           TEXT,
    evidence_refs   TEXT        NOT NULL DEFAULT '[]',

    reviewed_at     TEXT        NOT NULL,
    schema_version  TEXT        NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 8. Indexes — fa_clm_cert_reviews
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_clm_cert_reviews_cert_id
    ON fa_clm_cert_reviews (cert_id);

CREATE INDEX IF NOT EXISTS ix_fa_clm_cert_reviews_tenant_id
    ON fa_clm_cert_reviews (tenant_id);

-- ---------------------------------------------------------------------------
-- 9. RLS — fa_clm_cert_reviews
-- ---------------------------------------------------------------------------

ALTER TABLE fa_clm_cert_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE fa_clm_cert_reviews FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fa_clm_cert_reviews_tenant_isolation ON fa_clm_cert_reviews;
CREATE POLICY fa_clm_cert_reviews_tenant_isolation
    ON fa_clm_cert_reviews
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- Append-only guards
DROP TRIGGER IF EXISTS fa_clm_cr_append_only_update ON fa_clm_cert_reviews;
CREATE TRIGGER fa_clm_cr_append_only_update
    BEFORE UPDATE ON fa_clm_cert_reviews
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

DROP TRIGGER IF EXISTS fa_clm_cr_append_only_delete ON fa_clm_cert_reviews;
CREATE TRIGGER fa_clm_cr_append_only_delete
    BEFORE DELETE ON fa_clm_cert_reviews
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

-- ---------------------------------------------------------------------------
-- 10. CLM Cert Attestations (append-only)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_clm_cert_attestations (
    id                  TEXT        NOT NULL PRIMARY KEY,
    cert_id             TEXT        NOT NULL,
    tenant_id           TEXT        NOT NULL,
    engagement_id       TEXT        NOT NULL,

    attestation_type    TEXT        NOT NULL,   -- internal|customer|auditor|executive|agent
    attester            TEXT        NOT NULL,
    attester_type       TEXT        NOT NULL DEFAULT 'human',

    attestation_data    TEXT        NOT NULL DEFAULT '{}',
    attestation_hash    TEXT        NOT NULL DEFAULT '',

    attested_at         TEXT        NOT NULL,
    schema_version      TEXT        NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 11. Indexes — fa_clm_cert_attestations
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_clm_cert_attestations_cert_id
    ON fa_clm_cert_attestations (cert_id);

CREATE INDEX IF NOT EXISTS ix_fa_clm_cert_attestations_tenant_id
    ON fa_clm_cert_attestations (tenant_id);

-- ---------------------------------------------------------------------------
-- 12. RLS — fa_clm_cert_attestations
-- ---------------------------------------------------------------------------

ALTER TABLE fa_clm_cert_attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE fa_clm_cert_attestations FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fa_clm_cert_attestations_tenant_isolation ON fa_clm_cert_attestations;
CREATE POLICY fa_clm_cert_attestations_tenant_isolation
    ON fa_clm_cert_attestations
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- Append-only guards
DROP TRIGGER IF EXISTS fa_clm_ca_append_only_update ON fa_clm_cert_attestations;
CREATE TRIGGER fa_clm_ca_append_only_update
    BEFORE UPDATE ON fa_clm_cert_attestations
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

DROP TRIGGER IF EXISTS fa_clm_ca_append_only_delete ON fa_clm_cert_attestations;
CREATE TRIGGER fa_clm_ca_append_only_delete
    BEFORE DELETE ON fa_clm_cert_attestations
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

-- ---------------------------------------------------------------------------
-- 13. CLM Cert Renewals (append-only)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_clm_cert_renewals (
    id                  TEXT        NOT NULL PRIMARY KEY,
    cert_id             TEXT        NOT NULL,
    tenant_id           TEXT        NOT NULL,
    engagement_id       TEXT        NOT NULL,

    renewal_type        TEXT        NOT NULL DEFAULT 'routine',     -- routine|emergency|compliance_driven
    renewal_status      TEXT        NOT NULL DEFAULT 'initiated',   -- initiated|in_progress|completed|abandoned

    initiated_by        TEXT        NOT NULL DEFAULT 'system',
    initiated_at        TEXT        NOT NULL,
    completed_at        TEXT,

    new_cert_id         TEXT,   -- CLM cert that supersedes this one

    renewal_readiness   TEXT        NOT NULL DEFAULT '{}',  -- JSON health snapshot

    schema_version      TEXT        NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 14. Indexes — fa_clm_cert_renewals
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_clm_cert_renewals_cert_id
    ON fa_clm_cert_renewals (cert_id);

CREATE INDEX IF NOT EXISTS ix_fa_clm_cert_renewals_tenant_id
    ON fa_clm_cert_renewals (tenant_id);

-- ---------------------------------------------------------------------------
-- 15. RLS — fa_clm_cert_renewals
-- ---------------------------------------------------------------------------

ALTER TABLE fa_clm_cert_renewals ENABLE ROW LEVEL SECURITY;
ALTER TABLE fa_clm_cert_renewals FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fa_clm_cert_renewals_tenant_isolation ON fa_clm_cert_renewals;
CREATE POLICY fa_clm_cert_renewals_tenant_isolation
    ON fa_clm_cert_renewals
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- Append-only guards
DROP TRIGGER IF EXISTS fa_clm_rn_append_only_update ON fa_clm_cert_renewals;
CREATE TRIGGER fa_clm_rn_append_only_update
    BEFORE UPDATE ON fa_clm_cert_renewals
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

DROP TRIGGER IF EXISTS fa_clm_rn_append_only_delete ON fa_clm_cert_renewals;
CREATE TRIGGER fa_clm_rn_append_only_delete
    BEFORE DELETE ON fa_clm_cert_renewals
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

-- ---------------------------------------------------------------------------
-- 16. CLM Cert Manifests (append-only, cert_id UNIQUE)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_clm_cert_manifests (
    id                  TEXT        NOT NULL PRIMARY KEY,
    cert_id             TEXT        NOT NULL UNIQUE,
    tenant_id           TEXT        NOT NULL,
    engagement_id       TEXT        NOT NULL,

    -- Optional link to static Trust Arc cert
    trust_arc_cert_id   TEXT,

    -- Source ID arrays (JSON)
    snapshot_ids        TEXT        NOT NULL DEFAULT '[]',
    bundle_ids          TEXT        NOT NULL DEFAULT '[]',
    timeline_refs       TEXT        NOT NULL DEFAULT '[]',
    decision_refs       TEXT        NOT NULL DEFAULT '[]',
    evidence_refs       TEXT        NOT NULL DEFAULT '[]',

    -- Integrity
    manifest_hash       TEXT        NOT NULL DEFAULT '',

    generated_at        TEXT        NOT NULL,
    schema_version      TEXT        NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 17. Indexes — fa_clm_cert_manifests
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_clm_cert_manifests_cert_id
    ON fa_clm_cert_manifests (cert_id);

CREATE INDEX IF NOT EXISTS ix_fa_clm_cert_manifests_tenant_id
    ON fa_clm_cert_manifests (tenant_id);

-- ---------------------------------------------------------------------------
-- 18. RLS — fa_clm_cert_manifests
-- ---------------------------------------------------------------------------

ALTER TABLE fa_clm_cert_manifests ENABLE ROW LEVEL SECURITY;
ALTER TABLE fa_clm_cert_manifests FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fa_clm_cert_manifests_tenant_isolation ON fa_clm_cert_manifests;
CREATE POLICY fa_clm_cert_manifests_tenant_isolation
    ON fa_clm_cert_manifests
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- Append-only guards
DROP TRIGGER IF EXISTS fa_clm_cm_append_only_update ON fa_clm_cert_manifests;
CREATE TRIGGER fa_clm_cm_append_only_update
    BEFORE UPDATE ON fa_clm_cert_manifests
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

DROP TRIGGER IF EXISTS fa_clm_cm_append_only_delete ON fa_clm_cert_manifests;
CREATE TRIGGER fa_clm_cm_append_only_delete
    BEFORE DELETE ON fa_clm_cert_manifests
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

COMMIT;
