-- Migration: 0114_quarterly_trust_briefs
-- Creates Quarterly Trust Brief (QTB) persistence tables for P0-9.
--
-- Tables:
--   fa_qtb_briefs         — one row per generated report (status mutable for workflow)
--   fa_qtb_brief_sections — immutable content sections (posture/drift/cert/governance/evidence/board)
--   fa_qtb_brief_manifests — immutable deterministic manifest per brief
--
-- Design:
--   fa_qtb_briefs: NOT append-only — status field progresses through workflow states.
--   fa_qtb_brief_sections: append-only (content never changes after generation).
--   fa_qtb_brief_manifests: append-only (manifest is the audit anchor).
--   All tables are tenant-scoped and RLS enforced.
--
-- Governance Readiness:
--   generated_by / reviewed_by / approved_by support: human | agent | system | workflow
--   report_type supports: quarterly | board | executive | governance | certification | continuous
--   schema_version allows forward-compatible schema evolution without migrations.
--
-- Versioning states (fa_qtb_briefs.status):
--   draft → generated → reviewed → approved → delivered → archived
--
-- RLS:
--   ENABLE + FORCE ensures table owners / superusers are subject to tenant isolation.
--
-- Rollback:
--   DROP TABLE IF EXISTS fa_qtb_brief_manifests;
--   DROP TABLE IF EXISTS fa_qtb_brief_sections;
--   DROP TABLE IF EXISTS fa_qtb_briefs;

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Quarterly Trust Briefs (main record)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_qtb_briefs (
    id                  TEXT        NOT NULL PRIMARY KEY,
    tenant_id           TEXT        NOT NULL,
    engagement_id       TEXT        NOT NULL,

    -- Report classification
    report_type         TEXT        NOT NULL DEFAULT 'quarterly',
    year                INTEGER,
    quarter             INTEGER,
    period_start        TEXT,
    period_end          TEXT,

    -- Workflow status (the only mutable fields after generation)
    status              TEXT        NOT NULL DEFAULT 'draft',
    generated_by        TEXT        NOT NULL DEFAULT 'system',
    generated_at        TEXT        NOT NULL,
    reviewed_by         TEXT,
    reviewed_at         TEXT,
    approved_by         TEXT,
    approved_at         TEXT,

    -- Integrity hashes (immutable after set)
    brief_hash          TEXT,
    report_hash         TEXT,

    -- Provenance
    generation_version  TEXT        NOT NULL DEFAULT 'qtb-1.0',
    authority_version   TEXT        NOT NULL DEFAULT 'v1',
    schema_version      TEXT        NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 2. Indexes — fa_qtb_briefs
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_qtb_briefs_tenant_id
    ON fa_qtb_briefs (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_qtb_briefs_tenant_engagement
    ON fa_qtb_briefs (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_qtb_briefs_status
    ON fa_qtb_briefs (tenant_id, status);

-- ---------------------------------------------------------------------------
-- 3. RLS — fa_qtb_briefs
-- ---------------------------------------------------------------------------

ALTER TABLE fa_qtb_briefs ENABLE ROW LEVEL SECURITY;
ALTER TABLE fa_qtb_briefs FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fa_qtb_briefs_tenant_isolation ON fa_qtb_briefs;
CREATE POLICY fa_qtb_briefs_tenant_isolation
    ON fa_qtb_briefs
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- ---------------------------------------------------------------------------
-- 4. Brief Sections (append-only immutable content)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_qtb_brief_sections (
    id              TEXT        NOT NULL PRIMARY KEY,
    brief_id        TEXT        NOT NULL,
    tenant_id       TEXT        NOT NULL,
    engagement_id   TEXT        NOT NULL,

    -- Section classification
    section_type    TEXT        NOT NULL,   -- posture | drift | certification | governance | evidence | board_summary
    section_order   INTEGER     NOT NULL DEFAULT 0,

    -- Content (JSON)
    section_data    TEXT        NOT NULL DEFAULT '{}',

    -- Evidence linkage (JSON array of referenced source IDs)
    evidence_refs   TEXT        NOT NULL DEFAULT '[]',

    -- Integrity
    section_hash    TEXT        NOT NULL DEFAULT '',

    generated_at    TEXT        NOT NULL,
    schema_version  TEXT        NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 5. Indexes — fa_qtb_brief_sections
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_qtb_sections_brief_id
    ON fa_qtb_brief_sections (brief_id);

CREATE INDEX IF NOT EXISTS ix_fa_qtb_sections_tenant_id
    ON fa_qtb_brief_sections (tenant_id);

-- ---------------------------------------------------------------------------
-- 6. RLS — fa_qtb_brief_sections
-- ---------------------------------------------------------------------------

ALTER TABLE fa_qtb_brief_sections ENABLE ROW LEVEL SECURITY;
ALTER TABLE fa_qtb_brief_sections FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fa_qtb_brief_sections_tenant_isolation ON fa_qtb_brief_sections;
CREATE POLICY fa_qtb_brief_sections_tenant_isolation
    ON fa_qtb_brief_sections
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- Append-only: sections are immutable after creation
DROP TRIGGER IF EXISTS fa_qtbs_append_only_update ON fa_qtb_brief_sections;
CREATE TRIGGER fa_qtbs_append_only_update
    BEFORE UPDATE ON fa_qtb_brief_sections
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

DROP TRIGGER IF EXISTS fa_qtbs_append_only_delete ON fa_qtb_brief_sections;
CREATE TRIGGER fa_qtbs_append_only_delete
    BEFORE DELETE ON fa_qtb_brief_sections
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

-- ---------------------------------------------------------------------------
-- 7. Brief Manifests (append-only deterministic audit anchor)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_qtb_brief_manifests (
    id                  TEXT        NOT NULL PRIMARY KEY,
    brief_id            TEXT        NOT NULL UNIQUE,
    tenant_id           TEXT        NOT NULL,
    engagement_id       TEXT        NOT NULL,

    -- Source IDs that produced this report (JSON arrays)
    snapshot_ids        TEXT        NOT NULL DEFAULT '[]',
    certification_ids   TEXT        NOT NULL DEFAULT '[]',
    drift_event_ids     TEXT        NOT NULL DEFAULT '[]',
    timeline_refs       TEXT        NOT NULL DEFAULT '[]',
    evidence_refs       TEXT        NOT NULL DEFAULT '[]',
    decision_refs       TEXT        NOT NULL DEFAULT '[]',
    bundle_refs         TEXT        NOT NULL DEFAULT '[]',

    -- Integrity hashes
    manifest_hash       TEXT        NOT NULL DEFAULT '',
    report_hash         TEXT        NOT NULL DEFAULT '',

    -- Provenance
    generation_version  TEXT        NOT NULL DEFAULT 'qtb-1.0',
    authority_version   TEXT        NOT NULL DEFAULT 'v1',
    replay_version      TEXT        NOT NULL DEFAULT 'v1',

    generated_at        TEXT        NOT NULL,
    schema_version      TEXT        NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 8. Indexes — fa_qtb_brief_manifests
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_qtb_manifests_brief_id
    ON fa_qtb_brief_manifests (brief_id);

CREATE INDEX IF NOT EXISTS ix_fa_qtb_manifests_tenant_id
    ON fa_qtb_brief_manifests (tenant_id);

-- ---------------------------------------------------------------------------
-- 9. RLS — fa_qtb_brief_manifests
-- ---------------------------------------------------------------------------

ALTER TABLE fa_qtb_brief_manifests ENABLE ROW LEVEL SECURITY;
ALTER TABLE fa_qtb_brief_manifests FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fa_qtb_manifests_tenant_isolation ON fa_qtb_brief_manifests;
CREATE POLICY fa_qtb_manifests_tenant_isolation
    ON fa_qtb_brief_manifests
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- Append-only: manifests are the audit anchor — never mutate
DROP TRIGGER IF EXISTS fa_qtbm_append_only_update ON fa_qtb_brief_manifests;
CREATE TRIGGER fa_qtbm_append_only_update
    BEFORE UPDATE ON fa_qtb_brief_manifests
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

DROP TRIGGER IF EXISTS fa_qtbm_append_only_delete ON fa_qtb_brief_manifests;
CREATE TRIGGER fa_qtbm_append_only_delete
    BEFORE DELETE ON fa_qtb_brief_manifests
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

COMMIT;
