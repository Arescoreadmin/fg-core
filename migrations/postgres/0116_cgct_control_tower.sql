-- Migration: 0116_cgct_control_tower
-- Creates Continuous Governance Control Tower (CGCT) persistence tables for P0-11.
--
-- Tables:
--   fg_cgct_posture_snapshots — append-only governance posture snapshots
--   fg_cgct_action_queue      — deterministic action items from authoritative sources
--   fg_cgct_graph_edges       — graph-ready governance relationships
--
-- Design:
--   All tables: append-only (guarded by append_only_guard() triggers).
--   All tables: tenant-scoped + RLS enforced (ENABLE + FORCE, app.tenant_id GUC).
--   CGCT aggregates from existing authority systems only — no new trust engines.
--
-- Authority sources:
--   Trust Arc (FaTrustCertification), TIM (FaTimTrustSnapshot, FaTimDriftEvent),
--   CLM (FaClmCert, FaClmLifecycleEvent), Governance Decision (FaGovernanceDecision),
--   Verification Bundle (FaVerificationBundle), Timeline (TimelineEventRecord),
--   QTB (FaQtbBrief)
--
-- Governance Readiness:
--   actor_type: human | agent | system | workflow
--
-- Rollback:
--   DROP TABLE IF EXISTS fg_cgct_graph_edges;
--   DROP TABLE IF EXISTS fg_cgct_action_queue;
--   DROP TABLE IF EXISTS fg_cgct_posture_snapshots;

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. CGCT Posture Snapshots (append-only)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fg_cgct_posture_snapshots (
    id                      TEXT        NOT NULL PRIMARY KEY,
    tenant_id               TEXT        NOT NULL,
    engagement_id           TEXT        NOT NULL,

    -- Composite governance score
    overall_score           INTEGER     NOT NULL DEFAULT 0,   -- 0-100
    governance_health       TEXT        NOT NULL DEFAULT 'critical',  -- healthy|attention_required|degraded|at_risk|critical

    -- Component scores (0-100 each)
    trust_score             INTEGER     NOT NULL DEFAULT 0,
    cert_score              INTEGER     NOT NULL DEFAULT 0,
    risk_score              INTEGER     NOT NULL DEFAULT 0,
    evidence_score          INTEGER     NOT NULL DEFAULT 0,

    -- Operational context
    operational_readiness   TEXT,       -- e.g. full|partial|limited|not_ready
    governance_status       TEXT,       -- e.g. compliant|non_compliant|under_review

    -- Open item counts
    open_action_count       INTEGER     NOT NULL DEFAULT 0,
    open_drift_count        INTEGER     NOT NULL DEFAULT 0,
    active_cert_count       INTEGER     NOT NULL DEFAULT 0,
    total_cert_count        INTEGER     NOT NULL DEFAULT 0,

    -- Explainability — source IDs enabling audit trail from score → source record
    trust_source_id         TEXT,       -- FaTimTrustSnapshot.id
    cert_source_id          TEXT,       -- most recent FaClmCert.id
    risk_source_id          TEXT,       -- FaTimTrustSnapshot.id (risk_level)
    evidence_source_id      TEXT,       -- FaVerificationBundle.id

    score_inputs_json       TEXT        NOT NULL DEFAULT '{}',  -- JSON with all contributing scores and IDs

    -- Governance readiness
    actor_type              TEXT        NOT NULL DEFAULT 'system',  -- human|agent|system|workflow

    computed_at             TEXT        NOT NULL,
    schema_version          TEXT        NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 2. Indexes — fg_cgct_posture_snapshots
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fg_cgct_ps_tenant_id
    ON fg_cgct_posture_snapshots (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fg_cgct_ps_tenant_engagement
    ON fg_cgct_posture_snapshots (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fg_cgct_ps_computed_at
    ON fg_cgct_posture_snapshots (tenant_id, computed_at);

-- ---------------------------------------------------------------------------
-- 3. RLS — fg_cgct_posture_snapshots
-- ---------------------------------------------------------------------------

ALTER TABLE fg_cgct_posture_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE fg_cgct_posture_snapshots FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fg_cgct_posture_snapshots_tenant_isolation ON fg_cgct_posture_snapshots;
CREATE POLICY fg_cgct_posture_snapshots_tenant_isolation
    ON fg_cgct_posture_snapshots
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- Append-only guards
DROP TRIGGER IF EXISTS fg_cgct_ps_append_only_update ON fg_cgct_posture_snapshots;
CREATE TRIGGER fg_cgct_ps_append_only_update
    BEFORE UPDATE ON fg_cgct_posture_snapshots
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

DROP TRIGGER IF EXISTS fg_cgct_ps_append_only_delete ON fg_cgct_posture_snapshots;
CREATE TRIGGER fg_cgct_ps_append_only_delete
    BEFORE DELETE ON fg_cgct_posture_snapshots
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

-- ---------------------------------------------------------------------------
-- 4. CGCT Action Queue (append-only)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fg_cgct_action_queue (
    id                  TEXT        NOT NULL PRIMARY KEY,
    tenant_id           TEXT        NOT NULL,
    engagement_id       TEXT        NOT NULL,

    -- Action classification
    action_type         TEXT        NOT NULL,  -- review_certification|renew_certification|investigate_drift|validate_evidence|review_exception|escalate_risk|close_finding|verify_trust
    action_title        TEXT        NOT NULL,
    action_description  TEXT,

    -- Priority and status
    priority            TEXT        NOT NULL DEFAULT 'medium',  -- critical|high|medium|low
    status              TEXT        NOT NULL DEFAULT 'open',    -- open|closed|deferred|acknowledged

    -- Source authority link
    source_system       TEXT        NOT NULL,  -- clm|tim|trust_arc|qtb|decision_ledger|verification_bundle
    source_id           TEXT,                  -- FK reference to the source record

    -- Evidence references
    evidence_refs_json  TEXT        NOT NULL DEFAULT '[]',

    -- Governance readiness
    actor_type          TEXT        NOT NULL DEFAULT 'system',  -- human|agent|system|workflow

    created_at          TEXT        NOT NULL,
    closed_at           TEXT,
    closed_by           TEXT,
    schema_version      TEXT        NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 5. Indexes — fg_cgct_action_queue
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fg_cgct_aq_tenant_id
    ON fg_cgct_action_queue (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fg_cgct_aq_tenant_engagement
    ON fg_cgct_action_queue (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fg_cgct_aq_tenant_status
    ON fg_cgct_action_queue (tenant_id, status);

CREATE INDEX IF NOT EXISTS ix_fg_cgct_aq_tenant_priority
    ON fg_cgct_action_queue (tenant_id, priority);

-- ---------------------------------------------------------------------------
-- 6. RLS — fg_cgct_action_queue
-- ---------------------------------------------------------------------------

ALTER TABLE fg_cgct_action_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE fg_cgct_action_queue FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fg_cgct_action_queue_tenant_isolation ON fg_cgct_action_queue;
CREATE POLICY fg_cgct_action_queue_tenant_isolation
    ON fg_cgct_action_queue
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- Append-only guards
DROP TRIGGER IF EXISTS fg_cgct_aq_append_only_update ON fg_cgct_action_queue;
CREATE TRIGGER fg_cgct_aq_append_only_update
    BEFORE UPDATE ON fg_cgct_action_queue
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

DROP TRIGGER IF EXISTS fg_cgct_aq_append_only_delete ON fg_cgct_action_queue;
CREATE TRIGGER fg_cgct_aq_append_only_delete
    BEFORE DELETE ON fg_cgct_action_queue
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

-- ---------------------------------------------------------------------------
-- 7. CGCT Graph Edges (append-only, graph-ready governance relationships)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fg_cgct_graph_edges (
    id              TEXT        NOT NULL PRIMARY KEY,
    tenant_id       TEXT        NOT NULL,

    -- Source node
    from_node_type  TEXT        NOT NULL,  -- trust|certification|evidence|decision|drift|risk|monitoring|attestation|lifecycle|renewal|timeline_event|verification_bundle
    from_node_id    TEXT        NOT NULL,

    -- Target node
    to_node_type    TEXT        NOT NULL,
    to_node_id      TEXT        NOT NULL,

    -- Relationship metadata
    relationship    TEXT        NOT NULL,  -- influences|impacts|drives|supports|references|validates|supersedes
    weight          INTEGER     NOT NULL DEFAULT 1,
    direction       TEXT        NOT NULL DEFAULT 'directed',  -- directed|bidirectional

    created_at      TEXT        NOT NULL,
    schema_version  TEXT        NOT NULL DEFAULT '1.0',

    -- Prevent duplicate edges
    UNIQUE (tenant_id, from_node_type, from_node_id, to_node_type, to_node_id, relationship)
);

-- ---------------------------------------------------------------------------
-- 8. Indexes — fg_cgct_graph_edges
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fg_cgct_ge_tenant_id
    ON fg_cgct_graph_edges (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fg_cgct_ge_from_node
    ON fg_cgct_graph_edges (tenant_id, from_node_type, from_node_id);

CREATE INDEX IF NOT EXISTS ix_fg_cgct_ge_to_node
    ON fg_cgct_graph_edges (tenant_id, to_node_type, to_node_id);

-- ---------------------------------------------------------------------------
-- 9. RLS — fg_cgct_graph_edges
-- ---------------------------------------------------------------------------

ALTER TABLE fg_cgct_graph_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE fg_cgct_graph_edges FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fg_cgct_graph_edges_tenant_isolation ON fg_cgct_graph_edges;
CREATE POLICY fg_cgct_graph_edges_tenant_isolation
    ON fg_cgct_graph_edges
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- Append-only guards
DROP TRIGGER IF EXISTS fg_cgct_ge_append_only_update ON fg_cgct_graph_edges;
CREATE TRIGGER fg_cgct_ge_append_only_update
    BEFORE UPDATE ON fg_cgct_graph_edges
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

DROP TRIGGER IF EXISTS fg_cgct_ge_append_only_delete ON fg_cgct_graph_edges;
CREATE TRIGGER fg_cgct_ge_append_only_delete
    BEFORE DELETE ON fg_cgct_graph_edges
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

COMMIT;
