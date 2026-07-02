-- PR 18.5A: Governance Intelligence Authority — Evidence Graph & Decision Provenance
-- Creates:
--   fa_gov_intel_provenance_node      -- provenance graph nodes
--   fa_gov_intel_provenance_edge      -- append-only provenance edges
--   fa_gov_intel_replay_snapshot      -- historical replay snapshots
--   fa_gov_intel_evidence_matrix      -- recommendation evidence matrices
--   fa_gov_intel_quality_score        -- append-only intelligence quality scores
--   fa_gov_intel_simulation_comparison -- simulation comparisons
--   fa_gov_intel_timeline_diff        -- governance timeline diffs
--   fa_gov_intel_counterfactual       -- counterfactual scenario runs
--   fa_gov_intel_export_history       -- append-only export history

-- ---------------------------------------------------------------------------
-- fa_gov_intel_provenance_node
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_provenance_node (
    id                VARCHAR(64)  PRIMARY KEY,
    tenant_id         VARCHAR(255) NOT NULL,
    node_type         VARCHAR(64)  NOT NULL,
    authority         VARCHAR(255) NOT NULL,
    authority_version VARCHAR(32)  NOT NULL DEFAULT '1.0',
    source_object_id  VARCHAR(255) NOT NULL,
    sha256_digest     VARCHAR(64)  NOT NULL,
    timestamp         VARCHAR(64)  NOT NULL,
    parent_ids        TEXT,
    child_ids         TEXT,
    trust_ref         VARCHAR(255),
    transparency_ref  VARCHAR(255),
    confidence_ref    VARCHAR(255),
    simulation_ref    VARCHAR(255),
    replay_ref        VARCHAR(255),
    created_at        VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_provenance_node_tenant
    ON fa_gov_intel_provenance_node (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_provenance_node_tenant_type
    ON fa_gov_intel_provenance_node (tenant_id, node_type);

ALTER TABLE fa_gov_intel_provenance_node ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_provenance_node'
          AND policyname = 'fa_gov_intel_provenance_node_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_provenance_node_tenant_isolation
            ON fa_gov_intel_provenance_node
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_provenance_edge (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_provenance_edge (
    id         VARCHAR(64)  PRIMARY KEY,
    tenant_id  VARCHAR(255) NOT NULL,
    parent_id  VARCHAR(255) NOT NULL,
    child_id   VARCHAR(255) NOT NULL,
    edge_type  VARCHAR(64)  NOT NULL DEFAULT 'DERIVED_FROM',
    created_at VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_provenance_edge_tenant
    ON fa_gov_intel_provenance_edge (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_provenance_edge_tenant_parent
    ON fa_gov_intel_provenance_edge (tenant_id, parent_id);

ALTER TABLE fa_gov_intel_provenance_edge ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_provenance_edge'
          AND policyname = 'fa_gov_intel_provenance_edge_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_provenance_edge_tenant_isolation
            ON fa_gov_intel_provenance_edge
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_intel_provenance_edge'
          AND rulename  = 'fa_gov_intel_provenance_edge_no_update'
    ) THEN
        CREATE RULE fa_gov_intel_provenance_edge_no_update
            AS ON UPDATE TO fa_gov_intel_provenance_edge DO INSTEAD NOTHING;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_intel_provenance_edge'
          AND rulename  = 'fa_gov_intel_provenance_edge_no_delete'
    ) THEN
        CREATE RULE fa_gov_intel_provenance_edge_no_delete
            AS ON DELETE TO fa_gov_intel_provenance_edge DO INSTEAD NOTHING;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_replay_snapshot
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_replay_snapshot (
    id              VARCHAR(64)  PRIMARY KEY,
    tenant_id       VARCHAR(255) NOT NULL,
    policy_version  VARCHAR(32)  NOT NULL,
    time_window     TEXT,
    snapshot_data   TEXT,
    result          TEXT,
    replay_label    VARCHAR(32)  NOT NULL DEFAULT 'REPLAY',
    created_at      VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_replay_snapshot_tenant
    ON fa_gov_intel_replay_snapshot (tenant_id);

ALTER TABLE fa_gov_intel_replay_snapshot ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_replay_snapshot'
          AND policyname = 'fa_gov_intel_replay_snapshot_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_replay_snapshot_tenant_isolation
            ON fa_gov_intel_replay_snapshot
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_evidence_matrix
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_evidence_matrix (
    id                VARCHAR(64)  PRIMARY KEY,
    tenant_id         VARCHAR(255) NOT NULL,
    recommendation_id VARCHAR(255) NOT NULL,
    matrix_data       TEXT,
    coverage          REAL         NOT NULL DEFAULT 0.0,
    created_at        VARCHAR(64)  NOT NULL,
    updated_at        VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_evidence_matrix_tenant
    ON fa_gov_intel_evidence_matrix (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_evidence_matrix_tenant_rec
    ON fa_gov_intel_evidence_matrix (tenant_id, recommendation_id);

ALTER TABLE fa_gov_intel_evidence_matrix ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_evidence_matrix'
          AND policyname = 'fa_gov_intel_evidence_matrix_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_evidence_matrix_tenant_isolation
            ON fa_gov_intel_evidence_matrix
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_quality_score (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_quality_score (
    id          VARCHAR(64)  PRIMARY KEY,
    tenant_id   VARCHAR(255) NOT NULL,
    entity_id   VARCHAR(255) NOT NULL,
    entity_type VARCHAR(64)  NOT NULL,
    score       REAL         NOT NULL,
    grade       VARCHAR(32)  NOT NULL,
    inputs      TEXT,
    computed_at VARCHAR(64)  NOT NULL,
    created_at  VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_quality_score_tenant
    ON fa_gov_intel_quality_score (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_quality_score_tenant_entity
    ON fa_gov_intel_quality_score (tenant_id, entity_id, created_at);

ALTER TABLE fa_gov_intel_quality_score ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_quality_score'
          AND policyname = 'fa_gov_intel_quality_score_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_quality_score_tenant_isolation
            ON fa_gov_intel_quality_score
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_intel_quality_score'
          AND rulename  = 'fa_gov_intel_quality_score_no_update'
    ) THEN
        CREATE RULE fa_gov_intel_quality_score_no_update
            AS ON UPDATE TO fa_gov_intel_quality_score DO INSTEAD NOTHING;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_intel_quality_score'
          AND rulename  = 'fa_gov_intel_quality_score_no_delete'
    ) THEN
        CREATE RULE fa_gov_intel_quality_score_no_delete
            AS ON DELETE TO fa_gov_intel_quality_score DO INSTEAD NOTHING;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_simulation_comparison
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_simulation_comparison (
    id              VARCHAR(64)  PRIMARY KEY,
    tenant_id       VARCHAR(255) NOT NULL,
    baseline_id     VARCHAR(255) NOT NULL,
    proposed_id     VARCHAR(255) NOT NULL,
    comparison_data TEXT,
    created_at      VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_sim_comparison_tenant
    ON fa_gov_intel_simulation_comparison (tenant_id);

ALTER TABLE fa_gov_intel_simulation_comparison ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_simulation_comparison'
          AND policyname = 'fa_gov_intel_simulation_comparison_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_simulation_comparison_tenant_isolation
            ON fa_gov_intel_simulation_comparison
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_timeline_diff
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_timeline_diff (
    id         VARCHAR(64)  PRIMARY KEY,
    tenant_id  VARCHAR(255) NOT NULL,
    time_window VARCHAR(64)  NOT NULL,
    diff_data   TEXT,
    created_at  VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_timeline_diff_tenant
    ON fa_gov_intel_timeline_diff (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_timeline_diff_tenant_window
    ON fa_gov_intel_timeline_diff (tenant_id, time_window);

ALTER TABLE fa_gov_intel_timeline_diff ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_timeline_diff'
          AND policyname = 'fa_gov_intel_timeline_diff_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_timeline_diff_tenant_isolation
            ON fa_gov_intel_timeline_diff
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_counterfactual
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_counterfactual (
    id            VARCHAR(64)  PRIMARY KEY,
    tenant_id     VARCHAR(255) NOT NULL,
    scenario      VARCHAR(64)  NOT NULL,
    baseline_data TEXT,
    parameters    TEXT,
    result        TEXT,
    created_at    VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_counterfactual_tenant
    ON fa_gov_intel_counterfactual (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_counterfactual_tenant_scenario
    ON fa_gov_intel_counterfactual (tenant_id, scenario);

ALTER TABLE fa_gov_intel_counterfactual ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_counterfactual'
          AND policyname = 'fa_gov_intel_counterfactual_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_counterfactual_tenant_isolation
            ON fa_gov_intel_counterfactual
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_export_history (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_export_history (
    id             VARCHAR(64)  PRIMARY KEY,
    tenant_id      VARCHAR(255) NOT NULL,
    package_id     VARCHAR(255) NOT NULL,
    export_format  VARCHAR(32)  NOT NULL,
    contents_hash  VARCHAR(64)  NOT NULL,
    created_at     VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_export_history_tenant
    ON fa_gov_intel_export_history (tenant_id);

ALTER TABLE fa_gov_intel_export_history ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_export_history'
          AND policyname = 'fa_gov_intel_export_history_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_export_history_tenant_isolation
            ON fa_gov_intel_export_history
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_intel_export_history'
          AND rulename  = 'fa_gov_intel_export_history_no_update'
    ) THEN
        CREATE RULE fa_gov_intel_export_history_no_update
            AS ON UPDATE TO fa_gov_intel_export_history DO INSTEAD NOTHING;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_intel_export_history'
          AND rulename  = 'fa_gov_intel_export_history_no_delete'
    ) THEN
        CREATE RULE fa_gov_intel_export_history_no_delete
            AS ON DELETE TO fa_gov_intel_export_history DO INSTEAD NOTHING;
    END IF;
END $$;
