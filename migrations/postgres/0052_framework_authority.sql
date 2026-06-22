-- 0052_framework_authority.sql
-- PR 14.6.3 / 14.6.4 — Framework Authority & Control Framework Mapping Foundation.

CREATE TABLE IF NOT EXISTS fa_frameworks (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT,
    scope_type      TEXT NOT NULL,
    framework_key   TEXT NOT NULL,
    name            TEXT NOT NULL,
    version         TEXT NOT NULL,
    category        TEXT NOT NULL,
    publisher       TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'DRAFT',
    effective_date  DATE,
    retired_date    DATE,
    schema_version  INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_fa_framework_scope CHECK (scope_type IN ('SYSTEM','TENANT')),
    CONSTRAINT chk_fa_framework_status CHECK (status IN ('DRAFT','ACTIVE','RETIRED')),
    CONSTRAINT chk_fa_framework_scope_tenant CHECK (
        (scope_type = 'SYSTEM' AND tenant_id IS NULL)
        OR (scope_type = 'TENANT' AND tenant_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_framework_identity
    ON fa_frameworks (scope_type, tenant_id, framework_key, version);
CREATE INDEX IF NOT EXISTS ix_fa_frameworks_tenant_status
    ON fa_frameworks (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_fa_frameworks_scope_key
    ON fa_frameworks (scope_type, framework_key);

CREATE TABLE IF NOT EXISTS fa_framework_controls (
    id                       TEXT PRIMARY KEY,
    framework_id             TEXT NOT NULL REFERENCES fa_frameworks(id) ON DELETE CASCADE,
    tenant_id                TEXT,
    scope_type               TEXT NOT NULL,
    control_ref              TEXT NOT NULL,
    title                    TEXT NOT NULL,
    description              TEXT NOT NULL DEFAULT '',
    domain                   TEXT NOT NULL DEFAULT '',
    family                   TEXT NOT NULL DEFAULT '',
    clause                   TEXT NOT NULL DEFAULT '',
    objective                TEXT NOT NULL DEFAULT '',
    implementation_guidance  TEXT NOT NULL DEFAULT '',
    status                   TEXT NOT NULL DEFAULT 'DRAFT',
    schema_version           INTEGER NOT NULL DEFAULT 1,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_fa_framework_control_scope CHECK (scope_type IN ('SYSTEM','TENANT')),
    CONSTRAINT chk_fa_framework_control_status CHECK (
        status IN ('DRAFT','ACTIVE','DEPRECATED','RETIRED')
    ),
    CONSTRAINT chk_fa_framework_control_scope_tenant CHECK (
        (scope_type = 'SYSTEM' AND tenant_id IS NULL)
        OR (scope_type = 'TENANT' AND tenant_id IS NOT NULL)
    ),
    CONSTRAINT uq_fa_framework_controls_ref UNIQUE (framework_id, control_ref)
);

CREATE INDEX IF NOT EXISTS ix_fa_framework_controls_framework
    ON fa_framework_controls (framework_id, status);
CREATE INDEX IF NOT EXISTS ix_fa_framework_controls_tenant_scope
    ON fa_framework_controls (tenant_id, scope_type, control_ref);

CREATE TABLE IF NOT EXISTS control_framework_mappings (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL,
    control_id           TEXT NOT NULL,
    framework_id         TEXT NOT NULL REFERENCES fa_frameworks(id) ON DELETE CASCADE,
    framework_control_id TEXT NOT NULL REFERENCES fa_framework_controls(id) ON DELETE CASCADE,
    mapping_type         TEXT NOT NULL,
    coverage_level       TEXT NOT NULL,
    confidence           INTEGER NOT NULL DEFAULT 0,
    rationale            TEXT NOT NULL DEFAULT '',
    mapped_by            TEXT NOT NULL,
    mapped_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status               TEXT NOT NULL DEFAULT 'DRAFT',
    schema_version       INTEGER NOT NULL DEFAULT 1,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_control_framework_mapping_type CHECK (
        mapping_type IN ('FULL','PARTIAL','SUPPORTING','COMPENSATING','RELATED','NOT_APPLICABLE')
    ),
    CONSTRAINT chk_control_framework_coverage_level CHECK (
        coverage_level IN ('NONE','LOW','MEDIUM','HIGH','COMPLETE')
    ),
    CONSTRAINT chk_control_framework_mapping_status CHECK (
        status IN ('DRAFT','ACTIVE','SUPERSEDED','REJECTED','RETIRED')
    ),
    CONSTRAINT chk_control_framework_confidence CHECK (
        confidence >= 0 AND confidence <= 100
    )
);

CREATE INDEX IF NOT EXISTS ix_cfm_tenant_control
    ON control_framework_mappings (tenant_id, control_id);
CREATE INDEX IF NOT EXISTS ix_cfm_tenant_framework
    ON control_framework_mappings (tenant_id, framework_id);
CREATE INDEX IF NOT EXISTS ix_cfm_framework_control_status
    ON control_framework_mappings (framework_control_id, status);

CREATE TABLE IF NOT EXISTS control_framework_mapping_audits (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    mapping_id     TEXT NOT NULL REFERENCES control_framework_mappings(id) ON DELETE CASCADE,
    event_type     TEXT NOT NULL,
    actor          TEXT NOT NULL,
    event_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    old_state      JSONB NOT NULL DEFAULT '{}'::jsonb,
    new_state      JSONB NOT NULL DEFAULT '{}'::jsonb,
    reason         TEXT NOT NULL DEFAULT '',
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_control_framework_mapping_audit_event_type CHECK (
        event_type IN ('CREATED','UPDATED','ACTIVATED','SUPERSEDED','REJECTED','RETIRED')
    )
);

CREATE INDEX IF NOT EXISTS ix_cfm_audit_tenant_mapping
    ON control_framework_mapping_audits (tenant_id, mapping_id, event_at);

ALTER TABLE fa_frameworks ENABLE ROW LEVEL SECURITY;
ALTER TABLE fa_frameworks FORCE ROW LEVEL SECURITY;
ALTER TABLE fa_framework_controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE fa_framework_controls FORCE ROW LEVEL SECURITY;
ALTER TABLE control_framework_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_framework_mappings FORCE ROW LEVEL SECURITY;
ALTER TABLE control_framework_mapping_audits ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_framework_mapping_audits FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'fa_frameworks'
          AND policyname = 'fa_frameworks_select_visibility'
    ) THEN
        CREATE POLICY fa_frameworks_select_visibility
            ON fa_frameworks
            FOR SELECT
            USING (
                (scope_type = 'SYSTEM' AND tenant_id IS NULL)
                OR (
                    scope_type = 'TENANT'
                    AND tenant_id IS NOT NULL
                    AND current_setting('app.tenant_id', true) IS NOT NULL
                    AND tenant_id = current_setting('app.tenant_id', true)
                )
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'fa_frameworks'
          AND policyname = 'fa_frameworks_tenant_write'
    ) THEN
        CREATE POLICY fa_frameworks_tenant_write
            ON fa_frameworks
            USING (
                tenant_id IS NOT NULL
                AND scope_type = 'TENANT'
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                tenant_id IS NOT NULL
                AND scope_type = 'TENANT'
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'fa_frameworks'
          AND policyname = 'fa_frameworks_system_write'
    ) THEN
        CREATE POLICY fa_frameworks_system_write
            ON fa_frameworks
            USING (
                scope_type = 'SYSTEM'
                AND tenant_id IS NULL
                AND current_setting('app.allow_system_write', true) = 'true'
            )
            WITH CHECK (
                scope_type = 'SYSTEM'
                AND tenant_id IS NULL
                AND current_setting('app.allow_system_write', true) = 'true'
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'fa_framework_controls'
          AND policyname = 'fa_framework_controls_select_visibility'
    ) THEN
        CREATE POLICY fa_framework_controls_select_visibility
            ON fa_framework_controls
            FOR SELECT
            USING (
                (scope_type = 'SYSTEM' AND tenant_id IS NULL)
                OR (
                    scope_type = 'TENANT'
                    AND tenant_id IS NOT NULL
                    AND current_setting('app.tenant_id', true) IS NOT NULL
                    AND tenant_id = current_setting('app.tenant_id', true)
                )
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'fa_framework_controls'
          AND policyname = 'fa_framework_controls_tenant_write'
    ) THEN
        CREATE POLICY fa_framework_controls_tenant_write
            ON fa_framework_controls
            USING (
                tenant_id IS NOT NULL
                AND scope_type = 'TENANT'
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                tenant_id IS NOT NULL
                AND scope_type = 'TENANT'
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'fa_framework_controls'
          AND policyname = 'fa_framework_controls_system_write'
    ) THEN
        CREATE POLICY fa_framework_controls_system_write
            ON fa_framework_controls
            USING (
                scope_type = 'SYSTEM'
                AND tenant_id IS NULL
                AND current_setting('app.allow_system_write', true) = 'true'
            )
            WITH CHECK (
                scope_type = 'SYSTEM'
                AND tenant_id IS NULL
                AND current_setting('app.allow_system_write', true) = 'true'
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'control_framework_mappings'
          AND policyname = 'control_framework_mappings_tenant_isolation'
    ) THEN
        CREATE POLICY control_framework_mappings_tenant_isolation
            ON control_framework_mappings
            USING (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'control_framework_mapping_audits'
          AND policyname = 'control_framework_mapping_audits_tenant_isolation'
    ) THEN
        CREATE POLICY control_framework_mapping_audits_tenant_isolation
            ON control_framework_mapping_audits
            USING (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'control_framework_mapping_audits_append_only_update'
    ) THEN
        CREATE TRIGGER control_framework_mapping_audits_append_only_update
        BEFORE UPDATE ON control_framework_mapping_audits
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'control_framework_mapping_audits_append_only_delete'
    ) THEN
        CREATE TRIGGER control_framework_mapping_audits_append_only_delete
        BEFORE DELETE ON control_framework_mapping_audits
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;
END $$;
