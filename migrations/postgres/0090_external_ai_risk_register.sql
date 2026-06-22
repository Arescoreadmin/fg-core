-- PR 3: External AI Risk Register.
-- Creates fa_external_ai_risk_records table and extends durable scan-job
-- scanner_type constraint to include external_ai_risk_register.

DO $$
BEGIN
    -- Create fa_external_ai_risk_records if not already present
    IF to_regclass('public.fa_external_ai_risk_records') IS NULL THEN
        CREATE TABLE fa_external_ai_risk_records (
            id                      VARCHAR(64)  PRIMARY KEY,
            tenant_id               VARCHAR(255) NOT NULL,
            engagement_id           VARCHAR(64)  NOT NULL,
            tool_id                 VARCHAR(255),
            tool_name               VARCHAR(255) NOT NULL,
            vendor                  VARCHAR(255) NOT NULL,
            business_owner          VARCHAR(255) NOT NULL DEFAULT 'Unknown',
            technical_owner         VARCHAR(255) NOT NULL DEFAULT 'Unknown',
            permissions             JSONB        NOT NULL DEFAULT '[]',
            data_access_summary     TEXT,
            sensitive_data_exposure JSONB        NOT NULL DEFAULT '[]',
            publisher_trust         VARCHAR(32)  NOT NULL DEFAULT 'unknown',
            user_count              INTEGER,
            admin_consent           BOOLEAN      NOT NULL DEFAULT FALSE,
            risk_score              VARCHAR(32)  NOT NULL,
            risk_reason             TEXT         NOT NULL,
            risk_category           VARCHAR(64)  NOT NULL,
            risk_categories         JSONB        NOT NULL DEFAULT '[]',
            recommended_action      TEXT         NOT NULL,
            review_status           VARCHAR(32)  NOT NULL DEFAULT 'unreviewed',
            evidence_refs           JSONB        NOT NULL DEFAULT '[]',
            finding_refs            JSONB        NOT NULL DEFAULT '[]',
            graph_node_id           VARCHAR(255),
            source_scan_result_id   VARCHAR(64),
            pr1_scan_result_id      VARCHAR(64),
            created_at              VARCHAR(64)  NOT NULL,
            updated_at              VARCHAR(64)  NOT NULL,
            CONSTRAINT uq_fa_ext_ai_risk_tool
                UNIQUE (engagement_id, tenant_id, tool_name)
        );

        CREATE INDEX ix_fa_ext_ai_risk_tenant_eng
            ON fa_external_ai_risk_records (tenant_id, engagement_id);

        CREATE INDEX ix_fa_ext_ai_risk_tenant_score
            ON fa_external_ai_risk_records (tenant_id, risk_score);

        CREATE INDEX ix_fa_ext_ai_risk_tenant_category
            ON fa_external_ai_risk_records (tenant_id, risk_category);

        RAISE NOTICE 'Created fa_external_ai_risk_records table';
    ELSE
        RAISE NOTICE 'fa_external_ai_risk_records already exists — skipping create';
    END IF;
END $$;

-- Extend scanner_type constraint
DO $$
BEGIN
    IF to_regclass('public.fa_scan_jobs') IS NOT NULL THEN
        ALTER TABLE fa_scan_jobs DROP CONSTRAINT IF EXISTS fa_scan_jobs_scanner_type_check;
        ALTER TABLE fa_scan_jobs
            ADD CONSTRAINT fa_scan_jobs_scanner_type_check
            CHECK (scanner_type IN (
                'network_scan',
                'web_headers',
                'dns_email',
                'oauth_inventory',
                'oauth_risk',
                'endpoint_inventory',
                'entra_governance',
                'sharepoint_onedrive',
                'msgraph',
                'microsoft_graph',
                'ai_tool_discovery',
                'ai_data_access_mapping',
                'external_ai_risk_register'
            ));
    END IF;
END $$;
