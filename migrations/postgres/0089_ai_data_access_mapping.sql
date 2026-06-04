-- PR 2: AI Data Access Mapping scan support.
-- Extends durable scan-job scanner_type constraint for ai_data_access_mapping.

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
                'ai_data_access_mapping'
            ));
    END IF;
END $$;
