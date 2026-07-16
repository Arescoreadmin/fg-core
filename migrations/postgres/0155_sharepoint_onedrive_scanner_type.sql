-- Migration 0155: add sharepoint_onedrive to fa_scan_jobs scanner_type constraint.
--
-- Migration 0092 settled on 'sharepoint' but the code inserts 'sharepoint_onedrive'.
-- Also retains both legacy aliases (msgraph/microsoft_graph, sharepoint/sharepoint_onedrive)
-- so existing job records remain valid.

ALTER TABLE fa_scan_jobs DROP CONSTRAINT IF EXISTS fa_scan_jobs_scanner_type_check;
ALTER TABLE fa_scan_jobs
    ADD CONSTRAINT fa_scan_jobs_scanner_type_check
    CHECK (scanner_type IN (
        'msgraph', 'microsoft_graph',
        'network_scan', 'dns_email', 'web_headers',
        'oauth_inventory', 'oauth_risk', 'endpoint_inventory',
        'entra_governance',
        'sharepoint', 'sharepoint_onedrive',
        'ai_tool_discovery', 'ai_data_access_mapping',
        'external_ai_risk_register', 'ai_vendor_governance'
    ));
