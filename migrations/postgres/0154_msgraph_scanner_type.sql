-- Migration 0154: restore microsoft_graph to fa_scan_jobs scanner_type constraint.
--
-- Migration 0092 (ai_vendor_governance) recreated the constraint omitting
-- 'microsoft_graph', which had been added by 0088–0090.  This reinstates it
-- so device-code MS Graph scans can create durable job records.

ALTER TABLE fa_scan_jobs DROP CONSTRAINT IF EXISTS fa_scan_jobs_scanner_type_check;
ALTER TABLE fa_scan_jobs
    ADD CONSTRAINT fa_scan_jobs_scanner_type_check
    CHECK (scanner_type IN (
        'msgraph', 'microsoft_graph',
        'network_scan', 'dns_email', 'web_headers',
        'oauth_inventory', 'oauth_risk', 'endpoint_inventory',
        'entra_governance', 'sharepoint',
        'ai_tool_discovery', 'ai_data_access_mapping',
        'external_ai_risk_register', 'ai_vendor_governance'
    ));
