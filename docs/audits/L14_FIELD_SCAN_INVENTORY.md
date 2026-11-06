# L14 Field Scan Inventory

**Audit ID:** L14-FIELD-SCAN-DEEP-AUDIT-001
**Date:** 2026-11-06

Complete scanner/connector inventory. 14 connectors have runner implementations. 4 are registered only.

---

## Implemented Connectors

### CONN-01: Microsoft Graph (Full Assessment)

| Field | Value |
|-------|-------|
| Scanner ID | microsoft_graph |
| Purpose | Full M365 tenant posture assessment |
| Source file | services/connectors/msgraph/runner.py |
| Entry point | `run_scan(tenant_id, engagement_id, receipt)` |
| Target | Azure AD / Microsoft 365 tenant (OAuth2 token) |
| Technique | Graph API read-only: users, groups, MFA, conditional access, OAuth consent, enterprise apps, privileged roles, guest accounts, DLP signals, AI signals |
| Credentials | Bearer token (OAuth2 / service account); acknowledgment receipt required before scan |
| Evidence output | ScanResult with signed manifest; analyzer outputs cover 8 domains |
| Persistence | FaScanResult with `source_type=microsoft_graph`; msgraph-specific report and manifest tables |
| Safety controls | Acknowledgment receipt gate; tenant lock (one scan at a time per tenant); SCAN_TOTAL_TIMEOUT_SECONDS enforced; authorized scopes allowlist enforced |
| Tests | tests/connectors/msgraph/ (85 tests); tests/test_field_assessment_msgraph_bridge.py |
| Maturity | IMPLEMENTED_AND_TESTED |
| Gaps | Detection accuracy not ground-truth tested; sign-in log analysis limited to recent 50 events |
| Risk | Low — read-only Graph API; no write permissions |

### CONN-02: Entra ID Governance

| Field | Value |
|-------|-------|
| Scanner ID | entra_governance |
| Purpose | PIM role assignments, access reviews, identity protection, conditional access |
| Source file | services/connectors/entra_governance/runner.py |
| Entry point | `run_entra_governance(access_token, tenant_id, engagement_id)` |
| Target | Azure AD tenant (OAuth2 token) |
| Technique | Graph API: roleAssignments, roleEligibilitySchedules, accessReviews/definitions, riskyUsers (P2-gated), conditionalAccess/policies |
| Credentials | Bearer token; requires RoleManagement.Read.Directory, IdentityRiskyUser.Read.All (P2), Policy.Read.All |
| Evidence output | Dict with role_assignments, eligibility_schedules, access_reviews, risky_users, ca_policies, findings; findings cover 8 types |
| Persistence | FaScanResult with `source_type=entra_governance` |
| Safety controls | 403 on P2-gated endpoints returns empty list (graceful degradation); pagination capped at 20 pages |
| Tests | tests/connectors/msgraph/ includes CA analyzer tests; tests/test_field_assessment.py |
| Maturity | IMPLEMENTED_AND_TESTED |
| Gaps | Stale eligible assignment threshold (90 days) is not configurable per engagement; no ground-truth accuracy tests |
| Risk | Low — read-only |

### CONN-03: Endpoint Inventory

| Field | Value |
|-------|-------|
| Scanner ID | endpoint_inventory |
| Purpose | Azure AD device inventory, Intune compliance, encryption status |
| Source file | services/connectors/endpoint_inventory/runner.py |
| Entry point | `run_endpoint_inventory(access_token, tenant_id, engagement_id)` |
| Target | Azure AD / Intune tenant |
| Technique | Graph API: /devices (Azure AD registration), /deviceManagement/managedDevices (Intune, 403-graceful) |
| Credentials | Bearer token; requires Device.Read.All, DeviceManagementManagedDevices.Read.All (optional) |
| Evidence output | Dict with endpoints list, findings (non-compliant, unmanaged, stale, unencrypted), summary |
| Persistence | FaScanResult with `source_type=endpoint_inventory` |
| Safety controls | Pagination capped at 20 pages; 403 on Intune gracefully skipped |
| Tests | tests/test_field_assessment.py; tests/test_scan_import.py |
| Maturity | IMPLEMENTED_AND_TESTED |
| Gaps | No detection of unencrypted devices when Intune data unavailable; stale threshold fixed at 90 days |
| Risk | Low — read-only |

### CONN-04: OAuth Inventory

| Field | Value |
|-------|-------|
| Scanner ID | oauth_inventory |
| Purpose | Enumerate OAuth app registrations and consent grants |
| Source file | services/connectors/oauth_inventory/runner.py |
| Entry point | `run_oauth_inventory(access_token, tenant_id, engagement_id)` |
| Target | Azure AD tenant |
| Technique | Graph API: /applications, /servicePrincipals, /oauth2PermissionGrants |
| Credentials | Bearer token; requires Application.Read.All |
| Evidence output | Dict with apps list, grants_summary, findings (admin_consented, unverified_publishers, broad_scope) |
| Persistence | FaScanResult with `source_type=oauth_inventory` |
| Safety controls | Pagination capped at 20 pages; broad_scope threshold = 10 scopes |
| Tests | tests/test_field_assessment.py; tests/connectors/msgraph/test_analyzers/test_oauth_consent.py |
| Maturity | IMPLEMENTED_AND_TESTED |
| Gaps | No detection of revoked grants that were re-added; no historical grant analysis |
| Risk | Low — read-only |

### CONN-05: OAuth Risk Deep Scan

| Field | Value |
|-------|-------|
| Scanner ID | oauth_risk |
| Purpose | Classify OAuth grants by scope sensitivity, consent type, publisher trust, AI tool patterns |
| Source file | services/connectors/oauth_risk/runner.py |
| Entry point | `run_oauth_risk(access_token, tenant_id, engagement_id)` |
| Target | Azure AD tenant |
| Technique | Graph API: /oauth2PermissionGrants, /servicePrincipals with detailed scope analysis |
| Credentials | Bearer token; requires Application.Read.All |
| Evidence output | Dict with grants list classified as critical/high/medium/low risk; findings |
| Persistence | FaScanResult with `source_type=oauth_risk` |
| Safety controls | Scope classification uses explicit allowlists for critical, high, and high-AI scopes |
| Tests | tests/connectors/msgraph/test_analyzers/test_oauth_consent.py |
| Maturity | IMPLEMENTED_AND_TESTED |
| Gaps | No detection of token-level abuse (requires audit log); classification thresholds are static |
| Risk | Low — read-only |

### CONN-06: AI Tool Discovery

| Field | Value |
|-------|-------|
| Scanner ID | ai_tool_discovery |
| Purpose | Detect AI-connected applications in M365 tenant via vendor registry matching |
| Source file | services/connectors/ai_tool_discovery/runner.py |
| Entry point | `run_ai_tool_discovery(access_token, tenant_id, engagement_id)` |
| Target | Azure AD tenant |
| Technique | Graph API: applications, servicePrincipals, oauth2PermissionGrants, appRoleAssignments, signIns (50), directoryAudits (50); vendor registry pattern matching |
| Credentials | Bearer token; requires Application.Read.All, AuditLog.Read.All |
| Evidence output | Dict with tools list (confirmed/suspected AI tools), findings (sensitive_permissions, unverified_publishers), summary with per-source collection status |
| Persistence | FaScanResult with `source_type=ai_tool_discovery` |
| Safety controls | 403/404 returns skipped status per endpoint; pagination capped at 20 pages; sign-in and audit log samples capped at 50 each |
| Tests | tests/test_ai_tool_discovery.py (significant coverage) |
| Maturity | IMPLEMENTED_AND_TESTED |
| Gaps | Vendor registry completeness not audited; shadow AI detection limited to M365-registered apps (no browser-based shadow AI) |
| Risk | Low — read-only |

### CONN-07: AI Data Access Mapping

| Field | Value |
|-------|-------|
| Scanner ID | ai_data_access_mapping |
| Purpose | Map AI tool OAuth permissions to data categories and sensitivity levels |
| Source file | services/connectors/ai_data_access_mapping/mapper.py |
| Entry point | `run_ai_data_access_mapping(pr1_tools, tenant_id, engagement_id)` |
| Target | Derived from AI tool discovery output (no live API calls) |
| Technique | Deterministic permission-to-resource-to-category mapping; 70+ permission mappings; exposure scope derivation; governance readiness scoring |
| Credentials | None (derives from PR1 token-collected data) |
| Evidence output | Dict with mappings list; each mapping includes data categories, sensitivity, exposure_scope, governance_readiness |
| Persistence | FaScanResult with `source_type=ai_data_access_mapping` |
| Safety controls | No network I/O; deterministic only |
| Tests | tests/test_field_assessment.py |
| Maturity | IMPLEMENTED_AND_TESTED |
| Gaps | No real-time data flow analysis; mapping is permission-based not content-based |
| Risk | Zero — no network I/O |

### CONN-08: External AI Risk Register

| Field | Value |
|-------|-------|
| Scanner ID | external_ai_risk_register |
| Purpose | Deterministic risk scoring for each discovered AI tool |
| Source file | services/connectors/external_ai_risk_register/risk_engine.py |
| Entry point | `generate_risk_records(pr1_tools, pr2_mappings, tenant_id, engagement_id)` |
| Target | Derived from PR1 + PR2 outputs (no live API calls) |
| Technique | Additive scoring: unverified publisher (+25), admin consent (+15/+30), sensitivity (+10/+20/+30), unknown owner (+15), shadow AI (+10), overprivileged (+10); bands: 0-24=low, 25-49=moderate, 50-74=high, 75+=critical |
| Credentials | None |
| Evidence output | Dict with risk_records; each with numeric score, risk_categories, regulatory_flags (GDPR, HIPAA, PCI_DSS, SOX, etc.) |
| Persistence | FaScanResult with `source_type=external_ai_risk_register` |
| Safety controls | No network I/O; deterministic |
| Tests | tests/test_field_assessment.py |
| Maturity | IMPLEMENTED_AND_TESTED |
| Gaps | Regulatory flags are approximations based on permission signals, not authoritative legal determinations |
| Risk | Zero — no network I/O |

### CONN-09: AI Vendor Governance Engine

| Field | Value |
|-------|-------|
| Scanner ID | ai_vendor_governance |
| Purpose | Generate structured governance records and 16-type finding set for each AI tool |
| Source file | services/connectors/ai_vendor_governance/governance_engine.py |
| Entry point | `generate_governance_records(risk_records, tenant_id, engagement_id, ...)` |
| Target | Derived from PR1+PR2+PR3 outputs |
| Technique | Deterministic governance readiness computation; 16 finding types mapped to NIST AI RMF controls; workflow state machine (discovered → needs_owner → needs_review → approved/rejected/restricted/exception_granted) |
| Credentials | None |
| Evidence output | Governance records with ownership, DPA/BAA status, security/privacy review status, SOC2/ISO27001 tracking, risk acceptance tracking; 16 finding types |
| Persistence | FaAiVendorGovernanceRecord per tool; FaScanResult with `source_type=ai_vendor_governance` |
| Safety controls | No network I/O; all outputs deterministic from input evidence |
| Tests | tests/test_field_assessment.py |
| Maturity | IMPLEMENTED_AND_TESTED |
| Gaps | Governance record fields must be populated by operator after generation; initial state is mostly unknown/not_started |
| Risk | Zero — no network I/O |

### CONN-10: Network Scan

| Field | Value |
|-------|-------|
| Scanner ID | network_scan |
| Purpose | Port scan and TLS certificate inspection for authorized external hosts |
| Source file | services/connectors/network_scan/runner.py |
| Entry point | `run_network_scan(target_hosts, engagement_id)` |
| Target | Operator-specified external IP addresses / hostnames |
| Technique | Concurrent TCP socket probing (30 workers, 2s timeout); TLS handshake inspection on port 443; 20 ports including AI model server ports (11434 Ollama, 7860 Gradio, 8888 Jupyter) |
| Credentials | None — passive probe |
| Evidence output | Dict with hosts (open_ports, TLS info), rejected_targets (SSRF-blocked), findings (unsafe_services, plain_http, invalid_tls, ai_ports_exposed), summary |
| Persistence | FaScanResult with `source_type=network_scan` |
| Safety controls | SafeTargetValidationService at BOTH API layer and runner layer; MAX_HOSTS=50; CIDR expansion capped at /28 |
| Tests | tests/test_c6_scanner_containment.py (114 tests) |
| Maturity | IMPLEMENTED_AND_TESTED |
| Gaps | No service banner grabbing; no OS fingerprinting; TLS inspection only on 443; no CVE correlation |
| Risk | Low with SSRF controls; medium without (never bypass the validator) |

### CONN-11: Web Security Headers

| Field | Value |
|-------|-------|
| Scanner ID | web_headers |
| Purpose | HTTP security header inspection for authorized external web applications |
| Source file | services/connectors/web_headers/runner.py |
| Entry point | `run(targets)` |
| Target | Operator-specified external URLs |
| Technique | HTTP HEAD request; check 9 security headers; HSTS max-age validation; CSP unsafe-inline/eval/wildcard detection; X-Frame-Options, Referrer-Policy, Permissions-Policy; redirect chain follow with re-validation |
| Credentials | None — passive |
| Evidence output | Dict with targets (headers_present, headers_missing, score 0-100, findings), all_findings, summary |
| Persistence | FaScanResult with `source_type=web_headers` |
| Safety controls | SafeTargetValidationService pre-check; every redirect Location re-validated before following; follow_redirects=False on httpx client; MAX_REDIRECT_HOPS=5 |
| Tests | tests/test_c6_scanner_containment.py (URL target tests) |
| Maturity | IMPLEMENTED_AND_TESTED |
| Gaps | Only HEAD request (not GET/POST); no JavaScript analysis; CORS policy not inspected |
| Risk | Low with SSRF controls |

### CONN-12: DNS & Email Security

| Field | Value |
|-------|-------|
| Scanner ID | dns_email |
| Purpose | SPF, DKIM, DMARC, MX, DNSSEC assessment per domain |
| Source file | services/connectors/dns_email/runner.py |
| Entry point | `run(domains, dkim_selectors)` |
| Target | Operator-specified domain names |
| Technique | dnspython queries: SPF TXT, DMARC TXT, DKIM TXT (7 default selectors), MX, DNSKEY; policy strength analysis |
| Credentials | None — passive DNS queries |
| Evidence output | Dict with domains (spf, dmarc, dkim, mx, dnssec details, findings), all_findings, summary |
| Persistence | FaScanResult with `source_type=dns_email` |
| Safety controls | No SafeTargetValidationService (DNS queries are passive; different risk model than sockets); dnspython 5-second lifetime per query |
| Tests | tests/test_field_assessment.py |
| Maturity | IMPLEMENTED_AND_TESTED |
| Gaps | DKIM selector coverage limited to 7 default selectors; no BIMI check; DNSSEC validation is presence-only (not chain validation); no zone transfer attempt |
| Risk | Very low — read-only DNS queries |

### CONN-13: SharePoint & OneDrive Data Exposure

| Field | Value |
|-------|-------|
| Scanner ID | sharepoint_onedrive |
| Purpose | External sharing, anonymous links, guest access in SharePoint/OneDrive |
| Source file | services/connectors/sharepoint/runner.py |
| Entry point | `run_sharepoint_scan(access_token, tenant_id, engagement_id)` |
| Target | M365 SharePoint/OneDrive tenant |
| Technique | Graph API: /sites, /drives, /items, permission enumeration; anonymous link detection; guest access detection |
| Credentials | Bearer token; requires Sites.Read.All |
| Evidence output | Dict with sites list (sharing analysis), findings (anonymous links, guest access), summary |
| Persistence | FaScanResult with `source_type=sharepoint_onedrive` |
| Safety controls | MAX_SITES=30, MAX_DRIVES_PER_SITE=3, MAX_ITEMS_PER_DRIVE=100, MAX_PERMISSION_CHECKS_PER_DRIVE=15; 403 gracefully skipped |
| Tests | tests/test_field_assessment.py |
| Maturity | IMPLEMENTED_AND_TESTED |
| Gaps | Scan limits may miss exposure in large tenants (>30 sites); no OneDrive personal space analysis |
| Risk | Low — read-only |

---

## Registered-Only Connectors (No Runner)

| Scanner ID | Purpose | Contract Registered | Runner | Bridge | Status |
|-----------|---------|--------------------|----|--------|--------|
| google_workspace | Google Workspace user/group/app inventory | Yes | No | No | REGISTERED_NO_RUNNER |
| aws | AWS account security posture | Yes | No | No | REGISTERED_NO_RUNNER |
| azure | Azure subscription posture | Yes | No | No | REGISTERED_NO_RUNNER |
| gcp | Google Cloud Platform posture | Yes | No | No | REGISTERED_NO_RUNNER |

Manual scan import works for all four (operator provides pre-collected JSON). Automated runner execution is not available.
