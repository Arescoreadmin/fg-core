# L14 Scan Remediation Roadmap

**Audit ID:** L14-FIELD-SCAN-DEEP-AUDIT-001
**Date:** 2026-11-06

Prioritized remediation backlog in four waves. Wave 1 items must be addressed before claiming the capability is production-proven for regulated-industry clients.

---

## Wave 1: Safety, Truth, and Provenance (P0–P1)

### W1-01: Add scan_id and engagement_id to web_headers and dns_email runner outputs

| Field | Value |
|-------|-------|
| Objective | web_headers and dns_email runners should emit scan_id, engagement_id, scan_initiated_at, scan_completed_at, schema_version in their output payloads |
| Root cause | Runners were implemented before the evidence provenance standard was established by network_scan and oauth_inventory |
| Affected modules | services/connectors/web_headers/runner.py, services/connectors/dns_email/runner.py |
| Acceptance criteria | Runner output dicts contain scan_id (uuid4 hex), engagement_id (passed as parameter), scan_initiated_at, scan_completed_at, schema_version="1.0" |
| Effort | 1 day |
| Revenue/quality impact | Required for evidence defensibility claims in regulated-industry engagements |
| Priority | P1 |

### W1-02: Document DNS/Email domain validation asymmetry

| Field | Value |
|-------|-------|
| Objective | Explicitly document why dns_email does not route through SafeTargetValidationService and what the safety properties of DNS queries are |
| Root cause | The asymmetry exists for valid technical reasons (DNS queries are passive) but is undocumented |
| Affected modules | services/connectors/dns_email/runner.py (docstring), docs/audits/L14_SCAN_EXECUTION_SAFETY.md |
| Acceptance criteria | Runner module docstring explains the domain validation approach and its safety properties; L14_SCAN_EXECUTION_SAFETY.md updated |
| Effort | 0.5 days |
| Priority | P1 |

### W1-03: Implement emergency scan cancellation endpoint

| Field | Value |
|-------|-------|
| Objective | Add PATCH /engagements/{id}/scan-jobs/{job_id}/cancel so operators can abort in-flight scans |
| Root cause | No cancellation mechanism exists; reliance on job expiry only |
| Affected modules | api/field_assessment.py, api/db_models_field_assessment.py |
| Acceptance criteria | Endpoint marks job as cancelled; subsequent scan execution checks cancelled flag and aborts; audit event written |
| Effort | 2 days |
| Priority | P1 |

---

## Wave 2: Coverage Depth (P1–P2)

### W2-01: Ground-truth fixture tests for detection accuracy

| Field | Value |
|-------|-------|
| Objective | Create known-answer fixture tests for network_scan, dns_email, and web_headers connectors |
| Root cause | No tests validate that specific input conditions produce specific expected findings |
| Affected modules | tests/test_network_scan_accuracy.py (new), tests/test_dns_email_accuracy.py (new), tests/test_web_headers_accuracy.py (new) |
| Acceptance criteria | Test suite provides mock inputs with known configurations and asserts expected finding types and severities; all tests pass |
| Effort | 2 days |
| Revenue/quality impact | Required to make defensible accuracy claims in contracts and marketing |
| Priority | P1 |

### W2-02: Break-glass account detection in entra_governance

| Field | Value |
|-------|-------|
| Objective | Detect Global Administrator accounts with no MFA enrollment and no recent sign-in (break-glass patterns) |
| Root cause | entra_governance reports aggregate counts; no per-account cross-reference with MFA status |
| Affected modules | services/connectors/entra_governance/runner.py |
| Acceptance criteria | New finding type: permanent_global_admin_no_mfa; cross-references role assignments with MFA status |
| Effort | 2 days |
| Priority | P2 |

### W2-03: AWS IAM scanner runner

| Field | Value |
|-------|-------|
| Objective | Implement basic AWS IAM + CloudTrail scanner runner |
| Root cause | aws ScanSourceType is registered but has no runner |
| Affected modules | services/connectors/aws/ (new), services/field_assessment/connectors/aws_bridge.py (new) |
| Acceptance criteria | Runner accepts AWS credentials (read-only), queries IAM users/roles/policies/access-keys, CloudTrail trail status; produces findings; stores to FaScanResult with source_type=aws |
| Effort | 5 days |
| Revenue/quality impact | Unlocks AWS-first clients; directly addresses coverage gap in multi-cloud assessments |
| Priority | P2 |

### W2-04: DKIM key strength validation in dns_email

| Field | Value |
|-------|-------|
| Objective | Parse DKIM TXT records to extract key type and bit length; flag 1024-bit RSA keys as medium finding |
| Root cause | dns_email runner checks DKIM presence but not key strength |
| Affected modules | services/connectors/dns_email/runner.py |
| Acceptance criteria | DKIM check parses p= field; 1024-bit RSA triggers medium finding; missing key strength triggers low finding |
| Effort | 1 day |
| Priority | P2 |

### W2-05: Service principal auth method detection (certificate vs secret)

| Field | Value |
|-------|-------|
| Objective | In oauth_inventory, detect service principals using client secrets instead of certificates |
| Root cause | Current connector does not check keyCredentials vs passwordCredentials |
| Affected modules | services/connectors/oauth_inventory/runner.py |
| Acceptance criteria | New finding type: service_principal_using_client_secret; medium severity |
| Effort | 1 day |
| Priority | P2 |

---

## Wave 3: Correlation and Reporting (P2)

### W3-01: Cross-scanner evidence graph traversal API

| Field | Value |
|-------|-------|
| Objective | Expose graph traversal queries that correlate findings across identity, AI governance, endpoint, and network scanners |
| Root cause | Graph node IDs exist in all connectors but no traversal layer is built |
| Affected modules | services/governance_graph/builder.py (extend), api/field_assessment.py (new endpoints) |
| Acceptance criteria | GET /engagements/{id}/risk-graph/nodes returns correlated risk nodes; correlation queries link AI tools to their consenting users to their device compliance status |
| Effort | 8 days |
| Priority | P2 |

### W3-02: Payload cryptographic integrity for all non-Graph scanners

| Field | Value |
|-------|-------|
| Objective | Add SHA-256 payload_hash to all FaScanResult rows; optionally sign with Vault Transit for regulated clients |
| Root cause | Only msgraph has manifest signing; all other scanners lack tamper-evidence |
| Affected modules | services/field_assessment/store.py, api/db_models_field_assessment.py (migration needed) |
| Acceptance criteria | All scan results store payload_hash; hash is verified on retrieval; optional Vault Transit signing controlled by feature flag |
| Effort | 3 days |
| Priority | P2 |

### W3-03: Longitudinal drift monitoring for AI governance

| Field | Value |
|-------|-------|
| Objective | Connect AI governance scan results to the drift engine for change detection between assessments |
| Root cause | Drift engine exists but is not connected to AI governance chain |
| Affected modules | services/connectors/drift/engine.py, services/field_assessment/connectors/ai_vendor_governance_bridge.py |
| Acceptance criteria | Drift events emitted when governance records change state; new finding type: ai_governance_drift_detected |
| Effort | 5 days |
| Priority | P2 |

---

## Wave 4: Intelligence and Competitive Moat (P3)

### W4-01: AI model server network discovery mode

| Field | Value |
|-------|-------|
| Objective | Optional pre-scan discovery of AI-serving hosts from CIDR range before full port scan |
| Root cause | network_scan only scans operator-specified hosts; shadow AI infrastructure on unknown hosts is missed |
| Affected modules | services/connectors/network_scan/runner.py |
| Acceptance criteria | discovery_mode=True scans only AI ports; returns candidate host list for operator review before full scan; all SSRF controls apply |
| Effort | 2 days |
| Priority | P3 |

### W4-02: Assessment benchmarking data layer

| Field | Value |
|-------|-------|
| Objective | Anonymized, opt-in benchmark aggregation across engagements for industry percentile positioning |
| Root cause | No cross-engagement comparison exists; each assessment is isolated |
| Affected modules | services/field_assessment/ (new aggregation service), api/field_assessment.py (new benchmark endpoint) |
| Acceptance criteria | Opt-in clients contribute anonymized score distributions; GET /benchmarks/{assessment_type}/percentiles returns percentile bands; zero raw data crosses tenant boundaries |
| Effort | 10 days |
| Priority | P3 |

### W4-03: Google Workspace scanner runner

| Field | Value |
|-------|-------|
| Objective | Implement Google Workspace scanner (Workspace Admin SDK: users, groups, apps, 2SV status) |
| Root cause | google_workspace ScanSourceType registered but no runner |
| Affected modules | services/connectors/google_workspace/ (new), services/field_assessment/connectors/google_workspace_bridge.py (new) |
| Acceptance criteria | Runner queries Google Admin SDK read-only; produces findings on 2SV coverage, unmanaged apps, guest access; stores to FaScanResult |
| Effort | 5 days |
| Priority | P3 |
