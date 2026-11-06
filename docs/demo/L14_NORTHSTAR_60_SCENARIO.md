# L14 Northstar Demo Scenario — Northstar Regional Services, Inc.

**Scenario ID:** northstar-60
**Expected Score Range:** 55–65% (not exactly 60%)
**Status:** SPECIFICATION — no actual data seeded; all details are synthetic
**Last Updated:** 2026-11-06

---

## 1. Organization Profile (Synthetic — Not Real)

| Field | Value |
|-------|-------|
| Organization name | Northstar Regional Services, Inc. |
| Industry | Healthcare / Regional Healthcare Operator |
| Employee count | 201–500 |
| Revenue range | $25M–$100M ARR |
| Profile type | regulated |
| Handles PHI | Yes |
| Handles CUI | No |
| DoD contractor | No |
| FedRAMP required | No |
| Assessment type | ai_governance |
| Geographic footprint | 3-state US regional (fictional) |

**Synthetic marker:** All client names, domains, contact details, scan results, and policy documents in this scenario are entirely fabricated for demonstration purposes. No real organization data is used.

---

## 2. Assessment Scope

The engagement covers all seven domains assessed in the AI governance framework:

| Domain | Weight | Expected Score Range | Rationale |
|--------|--------|---------------------|-----------|
| data_governance | 20% | 45–55% | Partial data classification; PHI handling policy is informal |
| security_posture | 18% | 60–70% | Good perimeter controls; AD hygiene issues |
| ai_maturity | 18% | 35–50% | Early AI adoption; no formal AI policy |
| ai_trustworthiness | 15% | 25–45% | No AI audit log; shadow AI tool use detected |
| infra_readiness | 12% | 65–75% | Reasonably modern infrastructure |
| compliance_awareness | 12% | 55–65% | HIPAA awareness high; AI regulation awareness low |
| automation_potential | 5% | 70–80% | Good workflow tooling |

Expected overall: approximately 50–62% (risk_band: high → medium boundary)

---

## 3. Domain Detail: Data Governance

**Control conditions:**
- Data classification policy exists in draft but not formally approved
- PHI handling procedure documented for clinical applications, not for AI pipelines
- No data lineage tracking for AI training data
- Access control reviews occur annually (not quarterly)

**Evidence artifacts to collect:**
- Document analysis: "Data Classification Policy v0.3 (Draft)" — classification: data_governance_policy, freshness: 90 days
- Document analysis: "PHI Handling Procedure for EHR" — classification: privacy_policy, freshness: 365 days
- Scan result: Active Directory user account inventory (via Microsoft Graph)
- Field observation: Interview with Data Governance Lead confirming draft status

**Expected findings:**
- MEDIUM: "AI Pipeline Data Classification Gap" — no classification applied to AI training datasets
- LOW: "PHI Handling Procedure Lacks AI Context" — existing procedure does not address AI model training or inference scenarios

---

## 4. Domain Detail: Security Posture

**Control conditions:**
- MFA enforced for clinical applications; not enforced for all corporate M365 applications
- Privileged access management: PAM solution deployed for clinical systems, manual process for IT
- Vulnerability management: monthly scanning, 2-week SLA for critical patches
- Endpoint management: MDM deployed for ~85% of endpoints

**Evidence artifacts to collect:**
- Scan result: Microsoft Graph user/group/MFA status report
- Scan result: Endpoint inventory scan showing MDM enrollment status
- Document analysis: "Vulnerability Management Policy 2025" — freshness: 180 days
- Field observation: Interview with CISO/IT Director on PAM coverage

**Expected findings:**
- HIGH: "Incomplete MFA Enforcement" — 23% of M365 accounts lack MFA
- MEDIUM: "Privileged Access Management Gap for Corporate IT" — PAM coverage stops at clinical boundary

---

## 5. Domain Detail: AI Maturity

**Control conditions:**
- No formal AI governance policy in place
- Three AI tools deployed in clinical workflows (EHR AI assistant, clinical decision support, scheduling optimizer)
- Two AI tools deployed in corporate workflows (HR chatbot, finance forecasting)
- AI tool approval process: informal, through IT ticket system
- No AI risk assessment process

**Evidence artifacts to collect:**
- Document analysis: Search for AI governance policy — ABSENT (finding: gap)
- Scan result: OAuth inventory scan (discover authorized AI app integrations)
- Scan result: AI tool discovery scan (shadow AI detection)
- Field observation: Interview with CIO on AI adoption roadmap

**Expected findings:**
- HIGH: "No Formal AI Governance Policy" — no approved AI policy; informal deployment
- MEDIUM: "AI Risk Assessment Process Absent" — no mechanism to assess AI tools before deployment
- LOW: "Shadow AI Usage Detected" — 4 unapproved AI integrations found in OAuth scan

---

## 6. Domain Detail: AI Trustworthiness

**Control conditions:**
- Clinical AI tools: audit logging provided by vendor; not retained by Northstar
- Corporate AI tools: no audit logging
- AI explainability: clinical decision support tool provides explanations; others do not
- Bias and fairness: not assessed for any deployed AI tool
- Human oversight: clinical AI tools have clinical override; corporate tools operate autonomously

**Evidence artifacts to collect:**
- Document analysis: "AI Tool Vendor Contracts" — checking for audit log provisions
- Scan result: AI vendor governance data (audit log retention terms)
- Field observation: Interview with clinical informatics team on audit log access

**Expected findings:**
- CRITICAL: "AI Audit Logs Not Retained by Organization" — vendor-held logs only; Northstar cannot produce audit trails for regulatory inquiries
- HIGH: "Bias and Fairness Assessment Missing" — no process for evaluating AI fairness in clinical decisions
- MEDIUM: "Corporate AI Tools Operate Without Human Oversight"

---

## 7. Domain Detail: Infrastructure Readiness

**Control conditions:**
- Cloud: Azure primary, some AWS workloads
- Identity: Azure AD (Entra ID) as primary identity provider
- Network: segmented clinical vs. corporate networks
- Backup: daily backups of clinical systems; RTO 4 hours tested annually

**Evidence artifacts to collect:**
- Scan result: Microsoft Graph tenant health report
- Scan result: DNS/email security scan (SPF, DKIM, DMARC)
- Document analysis: "Disaster Recovery Plan 2025"

**Expected findings:**
- LOW: "DMARC Not Enforced" — DMARC policy in monitoring mode, not reject/quarantine

---

## 8. Domain Detail: Compliance Awareness

**Control conditions:**
- HIPAA compliance: formal program, annual training, BAA process in place
- SOC 2: Type I completed 2024; Type II in progress
- AI-specific regulation: minimal awareness (no NIST AI RMF mapping, no EU AI Act assessment)
- Incident response: documented and tested for data breaches; not for AI incidents

**Evidence artifacts to collect:**
- Document analysis: "HIPAA Privacy Program Overview"
- Document analysis: "SOC 2 Type I Report" (most recent)
- Field observation: Interview with Compliance Officer on AI regulation awareness

**Expected findings:**
- MEDIUM: "AI Incident Response Process Absent" — IR plan does not address AI-specific failure modes
- LOW: "EU AI Act Assessment Not Performed" — no classification of AI tools against EU AI Act risk categories

---

## 9. Domain Detail: Automation Potential

**Control conditions:**
- IT service management: ServiceNow deployed
- HR workflows: partially automated via Workday
- Finance: ERP system with automation capabilities underutilized
- API availability: M365 and Azure APIs accessible for future integrations

**Evidence artifacts to collect:**
- Document analysis: "IT Automation Roadmap 2026"
- Field observation: Interview with IT Director on automation plans

**Expected findings:**
- INFO: "Automation Infrastructure in Place — Recommend AI Integration Assessment" — not adverse, but opportunity noted

---

## 10. Expected Score Summary

| Domain | Expected Score |
|--------|---------------|
| data_governance | 48 |
| security_posture | 65 |
| ai_maturity | 42 |
| ai_trustworthiness | 30 |
| infra_readiness | 68 |
| compliance_awareness | 60 |
| automation_potential | 75 |
| **Overall (weighted)** | **~57** |

**Risk band:** high (50–74 range)

---

## 11. Expected Finding Severity Distribution

| Severity | Count | Domains |
|----------|-------|---------|
| CRITICAL | 1 | ai_trustworthiness |
| HIGH | 3 | ai_trustworthiness, security_posture, ai_maturity |
| MEDIUM | 5 | data_governance (x2), security_posture, ai_maturity, compliance_awareness |
| LOW | 5 | data_governance, security_posture, ai_maturity, infra_readiness, compliance_awareness |
| INFO | 1 | automation_potential |
| **Total** | **15** | |

---

## 12. Evidence Artifact Types (Not Fake Data)

The following artifact TYPES should be collected, not specific fake files:

1. **Microsoft Graph scan** — user/group/MFA/app inventory
2. **Endpoint inventory scan** — MDM enrollment status
3. **OAuth inventory scan** — authorized third-party app integrations
4. **AI tool discovery scan** — shadow AI detection
5. **DNS/Email security scan** — SPF/DKIM/DMARC/MX
6. **Document analysis (policy)** — Data classification policy
7. **Document analysis (policy)** — PHI handling procedure
8. **Document analysis (compliance)** — HIPAA program overview
9. **Document analysis (compliance)** — SOC 2 Type I report
10. **Document analysis (DR)** — Disaster recovery plan
11. **Field observation (interview)** — CIO: AI adoption roadmap
12. **Field observation (interview)** — CISO: PAM and MFA coverage
13. **Field observation (interview)** — Compliance Officer: AI regulation
14. **Field observation (interview)** — Clinical Informatics: AI audit logs
15. **Artifact upload (audio)** — Interview recordings (optional, for chain of custody)

---

## 13. Seed Script Status

A seed script (`tools/demo/seed_field_assessment.py`) was NOT created in this audit.

**Reason:** The platform supports creating this scenario through canonical API routes, but implementing the seed script requires:

1. The seed script must call API routes in order (create engagement → ingest scans → create observations → generate findings). This requires a running API server, not direct DB access.
2. Synthetic scan payloads for each of the 5 scan types must be constructed to match the expected schema for each `ScanSourceType`. These are non-trivial to construct correctly without reference to the actual normalizer implementations.
3. The seed script must refuse to run outside synthetic/test environments — this requires environment detection logic.

**What is needed to implement it:**
- A `FROSTGATE_SYNTHETIC_DEMO=true` environment variable guard
- Synthetic scan payload templates for microsoft_graph, endpoint_inventory, oauth_inventory, ai_tool_discovery, dns_email source types
- An HTTP client targeting the running API server (not direct DB writes)
- Idempotency via engagement client_name uniqueness check before creation

This is recommended as the next P2 task after the operator runbook.
