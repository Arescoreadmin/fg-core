# Data Processing Agreement

**Between:** Jason Cosat, operating as FrostGate ("Processor")  
**And:** [CLIENT_ORG] ("Controller")  
**Effective date:** [DATE]  
**Engagement ID:** [ENGAGEMENT_ID]

---

## 1. Subject Matter

FrostGate will process data obtained from [CLIENT_ORG]'s Microsoft 365 environment, public DNS records, and public web infrastructure solely for the purpose of conducting an AI Governance Field Assessment and delivering the associated report and portal access.

---

## 2. Nature and Purpose of Processing

| Purpose | Legal basis |
|---------|------------|
| Collecting identity metadata, security policy configuration, and application registrations via Microsoft Graph API | Performance of services under the engagement authorization letter |
| Generating findings, risk scores, and remediation recommendations | Legitimate interest in delivering contracted assessment services |
| Storing assessment data in the FrostGate portal for client review | Performance of services — client accesses their own data |
| Generating an AI-assisted executive summary using Anthropic Claude | Performance of services; data is not used to train Anthropic models |

---

## 3. Categories of Data Processed

| Category | Examples | Approximate volume |
|----------|----------|-------------------|
| Identity metadata | User display names, UPNs, MFA status, role assignments | Hundreds to thousands of user records |
| Security policy configuration | Conditional access policy settings, guest sharing policies | Tens of policy objects |
| Application registrations | App names, OAuth permission scopes, consent records | Tens to hundreds of app records |
| Device metadata | Device names, OS versions, compliance status | Tens to hundreds of device records |
| Public DNS records | DMARC, SPF, DKIM, MX, DNSSEC records | Tens of records |
| Public HTTP headers | Security headers on public web URLs | Tens of response objects |

No data categories of special sensitivity (health data, financial account data, criminal records, biometric data) are collected or processed.

---

## 4. Sub-Processors

FrostGate uses the following sub-processors. [CLIENT_ORG] acknowledges and accepts these sub-processors by signing this agreement.

| Sub-processor | Role | Data transferred | Location | Security certification |
|---------------|------|-----------------|----------|----------------------|
| Railway (Brex Inc.) | API compute and Postgres database hosting | All assessment data | United States | SOC 2 Type II |
| Vercel Inc. | Console and portal hosting | No raw assessment data; portal serves client-facing views | United States | SOC 2 Type II |
| Anthropic PBC | AI executive summary generation | Anonymized finding summaries and NIST control context | United States | No training on customer data (per Anthropic API terms) |
| Auth0 (Okta Inc.) | Operator authentication for the FrostGate console | Operator identity only; no client assessment data | United States | SOC 2 Type II |

---

## 5. Retention and Deletion

Assessment data is retained for **90 days** from the engagement date ([DATA_EXPIRY_DATE]).

After 90 days, all assessment data is purged from FrostGate systems, including:
- Raw scan results
- Processed findings
- NIST questionnaire responses
- Report content stored in the database

The PDF report delivered to [CLIENT_ORG] is not subject to the 90-day window. It is the client's copy to retain.

[CLIENT_ORG] may request early deletion by contacting jason@frostgate.ai. Deletion will be completed within 5 business days of the request.

---

## 6. Security Measures

FrostGate implements the following technical and organizational measures:

**Technical:**
- All data in transit encrypted via TLS 1.2+
- Database encrypted at rest (Railway managed Postgres with encryption)
- API authentication required for all non-public endpoints (API key + tenant scoping)
- Operator access authenticated via Auth0 with MFA enforced
- Evidence hash chain (SHA-256) for tamper-evident scan records
- Operator acknowledgment receipt (HMAC-SHA256) per engagement for chain of custody

**Organizational:**
- Assessment data is accessible only to the operator (Jason Cosat) and the client via their password-protected portal
- No third parties have access to assessment data except the sub-processors listed in Section 4
- The portal password is delivered via a separate secure channel from the URL

---

## 7. Data Subject Rights

To the extent that personal data (as defined under applicable law) is processed during the assessment, [CLIENT_ORG] is the data controller and FrostGate is the processor. [CLIENT_ORG] is responsible for handling data subject requests from its employees.

FrostGate will assist [CLIENT_ORG] in responding to data subject requests that require access to assessment data by providing relevant records within 5 business days of a written request.

---

## 8. Breach Notification

In the event of a confirmed personal data breach affecting assessment data, FrostGate will notify [CLIENT_ORG] within **72 hours** of becoming aware of the breach. Notification will be sent to [CLIENT_CONTACT_EMAIL] and will include: nature of the breach, categories of data affected, approximate number of individuals affected, and remediation steps taken or planned.

---

## 9. Audit Rights

[CLIENT_ORG] may request a written summary of FrostGate's security controls and sub-processor agreements once per engagement year. On-site audits may be requested with 30 days notice; FrostGate may satisfy audit requests by providing third-party audit reports (e.g., sub-processor SOC 2 reports) in lieu of on-site inspection.

---

## 10. Term and Termination

This agreement is effective from the engagement date and remains in force until all assessment data has been deleted per Section 5. Either party may terminate the agreement by providing written notice; upon termination, FrostGate will delete all assessment data within 10 business days.

---

## 11. Governing Law

This agreement is governed by the laws of [GOVERNING_STATE], United States, without regard to conflict of law principles.

---

## Signatures

**Processor (FrostGate)**

Signed: _________________________________ Date: ___________

Jason Cosat, Founder  
FrostGate | jason@frostgate.ai | [PHONE]

---

**Controller ([CLIENT_ORG])**

Signed: _________________________________ Date: ___________

Name: _________________________________

Title: _________________________________

Organization: [CLIENT_ORG]

---

*This agreement supplements and is incorporated into the Engagement Authorization Letter dated [DATE]. In the event of conflict, this agreement governs with respect to data processing obligations.*
