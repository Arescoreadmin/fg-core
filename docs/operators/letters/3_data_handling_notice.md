# FrostGate Data Handling Notice

**Template use:** Send this alongside the proposal and authorization letter, or include it as an attachment to either. One page. No signature required — it is informational. Clients in regulated industries (banking, healthcare) will expect this.

---

## DATA HANDLING NOTICE

**FrostGate AI Governance Field Assessment**
**Issued by:** Jason Cosat, FrostGate (jason@frostgate.ai)
**Version:** 1.0 | **Date:** [DATE]

---

This notice describes how FrostGate collects, uses, stores, and destroys data obtained during a Field Assessment engagement. It is provided to help your organization evaluate FrostGate as a vendor and satisfy any third-party vendor review requirements.

---

### What Data We Collect

FrostGate collects the following categories of data during an assessment, depending on the connectors authorized:

| Data Category | Source | Examples |
|---------------|--------|---------|
| Identity metadata | Microsoft 365 (Azure AD) | User display names, UPNs, MFA registration status, role assignments |
| Security policy configuration | Microsoft 365 | Conditional access policy names and settings, guest sharing policies |
| Application registrations | Microsoft 365 | App names, permission scopes, consent grant records |
| Device metadata | Microsoft Intune | Device names, OS versions, compliance status — no personal device content |
| DNS records | Public DNS | DMARC, SPF, DKIM, MX records — all publicly visible |
| HTTP response headers | Public web server | Security headers on your public URLs — no authenticated requests |
| Network port/TLS data | Your public IP ranges | Open ports, TLS certificate issuer and expiry |
| External sharing metadata | SharePoint / OneDrive | Sites and drives with external sharing enabled — file content is never read |

**We do not collect:** email content, calendar data, Teams messages, file contents, passwords, payment data, or health records.

---

### How We Use Your Data

Data collected during the assessment is used exclusively to:

1. Generate security findings identifying risks and gaps
2. Produce your assessment report and remediation roadmap
3. Populate your client portal during the 90-day access window
4. Calculate NIST AI RMF control coverage

Your data is not used to train AI models, benchmark against other clients, or for any purpose beyond delivering your assessment.

---

### Data Storage and Security

| Control | Detail |
|---------|--------|
| **Hosting** | Railway (API/database) and Vercel (portal) — US-based, SOC 2 Type II certified providers |
| **Encryption in transit** | TLS 1.2 or higher for all data transmission |
| **Encryption at rest** | AES-256 at the database layer |
| **Access control** | Multi-tenant isolation — your data is logically separated from all other clients |
| **Authentication** | API key + scope enforcement on all data access; Auth0 OIDC for operator console |
| **Audit trail** | Every data access event is logged to an immutable audit ledger |

---

### Data Retention and Deletion

- Assessment data (findings, scan results, questionnaire responses, report) is retained for **90 days** from the date of collection
- At the end of 90 days, all engagement data is purged from FrostGate systems
- You may request early deletion at any time by emailing jason@frostgate.ai
- Upon deletion, FrostGate will confirm in writing within 5 business days

---

### Subprocessors

FrostGate uses the following subprocessors in delivering this service:

| Subprocessor | Role | Location |
|-------------|------|----------|
| **Railway** | API hosting and managed PostgreSQL/Redis database | United States |
| **Vercel** | Portal frontend hosting | United States (edge) |
| **Anthropic** | AI model for executive summary generation (report narrative only) | United States |
| **Auth0 (Okta)** | Operator console authentication | United States |

No assessment data (findings, scan results, client information) is transmitted to Anthropic. Only the anonymized statistical summary used to generate the executive narrative is sent. Raw scan data never leaves Railway's managed database.

---

### Your Rights

You may at any time:

- **Request a copy** of the data FrostGate holds for your organization
- **Request correction** of inaccurate information
- **Request deletion** of your engagement data ahead of the 90-day schedule
- **Revoke access authorization** — FrostGate will immediately cease data collection

Submit requests to jason@frostgate.ai. We will respond within 5 business days.

---

### Contact

**Jason Cosat**
FrostGate
jason@frostgate.ai | [PHONE]

*This notice may be updated from time to time. The version in effect at the time of your engagement governs data handling for that engagement.*
