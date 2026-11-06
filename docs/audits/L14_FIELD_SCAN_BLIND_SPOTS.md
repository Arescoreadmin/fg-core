# L14 Field Scan Blind Spots and False-Negative Analysis

**Audit ID:** L14-FIELD-SCAN-DEEP-AUDIT-001
**Date:** 2026-11-06

This document catalogues detection gaps and false-negative scenarios for each assessment domain. All findings are from source inspection only. No live scanning was performed.

---

## IAM and Identity

### BLIND-01: Break-glass accounts without MFA

| Field | Detail |
|-------|--------|
| Weakness | Emergency break-glass accounts may not be enrolled in MFA while holding Global Administrator |
| Current detection | MFA analyzer reports aggregate percentages; no specific break-glass account detection |
| Required evidence | Graph API: users with Global Admin role + MFA status + sign-in pattern |
| Detection limitation | FrostGate reports whether MFA is configured for each user but does not identify accounts as break-glass |
| Likely false-negative mechanism | Break-glass accounts often have UPNs like svc-emrg-admin@; they may appear in MFA stats but not be called out as governance risk |
| Safe validation method | Query Graph for Global Admin role members, cross-reference with MFA registration, flag accounts with no recent sign-in activity |
| Priority | P1 |

### BLIND-02: Service principal with overprivileged client secrets (not covered by MFA)

| Field | Detail |
|-------|--------|
| Weakness | Service principals authenticating with client secrets (not certificates) are not covered by MFA and are not detected as a risk |
| Current detection | oauth_inventory reports scope count but not authentication method |
| Required evidence | Graph API: servicePrincipal keyCredentials vs passwordCredentials |
| Detection limitation | No connector checks keyCredentials vs passwordCredentials |
| Safe validation method | Add field to oauth_inventory to capture auth method type |
| Priority | P2 |

### BLIND-03: Stale admin role assignments never activated

| Field | Detail |
|-------|--------|
| Weakness | PIM eligible assignments created but never activated in 90+ days silently accumulate |
| Current detection | entra_governance flags stale eligible assignments using createdDateTime threshold |
| Detection limitation | The check only uses createdDateTime as a proxy for last activation — PIM activation records require additional Graph queries |
| Likely false-negative mechanism | An account activated once and then dormant would not be caught |
| Safe validation method | Query roleActivationSchedules to get actual last activation times |
| Priority | P2 |

---

## OAuth and Application

### BLIND-04: Browser-based shadow AI tools

| Field | Detail |
|-------|--------|
| Weakness | ChatGPT, Claude, Gemini accessed directly via browser are not visible in Microsoft Graph — they create no service principal or OAuth grant |
| Current detection | AI tool discovery only detects Microsoft 365 integrated apps (OAuth/service principal) |
| Required evidence | Web proxy logs, DNS query logs, browser extensions, or agent-based endpoint monitoring |
| Detection limitation | Fundamental: browser-only AI access is architecturally invisible to Graph API |
| Likely false-negative mechanism | Most shadow AI usage in a healthcare org is likely browser-based |
| Safe validation method | Interview-based: ask users about AI tool usage; survey IT for proxy/DNS log availability |
| Priority | P1 — this is the most significant blind spot for the AI governance product proposition |

### BLIND-05: AI tools accessed via API keys (not OAuth)

| Field | Detail |
|-------|--------|
| Weakness | Developers calling OpenAI, Anthropic, or Cohere APIs using API keys stored in code/config are invisible to Microsoft Graph |
| Current detection | No detection |
| Required evidence | SAST scan of repositories; secrets scanner; developer interview |
| Detection limitation | Requires code access or secrets scanning — neither implemented as a connector |
| Safe validation method | Interview developers; check Azure KeyVault / AWS Secrets Manager for AI API keys |
| Priority | P1 |

---

## Network and Infrastructure

### BLIND-06: Internal network segmentation failures

| Field | Detail |
|-------|--------|
| Weakness | The network scanner is scoped to external-facing hosts only (SSRF controls block internal targets by design). Internal segmentation between clinical and corporate networks cannot be tested |
| Current detection | External port scan only |
| Required evidence | On-site network test (requires physical presence and pre-authorized scanning tool) |
| Detection limitation | SSRF controls deliberately prevent internal scanning; this is correct behavior |
| Likely false-negative mechanism | The assessment may report good external posture while internal segmentation is flat |
| Safe validation method | Assessor field interview with network architect; review firewall rules documentation |
| Priority | P1 for clinical environments (HIPAA requires network segmentation for PHI systems) |

### BLIND-07: Cloud metadata endpoint exposure in containerized environments

| Field | Detail |
|-------|--------|
| Weakness | Kubernetes pods with IMDS access and no NetworkPolicy restriction are not detected |
| Current detection | SafeTargetValidationService blocks all 169.254.x.x; this protects the scanner but does not detect client-side IMDS exposure in the assessed environment |
| Required evidence | Cloud provider API (AWS SecurityHub, Azure Defender) or Kubernetes cluster access |
| Detection limitation | Requires cloud infrastructure access; no connector exists |
| Safe validation method | Document review: ask for Kubernetes NetworkPolicy examples and AWS IMDSv2 enforcement evidence |
| Priority | P2 |

---

## Email and DNS

### BLIND-08: DKIM rotation and key strength

| Field | Detail |
|-------|--------|
| Weakness | DKIM key age and bit length (1024 vs 2048) are not checked |
| Current detection | DKIM presence only (at 7 default selectors) |
| Required evidence | DKIM TXT record parsing to extract key size from p= field |
| Detection limitation | The runner checks for DKIM presence, not key strength |
| Safe validation method | Extend dns_email runner to parse DKIM TXT records and validate key length |
| Priority | P3 |

### BLIND-09: Email provider mismatch (MX vs SPF)

| Field | Detail |
|-------|--------|
| Weakness | A domain with MX pointing at Exchange Online but SPF not including outlook.com is a misconfiguration that the current scanner may not catch as a critical finding |
| Current detection | SPF checks for permissive mechanisms (+all, ?all) but does not validate alignment between MX providers and SPF includes |
| Likely false-negative mechanism | spf_no_all medium finding may understate severity for misaligned configurations |
| Safe validation method | Extend SPF check to correlate MX records with SPF include chain |
| Priority | P3 |

---

## AI Governance Specific

### BLIND-10: AI model training on PII without consent mechanism

| Field | Detail |
|-------|--------|
| Weakness | Whether customer data is used for vendor model training (opt-out vs opt-in) is not automatically detectable |
| Current detection | No scanner; ai_vendor_governance tracks DPA status (manual) |
| Required evidence | Contract review; vendor DPA; privacy policy analysis |
| Detection limitation | No automated scanner can determine training data usage from API access |
| Safe validation method | Document review in governance engine; assessor marks DPA fields after reviewing contracts |
| Priority | P2 |

### BLIND-11: AI audit log retention and access

| Field | Detail |
|-------|--------|
| Weakness | Whether an organization can actually produce AI decision audit logs for regulatory inquiry is not tested |
| Current detection | Governance engine tracks audit log status as a manually-entered field; no scanner |
| Required evidence | Access to AI platform audit logs (clinical AI vendor portal); interview with clinical informatics |
| Detection limitation | Fundamental: requires vendor portal access the assessor cannot automate |
| Safe validation method | Assessor field interview with clinical informatics; document sample audit log export |
| Priority | P1 for HIPAA-regulated AI assessments |

### BLIND-12: Undocumented AI model versions in production

| Field | Detail |
|-------|--------|
| Weakness | Whether the AI model version actually deployed matches what was approved in the governance record is not verifiable |
| Current detection | No scanner |
| Required evidence | Deployment pipeline access; version pinning in configuration |
| Detection limitation | Fundamental: requires CI/CD or deployment platform access |
| Safe validation method | Assessor review of deployment documentation; compare approved version in governance record vs current production |
| Priority | P2 |
