# Connector Cross-Reference: Client Technology → Data Collected

Use this sheet during scoping to determine which connectors apply and what findings to expect
based on what the client has. Also use it post-engagement to explain why certain data is absent.

---

## Quick Lookup Matrix

| Client Has | Connector | Auth Required |
|---|---|---|
| Any domain name | DNS & Email Security | None (read-only DNS) |
| Any public URL | Web Security Headers | None (HTTP HEAD) |
| Any IP range / hostname | Network Scan | None (TCP probes) |
| Microsoft 365 (any license) | MS Graph (core) | Device-code (delegated) |
| Microsoft 365 (any license) | OAuth Inventory | Device-code (delegated) |
| Microsoft 365 (any license) | OAuth Risk | Device-code (delegated) |
| Microsoft 365 (any license) | Endpoint Inventory | Device-code (delegated) |
| Microsoft 365 + SharePoint | SharePoint / OneDrive | Device-code (delegated) |
| Microsoft 365 + Azure AD P1 | Entra Governance (CA + roles) | Device-code (delegated) |
| Microsoft 365 + Azure AD P2 | Entra Governance (full) | Device-code (delegated) |

---

## No-Auth Connectors (Run Against Any Client)

### DNS & Email Security

**What the client needs:** Domain name(s) — nothing else.

**MS Graph scopes:** None.

| Data Collected | Findings Generated | Severity |
|---|---|---|
| DMARC record + policy tag | DMARC missing | Critical |
| SPF record + mechanism | DMARC policy set to `none` (monitoring only) | High |
| DKIM for 7 common selectors | SPF missing | High |
| MX record presence | SPF uses `+all` (open relay) | High |
| DNSSEC status | DKIM not detected on any tested selector | Medium |
| | DNSSEC not enabled | Low |

**Data gaps:** DKIM results are heuristic (7 selectors probed). Custom selectors not on the default list
will show as not detected even if configured. Supply custom selectors at scan initiation.

---

### Web Security Headers

**What the client needs:** Publicly reachable URL(s) — nothing else.

**MS Graph scopes:** None.

| Data Collected | Findings Generated | Severity |
|---|---|---|
| HSTS header + max-age | HSTS missing | High |
| Content-Security-Policy | HSTS max-age < 6 months | Medium |
| X-Frame-Options | HSTS missing `includeSubDomains` | Low |
| X-Content-Type-Options | CSP missing | High |
| Referrer-Policy | CSP contains `unsafe-inline` or `unsafe-eval` | Medium |
| Permissions-Policy | CSP contains wildcard source (`*`) | Medium |
| HTTP→HTTPS redirect | X-Frame-Options missing | Medium |
| | X-Content-Type-Options missing | Low |
| | Referrer-Policy missing or overly permissive | Low |
| | Permissions-Policy absent | Low |
| | Target reachable over plain HTTP only | High |

**Data gaps:** Internal / VPN-only URLs are not reachable. Authenticate-first pages (login walls)
return the login page headers, not the protected app headers.

---

### Network Scan

**What the client needs:** IP addresses, hostnames, or CIDR ranges (≤ /28 expanded inline).

**MS Graph scopes:** None.

Ports probed: 21, 22, 23, 25, 80, 443, 3306, 3389, 5000, 5432, 5900, 6006, 6379, 7860,
8000, 8080, 8443, 8888, 9200, 11434.

| Data Collected | Findings Generated | Severity |
|---|---|---|
| Open ports per host | Unsafe services exposed (RDP 3389, VNC 5900, Telnet 23, FTP 21) | Critical |
| TLS cert validity + expiry | Plain HTTP services with no HTTPS counterpart | High |
| Days until cert expiry | Expired or invalid TLS certificates | High |
| | AI model server ports accessible (Ollama 11434, Gradio 7860, Jupyter 8888) | Medium |

**Data gaps:** Scan is network-scoped (attacker-reachable surface). Firewall-blocked ports will
appear closed. Internal-only hosts require network adjacency. Up to 50 hosts per run.

---

## Microsoft 365 Connectors

All MS 365 connectors use MSAL device-code flow. The user completing the device-code
sign-in must be a **Global Reader** or higher to get meaningful coverage.

### Microsoft 365 License Tier Impact

| Feature | Free / Basic | P1 (E3 / Business Premium) | P2 (E5 / EMS E5) |
|---|---|---|---|
| User & MFA inventory | ✅ | ✅ | ✅ |
| Guest account exposure | ✅ | ✅ | ✅ |
| OAuth app registrations | ✅ | ✅ | ✅ |
| Privileged role assignments | ✅ | ✅ | ✅ |
| Conditional Access policies | ❌ (no CA on Free) | ✅ | ✅ |
| Intune device compliance | ❌ | ✅ | ✅ |
| PIM eligible assignments | ❌ | ❌ | ✅ |
| Identity Protection (risky users) | ❌ | ❌ | ✅ |
| Access Review definitions | ❌ | ❌ | ✅ |
| SharePoint file permissions | Requires SharePoint license (included E1+) |

---

### MS Graph Core Scan

**Connector:** `msgraph_v1`  
**MS Graph scopes:** `User.Read.All`, `Directory.Read.All`, `Policy.Read.All`, `Application.Read.All`,
`AuditLog.Read.All`, `Reports.Read.All`, `InformationProtectionPolicy.Read`

This is the broadest single-connector scan. Run it first on any Microsoft 365 client.

| Area | Data Collected | Key Findings | Severity |
|---|---|---|---|
| MFA | Per-user MFA method, registration state | Admins with no MFA | Critical |
| | | MFA coverage < 80% | High |
| | | MFA coverage 80–95% | Medium |
| | | Users on SMS/voice only (phishable MFA) | Medium |
| Conditional Access | All CA policies, state, conditions, grant controls | No legacy auth block | Critical |
| | | No MFA requirement for privileged roles | Critical |
| | | No CA policies enabled | High |
| | | >10 users excluded from MFA policies | High |
| | | No compliant device requirement | Medium |
| | | No sign-in risk policy (P2 feature) | Medium |
| Enterprise Apps | App registrations, SP activity, consent type | Unverified publisher with high-privilege perms | High |
| | | Stale apps (90+ days no activity) with active perms | High |
| | | New apps created in last 30 days | Medium |
| | | User-consented apps with sensitive resource access | Medium |
| OAuth Grants | Delegated and application consent grants | User-consented grant, full risk profile | Critical |
| | | User-consented grant, elevated risk | High |
| | | Admin-consented to unverified publisher | High |
| | | Stale grants (180+ days) | Medium |
| AI Signals | AI app detection, DLP exposure scoring | AI app — max DLP exposure (uncontrolled data access) | Critical |
| | Copilot license detection, admin approval records | AI app — elevated DLP exposure | High |
| | | AI apps with user-consented perms (no admin governance) | High |
| | | Copilot active, no AI acceptable use policy | Medium |
| Guest Exposure | Guest accounts, sign-in recency, group/role membership | Guest with privileged role assignment | High |
| | | Guest in sensitive security group | High |
| | | Stale guests (90+ days no sign-in) | Medium |
| | | Never-activated guest (invited, never signed in) | Low |
| Privileged Roles | Global Admin, all directory role assignments | Global Admin account with no MFA | Critical |
| | On-prem sync status for admin accounts | >5 Global Administrators | High |
| | | Admins using synchronized on-prem identities | High |
| | | Permanent privileged role assignments (no PIM) | High |
| | | 3–5 Global Admins (above minimum) | Medium |

**License gap:** CA findings will be sparse/absent if client is on Free tier (no CA product).
Sign-in risk policy finding requires P2. AI governance findings require audit log access.

---

### OAuth Inventory

**Connector:** `oauth_inventory`  
**MS Graph scopes:** Same as MS Graph core (`_MSGRAPH_AUTHORIZED_SCOPES`)

Focused snapshot of the OAuth app/grant landscape. Complements MS Graph core.

| Data Collected | Findings Generated | Severity |
|---|---|---|
| App registrations (display name, created, audience) | Admin-consented OAuth grants (≤5) | Medium |
| Service principals + publisher verification status | Admin-consented OAuth grants (>5) | High |
| OAuth2 permission grants + consent type | Apps from unverified publishers | Medium |
| Required resource access scope counts | Apps requesting >10 permission scopes | Medium |

---

### OAuth Risk (Deep Scan)

**Connector:** `oauth_risk`  
**MS Graph scopes:** `Application.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`

Specialized scanner distinct from OAuth Inventory. Covers the illicit consent grant attack pattern,
over-privileged application permissions, and AI tool data access detection.

| Data Collected | Findings Generated | Severity |
|---|---|---|
| All delegated OAuth grants + scope strings | Illicit consent grant: critical delegated scope by non-admin user | Critical |
| Application role assignments (tenant-wide, 3 API calls) | High-risk delegated grant (Mail.Read, Calendar, etc.) | High |
| AI tool detection via 15 pattern matches | Excessive app-level permissions (Mail.ReadWrite.All, etc.) | Critical |
| Data-access scope classification | High app-level permissions (User.Read.All, GroupMember.Read.All) | High |
| | AI tool with data-access scopes | High |
| | AI tool with application-level permissions | Critical |

**Efficiency:** Uses `appRoleAssignedTo` on the Microsoft Graph SP — returns all application
permissions for the entire tenant in 3 API calls instead of O(n) per-SP calls.

**License gap:** `AuditLog.Read.All` requires at least Azure AD Free + audit log retention enabled.
On Free tier, log retention is 7 days (P1 = 30 days, P2 = 90 days).

---

### Endpoint Inventory

**Connector:** `endpoint_inventory`  
**MS Graph scopes:** Same as MS Graph core + `DeviceManagementManagedDevices.Read.All` (Intune-gated)

| Data Collected | Findings Generated | Severity |
|---|---|---|
| Azure AD device list (OS, trust type, last sign-in) | Non-compliant managed devices | High |
| Intune managed device list (requires Intune license) | Unmanaged devices in tenant | High |
| Compliance state per device | Stale devices (90+ days no sign-in) | Medium |
| Disk encryption status (BitLocker / FileVault) | Managed devices without disk encryption | High |

**License gap:** Intune data (compliance, encryption) requires an Intune license.
On Free/Basic, Intune API returns 403 — the connector completes without Intune enrichment.
Devices still appear in the list from Azure AD registration, but `is_managed`, `is_compliant`,
and encryption status will be absent.

---

### Entra ID Governance

**Connector:** `entra_governance`  
**MS Graph scopes:** `Directory.Read.All`, `Policy.Read.All`, `AccessReview.Read.All`,
`IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`,
`RoleEligibilitySchedule.Read.Directory`, `RoleAssignmentSchedule.Read.Directory`

Covers PIM, Access Reviews, Identity Protection, and Conditional Access posture.

| Data Collected | Available On | Findings Generated | Severity |
|---|---|---|---|
| Permanent role assignments | Any M365 | Permanent Global Admin assignment | High |
| | | >5 Global Administrators | Medium |
| | | Permanent privileged role without PIM | High |
| Conditional Access policies | P1+ | No CA policies configured | Critical |
| | | CA policies in report-only mode | Medium |
| | | No CA policy blocking legacy auth | High |
| | | No CA policy requiring MFA | High |
| PIM eligibility schedules | P2 only | Stale PIM eligible assignments (90+ days) | Medium |
| Identity Protection risky users | P2 only | High-risk users not remediated | Critical |
| | | Medium-risk users not remediated | High |
| Access Review definitions | P2 only | No access reviews configured | High |
| | | Reviews don't cover privileged roles | Medium |
| | | Non-recurring (one-time) reviews | Low |

**License gap:** On P1 tenants, PIM / Identity Protection / Access Review API calls return 403
and the connector skips those sections cleanly. The scan completes with CA + role assignment
findings only. Flag to client that P2 findings are absent due to license.

---

### SharePoint & OneDrive Data Exposure

**Connector:** `sharepoint_onedrive`  
**MS Graph scopes:** `Sites.Read.All`, `Files.Read.All`, `Directory.Read.All`

**What the client needs:** Microsoft 365 with a SharePoint license (E1, E3, E5, Business Standard+).

Sampling bounds: up to 30 sites, 3 drives/site, 100 items/drive, 15 permission checks/drive.

| Data Collected | Findings Generated | Severity |
|---|---|---|
| Site list + external sharing setting | Anonymous (anyone-with-link) sharing — broad | Critical |
| Drive items with `shared` property | Anonymous sharing — moderate | High |
| Sharing link type (anonymous / organization / specific) | External sharing with non-tenant users | High |
| External link recipients vs tenant domain | Guest user file access | Medium |
| Guest user detection | External sharing baseline present | Informational |

**Anonymous sharing severity escalation:** If >10 items are anonymously shared, the finding
escalates from High to Critical automatically.

**Data gaps:** Only items where the `shared` DriveItem property is present are permission-checked
(avoids N+1 API calls). Very new shares or shares without metadata propagation may be missed.
OneDrive for Business (personal drives) is included; Teams-connected SharePoint is included.

---

## Connector Combination Guide

| Engagement Type | Recommended Connector Set |
|---|---|
| Domain / email security only | DNS & Email, Web Headers |
| External surface review | DNS & Email, Web Headers, Network Scan |
| Microsoft 365 baseline | MS Graph Core |
| Microsoft 365 full | MS Graph Core + OAuth Inventory + OAuth Risk + Endpoint Inventory |
| Microsoft 365 with P2 | All of the above + Entra Governance |
| Microsoft 365 with SharePoint | Add SharePoint/OneDrive to any M365 set |
| AI governance focus | MS Graph Core (AI Signals) + OAuth Risk (AI tool detection) |
| Identity / access focus | MS Graph Core + Entra Governance + OAuth Risk |
| Full assessment | All connectors |

---

## Data Gaps to Disclose to Client

When a connector runs but specific data is absent, use this table to explain why.

| What's missing | Likely cause | How to confirm |
|---|---|---|
| No CA policy findings | Free/Basic M365 tier — no CA product | Check Azure AD edition in Portal > Overview |
| No Intune compliance/encryption data | No Intune license assigned | Check if Intune appears in M365 admin portal |
| No PIM findings | Azure AD P2 not licensed | Check Azure AD Privileged Identity Management — if locked, P2 absent |
| No risky users / Identity Protection | Azure AD P2 not licensed | Same as PIM |
| No Access Review findings | Azure AD P2 not licensed | Same as PIM |
| No SharePoint sites | SharePoint not licensed | Check if SharePoint admin center exists |
| DKIM not detected | Custom selector not in default list | Ask client for selector names; re-run with custom selectors |
| Hosts appear closed | Firewall rules | Cross-check with client's internal port list |
| AI tool findings absent | No AI apps registered in tenant | Validate with OAuth Inventory app list |
