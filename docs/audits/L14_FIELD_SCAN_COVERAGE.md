# L14 Field Scan Coverage Matrix

**Audit ID:** L14-FIELD-SCAN-DEEP-AUDIT-001
**Date:** 2026-11-06

Assessment domain and technique coverage, mapped to available connectors. Status reflects source-inspection findings only; detection accuracy is NOT_MEASURED unless confirmed by test execution.

---

## Identity and Access Management

| Capability | Evidence Type | Connector | Maturity | Verified Coverage | Gap |
|-----------|--------------|-----------|----------|-------------------|-----|
| MFA enrollment status per user | Scan result | microsoft_graph (mfa analyzer) | IMPLEMENTED_AND_TESTED | Yes — test coverage in msgraph analyzer tests | Per-user MFA method not captured, only enabled/disabled |
| Conditional Access policy inventory | Scan result | microsoft_graph (CA analyzer), entra_governance | IMPLEMENTED_AND_TESTED | Yes | Report-only mode detection; legacy auth blocking check; MFA requirement check |
| Privileged role assignments (permanent vs PIM) | Scan result | entra_governance | IMPLEMENTED_AND_TESTED | Yes | PIM eligible assignment stale check (90d); permanent global admin count vs 5 threshold |
| Access review configuration | Scan result | entra_governance | IMPLEMENTED_AND_TESTED | Yes | Non-recurring review detection; privileged role coverage check |
| Risky users (Identity Protection) | Scan result | entra_governance | IMPLEMENTED_AND_TESTED | Yes (graceful 403) | P2 license gated; count only, no user identity returned |
| Guest account exposure | Scan result | microsoft_graph (guest_exposure analyzer) | IMPLEMENTED_AND_TESTED | Yes | External collaboration policy check |
| Legacy authentication protocol usage | Scan result | microsoft_graph (CA analyzer) | IMPLEMENTED_AND_TESTED | Yes | Checks for CA policy blocking exchangeActiveSync and 'other' |
| SSPR / password policy | Scan result | microsoft_graph | PARTIALLY_IMPLEMENTED | Partial — not a dedicated analyzer | No explicit SSPR check; password policy inspection limited |
| Break-glass account detection | Scan result | None | MISSING | No | No connector checks for break-glass accounts lacking MFA |

---

## OAuth and Application Governance

| Capability | Evidence Type | Connector | Maturity | Verified Coverage | Gap |
|-----------|--------------|-----------|----------|-------------------|-----|
| OAuth app registration inventory | Scan result | oauth_inventory | IMPLEMENTED_AND_TESTED | Yes | App count, publisher verification, scope count per app |
| Admin-consented grant detection | Scan result | oauth_inventory, oauth_risk | IMPLEMENTED_AND_TESTED | Yes | AllPrincipals consent type; critical/high/medium scope classification |
| AI-connected application detection | Scan result | ai_tool_discovery | IMPLEMENTED_AND_TESTED | Yes | Vendor registry matching; sign-in log correlation |
| Shadow AI detection | Scan result | ai_tool_discovery | IMPLEMENTED_AND_TESTED | Yes | confidence=suspected tools flagged |
| OAuth scope overprivilege | Scan result | oauth_risk | IMPLEMENTED_AND_TESTED | Yes | Critical, high, and AI-specific scope classifications |
| Token-level abuse detection | None | MISSING | MISSING | No | Requires audit log forensics; not implemented |

---

## Endpoint and Device Management

| Capability | Evidence Type | Connector | Maturity | Verified Coverage | Gap |
|-----------|--------------|-----------|----------|-------------------|-----|
| Device compliance status | Scan result | endpoint_inventory | IMPLEMENTED_AND_TESTED | Yes | isCompliant from Azure AD + Intune |
| MDM enrollment coverage | Scan result | endpoint_inventory | IMPLEMENTED_AND_TESTED | Yes | isManaged flag; unmanaged count |
| Disk encryption status | Scan result | endpoint_inventory | IMPLEMENTED_AND_TESTED | Yes (Intune-gated) | isEncrypted from Intune; falls back gracefully on 403 |
| Stale device detection | Scan result | endpoint_inventory | IMPLEMENTED_AND_TESTED | Yes | 90-day threshold |
| OS patch level | None | MISSING | MISSING | No | Graph API does not expose OS patch level reliably |
| EDR coverage | None | MISSING | MISSING | No | Requires EDR platform API integration |

---

## Network and Web Security

| Capability | Evidence Type | Connector | Maturity | Verified Coverage | Gap |
|-----------|--------------|-----------|----------|-------------------|-----|
| External port exposure | Scan result | network_scan | IMPLEMENTED_AND_TESTED | Yes | 20 ports including RDP, VNC, Telnet, FTP, AI model servers |
| TLS certificate validity | Scan result | network_scan | IMPLEMENTED_AND_TESTED | Yes | Expiry, validity; SNI-based |
| HTTP security headers | Scan result | web_headers | IMPLEMENTED_AND_TESTED | Yes | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORP, COEP, COOP |
| Plain HTTP services | Scan result | network_scan, web_headers | IMPLEMENTED_AND_TESTED | Yes | Both detect HTTP without TLS |
| AI model server exposure | Scan result | network_scan | IMPLEMENTED_AND_TESTED | Yes | Ports 11434, 7860, 8888, 6006, 5000 |
| WAF detection | None | MISSING | MISSING | No | No WAF presence detection |
| Firewall rule analysis | None | MISSING | MISSING | No | Requires cloud provider API |
| VPN/zero-trust network access | None | MISSING | MISSING | No | Interview/document evidence only |

---

## Email and DNS Security

| Capability | Evidence Type | Connector | Maturity | Verified Coverage | Gap |
|-----------|--------------|-----------|----------|-------------------|-----|
| SPF configuration | Scan result | dns_email | IMPLEMENTED_AND_TESTED | Yes | Present/missing, all mechanism strength, permissive detection |
| DMARC policy | Scan result | dns_email | IMPLEMENTED_AND_TESTED | Yes | p=none vs quarantine vs reject; pct coverage; reporting URIs |
| DKIM key presence | Scan result | dns_email | IMPLEMENTED_AND_TESTED | Yes | 7 default selectors; custom selectors supported |
| DNSSEC | Scan result | dns_email | IMPLEMENTED_AND_TESTED | Yes (presence only) | DNSKEY record presence; not full chain validation |
| MX record existence | Scan result | dns_email | IMPLEMENTED_AND_TESTED | Yes | Present/missing |
| BIMI (Brand Indicators for Message Identification) | None | MISSING | MISSING | No | Not implemented |
| SMTP TLS (MTA-STS / TLS-RPT) | None | MISSING | MISSING | No | Not implemented |

---

## AI Governance Chain

| Capability | Evidence Type | Connector | Maturity | Verified Coverage | Gap |
|-----------|--------------|-----------|----------|-------------------|-----|
| AI tool inventory | Scan result | ai_tool_discovery | IMPLEMENTED_AND_TESTED | Yes | Vendor registry + Graph matching |
| Data access mapping | Scan result | ai_data_access_mapping | IMPLEMENTED_AND_TESTED | Yes | 70+ permission-to-category mappings |
| Risk scoring | Scan result | external_ai_risk_register | IMPLEMENTED_AND_TESTED | Yes | Additive score; low/moderate/high/critical bands |
| Governance record creation | Scan result | ai_vendor_governance | IMPLEMENTED_AND_TESTED | Yes | Ownership, DPA/BAA, security review, risk acceptance tracking |
| Shadow AI identification | Scan result | ai_tool_discovery + risk_register | IMPLEMENTED_AND_TESTED | Yes | confidence=suspected + shadow_ai risk category |
| DPA/BAA tracking | Governance record | ai_vendor_governance | IMPLEMENTED_AND_TESTED | Yes | Flags when DPA/BAA required but not executed |
| Risk acceptance expiration | Governance record | ai_vendor_governance | IMPLEMENTED_AND_TESTED | Yes | Checks risk_acceptance_expiration against current date |
| AI audit log retention | None | MISSING | MISSING | No | Requires vendor API or document review; no scanner |
| AI model bias/fairness | None | MISSING | MISSING | No | No automated scanner; requires document review / interview |
| AI training data lineage | None | MISSING | MISSING | No | No automated scanner |

---

## SharePoint and Data Exposure

| Capability | Evidence Type | Connector | Maturity | Verified Coverage | Gap |
|-----------|--------------|-----------|----------|-------------------|-----|
| External sharing detection | Scan result | sharepoint_onedrive | IMPLEMENTED_AND_TESTED | Yes | Anonymous links; external sharing per site |
| Guest user data access | Scan result | sharepoint_onedrive | IMPLEMENTED_AND_TESTED | Yes | Guest permission detection |
| DLP policy coverage | Scan result | microsoft_graph (dlp_scoring) | IMPLEMENTED_AND_TESTED | Yes | DLP policy count and coverage scoring |
| Data classification coverage | None (interview) | MISSING | MISSING | No | No automated scanner; requires document review |

---

## Cloud Infrastructure (Multi-cloud)

| Capability | Evidence Type | Connector | Maturity | Verified Coverage | Gap |
|-----------|--------------|-----------|----------|-------------------|-----|
| Azure AD / M365 | Scan result | microsoft_graph + 7 connectors | IMPLEMENTED_AND_TESTED | Yes | Full chain |
| AWS IAM / CloudTrail | Scan result | REGISTERED_NO_RUNNER | MISSING | No | Manual import only |
| Azure subscription posture | Scan result | REGISTERED_NO_RUNNER | MISSING | No | Manual import only |
| GCP IAM / Cloud Audit | Scan result | REGISTERED_NO_RUNNER | MISSING | No | Manual import only |
| Google Workspace | Scan result | REGISTERED_NO_RUNNER | MISSING | No | Manual import only |
