# L14 Scan Framework Coverage Mapping

**Audit ID:** L14-FIELD-SCAN-DEEP-AUDIT-001
**Date:** 2026-11-06

Framework-to-control-to-connector mapping. Coverage is derived from source inspection. Verified means a test exists that exercises the specific finding path.

---

## NIST AI RMF Coverage

| Function | Control | Required Evidence | FrostGate Capability | Connector | Verified |
|---------|---------|-------------------|---------------------|-----------|---------|
| GOVERN | 1.1 — AI governance roles and responsibilities | Business/technical owner assignment | AI vendor governance finding: no_business_owner, no_technical_owner | ai_vendor_governance | Yes |
| GOVERN | 1.2 — Senior AI leadership | Executive sponsor | AI vendor governance finding: no_executive_sponsor | ai_vendor_governance | Yes |
| GOVERN | 1.3 — Vendor contract governance | Contract on file; review cadence | AI vendor governance finding: no_contract, review_overdue | ai_vendor_governance | Yes |
| GOVERN | 1.4 — Exception governance | Exception expiration | AI vendor governance finding: exception_expired | ai_vendor_governance | Yes |
| GOVERN | 6.1 — AI risk management processes | Access review cadence | entra_governance finding: no_access_reviews_configured | entra_governance | Yes |
| GOVERN | 6.2 — Vendor security/privacy review | Security review, privacy review, DPA, BAA | AI vendor governance findings: no_security_review, no_privacy_review, no_dpa, no_baa | ai_vendor_governance | Yes |
| MAP | 1.1 — AI tool inventory and risk mapping | Tool list with publisher and permissions | ai_tool_discovery + risk register | ai_tool_discovery, external_ai_risk_register | Yes |
| MAP | 3.5 — Device/asset inventory | Unmanaged device count | endpoint_inventory finding: unmanaged_devices | endpoint_inventory | Yes |
| MANAGE | 1.1 — Least privilege | OAuth scope analysis | oauth_inventory finding: broad_scope_apps | oauth_inventory | Yes |
| MANAGE | 1.3 — Stale access cleanup | Stale device/assignment cleanup | endpoint_inventory finding: stale_devices; entra_governance: stale_pim_eligible | endpoint_inventory, entra_governance | Yes |
| MANAGE | 2.2 — Risk acceptance and enforcement | Risk acceptance status; restricted/rejected tool enforcement | ai_vendor_governance findings: risk_acceptance_expired, restricted_still_active, rejected_still_active | ai_vendor_governance | Yes |
| MANAGE | 2.4 — Encryption and security controls | Disk encryption; TLS; plaintext services | endpoint_inventory: unencrypted_devices; network_scan: invalid_tls, plain_http | endpoint_inventory, network_scan | Yes |

**Coverage summary:** GOVERN 1.1–1.4, 6.1–6.2 — STRONG; MAP 1.1, 3.5 — STRONG; MANAGE 1.1, 1.3, 2.2, 2.4 — STRONG

**Gaps:** GOVERN 2.x (AI risk documentation frameworks), MAP 2.x (AI risk context assessment), MANAGE 3.x (AI incident response) — no automated scanner coverage; requires document review and interview.

---

## NIST CSF 2.0 Coverage

| Function | Category | Required Evidence | FrostGate Capability | Connector | Verified |
|---------|---------|-------------------|---------------------|-----------|---------|
| IDENTIFY | Asset Management (ID.AM) | Device/app inventory | endpoint_inventory, oauth_inventory, ai_tool_discovery | Multiple | Yes |
| IDENTIFY | Risk Assessment (ID.RA) | AI tool risk scores | external_ai_risk_register | external_ai_risk_register | Yes |
| PROTECT | Access Control (PR.AC) | MFA, privileged roles, CA policies | microsoft_graph, entra_governance | Multiple | Yes |
| PROTECT | Data Security (PR.DS) | Encryption, DLP, external sharing | endpoint_inventory, microsoft_graph, sharepoint | Multiple | Yes |
| PROTECT | Information Protection (PR.IP) | Email security, TLS | dns_email, web_headers | Multiple | Yes |
| DETECT | Anomalies (DE.AE) | Identity risk signals | entra_governance (risky users) | entra_governance | Partial |
| RESPOND | Response Planning (RS.RP) | Incident response documentation | Document review only | None | No |
| RECOVER | Recovery Planning (RC.RP) | DR plan documentation | Document review only | None | No |

---

## CIS Controls v8 Coverage

| Control | Safeguard | Description | FrostGate Capability | Connector | Maturity |
|---------|----------|-------------|---------------------|-----------|---------|
| CIS 1 | 1.1 | Establish and maintain detailed enterprise asset inventory | Endpoint inventory via Azure AD + Intune | endpoint_inventory | IMPLEMENTED |
| CIS 2 | 2.1 | Establish and maintain software asset inventory | OAuth app inventory | oauth_inventory, ai_tool_discovery | IMPLEMENTED |
| CIS 4 | 4.1 | Establish and maintain secure configuration process | Web security headers, TLS configuration | web_headers, network_scan | IMPLEMENTED |
| CIS 5 | 5.1 | Establish and maintain an inventory of accounts | Azure AD user inventory (via Graph) | microsoft_graph | IMPLEMENTED |
| CIS 5 | 5.3 | Disable dormant accounts | Stale device/account detection | endpoint_inventory (devices) | PARTIAL — no user account stale check |
| CIS 6 | 6.1 | Establish access granting and revoking process | Privileged role management, PIM | entra_governance | IMPLEMENTED |
| CIS 6 | 6.3 | Require MFA for externally-exposed applications | MFA enrollment, CA policy check | microsoft_graph, entra_governance | IMPLEMENTED |
| CIS 6 | 6.4 | Require MFA for remote network access | CA policy legacy auth check | entra_governance | IMPLEMENTED |
| CIS 9 | 9.5 | Implement DMARC and SPF | DNS/email security scan | dns_email | IMPLEMENTED |
| CIS 12 | 12.1 | Ensure network infrastructure is up-to-date | Port scan (exposure detection) | network_scan | PARTIAL — no patch level |
| CIS 12 | 12.2 | Establish and maintain a secure network architecture | External exposure, unsafe services | network_scan | IMPLEMENTED |
| CIS 16 | 16.1 | Establish and maintain a secure application development process | Web security headers | web_headers | PARTIAL |
| CIS 16 | 16.5 | Use up-to-date and trusted third-party software | OAuth publisher verification | oauth_inventory, ai_tool_discovery | IMPLEMENTED |

**CIS Controls gaps:** CIS 7 (continuous vulnerability management — no CVE correlation), CIS 8 (audit log management — no SIEM integration), CIS 10 (malware defenses — no EDR integration), CIS 13 (network monitoring — no flow logs), CIS 14 (security awareness — document review only).

---

## OWASP ASVS (Application Security — web_headers connector only)

| ASVS Category | Requirement | FrostGate Coverage | Gap |
|--------------|-------------|-------------------|-----|
| V3 Session Mgmt | 3.4.1 — Secure cookie attribute | Not checked | No cookie attribute inspection |
| V7 Error Handling | 7.1.1 — Server error disclosure | Not checked | No response body analysis |
| V8 Data Protection | 8.3.4 — X-Content-Type-Options | Yes — web_headers checks nosniff | Covered |
| V14 Config | 14.4.1 — HTTPS everywhere | Yes — plain HTTP detection | Covered |
| V14 Config | 14.4.3 — HSTS | Yes — HSTS max-age validation | Covered |
| V14 Config | 14.4.4 — X-Frame-Options | Yes | Covered |
| V14 Config | 14.4.5 — CSP | Yes — unsafe-inline, unsafe-eval, wildcard detection | Covered |
| V14 Config | 14.4.6 — Referrer-Policy | Yes | Covered |
| V14 Config | 14.4.7 — Permissions-Policy | Yes | Covered |

---

## EU AI Act Relevance

The External AI Risk Register regulatory_flags computation includes EU_AI_ACT when any of these conditions are met:
- `unverified_publisher` — Article 13 transparency
- `tenant_wide_permissions` — Article 10 data governance
- `shadow_ai` — Article 28 deployer obligations

No connector currently performs formal EU AI Act risk category classification (prohibited/high-risk/limited/minimal). This is a gap for EU-regulated clients. Assessors must conduct manual classification during the engagement.

---

## ISO 42001 (AI Management System) Coverage

ISO 42001 is an emerging standard for AI management systems. The ai_vendor_governance engine tracks:
- `no_dpa_baa_vendor_review` — maps to ISO 42001 §8.4 (supplier relationships)
- `no_approval_record` — maps to ISO 42001 §6.1 (risk treatment)
- `unknown_owner` — maps to ISO 42001 §5.3 (organizational roles)

The governance engine explicitly sets `ISO_42001` regulatory flag when these categories are present. No dedicated ISO 42001 scanner exists; coverage is through the AI governance chain.
