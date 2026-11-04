# FrostGate | Governed AI Security Assessment
## Engagement Proposal

**Prepared for:** [CLIENT NAME], [CLIENT TITLE]
[CLIENT ORGANIZATION]
[CLIENT ADDRESS]

**Prepared by:** Jason Cosat, Founder
FrostGate
jason@frostgate.ai | [PHONE]

**Date:** [DATE]
**Proposal validity:** 30 days from date above

---

## Executive Summary

[CLIENT ORGANIZATION] is using AI tools in [INDUSTRY CONTEXT]. This proposal outlines a FrostGate AI Governance Field Assessment — a structured, assessor-led evaluation of your current AI governance posture, delivered through a single working session and followed by a secure client portal with findings, risk scoring, and a prioritized remediation roadmap.

This engagement is designed to give [CLIENT ORGANIZATION] a defensible record of its AI governance posture — the specific findings, the evidence behind them, and the actions required to close the gaps — in a format that can be shared with executives, boards, and regulators.

---

## Assessment Scope

### What we will assess

| Area | What we evaluate |
|------|-----------------|
| AI tool inventory | Which AI applications (Copilot, ChatGPT, Claude, etc.) have access to your Microsoft 365 environment and what permissions they hold |
| Identity and access | MFA coverage, privileged account controls, guest user exposure, conditional access policy strength |
| Data exposure | SharePoint and OneDrive files accessible externally or via anonymous links |
| Endpoint posture | Device enrollment and compliance status via Microsoft Intune |
| Email and DNS security | DMARC, SPF, DKIM records protecting your domain |
| Web security | Public-facing website TLS and HTTP security headers |
| NIST AI RMF posture | 69-control structured evaluation against the NIST AI Risk Management Framework |
| Compliance alignment | Gap analysis against [APPLICABLE FRAMEWORKS — e.g., HIPAA / SOC 2 / CMMC 2.0 / ISO 27001] |

### Connectors: 13 total

Passive (no authentication required): DNS and Email Security, Web Security Headers, Network Scan.

Authenticated via Microsoft device-code OAuth (requires Global Administrator or Application Administrator present during session): MS Graph Core, MFA, Conditional Access, Devices, SharePoint, OAuth Inventory, OAuth Risk, Entra Governance, Identity Protection.

Operator-facilitated: NIST AI RMF questionnaire (69 controls).

### What is NOT included

- Continuous or recurring monitoring after engagement close
- Penetration testing or active exploitation
- SAML or SSO integration
- Real-time alerting
- Compliance certification or regulatory audit attestation
- Multiple Microsoft 365 tenants

---

## Deliverables

| Deliverable | Timing |
|-------------|--------|
| Secure portal access (risk dashboard, findings, remediation roadmap) | Within 24 hours of QA approval (subject to production portal verification being confirmed at kickoff) |
| PDF report (findings, severity, executive summary) | Within 5–7 business days of data collection session |
| NIST AI RMF coverage matrix (69 controls) | With portal access |
| Remediation roadmap (phased action plan) | With portal access |
| 30-day check-in and re-scan summary | 30 days after portal delivery |

**Delivery note:** Report delivery is conditioned on completion of FrostGate's production signing controls. If those controls are not complete at engagement start, the report will be delivered within 5 business days of control completion. All other deliverables — portal access, risk dashboard, and remediation roadmap — are available on the standard timeline regardless.

---

## Delivery Timeline

| Day | Milestone |
|-----|-----------|
| 0 | SOW executed; payment received; Azure AD app registration scheduled |
| 1–3 | Pre-meeting passive scans (DNS, web headers, network) |
| 5 | Data collection session (75–90 minutes) |
| 6–8 | Evidence curation, QA review |
| 9 | QA approval; portal access delivered |
| 10 | Delivery meeting (portal walkthrough, findings review) |
| 30 | 30-day check-in and re-scan |

**Commitment:** Portal access and all deliverables available within 5–7 business days of the data collection session.

---

## Investment

| Tier | Amount | Terms |
|------|--------|-------|
| [STANDARD / DESIGN PARTNER] | $[5,000 / 2,500] | [50% upon execution, 50% upon portal delivery / 100% upfront] |

[IF DESIGN PARTNER: This engagement is offered at the design partner rate of $2,500. This rate is a discretionary exception approved by FrostGate's founder and is not available to all prospects. It is offered in exchange for a 30-minute feedback interview at close and reference call rights (subject to [CLIENT ORGANIZATION]'s approval).]

**Payment:** ACH or check preferred. Stripe payment links are available but must be FrostGate-issued with the engagement identifier embedded — a generic Stripe payment link will not automatically record payment in FrostGate's systems. Invoice issued by FrostGate upon SOW execution.

---

## Client Obligations

To proceed, [CLIENT ORGANIZATION] agrees to:

1. Sign the Data Processing Agreement (DPA) before data collection begins
2. Provide a Global Administrator or Application Administrator who can be present during the data collection session to authorize the FrostGate application registration and complete Microsoft device-code authentication
3. Authorize the FrostGate app registration in [CLIENT ORGANIZATION]'s Azure AD tenant (operator provides setup instructions; estimated 30 minutes)
4. Provide primary domain name, secondary email domains, and public-facing URLs for scanning
5. Designate a technical contact for the duration of the engagement

---

## Next Steps

If this proposal meets your needs:

1. Reply confirming the engagement date
2. Sign and return the enclosed Statement of Work and Data Processing Agreement
3. Remit the first payment installment per the terms above

FrostGate will send calendar confirmation and an Azure AD setup checklist within 24 hours of receiving the signed SOW.

Questions? Contact jason@frostgate.ai or [PHONE].

---

## Signatures

**Accepted by FrostGate:**

Signed: _________________________________ Date: ___________

Jason Cosat, Founder
FrostGate | jason@frostgate.ai

---

**Accepted by [CLIENT ORGANIZATION]:**

Signed: _________________________________ Date: ___________

Name: _________________________________

Title: _________________________________

Organization: [CLIENT ORGANIZATION]

---

*This proposal is valid for 30 days from the date above. FrostGate does not resell client data, share findings with third parties, or retain assessment data beyond the 90-day portal window. This proposal does not constitute a binding agreement; a fully executed Statement of Work and DPA are required before any data collection begins.*
