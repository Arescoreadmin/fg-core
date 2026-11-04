# OFFER A — Paid Assessment Pilot Package
## Canonical Product Definition

**Product:** FrostGate AI Governance Field Assessment
**Version:** 1.0
**Price:** $5,000 USD fixed scope / $2,500 design partner rate
**Authority:** `docs/plans/revenue_first_roadmap_20261103.md` Section 2
**Date:** 2026-11-03

---

## Product Name and Tagline

**FrostGate AI Governance Field Assessment**

*The first assessor-led, evidence-chained AI governance assessment purpose-built for regulated mid-market organizations.*

---

## Target Buyer — Ideal Client Profile

**Who this is for:**

- Organizations of 25–500 employees using Microsoft 365 and Entra ID
- Regulated or regulated-adjacent industries: community banking, healthcare (medical groups, dental, behavioral health), law firms, insurance agencies, government contractors
- Companies already using AI tools (Microsoft Copilot, ChatGPT, Claude, etc.) with no formal governance program
- Buying triggers: upcoming audit, board inquiry about AI risk, new CISO/compliance hire, regulatory change (HIPAA, SOC 2, CMMC, NIST AI RMF)
- Decision maker: practice administrator, managing partner, CISO, compliance officer, or CFO with authority to sign a DPA and SOW

**Why they buy:** They are using AI without visibility into what it accesses, what policies govern it, or what a regulator would say. They need a defensible record — not a questionnaire PDF.

---

## Assessment Objectives

FrostGate evaluates:

1. **AI tool inventory and exposure** — which AI applications have access to the organization's Microsoft 365 data and what permissions they hold
2. **Identity and access posture** — MFA coverage, privileged account controls, guest user exposure, conditional access policy strength
3. **Data exposure risk** — SharePoint and OneDrive files accessible to external users or via anonymous links
4. **Endpoint compliance posture** — device enrollment and compliance status via Microsoft Intune/Endpoint Manager
5. **Email and DNS security** — DMARC, SPF, DKIM records protecting the domain from impersonation
6. **Web security headers** — public-facing website TLS and HTTP security header configuration
7. **Network exposure** — externally reachable services and open ports (in-scope hosts only)
8. **NIST AI RMF governance posture** — structured evaluation against all 69 NIST AI Risk Management Framework 1.0 controls
9. **Compliance framework alignment** — gap analysis against applicable frameworks (HIPAA, SOC 2, CMMC 2.0, ISO 27001) based on client profile

---

## Scope — What Is Included

### Connector Types (13 total)

| Connector | Category | Auth required |
|-----------|----------|--------------|
| DNS and Email Security | Public infrastructure | None — passive scan |
| Web Security Headers | Public infrastructure | None — passive scan |
| Network Scan | Public infrastructure | None — passive scan |
| MS Graph Core | Identity and access | Device-code OAuth (Entra ID) |
| MS Graph MFA | Identity governance | Device-code OAuth |
| MS Graph Conditional Access | Policy assessment | Device-code OAuth |
| MS Graph Devices | Endpoint posture | Device-code OAuth |
| MS Graph SharePoint | Data exposure | Device-code OAuth |
| MS Graph OAuth Inventory | AI tool exposure | Device-code OAuth |
| MS Graph OAuth Risk | Application risk | Device-code OAuth |
| MS Graph Entra Governance | Identity governance | Device-code OAuth |
| MS Graph Identity Protection | Risky users/sign-ins | Device-code OAuth |
| Questionnaire | NIST AI RMF | Operator-facilitated |

### Assessment Content

- 69-control NIST AI RMF 1.0 questionnaire (operator-facilitated walkthrough)
- Risk scoring across 6 governance domains
- Findings with severity classification (Critical, High, Medium, Low, Informational)
- AI-generated executive summary (Claude via Anthropic API)
- Compliance framework mapping: NIST AI RMF, HIPAA, SOC 2, CMMC 2.0, ISO 27001

### Portal Features

- Password-protected secure client portal at app.frostgate.ai
- Risk posture dashboard (findings by severity, domain scores, remediation roadmap)
- Finding explainers with remediation guidance
- Remediation tracking (client can mark findings resolved)
- Report viewer with download
- 90-day access window

---

## Exclusions — What Is NOT Included

- **Continuous monitoring** — no recurring automated scans after engagement close
- **Automated recurring scans** — this is a point-in-time assessment
- **SAML/SSO integration** — portal uses password authentication only
- **Real-time alerts** — no alerting infrastructure; remediation is tracked manually
- **Penetration testing** — no active exploitation, no red team activity
- **Legal or compliance certification** — this is an assessment, not a certification or audit attestation that satisfies a regulatory body
- **Network traffic analysis** — passive surface scan only; no PCAP, no IDS/IPS integration
- **Custom compliance frameworks beyond the five supported** — additional frameworks are Phase 2 scope
- **Multi-tenant environments** — one Microsoft 365 tenant per engagement

---

## Customer Prerequisites

Before the assessment can begin, the client must:

1. Have an active **Microsoft 365 tenant** with Entra ID (formerly Azure AD)
2. Provide a **Global Administrator or Application Administrator** who can be present during the data collection session to authorize the FrostGate application registration and complete the Microsoft device-code authentication flow
3. Grant **FrostGate app registration** in their Azure AD tenant (operator provides setup instructions via `docs/operators/azure_ad_app_setup.md`; estimated 30 minutes)
4. Provide their **primary domain name** and any secondary email domains for DNS/email scanning
5. Provide **public-facing URLs** for web security header scanning
6. Block **3–4 hours** for the data collection session (75–90 minutes active; remainder for questionnaire walkthrough and report generation)
7. Sign the **Data Processing Agreement** (DPA) and **Statement of Work** (SOW) before data collection begins
8. Remit **50% upfront payment** (or 100% for design partner rate) before the session date

---

## Evidence Collection Process

### Phase 1 — Pre-Meeting Passive Scans (operator, before client session)

Day 1–3 before the meeting:

1. Operator runs DNS and Email Security scan (client domain — no auth required)
2. Operator runs Web Security Headers scan (client public URLs — no auth required)
3. Operator runs Network Scan if in scope (client IP/hostname list — no auth required)
4. All three scans complete with status "Scan complete" before the meeting begins

### Phase 2 — In-Meeting Authenticated Scans (operator + client, 75–90 minutes)

During the scheduled session:

1. Client administrator navigates to `microsoft.com/devicelogin` on their device
2. Operator initiates MS Graph Core scan; client enters the device code and authenticates
3. Operator proceeds through each MS Graph connector in sequence (OAuth Inventory, OAuth Risk, Endpoint Inventory, Entra Governance, Identity Protection, SharePoint, MFA, Conditional Access, Devices)
4. Operator narrates findings as they populate (this is the demo — client sees their AI tool inventory, compliance gaps, and exposure in real time)

### Phase 3 — Questionnaire Walkthrough (operator + client, 20–40 minutes)

5. Operator walks client through the 69-control NIST AI RMF questionnaire
6. Client provides context; operator records responses
7. Operator uploads any relevant policy documents (acceptable use policy, AI governance policy, etc.)

### Phase 4 — Post-Collection Processing (operator, 1–2 days after session)

8. Operator reviews and curates evidence
9. Operator triggers AI executive summary generation
10. Operator performs QA review of report content
11. Operator triggers QA-approve (requires `governance:qa_approve` scope; assessor cannot self-approve per SoD policy)
12. Report is submitted for production qualification

---

## Deliverables

| Deliverable | Timing | Notes |
|-------------|--------|-------|
| Secure portal access | Within 24 hours of QA approval | Named-user invitation sent via Resend; password delivered via separate secure channel |
| PDF report | Within 5–7 business days of data collection session | Signed via Vault Transit (see delivery condition below) |
| Risk posture dashboard | With portal access | Findings by severity, domain scores, remediation roadmap |
| NIST AI RMF coverage matrix | With portal access | 69-control view of current governance posture |
| Remediation roadmap | With portal access | Phased plan (0–30 days, 31–60 days, 61–90 days) |
| AI executive summary | Included in report | Plain-language summary for executive/board audience |
| 30-day check-in | 30 days after portal delivery | Re-scan of quick-win items; delta summary email |

### Report Delivery Condition

> **IMPORTANT:** Report signing requires Vault Transit to be provisioned with the IDENTITY, APPROVAL, and ACCEPTANCE signing keys (per TRUST-BINDING-001, PR #731). Vault Transit is not currently running in production. If Vault Transit is not provisioned at the time of engagement, portal access, the risk dashboard, the remediation roadmap, and the NIST coverage matrix will be delivered on schedule. The signed PDF report will be delivered within 5 business days of Vault Transit provisioning. This condition will be disclosed in writing in the SOW and confirmed at engagement kickoff.
>
> Vault Transit provisioning is an operator decision (see `docs/plans/revenue_first_roadmap_20261103.md` Section 12 for options). The lowest-cost path (Vault OSS on Railway, ~$5–10/month) satisfies the OFFER A technical requirement.

---

## QA Process

Before any report is delivered to a client:

1. Report is generated by the operator using the FrostGate console
2. Operator (or designated reviewer) completes QA review against the report checklist
3. Reviewer with `governance:qa_approve` scope approves the report
4. **Separation of duties enforced:** the person who ran the scans cannot be the same person who QA-approves the report (SoD policy enforced by platform)
5. Founder reviews and confirms no production report issuance until mandatory production controls pass (see `docs/commercial/founder_approval_checklist.md`)

---

## Delivery Milestones

| Milestone | Target |
|-----------|--------|
| Paper signed, payment received | Day 0 |
| Azure AD app registration scheduled | Day 0 (long-lead item — start immediately) |
| Pre-meeting passive scans complete | Day 1–3 |
| Data collection session | Day 5 |
| Evidence curation and QA | Day 6–8 |
| QA approve; portal access provisioned | Day 9 |
| Delivery meeting (portal walkthrough) | Day 10 |
| 30-day re-scan and check-in | Day 30 |

**Commitment:** Portal access and deliverables available within 5–7 business days of the data collection session.

---

## Payment Terms

| Option | Terms |
|--------|-------|
| Standard ($5,000) | 50% ($2,500) upon SOW execution; 50% ($2,500) upon portal delivery |
| Design partner ($2,500) | 100% upfront; in exchange for feedback interview, reference call rights, and tolerance for minor manual touches |

**Payment methods:** ACH, check, or Stripe-linked payment link (payment flow proven in test mode; see `docs/commercial/billing_verification_report.md` for L14-STRIPE gate status).

**Invoice:** Issued via FrostGate. Remittance to jason@frostgate.ai (wire/ACH instructions on invoice).

---

## Acceptance Criteria

The engagement is considered delivered and the second payment is due when:

1. Client can log into the portal at app.frostgate.ai with their named-user credentials
2. Client can download or view the report
3. At least one finding is visible in the client's remediation dashboard
4. Portal access is confirmed by the client in writing (email is sufficient)

---

## Competitive Differentiation (FOUNDER DIRECTIVE)

This assessment is not a questionnaire. It is not a static PDF. It is not a Big 4 engagement.

| Competitor class | What they produce | What FrostGate produces |
|-----------------|-------------------|------------------------|
| Traditional GRC platforms (ServiceNow, OneTrust) | Workflow and questionnaire responses | Assessor-led field evidence with provenance chain |
| AI governance platforms (Credo AI, Fairly AI) | Model governance | Enterprise AI tool governance with field-assessed evidence — categorically outside their capability |
| Compliance automation (Vanta, Drata) | Questionnaire automation | Deterministic evidence chain, assessor-verified findings |
| Security assessment firms (Big 4, boutiques) | Static PDF report | Living portal, remediation tracking, re-scan at 30 days |

**The compounding moat:** Every engagement adds to the institutional memory of that client's governance posture. After five engagements, the governance graph, the evidence chain, and the RAG corpus are irreplaceable artifacts that cannot be migrated to a competitor.

---

## Price

| Tier | Price | Conditions |
|------|-------|-----------|
| Design partner | $2,500 | First 1–2 clients; full scope; feedback interview + reference call rights required |
| Pilot | $5,000 | Standard commercial rate; full scope |
| OFFER B premium | TBD | Requires cryptographic triple-signing (HCP Vault Dedicated); BLOCKED on cost authorization |

---

*This document is the canonical OFFER A product definition. It may not be changed without founder review. Delivery-conditional language in this document must be reproduced in every proposal, SOW, and client communication.*
