# Statement of Work
## FrostGate AI Governance Field Assessment

> **DISCLAIMER: This template has not been reviewed by legal counsel. Obtain legal review before execution with any client.**

---

## Parties

**Service Provider:**
Jason Cosat, operating as FrostGate
jason@frostgate.ai | [PHONE]
[ADDRESS]

**Client:**
[CLIENT ORGANIZATION]
[CLIENT ADDRESS]
[CLIENT CONTACT NAME], [CLIENT CONTACT TITLE]
[CLIENT CONTACT EMAIL]

---

## Effective Date and Term

**Effective date:** [DATE]
**Engagement term:** From the effective date through 90 days after portal delivery, or until all data is deleted per the Data Processing Agreement, whichever is later.

---

## Services Description

FrostGate will provide a single-engagement AI Governance Field Assessment as described in the OFFER A product definition (`docs/commercial/offer_a_pilot_package.md` on file with FrostGate). The assessment covers:

- Passive infrastructure scans: DNS and Email Security, Web Security Headers, Network Scan
- Authenticated Microsoft Graph scans (13 connector types) using device-code OAuth
- 69-control NIST AI Risk Management Framework 1.0 questionnaire
- Risk scoring across 6 governance domains
- Compliance framework gap analysis: [LIST APPLICABLE — HIPAA / SOC 2 / CMMC 2.0 / ISO 27001]
- AI-generated executive summary
- QA review and approval by FrostGate before delivery

This is a point-in-time assessment. It does not include continuous monitoring, recurring automated scans, or ongoing access to the FrostGate platform beyond the 90-day portal window.

---

## Client Obligations

Client agrees to:

1. Grant FrostGate's Azure AD application registration in Client's Microsoft Entra ID tenant before the data collection session. FrostGate will provide setup instructions. Estimated client effort: 30 minutes. This is the long-lead item and must be completed before the session date.
2. Make a Global Administrator or Application Administrator available during the data collection session to complete the Microsoft device-code authentication flow.
3. Designate a technical contact (name and email) for the duration of the engagement.
4. Provide primary domain name, any secondary email domains, and public-facing URLs.
5. Provide any IP addresses or hostnames for the network scan (if in scope).
6. Complete and sign the Data Processing Agreement (DPA) before data collection begins.
7. Remit payment per the schedule in Section 7 below.
8. Make a decision maker available for the data collection session (Day 5) and delivery meeting (Day 10).

---

## FrostGate Obligations

FrostGate agrees to:

1. Run all 13 connectors in scope during the data collection session.
2. Generate the AI executive summary and compile the full report within 5–7 business days of the data collection session.
3. QA review and approve the report before delivery.
4. Provision portal access (named-user invitation) within 24 hours of QA approval.
5. Deliver the portal URL and access credentials to [CLIENT CONTACT EMAIL] via secure channel (URL and password delivered separately).
6. Conduct a 45–60 minute delivery meeting to walk through findings and demonstrate the portal.
7. Conduct a 30-day check-in re-scan and deliver a delta summary.
8. Respond to business-hours inquiries within the same business day.
9. Not share findings with any third party except as required by law.

---

## Deliverables and Acceptance Criteria

| Deliverable | Timeline | Acceptance |
|-------------|----------|------------|
| Pre-meeting passive scans complete | Before data collection session | Scan status "complete" in FrostGate console |
| Secure portal access | Within 24 hours of QA approval | Client logs into portal using named-user credentials |
| Risk dashboard and remediation roadmap | With portal access | Visible in portal on first login |
| NIST AI RMF coverage matrix | With portal access | Visible in portal |
| PDF report | Within 5–7 business days of data collection session (see delivery condition below) | Client can download report from portal |
| 30-day check-in summary | 30 days after portal delivery | Delivered by email or in portal |

### Report Delivery Condition

Report signing requires FrostGate's Vault Transit signing infrastructure to be provisioned with IDENTITY, APPROVAL, and ACCEPTANCE keys (per FrostGate's internal TRUST-BINDING-001 control). If Vault Transit is not provisioned at the time of engagement execution, the PDF report will be delivered within 5 business days of Vault Transit provisioning. All other deliverables — portal access, risk dashboard, and remediation roadmap — will be available on the standard timeline. FrostGate will notify Client in writing if this condition applies at engagement kickoff.

**The existence of this condition does not change the payment schedule.** Portal delivery triggers the second payment installment regardless of report signing status, provided portal access, risk dashboard, and remediation roadmap are accessible.

---

## Payment Schedule

| Milestone | Amount | Due |
|-----------|--------|-----|
| SOW execution | $[2,500 / 100%] | At or before the data collection session date |
| Portal delivery | $[2,500 / N/A] | Within 5 business days of portal access confirmed |

**Total:** $[5,000 / 2,500]

[IF DESIGN PARTNER: This engagement is at the design partner rate of $2,500 paid in full at execution. Client agrees to: (a) a 30-minute feedback interview within 7 days of portal delivery, and (b) reference call rights subject to Client's reasonable approval.]

Payment by ACH, check, or Stripe payment link. FrostGate will issue an invoice upon SOW execution.

---

## IP Ownership

Client retains ownership of all data collected from Client's systems. Client grants FrostGate a limited license to process this data solely for the purpose of delivering the services described in this SOW.

FrostGate retains ownership of its platform, connectors, algorithms, and methodology. FrostGate may use aggregate, anonymized benchmark data derived from multiple client engagements (with all client-identifying information removed) for internal benchmarking and product improvement. No client-identifiable data is used in this manner.

The PDF report and portal deliverables are provided to Client for Client's internal use. Client may share the report internally and with counsel, auditors, or regulators.

---

## Confidentiality

Both parties agree to hold the other party's confidential information in confidence and not disclose it to third parties. This SOW supplements and is subject to any Master Services Agreement or standalone confidentiality agreement between the parties. In the absence of such an agreement, the Data Processing Agreement governs data-handling obligations.

---

## Data Retention

Assessment data is retained for 90 days from the engagement date as described in the Data Processing Agreement. The DPA governs all data retention, deletion, and breach notification obligations.

---

## Change Order Process

Any change to scope, timeline, or price requires a written change order signed by both parties before work begins. Changes requested after the data collection session that require additional scan runs will be quoted separately.

---

## Limitations

This assessment is a point-in-time evaluation based on evidence collected during the engagement session. It does not constitute a legal opinion, a regulatory compliance certification, or a guarantee that all security vulnerabilities have been identified. FrostGate is not a licensed attorney and this engagement does not create an attorney-client relationship.

---

## Signatures

**FrostGate:**

Signed: _________________________________ Date: ___________

Jason Cosat, Founder
FrostGate | jason@frostgate.ai

---

**[CLIENT ORGANIZATION]:**

Signed: _________________________________ Date: ___________

Name: _________________________________

Title: _________________________________

Organization: [CLIENT ORGANIZATION]

---

*This SOW incorporates by reference the Data Processing Agreement dated [DATE]. In the event of conflict, the DPA governs with respect to data processing obligations.*

*DISCLAIMER: This template has not been reviewed by legal counsel. Obtain legal review before execution.*
