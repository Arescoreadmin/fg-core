# Founder Commercial Approval Checklist

**Purpose:** Jason Cosat must complete and sign this checklist before any client agreement is executed, any customer data is collected, or any production assessment begins.

**Authority:** `docs/plans/revenue_first_roadmap_20261103.md` Section 4; `docs/commercial/production_delivery_boundary.md`

**Instructions:** Complete every field. If any item is NO, resolve it before proceeding. Do not leave any field blank. This document becomes part of the engagement record.

---

## Engagement Identification

| Field | Value |
|-------|-------|
| Client organization name | |
| Client technical contact name and email | |
| Engagement start date | |
| FrostGate engagement ID | |
| FrostGate tenant_id | |
| Proposal/SOW date | |
| Data collection session scheduled date | |

---

## Commercial Checklist

| # | Item | YES / NO | Evidence |
|---|------|----------|----------|
| 1 | DPA reviewed and signed by both parties | | File location or date signed |
| 2 | SOW executed (or proposal accepted in writing) | | File location or date signed |
| 3 | Client technical contact identified by name | | Name on file |
| 4 | Azure AD access scope confirmed in writing (admin confirmed they can grant app registration) | | Email or message reference |
| 5 | Report delivery condition disclosed to client in writing (Vault Transit pending provisioning — PDF report delivery may be delayed; portal, dashboard, and roadmap are not affected) | | Email or SOW section reference |
| 6 | 50% upfront payment received (or design partner exception granted in writing by founder) | | Payment confirmation or exception record |
| 7 | Engagement created in FrostGate console with correct tenant_id | | Engagement ID above |
| 8 | Engagement ID and tenant_id recorded in this document | | See fields above |
| 9 | Delivery timeline committed in writing (5–7 business days after data collection session for portal access) | | SOW or email reference |
| 10 | Founder confirms: no production report issuance until all mandatory production controls pass (see production_delivery_boundary.md) | | Founder signature below |

---

## Design Partner Exception (if applicable)

If the engagement is at the design partner rate ($2,500):

| Field | Value |
|-------|-------|
| Design partner rate granted? | YES / NO |
| Exception granted by | Jason Cosat |
| Exception date | |
| Conditions: feedback interview within 7 days of portal delivery | Confirmed? YES / NO |
| Conditions: reference call rights subject to client approval | Confirmed? YES / NO |
| Reason for design partner rate (record for learning) | |

---

## Production Gate Status at Time of Engagement

The following production controls must be confirmed before any customer data is collected or any production report is issued. Record the status at the time of this checklist completion.

| Control | Status at engagement date | Evidence reference |
|---------|--------------------------|-------------------|
| Vault Transit provisioned (IDENTITY, APPROVAL, ACCEPTANCE keys) | | |
| PRODUCTION_DEPENDENCY_SECURITY attested | | P0-DEP-REM-001 (#786) evidence satisfies this — attestable now |
| PRODUCTION_SCHEMA_AND_RLS attested | | |
| CANONICAL_ASSESSMENT_PROOF attested | | |
| DURABLE_EXECUTION_AND_RECOVERY attested | | |
| Mode B production authentication (PRODAUTH-RUN-001) executed | | |
| Portal live verification (PORTAL-RUN-001) executed | | |
| DELIV-001 confirmed (approved report deliverable to portal named user in production) | | |

**Gate policy:** No production assessment data may be collected and no production report may be issued until all eight controls above are marked confirmed with evidence. Commercial agreements may be signed and engagements may be scheduled before gates are confirmed. Data collection may not begin until all eight controls are confirmed and this checklist is signed by the founder.

This policy aligns with `docs/commercial/production_delivery_boundary.md`. There is no exception allowing data collection while any control remains unconfirmed.

---

## Attestation

I confirm that all items above are accurate. I have reviewed the commercial documents, confirmed payment, and verified the production gate status. No production assessment evidence will be collected and no production report will be issued until all mandatory production controls are proven.

I understand that the report delivery condition (Vault Transit pending provisioning) has been disclosed to the client in writing and that the client has accepted these terms.

**Founder:**

Signed: _________________________________ Date: ___________

Jason Cosat, Founder
FrostGate | jason@frostgate.ai

---

## Post-Engagement Closeout

Complete after the engagement is closed:

| Field | Value |
|-------|-------|
| Portal delivery date | |
| Report delivery date | |
| Second payment received date | |
| 30-day check-in completed | |
| Feedback interview completed (design partner) | |
| Reference call rights confirmed | |
| Data deletion date (90 days after engagement) | |
| Post-engagement retrospective filed | |

---

*This document is part of the engagement record and must be retained for the duration of the data retention period (90 days from engagement date per the DPA). It is a founder-level control document and must not be delegated or completed by anyone other than Jason Cosat until a formal delegation procedure is established.*
