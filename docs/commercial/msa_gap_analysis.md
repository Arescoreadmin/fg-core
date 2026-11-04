# MSA Review Checklist and Gap Analysis

**Date:** 2026-11-03
**Reviewed by:** L14-COMMERCIAL-ACTIVATION-001 audit
**Canonical DPA:** `contracts/dpa_template.md`

---

## What the DPA Covers

The existing Data Processing Agreement (`contracts/dpa_template.md`) provides coverage for:

| Topic | Coverage | Notes |
|-------|----------|-------|
| Subject matter and purpose | Yes | Assessment services, Microsoft 365 scope |
| Nature of processing | Yes | Four processing activities enumerated with legal basis |
| Data categories | Yes | Identity metadata, security configs, app registrations, device metadata, DNS records, HTTP headers |
| Sub-processors | Yes | Railway, Vercel, Anthropic, Auth0 — each with role, data transferred, location, and SOC 2 status |
| Retention period | Yes | 90 days; early deletion on request within 5 business days |
| Data subject rights | Yes | Controller/processor roles established; FrostGate assists with requests within 5 business days |
| Breach notification | Yes | 72-hour notification commitment; notification contents enumerated |
| Security measures | Yes | TLS in transit, encryption at rest, API auth, MFA, HMAC audit chain |
| Audit rights | Yes | Written summary once per year; on-site with 30 days notice; can satisfy via SOC 2 reports |
| Term and termination | Yes | Effective from engagement date; 10-day deletion on termination |
| Governing law | Partial | State placeholder present; actual state must be filled |
| Controller/processor roles | Yes | Client = controller; FrostGate = processor |

---

## What Is MISSING for a First Commercial Engagement

The DPA is a data processing agreement only. It does not constitute a full commercial framework. The following items are absent and must be addressed before or concurrent with the first paid engagement:

### 1. Full Master Services Agreement (MSA) — MISSING

Required clauses not present in DPA or SOW template:

| Clause | Why needed |
|--------|-----------|
| Limitation of liability | Without a cap, FrostGate has unlimited liability for any claim arising from the engagement. The standard market term is a cap equal to fees paid in the prior 12 months. |
| Indemnification | Mutual indemnification (each party indemnifies the other for its own acts/omissions) is standard. Without it, indemnification obligations are determined by common law — unpredictable and expensive. |
| Warranty disclaimers | The assessment is provided "as is" to the extent permitted by law. The report is not a warranty that all vulnerabilities have been found. This needs to be explicit. |
| Governing law and venue | The DPA has a placeholder. The SOW template has none. Both need governing law and venue specified. |
| Entire agreement / integration clause | Needed to prevent prior representations from becoming contractual obligations. |
| Force majeure | Standard commercial boilerplate. |
| Amendment process | How the agreement is modified in writing. |
| Assignment | Whether either party can assign the agreement. |

### 2. Acceptable Use Policy — MISSING

The DPA governs data processing. It does not govern what the client may do with the report, the portal access, or the findings. A short AUP (1–2 pages) should address:
- Client may not resell the report or portal access
- Client may not use FrostGate outputs to represent a certified compliance status
- Client may share the report with internal staff, counsel, auditors, and regulators

### 3. SLA Terms — MISSING

The SOW template commits to delivery timelines (5–7 business days, 30-day check-in) but does not specify:
- Remedies for missed timelines
- Support response commitments
- Portal availability expectations during the 90-day window

For the first engagement, a simple statement that "FrostGate will use commercially reasonable efforts to meet the delivery timelines in the SOW, and will notify Client promptly if a timeline cannot be met" is sufficient. A formal SLA is Phase 2 scope.

### 4. Report Defensibility Warranty Scope — MISSING

The report is based on evidence collected during the engagement session. The assessment reflects the security posture at the time of collection. Clients in regulated industries may ask:
- Is this report defensible in a regulatory examination?
- Can we cite this in a board resolution?

FrostGate must document what the report is (a point-in-time, assessor-verified, evidence-chained assessment) and what it is not (a certified audit, a legal opinion, a guarantee of complete coverage). This should be in the MSA as a warranty disclaimer and in the report itself.

### 5. AI Usage Disclosure — MISSING

The DPA lists Anthropic as a sub-processor for AI executive summary generation and notes that client data is not used to train Anthropic models. However, the engagement materials do not include an explicit AI disclosure to the client explaining:
- What AI is used for (executive summary generation only — not scan results, findings, or risk scores)
- What data is sent to Anthropic (anonymized finding summaries and NIST control context — not raw identity data)
- That the AI output is reviewed and QA-approved by a human before delivery

This disclosure should be added to the DPA sub-processors section and to the SOW.

---

## Gap Assessment Summary

| Gap | Severity | Resolution path |
|-----|----------|----------------|
| Full MSA (liability cap, indemnification, warranties) | HIGH — do not close a paid engagement without it | Have counsel draft a 2–4 page MSA |
| Governing law / venue | HIGH — DPA has placeholder; SOW has none | Fill in or have counsel recommend |
| Acceptable use policy | MEDIUM — first client may not ask, but protect early | Add 1-page AUP to engagement packet |
| SLA terms | LOW — first engagement is design partner; expectations are set by conversation | Add "commercially reasonable efforts" language to SOW |
| Report defensibility warranty scope | MEDIUM — regulated clients may ask | Add disclaimer to MSA and report template |
| AI usage disclosure | MEDIUM — increasingly asked by enterprise buyers | Add explicit AI disclosure to DPA and SOW |

---

## Recommended Next Step

**Before the first paid close:** Have counsel draft a 2–4 page Master Services Agreement to accompany the DPA. The MSA should cover limitation of liability, indemnification, warranty disclaimers, governing law, and an entire-agreement clause. Total estimated legal cost for a first draft from an attorney familiar with technology services: $500–$1,500.

**For the design partner engagement:** A fully executed DPA and SOW are the minimum required. The gap items above represent risk that the founder should understand and accept in writing before proceeding without a full MSA. See `docs/commercial/founder_approval_checklist.md` item 1 for the required attestation.

---

*This gap analysis does not constitute legal advice. All legal documents should be reviewed by qualified counsel before execution.*
