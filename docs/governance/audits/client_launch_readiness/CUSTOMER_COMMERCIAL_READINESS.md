# Customer & Commercial Readiness

**Question:** can FrostGate deliver a professional *paid* engagement a client will trust, act on, and buy again?
**Answer:** the deliverable set is unusually complete for this stage; the commercial wrapper (pricing mechanics, billing, SLA) is thin but adequate for invoice-based white-glove delivery. **Customer readiness 6/10 · commercial readiness 5/10 · support readiness 4/10.**

---

## Deliverables inventory (what the client actually receives)

| Deliverable | State | Evidence |
|-------------|-------|----------|
| Executive PDF report — cover, AI exec summary (advisory-labeled), confidence assessment, severity-sorted findings, remediation plan, framework coverage, evidence appendix, manifest-hash footer | Built; current-stack render pending QA (FG-LR-011) | PR 38; `export_pdf_bytes` |
| Data-collected disclosure appendix (per-connector scopes, retention, redaction, transmission, operator authorization) | Built | E10/CLIENT_READINESS E10 |
| Portal: risk dashboard, findings w/ plain-language explanations, remediation roadmap w/ quick-wins, coverage matrix, attestation, report viewer + verify | Built (see PORTAL_UX_AUDIT) | PRs 22/28/31/32/33 |
| Verification bundle (deterministic hash snapshot, tamper detection) | Built; client-visible status card | #52, migration 0086 |
| Client access code delivery flow + credential delivery procedure | Built + documented | item 39; credential_delivery.md |
| Engagement paper: proposal, authorization letter, data-handling notice, DPA template, delivery/follow-up/close-out letters | Templates exist | letters/ 1–6; contracts/dpa_template.md |

**Finding clarity / remediation usefulness:** the explainer + step runbooks + quick-wins matrix directly answer "what do I do next" — the thing a Big-4 PDF never does. This is the core of customer-perceived value; protect it in the dry-run QA.

**Executive summary quality:** AI-generated with template fallback, advisory-labeled, language rules ("aligned with", never "certified") enforced in the legacy engine and by prompt design in FA. **Human QA on real data is the launch gate** (FG-LR-011) — an LLM summary that misstates a finding in a board-facing PDF is the single biggest deliverable risk.

## Commercial mechanics

| Area | State | Assessment |
|------|-------|------------|
| Service definition | Field assessment engagement (pre-meeting scans + in-meeting 75–90 min + report + 30-day follow-up) is concrete in runbooks | Adequate |
| Pricing support | Tier table exists (SYSTEM.md §12) but FA engagement pricing (vs. $299 self-serve Snapshot) isn't formalized anywhere | Set a price card in the proposal template — 0 eng days, founder task |
| Billing | Stripe webhook configured; billing v2/capability metering incomplete (open PRs, placeholder numbers) | **Invoice manually through client 10** (FG-LR-022). Do not finish metering pre-revenue |
| Contracts | DPA has sub-processor table (Railway/Vercel/Anthropic/Auth0), 72h breach notice, audit rights | Blocked on: retention promise vs. no purge (FG-LR-006); breach notice vs. no incident process (FG-LR-005) — both in plan |
| SLA readiness | No SLA instrumentation | Don't offer SLAs before stage 3; say "business-hours best effort" in the proposal |
| Support expectations | Operator-relationship model + portal FAQ | Right for segment; formalize response-time expectation in letter #1 |
| Retention/expansion path | Remediation loop → 30-day follow-up (letter #5) → re-scan (manual) → monitoring status | Mechanically possible, not yet productized (FG-LR-020) — fine until client 3 |

## Will the customer…

- **Understand the value?** Yes — the portal home shows severity, coverage, and immediate actions on first login; the report opens with a business-language summary. Risk: NIST jargon (1-line tooltips, in FG-LR-008 day).
- **Trust the result?** Above-segment-norm trust artifacts (manifest hashes, verify page, disclosure appendix, DPA). Trust is most at risk from the *stub pages* and any login friction — both cheap fixes.
- **Know what to do next?** Yes — immediate-actions callout, phased roadmap, per-finding steps.
- **Receive a professional deliverable?** Pending FG-LR-011 QA. The bones are professional.
- **Return / expand?** The follow-up motion is manual but real (letters + re-scan). Continuous governance conversion needs productizing before it can carry revenue (post-launch).

## Competitive differentiation (FOUNDER_DIRECTIVE lens)

Every deliverable above should be framed in sales materials against the four competitor classes: the *disclosure appendix + manifest hash + verification bundle* displaces assessment-firm PDFs (no verifiable provenance); the *remediation closed loop with evidence capture* displaces GRC workflow tools (tickets without evidence); the *assessor-led scan suite across 13 connectors* is categorically outside Vanta/Drata questionnaire automation; and the AI-governance-specific findings (AI tool discovery, OAuth risk, vendor governance) are outside Credo/Holistic's model-governance surface. **[MOAT-WIDENING]** assets already shipped; the launch materials just have to say so.

## Operating model math (the numbers that decide whether this scales)

Hour estimates are derived from the runbooks (`first_client_prep.md` budgets 75–90 min in-meeting; `onboarding_runbook.md` splits pre-/in-meeting) plus reasonable allowances — classification: **strong inference / assumption**, to be replaced with actuals from the Stage-1 engagement retro. Timing yourself is already an H-step (H18); extend it to the whole engagement.

### Hours per engagement (solo operator)

| Phase | Est. hours |
|-------|-----------|
| Pre-sale call, proposal, authorization letter, scheduling | 2.0 |
| Azure AD app setup with client IT (or verify) | 1.0 |
| Pre-meeting no-auth scans + review | 1.5 |
| In-meeting: device-code scans + interviews | 1.5 |
| Questionnaire completion + evidence curation | 3.0 |
| Findings curation, report generation, QA, PDF review | 2.5 |
| Delivery meeting + portal walkthrough + access-code handoff | 1.0 |
| 30-day follow-up (review + call) | 1.0 |
| **Total per engagement** | **~13.5 h** |

### Capacity, pricing, and timeline

**Stated assumptions behind every number in this section** — revise the numbers when any assumption changes, and record the change here:

1. **One founder-operator** doing delivery, engineering, and sales — no second operator, no subcontractors.
2. **Microsoft 365 clients only** — the 13.5 h estimate assumes the full connector suite applies; a non-M365 client shifts hours from scans to interviews and breaks the estimate.
3. **Current automation level** — manual CG v0, manual re-scans, manual report QA; every Stage-3 automation item (FG-LR-014) reduces the recurring hours, not the engagement hours.
4. **Current engagement scope** — AI-governance field assessment per the runbooks; a CMMC-track or multi-site engagement is out-of-model.
5. **Local/remote delivery mix** — travel time excluded; on-site engagements add it back.

- **Onboarding capacity:** under the assumptions above, **1–2 engagements/week** sustained (~13.5 h each + context switching); burst 3. This independently confirms the rollout caps (Stage 2 = 3 concurrent, Stage 3 = 10 total) — they are operator-capacity numbers, not just risk numbers.
- **Delivery timeline per client:** ~2 weeks wall-clock (week 1: setup + scans + meeting; week 2: report + QA + delivery), then a 30/60/90-day remediation tail at ≤1 h/month.
- **Pricing floor (math, not advice):** at 13.5 operator-hours and a specialist-advisory effective rate of $250–400/h, the assessor-led engagement must price at **$3.5k–$5.5k minimum** to be a business. The $299–999 "Snapshot" tier (SYSTEM.md §12) is *self-serve* pricing and must not anchor the assessor-led offer — the current proposal template has no price card at all, which is how mispricing happens. The deliverable stack (13 scans, signed report, verified evidence, remediation portal, 30-day follow-up) supports mid-market pricing at that level against a Big-4-lite alternative costing 5–10×.
- **Support load:** delivery week ~2 h/client; steady-state ≤1 h/client/month (portal self-serve absorbs the rest). At 10 clients: ~10–15 h/month of support+follow-up — the ceiling of solo operation, which is exactly where Stage 3's automation gate (digests, re-scans) and second-operator requirement sit.
- **Renewal/upsell triggers (calendar-anchored, all already in the system):**
  - **Report delivery** → the CG offer (peak-trust moment; see below).
  - **Day 30** → follow-up letter #5 + remediation verification re-scan.
  - **Day 90** → the DPA retention boundary forces a contact: *purge or continue?* — turn the compliance obligation (FG-LR-006) into the renewal conversation.
  - **Quarterly** → CG review call (below).

## Executive report — target specification (not just "PDF generation")

The current PDF (PR 38: cover → AI exec summary → confidence → findings → remediation plan → framework coverage → evidence appendix + disclosure) is a strong *assessor's* report. An *enterprise buyer's* report has a different spine — it must let a CISO hand it upward without translation. Target chapter architecture, mapped against what exists:

| # | Target chapter | Exists today? | Gap and action |
|---|----------------|---------------|----------------|
| 1 | Executive summary (1 page, board language) | ✅ AI-generated, advisory-labeled (PR 27) | QA for tone in FG-LR-011; keep |
| 2 | **Business risk** — what these findings mean for *this* org's operations, clients, regulators | ⚠️ partial — severity/posture exists, but framed technically | Prompt + template work: industry-specific risk narrative ("for a medical group, finding X means…") — the playbook sector data already exists to condition it |
| 3 | **Financial impact** — categorized exposure, not dollar predictions | ❌ missing | v2: **categorize first, quantify only where defensible.** Every finding maps to one or more impact categories: **Regulatory Exposure · Operational Risk · Productivity · AI Governance · Data Protection · Business Continuity.** The chapter leads with the category profile ("your exposure concentrates in Regulatory and AI Governance"); dollar ranges appear *only* where a citable benchmark exists (published breach-cost studies, regulator fine schedules), always as ranges with the citation inline and a methodology note. Never "estimated annual savings," never single-point figures. This is strictly easier to defend in front of a board or regulator than any savings model, and the category mapping is deterministic from finding class — no AI in the loop for the categorization itself |
| 4 | **Top 10 actions** — one page, ranked, owner + effort | ⚠️ exists as data (immediate actions, quick-wins matrix in portal) but not distilled in the PDF | Lift into a dedicated PDF page — mostly serialization work |
| 5 | Roadmap (30/60/90) | ✅ (PR 31) | keep |
| 6 | Technical appendix (findings detail) | ✅ | keep |
| 7 | Evidence + provenance (manifest hash, data-collected disclosure, verification bundle reference) | ✅ — best-in-segment | keep; this chapter *is* the moat made visible |

**Action: FG-LR-026, "Report v2" — ~3 days, Stage 2→3 package.** Chapters 2–4 are content/serialization work on existing data, not new pipelines. For launch, the current report passes with FG-LR-011 QA; the v2 spine is what converts reports from deliverables into sales assets for the *next* buyer up the chain.

## Continuous Governance — the recurring-revenue engine (CG v0 costs zero engineering days)

Deferring the CG *scheduler* is right; deferring the CG *offer* would be wrong. The one-time assessment is the customer-acquisition event; CG is the business. The launch version needs no new engineering — every step below runs on shipped features, manually:

```
Assessment → Baseline → Monthly drift check → Quarterly review → AI governance updates → Risk trend → Renewal
```

| CG v0 step | Cadence | How it runs today (0 eng days) |
|-----------|---------|--------------------------------|
| Baseline | at delivery | The delivered report + verification bundle *is* the baseline (immutable, signed — migration 0086) |
| Drift check | monthly | Operator re-runs the scan suite on the same engagement (supported today); reviews new/changed findings; sends a templated delta email (letters framework) |
| Quarterly review | quarterly | 30-min call + regenerated report version (report versioning exists); refreshed coverage matrix |
| AI governance updates | continuous | AI tool discovery / OAuth risk / vendor governance re-scans surface new AI adoption — the exact recurring anxiety this segment buys relief from |
| Risk trend | quarterly | Risk-history snapshots + Recharts trend (PR 37) — already built for workforce; extend framing to engagement posture in v1 |
| Renewal | month 12 | Anchored by the day-90 retention decision and four quarterly touchpoints — the client has been *receiving* the subscription all year |

**Pricing shape:** $750–1,500/month against ~2–3 operator-hours/month keeps CG margin-positive from client one; it also means a single CG client is worth more per year than the assessment that acquired them.
**The pitch moment:** at report delivery — "this report is accurate today; here's how it stays accurate" — with the drift check as the demo (the platform can literally show what changed since the scans two weeks earlier).
**Moat note [MOAT-WIDENING]:** CG v0 is what starts the longitudinal drift history — the irreversible, non-backfillable asset (`MOAT_ASSESSMENT.md`). Every month a client is on CG v0, the switching cost compounds, even while the automation is still manual behind the curtain.
**Automation path:** Stage 3 replaces the manual steps with FG-LR-014 (digests, scheduled re-scans) and turns the `/changes` stub into the client-facing delta view — the CG v0 client base defines exactly what to automate first.

## Pre-launch commercial checklist (founder, ~0 engineering days)

1. Price card for the FA engagement in proposal template — **anchored at $3.5k–$5.5k, not Snapshot pricing** (math above).
2. CG v0 one-pager (offer, cadence, price) — pitched at every report delivery from client one.
3. Response-time expectation sentence in letter #1.
4. DPA cross-check after FG-LR-005/006 land (breach + retention now backed by process); frame the day-90 retention contact as the renewal touchpoint.
5. Anthropic auto-recharge (FG-LR-013).
6. Confirm Stripe invoice (not checkout) flow for engagement + CG subscription billing.
7. Extend the H18 timer to full-engagement time tracking — replace the hour estimates above with actuals after Stage 1.
