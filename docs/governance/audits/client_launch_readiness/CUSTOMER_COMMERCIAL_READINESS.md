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

## Pre-launch commercial checklist (founder, ~0 engineering days)

1. Price card for the FA engagement in proposal template.
2. Response-time expectation sentence in letter #1.
3. DPA cross-check after FG-LR-005/006 land (breach + retention now backed by process).
4. Anthropic auto-recharge (FG-LR-013).
5. Confirm Stripe invoice (not checkout) flow for engagement billing.
