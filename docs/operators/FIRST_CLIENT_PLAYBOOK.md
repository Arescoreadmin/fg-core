# First Client Playbook — The Script for the Stage 1 Engagement

**Purpose:** the operational script for FrostGate's first design-partner engagement. Not a technical document — the technical procedures live in the runbooks it links. This is what the founder-operator follows, says, sends, and measures, start to finish.
**Living document:** annotate it after every engagement (retro §9 feeds it directly) — mark what was wrong, what was unnecessary, what was missing, dated inline. The value of this playbook is the accumulated corrections, not the first draft; expect to simplify it by client #5 and to be surprised by it at client #20.
**Preconditions:** every Launch DoD item checked (`docs/governance/audits/client_launch_readiness/LAUNCH_DEFINITION_OF_DONE.md`). If any L-item is unchecked, this playbook does not start.
**Companion documents:** `first_client_prep.md` (day-of pre-flight) · `onboarding_runbook.md` (scan procedures) · `console_user_guide.md` · `credential_delivery.md` (⚠ rewrite pending, plan T14 — its PORTAL_PASSWORD instructions predate the named-user cutover and are rejected by production) · `letters/` #1–#6 · DPA template.

---

## 1. Customer profile — who qualifies for Stage 1

| Criterion | Requirement | Why |
|-----------|-------------|-----|
| Size | 25–500 employees | Fits the 13.5-hour delivery model; big enough for real findings |
| Stack | Microsoft 365 tenant, admin access reachable | 10 of 13 scan types depend on it; non-M365 collapses the value story |
| Sector | Regulated-adjacent: medical group, law firm, community bank, insurance agency | Pressure-aware buyer; matches playbooks and report language |
| Regulatory posture | **No** active exam, audit, or breach in flight; no hard deadline inside 90 days | A design partner absorbs rough edges; a firm under exam cannot |
| Relationship | Warm — founder knows the decision-maker or is one referral away | Honest feedback + patience are the product of this engagement |
| Buyer | Practice administrator / managing partner / compliance officer with authority to sign the authorization letter and DPA | One engagement = one accountable signer |

**Disqualifiers (decline politely, keep for Stage 2/3):** CMMC-mandated defense contractor; requires vendor SOC 2 attestation; non-M365; expects an SLA; expects the engagement to satisfy a regulator directly.

**Deal terms:** discounted from the price card with explicit design-partner framing — reduced fee in exchange for feedback interview, reference call rights (subject to their approval), and tolerance for manual touches. Put the discount and the feedback obligation in the proposal (letter #1).

## 2. Onboarding checklist (operator side)

Before first contact → signed paper → technical setup, in order:

- [ ] Qualification confirmed against §1 (write one paragraph on *why* they qualify; goes in the retro)
- [ ] Proposal sent (letter #1, with price card + response-time expectation + design-partner terms)
- [ ] Authorization letter signed (letter #2) — scans do not run without it
- [ ] Data-handling notice delivered (letter #3) + DPA signed
- [ ] CG v0 one-pager included in the packet (planted early; pitched at delivery)
- [ ] Tenant provisioned in console (`/admin/tenants`) — verify portal key persisted (no `PERSISTENCE_UNAVAILABLE`)
- [ ] Engagement created; assessment type selected; client domain recorded
- [ ] Azure AD app setup scheduled with their IT (per `azure_ad_app_setup.md`) — this is the long-lead item; start it the day paper is signed
- [ ] Client contact invited to portal; **confirm they received the email** (check spam folder together on a call if needed)
- [ ] Pre-engagement `pg_dump` taken (per `backup_restore.md`)
- [ ] Pre-flight checklist from `first_client_prep.md` executed the day before the meeting

## 3. Assessment timeline (2-week wall clock)

| Day | Activity | Who |
|-----|----------|-----|
| 0 | Paper signed; tenant + engagement created; Azure AD setup begins | Operator + client IT |
| 1–3 | No-auth scans run (DNS/email, web headers, network) — **before the meeting, always** | Operator |
| 3–4 | Portal invite accepted; client sees "assessment in progress" | Client contact |
| 5 | **On-site/remote meeting (75–90 min):** device-code scans + interviews (agenda §4) | Operator + client |
| 6–8 | Questionnaire completion, evidence curation, findings review | Operator |
| 9 | Report generated → QA checklist → QA approve → engagement `delivered`; confirm client portal access is live (named-user session — the console-displayed access code is not consumed by production auth; see `credential_delivery.md` rewrite, plan T14) | Operator |
| 10 | **Delivery meeting (45–60 min):** report walkthrough + portal tour + CG v0 pitch (§6) | Operator + client |
| 10–24 | Client works remediation in portal; operator monitors (≤1h/week) | Client |
| ~30 | 30-day follow-up (letter #5) + verification re-scan | Operator |

## 4. Meeting agendas

**Assessment meeting (75–90 min):**
1. (5 min) Frame: what will happen, what they'll see live, what they get at the end.
2. (10 min) Confirm authorization + scopes verbally against the signed letter — say the connector names out loud.
3. (40–50 min) Device-code scans (per `onboarding_runbook.md` order), narrating discoveries as they land — *"this is your AI tool inventory populating"* is the demo.
4. (15–20 min) Structured interviews (playbook roles for the assessment type).
5. (5 min) What happens next + delivery date commitment.

**Delivery meeting (45–60 min):**
1. (10 min) Executive summary walkthrough — business language only.
2. (10 min) Top findings + immediate actions ("if you do three things this month, these").
3. (15 min) Portal tour: findings → explainers → mark-resolved flow → roadmap. Have them click, not you.
4. (10 min) CG v0 pitch at the trust peak (§6).
5. (5 min) 30-day follow-up scheduled *in the meeting*, not by email later.

## 5. Communications plan

| Moment | Channel | Template |
|--------|---------|----------|
| Proposal / authorization / data handling | Email | Letters #1–#3 |
| Portal invite | System (Resend) | Built-in; verify delivery personally |
| Portal access | Named-user invite (verify received; walk through accept-invite on a call if needed) | — |
| Report delivered | Email | Letter #4 |
| Weekly during remediation window | Short personal email (manual — this is CG v0 practice) | 3 sentences: what changed, what's next, one ask |
| 30-day follow-up | Email + call | Letter #5 |
| Close-out / renewal | Email | Letter #6 |
| Any incident affecting them | Phone first, then email | Template in incident runbook |

Response-time commitment (from letter #1): business-hours, same-day acknowledgment. Do not promise more.

## 6. Expected deliverables

1. Executive PDF report (QA-checklist-passed) with manifest hash and data-collected appendix.
2. Portal access: risk dashboard, findings with explainers, remediation roadmap, coverage matrix, report viewer + verify.
3. Verification bundle status visible on their engagement.
4. 30-day verification re-scan + delta summary (their first taste of CG).
5. Close-out letter with posture summary.

When describing the record FrostGate keeps, use only the approved external framing: *"FrostGate preserves a continuously verified institutional record of evidence, decisions, exceptions, remediation, and reviewer rationale that would otherwise be fragmented or lost over time."* Pair with the portability story (export + verification bundles) if procurement asks.

## 7. Success criteria (this engagement)

From Stage 1 of the rollout plan — all measurable, all binary:
- [ ] Delivered within the 75–90 min in-meeting budget
- [ ] Report accepted without rework
- [ ] Client logs into portal unaided within 48h of invite
- [ ] Client marks ≥1 finding resolved within 21 days
- [ ] Zero cross-tenant / integrity incidents
- [ ] ≤2 support interventions for navigation confusion
- [ ] CG v0 pitched at delivery (outcome recorded either way)

## 8. Escalation path

| Situation | Action |
|-----------|--------|
| Scan fails in-meeting | Fall back per runbook: continue interviews, run scan post-meeting; never debug live >10 min |
| Portal lockout for client | Same-day fix; if >4h, deliver report by encrypted email and say so plainly |
| Platform incident during engagement | Incident runbook; client called (not emailed) if their data or timeline is affected |
| Any non-waivable-class event (tenant exposure, data loss, integrity failure) | **Stop the engagement.** Rollout stop conditions apply; founder communicates within 24h |
| Scope creep ("can you also assess X?") | "Great Stage-2 topic" — log it, don't deliver it |

## 9. Post-engagement retrospective (within 5 days of close-out)

Answer in writing, file alongside the dry-run log:

1. Actual hours per phase vs. the 13.5h model — update `CUSTOMER_COMMERCIAL_READINESS.md` numbers.
2. Every manual intervention not in a runbook (each is either a runbook edit or a Stage-2 backlog item).
3. Every support touch and its cause (navigation? wording? bug?).
4. Which report sections the client actually read/quoted (informs Report v2 priorities).
5. Where in the journey did the client hesitate or go quiet? (feeds journeyState design)
6. Did the discoveries-first dashboard land? What did they say at minute five?
7. What did they push back on in the DPA/paper?
8. Would they refer us? To whom, in their words?

## 10. Feedback interview (30 min, scheduled at close-out)

Questions to ask verbatim:
- "What almost made you not do this?"
- "At what moment did you decide it was worth it?"
- "What would you tell a peer this is?" (their words become the positioning)
- "What did you expect that didn't happen?"
- "If the monthly version existed today at $X, would you buy it? Why/why not?" (CG v0 validation)
- "Who else should see this report inside your org?" (Report v2 audience evidence)

## 11. Metrics to capture (fills the Stage-2 gate)

| Metric | Where recorded |
|--------|----------------|
| Hours per phase (actuals) | Retro §9.1 |
| In-meeting duration | Meeting notes |
| Time-to-first-portal-login after invite | Portal session records |
| Findings: total / resolved by day 21 / by day 30 | Engagement data |
| Support touches (count + cause) | Retro §9.3 |
| Defects found post-launch (count + severity) | Defect log |
| CG v0 outcome (signed / declined + reason) | Retro |
| Referral willingness | Feedback interview |

## 12. Evidence that unlocks Stage 2

Per the rollout plan, proceed to full-price clients only when: all §7 success criteria pass · retro complete with actual hours recorded · every manual intervention dispositioned (runbook edit or backlog item) · zero open non-waivable-class incidents · founder go decision recorded in `CLIENT_READINESS.md`. If any criterion fails: fix, and either extend the design-partner phase or run a second discounted engagement — do not price up on an unproven delivery motion.
