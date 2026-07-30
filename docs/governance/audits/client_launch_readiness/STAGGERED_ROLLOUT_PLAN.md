# Staggered Rollout Plan

Gates are evidence-based: no stage advances on calendar time alone. All stages assume the 19-day pre-launch plan is complete.

---

## Stage 0 — Internal validation (now → ~2026-08-15)

- **Customer profile:** none (FrostGate's own tenant + synthetic client tenant).
- **Enabled:** everything, internally.
- **Process:** the 30-day plan Weeks 1–2 (portal proof, backup drill, full dry run, load check).
- **Success metrics:** H1–H18 pass; restore drill pass; rollback drill <15 min; headroom ≥30%.
- **Failure threshold / stop:** any P0 exit criterion unmet → stay in Stage 0, push dates.
- **Evidence to proceed:** dated logs for dry run, restore, rollback; report QA checklist signed.
- **Max concurrent clients:** 0. **Review cadence:** end of each week.

## Stage 1 — First design partner (~2026-08-27 → +3–4 weeks)

- **Allowed profile:** ONE friendly Central-Florida org, 25–500 employees, Microsoft 365 tenant, regulated-adjacent (medical group, law firm, community bank **without** an imminent exam), explicit pilot framing, discounted, DPA signed.
- **Explicitly excluded:** CMMC-mandated defense contractors; orgs demanding vendor SOC 2; non-M365 shops (connector value collapses to the 3 no-auth scans); anyone with a hard regulatory deadline inside 90 days.
- **Enabled:** field-assessment engagement E2E; portal (gated 6-item nav + conditional Assistant); PDF report; remediation loop.
- **Disabled/hidden:** self-serve funnel + checkout; console legacy wing; portal stubs; continuous-governance promises (verbal roadmap only); SLAs.
- **Onboarding:** per `onboarding_runbook.md` — no-auth scans pre-meeting; device-code scans in-meeting; pre-engagement `pg_dump`.
- **Support model:** founder white-glove; business-hours response expectation stated in proposal.
- **Monitoring:** UptimeRobot + Sentry alert rule + daily Railway metrics glance during engagement week.
- **Success metrics:** engagement delivered inside the 75–90 min in-meeting budget; report accepted without rework; client logs into portal unaided within 48h; client marks ≥1 finding resolved within 21 days; zero cross-tenant/integrity incidents; ≤2 support interventions for navigation confusion.
- **Failure thresholds:** portal lockout >24h; report defect the client catches before we do; any data-loss event.
- **Stop conditions (immediate, all stages):** cross-tenant exposure of any kind; evidence/audit-chain integrity failure on untampered data; unrecoverable data loss; AI report content asserting fabricated compliance claims. On stop: freeze onboarding, incident runbook, client comms within 24h, root-cause before resuming.
- **Rollback conditions:** repeated scan failures in-meeting → fall back to pre-collected evidence + manual walkthrough (runbook already splits phases).
- **Commercial motion:** **CG v0 offered at report delivery** (baseline → monthly manual drift re-scan + delta email → quarterly review → renewal; 0 engineering days — see `CUSTOMER_COMMERCIAL_READINESS.md` CG section). The design partner is the first CG v0 candidate; extend the H18 timer to full-engagement time tracking to replace the operating-model hour estimates with actuals.
- **Evidence to proceed:** signed report delivery + the success metrics above + retro doc listing every manual intervention + actual hours-per-engagement recorded.
- **Max concurrent:** 1. **Review cadence:** weekly + engagement-day standup with self.

## Stage 2 — First 3 paying clients (+~6 weeks after clean Stage 1)

- **Profile:** same as Stage 1 but full price; up to 3 concurrent; may include one referral outside the friendly circle.
- **Newly enabled:** 30-day follow-up re-scan (manual trigger, becomes standard); testimonial/reference ask; **CG v0 contracts** (manual delivery is now proven from Stage 1).
- **Still disabled:** SLAs; automated continuous governance; self-serve.
- **Pre-stage gate work (from backlog):** admin_gateway topology decision (FG-LR-019, 0.5d); close/land open WIP PRs to stop drift (FG-LR-024).
- **During-stage build (the Stage 2→3 investment package, ~8.5d as delivery allows):** Operator Home v1 (FG-LR-027, 3d) · portal journey shell + stepper (FG-LR-028, 2.5d) · Report v2 business-risk/financial-impact/top-10 chapters (FG-LR-026, 3d). Sequenced here because each is amplified by real client feedback and none is safe to build during the launch window.
- **Success metrics:** 3 engagements delivered with <1 buffer-day of unplanned engineering each; ≥2 clients active in portal at day 30; **≥1 CG v0 subscription signed**; ≥1 expansion conversation started; support load ≤2h/client/week after delivery week.
- **Failure thresholds:** any Stage-1 stop condition; >3 engineering days firefighting per engagement (signals ops debt — pause intake, fix).
- **Evidence to proceed:** all 3 delivered + day-90 retention purge executed on schedule for the earliest engagement (proves FG-LR-006 runbook) + updated dry-run log after any stack change.
- **Max concurrent:** 3. **Review cadence:** bi-weekly.

## Stage 3 — Up to 10 clients (~Q4 2026)

- **Profile:** widen to secondary segments (credit unions, insurance, mid-market tech); still M365-centric; first CMMC-track client allowed **only** with the dedicated CMMC playbook validated in a dry run.
- **Gate work required to enter (P2 backlog, ~9 days):** automated retention purge honoring legal holds; client email digests + scheduled re-scan (FG-LR-014) — **this is also the CG v0→v1 automation: the manual drift/review steps the CG clients have been receiving become system-delivered, and the `/changes` stub becomes the client-facing delta view**; metrics scraping + 3 SLOs (FG-LR-017); Redis-backed explainer cache if scaling instances (FG-LR-016); failed-scan-job triage (arrives with Operator Home, FG-LR-027).
- **CG economics check at this stage:** with up to 10 clients, manual CG (~2–3 h/client/month) approaches the solo support ceiling — automation is not optional here, which is why FG-LR-014 sits in this gate and not later.
- **Success metrics:** ≥8/10 renewals or expansions in conversation; ≤4h/week aggregate support; SLO adherence ≥99% monthly uptime on portal.
- **Failure thresholds:** support load growth outpacing client growth; second occurrence of any incident class already root-caused once.
- **Evidence to proceed:** 3 consecutive months of SLO data; one full second-operator engagement delivery (proves transferability); continuous-governance package sold to ≥1 client.
- **Max concurrent:** 10. **Review cadence:** monthly ops review with written notes.

## Stage 4 — Broader availability (2027, evidence-gated — no date promise)

- **Preconditions (all):** SOC 2 Type II program underway (ENTERPRISE_PLAN Phase 4); worker-process architecture for scans/reports; second trained operator; automated onboarding; billing automation (revive FG-LR-022 work); documented DR with quarterly restore drills.
- **Only then:** self-serve funnel revival, SLA-backed contracts, non-M365 connector expansion, CGIN benchmark claims in marketing (needs tenant volume for honest math).

---

## Cross-stage rules

1. **Any production change — code *or configuration* (secrets, env vars, plan tier, provider settings) — after a validation gate passes re-runs the golden-path smoke** (subset of H-steps) before the next client touches it. Permanent invariant (S-1 origin): the configuration that was validated is the configuration that serves clients; anything else is an unvalidated deploy wearing a validated deploy's evidence.
2. **Stop conditions never downgrade** — the Stage-1 list applies forever.
3. **Every stage retro updates `CLIENT_READINESS.md`** — it is the living gate record (and is currently stale; FG-LR-009).
4. **Nothing ships to a stage it wasn't gated for** — feature exposure follows the stage table, not merge dates.
