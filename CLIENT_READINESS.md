# FrostGate — First Client Readiness Tracker

**Target engagement:** 2026-06-27  
**Owner:** Jason Cosat  
**Authority:** This document is the single tracker for go-live readiness. `ROADMAP.md` tracks shipped PRs; this tracks operational and pre-engagement gaps.

Check each item when verified or completed. Do not begin the client engagement until all P0 (blocking) items are checked.

---

## A. Infrastructure — Production Health

*Verify these before the engagement. They should already be deployed (PR 39).*

- [x] **A1** Railway API responds — `https://api-production-6d47.up.railway.app/health` returns 200, HEAD supported, `FG_ENV=prod` (confirmed 2026-05-31)
- [x] **A2** Console loads at `console.frostgate.ai` — Auth0 login page renders without errors (confirmed 2026-05-30)
- [x] **A3** Portal loads at `app.frostgate.ai` — password prompt appears (confirmed 2026-05-30)
- [x] **A4** Railway env vars confirmed (open Railway → API service → Variables):
  - [x] `FG_MSAL_CLIENT_ID` set — Azure AD app registered, 15 permissions granted, public client flow enabled (2026-05-31)
  - [x] `FG_ACKNOWLEDGMENT_KEY` set (confirmed 2026-05-30)
  - [x] `FG_ANTHROPIC_API_KEY` set (confirmed 2026-05-30)
  - [x] `FG_REPORT_VERIFY_URL` set to `https://console.frostgate.ai/verify` (confirmed 2026-05-30)
  - [x] `FG_KEY_PEPPER` set (confirmed 2026-05-30)
  - [x] `FG_SIGNING_SECRET` set (confirmed 2026-05-30)
  - [x] `FG_INTERNAL_AUTH_SECRET` set (confirmed 2026-05-30)
  - [x] `FG_ENV=prod` — API running in production mode (confirmed 2026-05-30)
  - [x] `STRIPE_WEBHOOK_SECRET` set — webhook endpoint created in Stripe, `whsec_` secret confirmed (2026-05-31)
- [x] **A5** Vercel console env vars confirmed (`console.frostgate.ai` project) — all set (confirmed 2026-05-31)
- [x] **A6** Vercel portal env vars confirmed (`app.frostgate.ai` project) — all set (confirmed 2026-05-31)
- [x] **A7** Postgres migrations current — `FG_DB_MIGRATIONS_RISK_ACCEPTED=1` set; migrations were run at initial deploy (confirmed 2026-05-31)
- [x] **A8** Redis reachable — no connection errors in Railway logs; Redis Online in Railway dashboard (confirmed 2026-05-31)
- [x] **A9** **Uptime monitoring** — UptimeRobot monitoring all 3 services: Railway API (`/health`), console (`console.frostgate.ai`), portal (`app.frostgate.ai/api/health`) (done 2026-05-30)
- [ ] **A10** Railway Hobby plan headroom checked — memory and CPU are not near limits before a live engagement

---

## B. Monitoring & Alerting

- [x] **B1** Prometheus alert rules reviewed — not wired to Railway (Hobby plan has no scrape endpoint); acceptable for first client
- [x] **B2** **Basic uptime check** — UptimeRobot monitoring all 3 services (confirmed 2026-05-30)
- [x] **B3** **Error alerting** — Sentry DSN set in Railway; confirmed capturing events during startup crash cycles (confirmed 2026-05-31)
- [x] **B4** Anthropic API credit verified — $3.50 balance, ~$0.05–0.25 per engagement (claude-haiku-4-5), sufficient for 35+ engagements (confirmed 2026-05-31)
- [ ] **B5** Railway logs bookmarked — bookmark `railway.app` dashboard tab before the engagement

---

## C. Operator Runbooks & Documentation

- [x] **C1** `docs/operators/azure_ad_app_setup.md` — 15-permission table with admin consent walkthrough
- [x] **C2** `docs/operators/onboarding_runbook.md` — covers all 9 connectors; before-meeting (no-auth) and in-meeting split
- [x] **C3** `docs/operators/first_client_prep.md` — full pre-flight checklist with 75–90 min time block
- [x] **C4** `docs/CONNECTOR_CROSSREF.md` — client technology → connector → data → findings matrix
- [x] **C5** `docs/operators/console_user_guide.md` — all 9 scan panels documented with auth flow, pre-meeting vs in-meeting split, P1/P2 caveats (confirmed 2026-05-31)
- [x] **C6** **Client engagement letter** — `docs/operators/letters/`: proposal (#1), authorization (#2), data handling notice (#3) (done 2026-05-30)
- [x] **C7** **Post-engagement follow-up email template** — `docs/operators/letters/`: report delivery (#4), 30-day follow-up (#5), close-out (#6) (done 2026-05-30)
- [x] **C8** ROADMAP.md updated — confidence degradation (#15), remediation scoring (#14), onboarding runbook (#20), connector crossref (#21), PDF disclosure (#22), FA policy (#23), CLIENT_READINESS.md (#24) all logged (done 2026-05-30)

---

## D. Connector Policy

- [x] **D1** **FA connector policy file** — `contracts/connectors/policies/fg_field_assessment.json`: all 9 FA connectors with per-connector MS Graph scopes, `retention.days=90`, `redaction_mode=strict`, conservative rate limits. The `default.json` placeholder (Slack/Google Drive) remains for the RAG path; FA engagements should reference `fg_field_assessment` version. (done 2026-05-30)

---

## E. Client-Facing Deliverables

*All portal and report features are built. Verify they work end-to-end in the dry run (Section H).*

- [x] **E1** PDF report — multi-page: cover, executive summary, findings, remediation plan, NIST coverage, evidence appendix (PR 38)
- [x] **E2** Report — AI executive summary with advisory label (PR 27)
- [x] **E3** Portal — risk posture dashboard: NIST coverage bar, severity strip, function heatmap, immediate actions (PR 33)
- [x] **E4** Portal — remediation roadmap: 3-phase lanes, quick-wins matrix, per-finding step runbooks (PR 31)
- [x] **E5** Portal — closed-loop remediation: client marks findings resolved, NIST questionnaire auto-updates (PR 32)
- [x] **E6** Portal — password authentication gate (PR 24)
- [x] **E7** Portal — plain-language finding explanations + remediation steps (PRs 22, 33)
- [x] **E8** Portal — NIST coverage matrix with gap view (PR 28)
- [x] **E9** Evidence freshness — confidence scores degrade as evidence ages; surfaced in portal and report (built 2026-05-30)
- [x] **E10** **"Data collected" appendix in PDF** — `services/governance/report/serialization.py`: per-connector data accessed table, retention/redaction/transmission statement, operator authorization note; populated from engagement scan results at export time (done 2026-05-30)
- [x] **E11** **Secure credential delivery plan** — `docs/operators/credential_delivery.md`: three options (1Password Share, Bitwarden Send, verbal), never send URL + password in same message (done 2026-05-31)

---

## F. Governance — FrostGate's Own Data Posture

- [x] **F1** Operator acknowledgment receipt — HMAC-SHA256, per-engagement, covers: operator identity, client org, MS Graph scopes, authorization timestamp, engagement ID (stored in scan result + report appendix)
- [x] **F2** Immutable audit event trail — append-only `FaEngagementAuditEvent` on all write routes and status transitions
- [x] **F3** Evidence hash chain — SHA-256 of every scan result's raw payload; tamper-evident
- [x] **F4** Connector policy enforcement — `enforce_connector_allowed()` blocks unlisted connectors at 403
- [x] **F5** **Real connector policy file** — same as D1; done 2026-05-30
- [x] **F6** **Data Processing Agreement (DPA) template** — `contracts/dpa_template.md`: sub-processors table, 90-day retention, breach notification (72hr), audit rights, signature blocks (done 2026-05-31)
- [ ] **F7** **Retention enforcement** — `retention.days` is defined in the policy schema but no scheduled job or API endpoint purges engagement data after the window. Post-first-client work.

---

## G. Client Remediation Tracking (Post-Engagement)

*These items determine how well you can track the client's progress between the engagement and follow-up.*

- [x] **G1** Client marks findings resolved in portal with evidence notes (PR 32)
- [x] **G2** Remediation roadmap updates live when findings are closed (PR 32)
- [x] **G3** Risk posture dashboard reflects updated questionnaire state (PR 33)
- [x] **G4** Remediation priority scoring — multi-factor formula (severity + exploitability + confidence + source bonus); phases recalibrated to match (built 2026-05-30)
- [ ] **G5** **Operator activity view** — no console view showing "client logged in, marked N findings resolved this week." Currently requires manual DB or audit log query. Post-first-client.
- [ ] **G6** **Scheduled re-scan / progress scan** — no automated follow-up scan 30 or 60 days later to compare to baseline. You can trigger manually (same engagement, new scan run). Automate post-first-client.
- [ ] **G7** **Client notifications** — no email when client marks a finding resolved; no reminder to client when remediations are overdue. Post-first-client.
- [ ] **G8** **Engagement snapshot comparison** — no before/after view: "at engagement: 12 critical findings. Today: 4." Drift detection exists (PR 6) but isn't surfaced as a client-facing delta. Post-first-client.

---

## H. End-to-End Dry Run

**Run this at least one week before June 27th.** Use your own domain and Azure AD tenant (or a sandbox). This is the single most important pre-engagement action — find problems now, not live.

- [ ] **H1** Create engagement — use `[TEST - yourdomain.com]`
- [ ] **H2** Run DNS & Email Security scan against your own domain — verify findings appear
- [ ] **H3** Run Web Security Headers scan against your public URL — verify findings appear
- [ ] **H4** Run Network Scan against a known host/IP — verify TLS and port findings appear
- [ ] **H5** Run MS Graph Core scan — full device-code flow; verify MFA/CA/GUEST findings
- [ ] **H6** Run OAuth Inventory scan — verify app registrations and OAuth grants appear
- [ ] **H7** Run OAuth Risk scan — verify illicit consent and AI tool findings
- [ ] **H8** Run Endpoint Inventory scan — verify device list and Intune findings
- [ ] **H9** Run Entra Governance scan — verify PIM roles, CA policies, risky users
- [ ] **H10** Run SharePoint & OneDrive scan — verify external sharing findings
- [ ] **H11** Fill questionnaire — answer all 69 NIST AI RMF controls; **time yourself**
- [ ] **H12** Generate report — verify AI executive summary generates (not timeout/error)
- [ ] **H13** Download PDF — open it; verify all sections render; no blank pages or import errors
- [ ] **H14** Log in to portal at `app.frostgate.ai` as client — verify all pages load cleanly
- [ ] **H15** Mark a finding resolved in portal — add evidence note
- [ ] **H16** Verify in console — finding status updated, NIST questionnaire control updated
- [ ] **H17** Regenerate report — verify updated state appears in new report version
- [ ] **H18** **Total time recorded** — know your actual end-to-end time before sitting in front of a client. Budget 75–90 min for the in-meeting portion; no-auth scans should be done pre-meeting.

---

## Priority Order

| Priority | Items | When |
|----------|-------|------|
| **P0 — Do now** | A9, B2, D1/F5, H1–H18 (dry run) | This week |
| **P1 — Week 2** | E10 (data collected appendix), C6 (engagement letter), C7 (follow-up template), C8 (ROADMAP update), B3 (error alerting) | By 2026-06-13 |
| **P2 — Week 3** | A10 (plan headroom), C5 (console guide review), E11 (credential delivery plan), B4 (Anthropic quota check) | By 2026-06-20 |
| **Post-engagement** | F6 (DPA), F7 (retention enforcement), G5–G8 (remediation tracking automation) | After 2026-06-27 |

---

*Cross-references: `ROADMAP.md` (shipped PR history) · `docs/operators/first_client_prep.md` (day-of checklist) · `docs/operators/onboarding_runbook.md` (step-by-step scan procedures) · `docs/CONNECTOR_CROSSREF.md` (connector scope matrix)*
