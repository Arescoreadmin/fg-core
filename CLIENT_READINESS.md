# FrostGate — First Client Readiness Tracker

**Target engagement:** 2026-06-27  
**Owner:** Jason Cosat  
**Authority:** This document is the single tracker for go-live readiness. `ROADMAP.md` tracks shipped PRs; this tracks operational and pre-engagement gaps.

Check each item when verified or completed. Do not begin the client engagement until all P0 (blocking) items are checked.

---

## A. Infrastructure — Production Health

*Verify these before the engagement. They should already be deployed (PR 39).*

- [ ] **A1** Railway API responds — `https://api-production-6d47.up.railway.app/health` returns 200
- [ ] **A2** Console loads at `console.frostgate.ai` — Auth0 login page renders without errors
- [ ] **A3** Portal loads at `app.frostgate.ai` — password prompt appears
- [ ] **A4** Railway env vars confirmed (open Railway → API service → Variables):
  - [ ] `FG_MSAL_CLIENT_ID` set and non-empty
  - [ ] `FG_ACKNOWLEDGMENT_KEY` set
  - [ ] `FG_ANTHROPIC_API_KEY` set
  - [ ] `FG_REPORT_VERIFY_URL` set (e.g. `https://console.frostgate.ai/verify`)
  - [ ] `FG_KEY_PEPPER` set
  - [ ] `FG_SIGNING_SECRET` set
  - [ ] `FG_INTERNAL_AUTH_SECRET` set
- [ ] **A5** Vercel console env vars confirmed (`console.frostgate.ai` project):
  - [ ] `CORE_API_URL`, `CORE_API_KEY`, `CORE_TENANT_ID`
  - [ ] `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_ISSUER_BASE_URL`
  - [ ] `AUTH_SECRET`, `NEXTAUTH_URL`
- [ ] **A6** Vercel portal env vars confirmed (`app.frostgate.ai` project):
  - [ ] `PORTAL_PASSWORD`, `PORTAL_SESSION_SECRET`
  - [ ] `CORE_API_URL`, `CORE_API_KEY`, `CORE_TENANT_ID`
- [ ] **A7** Postgres migrations current — Railway logs show migration assert passing on startup
- [ ] **A8** Redis reachable — no `redis connection refused` in Railway logs
- [ ] **A9** _(P0)_ **Uptime monitoring** — UptimeRobot or BetterUptime (free tier) pointed at `/health`; alerts to your phone/email if Railway goes down mid-engagement
- [ ] **A10** Railway Hobby plan headroom checked — memory and CPU are not near limits before a live engagement

---

## B. Monitoring & Alerting

- [ ] **B1** Prometheus alert rules reviewed — `deploy/prometheus/alerts.yml` exists; note these are not yet wired to Railway (Hobby plan has no scrape endpoint)
- [ ] **B2** _(P0)_ **Basic uptime check** — same as A9; single `/health` ping with SMS/email alert is the minimum
- [ ] **B3** **Error alerting** — Sentry or Rollbar free tier wired to Railway; catches silent crashes in report generation or scan runners without requiring you to watch logs
- [ ] **B4** Anthropic API credit verified — sufficient balance for report generation; check `platform.anthropic.com` usage dashboard
- [ ] **B5** Railway logs bookmarked — keep Railway dashboard open in a tab during the engagement as the fallback observability surface

---

## C. Operator Runbooks & Documentation

- [x] **C1** `docs/operators/azure_ad_app_setup.md` — 15-permission table with admin consent walkthrough
- [x] **C2** `docs/operators/onboarding_runbook.md` — covers all 9 connectors; before-meeting (no-auth) and in-meeting split
- [x] **C3** `docs/operators/first_client_prep.md` — full pre-flight checklist with 75–90 min time block
- [x] **C4** `docs/CONNECTOR_CROSSREF.md` — client technology → connector → data → findings matrix
- [ ] **C5** `docs/operators/console_user_guide.md` — verify it covers all connector scan panels added in PRs 40–45 (9 panels total)
- [ ] **C6** **Client engagement letter** — one-page document (not code) to give the client before the assessment covering: what FrostGate accesses, data retained, retention period, how to access the portal, and what happens after. See F6 (DPA) for the governance version.
- [ ] **C7** **Post-engagement follow-up email template** — send after the engagement: portal URL, key findings summary, how to mark remediations resolved, next check-in date
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
- [ ] **E11** **Secure credential delivery plan** — decide now how you hand the client `app.frostgate.ai` + the portal password. Options: 1Password share link, Bitwarden Send, verbal during meeting and written in follow-up. Do not send password and URL in the same plaintext message.

---

## F. Governance — FrostGate's Own Data Posture

- [x] **F1** Operator acknowledgment receipt — HMAC-SHA256, per-engagement, covers: operator identity, client org, MS Graph scopes, authorization timestamp, engagement ID (stored in scan result + report appendix)
- [x] **F2** Immutable audit event trail — append-only `FaEngagementAuditEvent` on all write routes and status transitions
- [x] **F3** Evidence hash chain — SHA-256 of every scan result's raw payload; tamper-evident
- [x] **F4** Connector policy enforcement — `enforce_connector_allowed()` blocks unlisted connectors at 403
- [x] **F5** **Real connector policy file** — same as D1; done 2026-05-30
- [ ] **F6** **Data Processing Agreement (DPA) template** — one-page document the client signs or verbally acknowledges before the scan. Not a hard blocker for first client if handled verbally + email, but required before scaling to multiple clients or regulated sectors
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
