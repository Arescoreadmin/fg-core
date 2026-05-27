# FrostGate Roadmap

**Owner:** Jason Cosat  
**Goal:** Client-ready field assessment delivery within 30 days of 2026-05-27  
**Authority:** `SYSTEM.md` (system design), `BLUEPRINT_STAGED.md` (governance compliance gates)

---

## How to use this document

Every PR that ships a feature, fixes a product gap, or changes the client-facing story must be listed here.  
Update the relevant section when a PR merges — do not backfill multiple PRs at once.  
"Not standalone" modules (field assessment, connectors, portal) require this note in their PR description:
> This module is not standalone. It requires the fg-core API, auth layer, and Postgres substrate.

---

## Phase 0 — Infrastructure Foundation
*30-day repo blitz: tenant isolation, auth boundary, CI stability, observability, agent packaging.*  
Tracking: `plans/30_day_repo_blitz.yaml` + `plans/30_day_repo_blitz.state.yaml` (complete as of PR 18.6)

All Phase 0 tasks are complete (tasks 1.1 – 18.6).

---

## Phase 1 — Field Assessment Layer
*Build the assessment-to-report pipeline: scan ingestion, findings, governance assets, report engine, portal.*

| PR | Title | Status | Key deliverable |
|----|-------|--------|----------------|
| PR 1 | FA Substrate | ✅ merged | Engagements, scan results, findings DB + API |
| PR 2 | FA Evidence & Playbooks | ✅ merged | Evidence anchoring, field observations, playbook engine |
| PR 3 | FA Connector Framework | ✅ merged | Connector registry, driver interface, scan dispatch |
| PR 4 | FA Governance Asset Layer | ✅ merged | Asset registry, attestation records, continuity tracking |
| PR 5 | FA Report Engine | ✅ merged | Report compilation, section hashes, manifest signing |
| PR 6 | FA Drift Detection | ✅ merged | Config drift detection, baseline snapshots, delta alerts |
| PR 7 | FA Console — Engagements | ✅ merged | Console UI: engagement list, finding list, report list |
| PR 8 | FA Console — Report Viewer | ✅ merged | Console UI: report viewer with finding expand, evidence lineage |
| PR 9 | FA Console — Governance | ✅ merged | Console UI: asset registry, attestation submit, continuity gaps |
| PR 10 | FA Portal — Client View | ✅ merged | Portal: client-facing engagement list + finding summary |
| PR 11 | FA Portal — Attestation | ✅ merged | Portal: attestation submission + health dashboard |
| PR 12 | FA MS Graph Connector | ✅ merged | MS Graph MSAL device-code scan (MFA, NIST AI RMF controls) |
| PR 13 | CI Budget Extension | ✅ merged | fg-fast 360s→480s, Guard timeout 15→20min |
| PR 14 | Dependency Authority | ✅ merged | Shared base requirements normalization |
| PR 15 | Report Engine Completion | ✅ merged | Full report engine: normalized findings, framework summary |
| PR 16 | Auth Runtime Guard + Key Store | ✅ merged | Persistent SQLite key store, auth runtime guard |
| PR 17 | Postgres Auth Authority | ✅ merged | Migrate auth to Postgres, multi-worker safe |
| PR 18 | FA Portal — Reports | ✅ merged | Portal: report version list, report viewer, export |
| PR 19 | FA Portal — Findings | ✅ merged | Portal: finding list with severity filter |
| PR 20 | FA Portal — Continuity | ✅ merged | Portal: continuity gap view, overdue alerts |
| PR 21 | FA Portal — Bug Fixes | ✅ merged | Portal attestation/continuity UI fixes + CI pass |
| PR 22 | Finding Explainer | ✅ merged (#390) | Plain-language finding explanations, LRU cache, provenance manifest |

---

## Phase 2 — Client Readiness
*Target: first client engagement by 2026-06-27.*  
*Every item below is a blocker or a strong-should for client delivery.*

### P0 — Blockers (cannot deliver without these)

| # | Item | Owner | PR | Status |
|---|------|-------|----|--------|
| 1 | **Portal authentication** — `middleware.ts` login gate; portal currently has no auth | — | PR 24 | ✅ done — HMAC-SHA256 session cookies, `/login` page, `PORTAL_PASSWORD` + `PORTAL_SESSION_SECRET` |
| 2 | **Scan trigger UI** — operator needs to initiate MS Graph device-code scan from console without running CLI | — | — | ⬜ not started |
| 3 | **NIST AI RMF questionnaire** — structured per-control manual evidence input; `FaFieldObservation` has no questionnaire schema | — | PR 26 | ✅ done — `fa_questionnaires` + `fa_questionnaire_responses` tables; 69 NIST AI RMF 1.0 controls; auto-seeded on init; per-control status + evidence; submit auto-links to findings |
| 4 | **Fix `VERIFY_BASE_URL`** — hardcoded as `"https://verify.fieldguide.io/report"` in `services/connectors/msgraph/report.py` | — | PR 23 | ✅ done — reads `FG_REPORT_VERIFY_URL`, defaults to `localhost:3001/verify` |
| 5 | **`.env.example`** — document `FG_MSAL_CLIENT_ID`, `FG_ACKNOWLEDGMENT_KEY`, `FG_CORE_TENANT_ID`, all required vars | — | PR 23 | ✅ done — all vars documented with descriptions and generation instructions |

### P1 — High-value for first client (ship before or during engagement)

| # | Item | Owner | PR | Status |
|---|------|-------|----|--------|
| 6 | **Executive summary in report** — currently no narrative opening section for client PDF | — | — | ⬜ not started |
| 7 | **NIST control coverage matrix** — portal view: which controls have evidence, which are gaps | — | — | ⬜ not started |
| 8 | **HIPAA playbook** — `services/field_assessment/playbooks.py` HIPAA falls back to `comprehensive`; banking clients need dedicated gates | — | — | ⬜ not started |
| 9 | **Portal engagement selector UI** — findings page currently requires engagement ID in URL, no picker | — | — | ⬜ not started |
| 10 | **Remediation roadmap in portal** — sequenced, owned remediation steps with priority ordering | — | — | ⬜ not started |
| 11 | **Azure AD app pre-registration guide** — required API scopes + admin consent walkthrough for MS Graph scan setup | — | — | ⬜ not started |

### P2 — Post-first-client (backlog)

| # | Item | Notes |
|---|------|-------|
| 12 | Redis-backed explanation cache | Replace in-memory LRU; needed for multi-worker |
| 13 | Explanation manifest persistence | Store `FindingExplanation` to DB alongside finding |
| 14 | `remediation_priority` scoring | Needs impact × exploitability formula decision |
| 15 | Evidence freshness degradation | Reduce confidence score as evidence ages |
| 16 | Cross-finding correlation | Surface related findings in explanation panel |
| 17 | Executive PDF export | WeasyPrint or Playwright → signed PDF |
| 18 | Portal rate limiter → Redis | Current in-memory `_rlBuckets` bypassed in multi-node |
| 19 | Dedicated CMMC/SOC2/ISO27001 playbooks | Currently all fall back to comprehensive |
| 20 | Operator onboarding runbook | Step-by-step: tenant create → scan → promote → report |

---

## How to add a PR to this roadmap

When a PR merges:
1. Add a row to the relevant Phase table with: PR number, title, status ✅, one-line deliverable
2. If it closes a P0/P1 item in Phase 2, update that row's Status and PR columns
3. If it introduces something not on the plan, add it as a new row — do not leave it untracked

---

*Last updated: 2026-05-27 (PR 26 in progress)*
