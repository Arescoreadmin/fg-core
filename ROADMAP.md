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
| PR 27 | Executive Summary | ✅ merged | AI-generated narrative section in report; risk posture + key concerns; console + portal |
| PR 28 | NIST Control Coverage Matrix | ✅ merged | Per-control evidence fusion (questionnaire + scan); coverage matrix in portal; `governance:read`-gated list endpoint |
| PR 29 | HIPAA + SOC 2 Playbooks | 🔄 in progress | Dedicated HIPAA and SOC 2 governance execution playbooks; Privacy/Security Officer gates (HIPAA); Executive Sponsor + 8 document class gates (SOC 2); annual evidence freshness on all policy docs |
| PR 30 | Portal Engagement Selector | 🔄 in progress | localStorage-backed engagement persistence (`fg_portal_eid`); engagement selector hub on home page; auto-select single engagement; all 4 sub-pages fall back to stored ID when `?e=` param absent |
| PR 31 | Remediation Roadmap v1 | ✅ merged | Priority scoring (severity × scan evidence × NIST coverage); 3-phase execution roadmap (0–30/31–60/61–90 days); per-phase compliance delta preview; quick-wins matrix (impact vs effort); step-by-step runbooks |
| PR 32 | Remediation Closed Loop | ✅ merged | Client marks finding resolved with evidence notes; `FaFieldObservation` + `FaEvidenceLink` created; NIST questionnaire responses bumped `not_implemented`→`partial`; live roadmap refresh in portal |
| PR 33 | Risk Posture Dashboard | ✅ merged | Home page risk intelligence: NIST coverage bar (current vs projected), finding severity strip, NIST function heatmap (GOVERN/MAP/MEASURE/MANAGE), immediate actions callout; `reportlab` dependency added (unblocks PDF export); remediation steps rendered in findings page explainer |
| PR 34 | Console Auth Gate | ✅ merged | Auth0 OIDC login protection on console via next-auth v5; middleware protects all routes; SessionProvider + sign-out in sidebar |
| PR 35 | Portal Field Assessment Workspace | ✅ merged | `/engagement` list + `/engagement/[id]` tabbed detail (Overview, Scans, Documents, Observations, Evidence, History); 7 new portalApi methods; "Assessment" nav link |
| PR 36 | Workforce Intelligence | ✅ merged | Per-user AI query attribution; `tenant_users` + `ai_query_log` tables; subject-matter classification; risk scoring; workforce admin dashboard in console; AI workspace in portal |
| PR 37 | Risk History + Keywords + Alerting | ✅ merged | Daily risk score snapshots with Recharts trend chart; tenant-configurable keyword triggers (contains/exact/word_boundary/prefix/regex + case sensitivity); threshold-based alert rules with cooldown + fired-alerts audit log; keyword backtest/preview against historical queries; Keywords + Alerts tabs in workforce dashboard |
| PR 38 | Executive PDF Export | ✅ merged | Client-ready multi-page PDF: cover page, AI executive summary (advisory-labeled), confidence assessment, severity-sorted findings, remediation plan, framework coverage, evidence appendix, per-page footer with manifest hash; replaces raw-data stub |
| PR 39 | Production Deployment Fixes | ✅ merged | FA tables created on Postgres startup (`create_all checkfirst`); auth gate injects BFF header tenant into result to satisfy security gate; federated Auth0 sign-out via route handler (`/api/auth/logout`); middleware makes landing page public + uses pathname callbackUrl; Railway GitHub auto-deploy + CI fixes (pr-base-mainline skip on push, release-images FG_ENV, scorecard drift) |
| PR 40 | Three New Scan Connectors | ✅ merged | OAuth Inventory (MS Graph device-code: app registrations, service principals, OAuth grants); Endpoint Inventory (MS Graph device-code: Azure AD devices + Intune); Network Scan (pure Python: port scan + TLS inspection for 20 ports including AI model server ports); 3 bridges, 3 API endpoints, 3 console scan panels |
| PR 41 | DNS &amp; Email Security Connector | ✅ merged | DMARC policy/reporting, SPF record + all-mechanism, DKIM selector probing, MX presence, DNSSEC validation; dnspython-based pure-Python runner; bridge with NIST AI RMF GOVERN 6.2 mappings; console scan panel |
| PR 42 | Web Security Headers Connector | ✅ merged | HSTS (max-age, includeSubDomains), CSP (unsafe-inline/eval/wildcard), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, plain-HTTP detection; httpx HEAD runner; bridge with NIST MANAGE 2.2/2.4 mappings; console scan panel |
| PR 45 | OAuth Risk Deep Scan Connector | ✅ merged | Illicit consent grant detection (user-consented critical/high-risk scopes — the consent phishing attack pattern); AI tool OAuth data access (ChatGPT, Claude, Copilot, Gemini + 15 patterns against Mail/Files/Calendar/Teams); over-privileged application permissions via MS Graph appRoleAssignedTo (3 API calls regardless of tenant size); unverified publisher + sensitive scope analysis; NIST MAP 1.1 + GOVERN 1.2/6.2 + MANAGE 2.4; Application.Read.All + Directory.Read.All scopes |
| PR 44 | SharePoint &amp; OneDrive Data Exposure Connector | ✅ merged | External sharing detection (anonymous "anyone with link", external domain users, org-wide links, no-expiry links); tenant domain resolution via /organization; 30-site / 3-drive / 100-item sampling with permission expansion; critical severity when ≥10 anonymous items; NIST MAP 1.1 + GOVERN 1.2/6.2; Sites.Read.All + Files.Read.All scopes; device-code console panel |
| PR 43 | Entra ID Governance Connector | ✅ merged | PIM permanent vs eligible role assignments; excess/stale Global Admin findings; Access Review coverage (privileged roles, recurring); Identity Protection risky users (P2-gated, graceful 403); Conditional Access posture (legacy auth block, MFA enforcement, report-only policies); 7 dedicated MS Graph scopes; NIST GOVERN 1.2/6.2 + MANAGE 2.2/2.4 mappings; device-code console panel |

---

## Phase 2 — Client Readiness
*Target: first client engagement by 2026-06-27.*  
*Every item below is a blocker or a strong-should for client delivery.*

### P0 — Blockers (cannot deliver without these)

| # | Item | Owner | PR | Status |
|---|------|-------|----|--------|
| 1 | **Portal authentication** — `middleware.ts` login gate; portal currently has no auth | — | PR 24 | ✅ done — HMAC-SHA256 session cookies, `/login` page, `PORTAL_PASSWORD` + `PORTAL_SESSION_SECRET` |
| 2 | **Scan trigger UI** — operator needs to initiate MS Graph device-code scan from console without running CLI | — | PR 25 | ✅ done — `ScanTriggerPanel` component; device-code flow with polling; status display in console engagement workspace |
| 3 | **NIST AI RMF questionnaire** — structured per-control manual evidence input; `FaFieldObservation` has no questionnaire schema | — | PR 26 | ✅ done — `fa_questionnaires` + `fa_questionnaire_responses` tables; 69 NIST AI RMF 1.0 controls; auto-seeded on init; per-control status + evidence; submit auto-links to findings |
| 4 | **Fix `VERIFY_BASE_URL`** — hardcoded as `"https://verify.fieldguide.io/report"` in `services/connectors/msgraph/report.py` | — | PR 23 | ✅ done — reads `FG_REPORT_VERIFY_URL`, defaults to `localhost:3001/verify` |
| 5 | **`.env.example`** — document `FG_MSAL_CLIENT_ID`, `FG_ACKNOWLEDGMENT_KEY`, `FG_CORE_TENANT_ID`, all required vars | — | PR 23 | ✅ done — all vars documented with descriptions and generation instructions |

### P1 — High-value for first client (ship before or during engagement)

| # | Item | Owner | PR | Status |
|---|------|-------|----|--------|
| 6 | **Executive summary in report** — currently no narrative opening section for client PDF | — | PR 27 | ✅ done — `executive_summary` section in report JSON; Claude narrative with risk posture + key concerns; graceful template fallback; rendered in console ReportViewer and portal inline view |
| 7 | **NIST control coverage matrix** — portal view: which controls have evidence, which are gaps | — | PR 28 | ✅ done — `GET /engagements/{id}/questionnaires` with evidence fusion (questionnaire + scan counts per control); `governance:read`-gated; portal Coverage page + nav link |
| 8 | **HIPAA + SOC 2 playbooks** — dedicated governance execution playbooks for healthcare and commercial compliance | — | PR 29 | ✅ done — `HIPAA_PLAYBOOK` (Privacy + Security Officer gates, 7 HIPAA document classes, BAA no-expiry) + `SOC2_PLAYBOOK` (Executive Sponsor gate, 8 Trust Service Criteria document classes, 6 observation domains, annual freshness) |
| 9 | **Portal engagement selector UI** — findings page currently requires engagement ID in URL, no picker | — | PR 30 | ✅ done — engagement selector hub on home page; localStorage persistence; all sub-pages fall back to stored ID |
| 10 | **Remediation roadmap in portal** — sequenced, owned remediation steps with priority ordering | — | PR 31 | ✅ done — priority scoring; 3-phase lanes; compliance delta preview; quick-wins matrix; per-finding step runbooks |
| 11 | **Azure AD app pre-registration guide** — required API scopes + admin consent walkthrough for MS Graph scan setup | — | PR 25 | ✅ done — `docs/operators/azure_ad_app_setup.md`: create app, 7 delegated permissions, public client flow, scan walkthrough, troubleshooting |

### P2 — Post-first-client (backlog)

| # | Item | Notes |
|---|------|-------|
| 12 | Redis-backed explanation cache | Replace in-memory LRU; needed for multi-worker |
| 13 | Explanation manifest persistence | Store `FindingExplanation` to DB alongside finding |
| 14 | `remediation_priority` scoring | ✅ done 2026-05-30 — 4-factor formula: severity base + exploitability class (by connector family) + confidence factor (integrates freshness degradation) + source bonus; `PHASE_IMMEDIATE_THRESHOLD=50`, `PHASE_SHORT_TERM_THRESHOLD=35`; effort mapping + step templates for all 9 connector families; 78 tests in `tests/test_remediation_scoring.py` |
| 15 | Evidence freshness degradation | ✅ done 2026-05-30 — `services/field_assessment/confidence.py`; decay table: 0–30d: ±0, 31–60d: −5, 61–90d: −15, 91+d: −30, floor 30; applied at read time in `_finding_to_response()`, report domain aggregation, and readiness low-confidence gate; 22 tests in `tests/test_confidence_degradation.py` |
| 16 | Cross-finding correlation | Surface related findings in explanation panel |
| 17 | Executive PDF export | PR 38 ✅ merged |
| 18 | Portal rate limiter → Redis | Current in-memory `_rlBuckets` bypassed in multi-node |
| 19 | Dedicated CMMC/SOC2/ISO27001 playbooks | Currently all fall back to comprehensive |
| 20 | Operator onboarding runbook | ✅ done 2026-05-30 — `docs/operators/onboarding_runbook.md` expanded: all 9 connectors, before-meeting (no-auth) + in-meeting split, P2-gated permission callout, full troubleshooting table |
| 21 | Connector cross-reference doc | ✅ done 2026-05-30 — `docs/CONNECTOR_CROSSREF.md`: client technology → connector → MS Graph scopes → data collected → findings matrix; MS 365 license tier impact table; no-auth connector section; data gaps disclosure table |
| 22 | PDF data collection disclosure appendix | ✅ done 2026-05-30 — New section in `export_pdf_bytes()`: per-connector data accessed table, retention/redaction/transmission statement, operator authorization note; populated from engagement scan results at export time |
| 23 | FA connector policy file | ✅ done 2026-05-30 — `contracts/connectors/policies/fg_field_assessment.json`: all 9 FA connectors with MS Graph scopes, `retention.days=90`, `redaction_mode=strict`; replaces Slack/Google Drive placeholder |
| 24 | First client readiness tracker | ✅ done 2026-05-30 — `CLIENT_READINESS.md` at repo root: 8-section checklist (infrastructure, monitoring, runbooks, policy, deliverables, governance, remediation tracking, dry-run script) with priority order and cross-references |

---

## How to add a PR to this roadmap

When a PR merges:
1. Add a row to the relevant Phase table with: PR number, title, status ✅, one-line deliverable
2. If it closes a P0/P1 item in Phase 2, update that row's Status and PR columns
3. If it introduces something not on the plan, add it as a new row — do not leave it untracked

---

*Last updated: 2026-05-30 (PR 39 complete; production live — field assessment + Auth0 sign-out working)*
