# Console UX Audit — Enterprise Operator Workspace

**Surface audited:** `apps/console` (37 pages), navigation registry `packages/navigation/src/registrations/console.ts` (~22 items, 6 groups), sidebar `apps/console/components/layout/Sidebar.tsx`.
**Frame:** can an operator efficiently run a real field-assessment engagement, administer tenants, and respond to problems — not "are the pages pretty."

---

## 1. Verdict

The **engagement workspace is task-complete**; the **shell around it is overgrown**. The core delivery loop (create engagement → run scans → questionnaire → findings → remediation hints → report → QA approve → deliver access code) is implemented as a guided, gate-driven workflow with live refresh — this is genuinely good operator UX and was battle-tested in the June dry run. But it sits inside a console carrying two product generations: the current field-assessment/governance platform and the older decision-engine/AI-plane product (decisions, forensics, alignment, corpus, retrieval, ingestion, evaluation lab, policies, providers) that no launch customer will buy this year. Four separate dashboard-class pages compete for the "start here" role.

**Console usability score: 4/10** for a hypothetical second operator; 6/10 for the founder who built it. Minimum launch action: nav gating (FG-LR-007, 2 days) — no redesign.

## 2. Workflow trace (the 15 operator tasks)

| # | Workflow | Entry point | Status | Evidence / notes |
|---|----------|------------|--------|-------------------|
| 1 | Sign in | `/login` → Auth0 OIDC (next-auth v5, middleware-protected) | ✅ works | PR 34, PR 39; federated logout route exists |
| 2 | Tenant identification | TopBar/session context; BFF `resolveAuthorizedTenant()` validates `?tenant_id=` against session | ✅ works, recently hardened | ROADMAP PR A+B #548; #587 stabilized first prod login |
| 3 | Provision/onboard a tenant | `/admin/tenants` → provision route | ✅ works; recently incident-hardened | Fail-closed on persistence failure (R0 #549); error taxonomy R0.1; zero-touch Edge Config + Redis fallback (P-3/P-3a) |
| 4 | Create/manage engagement | `/field-assessment` list → `[engagementId]` workspace | ✅ works | Tabbed workspace, guided execution panel with gate tracking (items 36–37) |
| 5 | Configure assessment | Engagement creation form (assessment type: AI governance, HIPAA, SOC 2, CMMC, ISO 27001, PCI, DORA, FedRAMP, 800-171) | ✅ works | Sprint 2 type expansion; framework filtering by type |
| 6 | Review submitted evidence | Engagement workspace Evidence/Documents/Observations tabs | ✅ works | PR 35; evidence lifecycle locks post-QA (H15) |
| 7 | Review findings | Workspace findings tab; expand cards; remediation form | ✅ works | Items 34; finding explainer (PR 22) |
| 8 | Manage governance state | AI vendor governance panel (8-state workflow, transition modal, decision ledger); governance decisions | ✅ works | PR 4 (13th scan); H14 decision ledger |
| 9 | Assign remediation | Remediation hint per finding; canonical remediation-authority routes | ⚠️ partial | No assignee/owner concept surfaced in console; hints only — acceptable for operator-led stage 1 |
| 10 | Monitor progress | Readiness page + guided panel gate counts | ✅ works | Live refresh on gate completion (item 36) |
| 11 | Investigate exceptions | Scan job status (`GET /scan-jobs`), audit page, Sentry (external) | ⚠️ partial | Dead-letter/orphan jobs visible via API; no console surface for failed-job triage — CLI/API knowledge required |
| 12 | Generate/approve reports | Reports tab: generate, finalize, QA approve button, verification bundle panel | ✅ works | Items 35, 52; SoD scope `governance:qa_approve` (Sprint 1) |
| 13 | Manage users/roles/service identities | `/admin/tenants/[id]` (invites via Resend), IdentityGovernancePanel (8+ sub-tabs), keys page | ⚠️ works but sprawling | Identity panel has ~20 tabs (PR 6–9 series) — power without hierarchy; invite flow had three 403 bugs fixed 2026-07-17 |
| 14 | Inspect operational health | `/dashboard/control-tower`, operations-center, readiness | ⚠️ diffuse | Four dashboards split the answer to "is the platform healthy?" |
| 15 | Respond to failures/alerts | Nothing in console | ❌ missing | Alerting is external (Sentry/UptimeRobot); acceptable if FG-LR-010 triage doc exists |

**Bottom line:** 11 of 15 workflows completable; the 4 partials are tolerable for a single expert operator at stage 1–2 and are already scheduled (assessor assignment, observability) in ENTERPRISE_PLAN Phase 2.

## 3. Where the console is cluttered, duplicative, or risky

1. **Four dashboards** — `executive-intelligence`, `command-center` (`/dashboard`), `operations-center`, `control-tower` all claim overview status. An operator cannot know which is authoritative. *(duplicative, high learning cost)*
2. **Legacy decision-engine wing** — `decisions`, `forensics`, `alignment`, `provenance`, `corpus`, `retrieval`, `ingestion`, `evaluation-lab`, `policies`, `providers` belong to Tier 3/4 products that are explicitly deferred (SYSTEM.md §15). They dilute nav, extend the attack/QA surface, and will show sparse data in front of clients during screen-shares. *(clutter, credibility risk)*
3. **Identity governance panel: ~20 sub-tabs** (score, drift, risk, timeline, types, provenance, approval, policy, snapshots, recommendations, trend, forecast, SLA, benchmark, findings, actions ledger…). Enterprise-depth machinery presented as a flat tab strip — for launch, 3 tabs (Users, Invitations, Audit) cover every real task. *(overly dense)*
4. **Legacy self-serve funnel pages** (`/`, `/onboarding`, `/assessment`, `/products`) mixed into the operator app. *(fragmented; see FG-LR-023)*
5. **No failed-scan triage surface** — the one operationally risky gap: a stuck device-code scan in-meeting requires API knowledge to diagnose. Mitigation: the runbook's pre-meeting/no-auth split plus dry-run familiarity. *(operationally unsafe, mitigated)*
6. **Naming** — "Control Tower," "Command Center," "Operations Center" are synonyms; "Alignment," "Provenance," "Corpus" are internal vocabulary. *(unclear terminology)*

## 4. Recommended launch information architecture

Mechanism exists already: `getNavigationItemsForPrincipal` filters by principal; add a launch-mode flag/role predicate in the registry. **Do not redesign pages.**

**Primary nav (launch mode, ≤9 items):**

| Group | Items | Responsibility |
|-------|-------|----------------|
| Operations | **Home** (keep `command-center` only) | One dashboard: engagement pipeline, platform health strip, recent activity |
| Delivery | **Field Assessments** (list → workspace drill-down) | The entire engagement lifecycle — already a guided workflow |
| Delivery | **Readiness** | Gate/coverage drill-down |
| Intelligence | **Workforce Intelligence** | AI usage attribution, keywords, alerts (sellable now, live data) |
| Administration | **Clients** (`/admin/tenants`) | Tenant provisioning, invites, portal grants |
| Administration | **Keys**, **Settings** | Credentials, config |
| Compliance | **Audit** | Audit log viewer |

**Hidden until their tier sells:** executive-intelligence, operations-center, control-tower, decisions, forensics, alignment, provenance, corpus, retrieval, ingestion, evaluation-lab, policies, providers, trust-center, workspace, products, onboarding/assessment wizard.

**Role visibility (maps to existing 6-role model, H14):** platform_admin sees Administration; assessor sees Delivery+Intelligence; qa_reviewer additionally sees QA queues; viewer read-only. SoD already enforced server-side (`governance:qa_approve` separate scope) — the nav should mirror it.

**Global search/filter strategy:** defer global search (P3). The two lists that matter (engagements, findings) already filter; saved views are P2-at-scale.

## 5. Target design — what the Console should become

The critique above (hide, merge, gate) is the launch action. This section is the destination: the Console should stop being a *map of the platform* and become a *work queue for the operator*. The organizing question changes from "what does FrostGate have?" to "what needs my attention right now?"

### 5.1 Operator Home (replaces all four dashboards)

One screen, seven zones, every zone a queue with counts and one-click drill-down. Every zone is backed by data that **already exists** — this is composition, not new plumbing:

| Zone | Contents | Existing data source |
|------|----------|---------------------|
| **Today's engagements** | Engagements with activity scheduled/expected today; status, next gate, client access state | `fa_engagements` (`in_progress`), guided-execution gate counts |
| **Waiting on client** | Unaccepted invites (with age), findings sitting in remediation with no client activity for N days, attestations past `next_attestation_due` | `portal_users` invitations; `FaEngagementAuditEvent` recency; governance assets `next_attestation_due` (FA-1 #541) |
| **Evidence needing review** | Evidence in `collected` (not locked), provenance events pending review | evidence lifecycle states (H15); `mark_provenance_reviewed` queue |
| **Reports pending approval** | Finalized report versions lacking the `qa_approved_report` gate | report version history + QA gate |
| **High-risk findings** | Open critical/high across all engagements, newest first | `fa_findings` severity/status |
| **Governance alerts** | Fired workforce alert rules, drift deltas since baseline | fired-alerts audit log (PR 37); drift detection (PR 6) |
| **System health** | Scan jobs in dead-letter/orphaned state, startup-validation status, uptime/Sentry links | `GET /scan-jobs`; `app.state.startup_validation`; external links |

Behavior rules: a zone with zero items collapses to a single line; every item's click lands on the *action* (the QA button, the finding card), never on a list page the operator must re-filter; counts are the navigation — if "Reports pending approval (2)" shows, that *is* the to-do list. This also closes the audit's §2 gap #11 (failed-scan triage had no surface) and #15 (health had no home).

**Acceptance criteria (Operator Home v1 is done when all five hold — these gate FG-LR-027, not aspirations):**

1. **≤3 clicks from Home to any piece of active work** — measured across all seven queues; the click path is Home → queue item → action control.
2. **Every work item displays a single owner** — the operator (or, post-second-hire, a named assignee); no item may render ownerless. Where the data model lacks an assignee today, the queue defaults ownership to the engagement's assessor.
3. **Every queue shows explicit aging** — each item carries "N days in this state," and each queue defines its amber/red thresholds (e.g., invite unaccepted 5/10 days; evidence unreviewed 3/7; report awaiting QA 2/5).
4. **No engagement can disappear from visibility** — every non-closed engagement appears in at least one zone at all times; an engagement matching no queue predicate surfaces in a fallback "quiet engagements" row rather than vanishing. This is testable: for all `fa_engagements` not in `closed|cancelled`, Home renders ≥1 entry.
5. **All exceptions surface within one screen** — dead-letter/orphaned scan jobs, failed report generations, and startup-validation warnings appear on Home itself (System health zone), never only behind an API or a sub-page.

Validation method: a scripted walkthrough against a seeded tenant with one item in every queue state, executed as part of the Stage-2 acceptance review.

### 5.2 Target screen map (post-launch end-state)

```
Operator Home  (the 7 queues above — the only "dashboard")
 ├── Engagements        → Engagement Workspace (existing guided workflow — unchanged)
 ├── Review Queue       → evidence review · report QA · governance decisions (SoD-gated)
 ├── Clients            → tenants, invitations, portal grants (existing /admin/tenants)
 ├── Intelligence       → workforce intel · risk history (existing, sellable)
 └── Admin              → keys · settings · audit log
```

Six top-level destinations. Configuration (Admin), operations (Home + Engagements), review (Review Queue), and reporting (inside the workspace) are cleanly separated — the role-visibility model in §4 maps onto this unchanged: assessors see Home/Engagements/Intelligence; qa_reviewers additionally see Review Queue; platform_admin sees Clients/Admin.

### 5.3 Sequencing and effort

- **Launch (in the 19-day plan):** nav gating to ≤9 items, keep `/dashboard` as interim Home — FG-LR-007, 2 days. Unchanged.
- **Stage 2→3 (post-launch): Operator Home v1 — ~3 days** (FG-LR-027): the 7-zone queue screen composed from the endpoints above, replacing the interim dashboard. This is the highest-leverage console investment after launch because it converts the console from founder-memory-driven to queue-driven — the precondition for a second operator ever being productive.

## 6. What this buys

- Operator training time drops from "tour of 22 surfaces" to "one guided workflow plus 5 admin pages"; with Operator Home, the daily loop becomes "clear the queues."
- Screen-shares during engagements only ever show live, populated, relevant surfaces — an enterprise-credibility gain at zero feature cost.
- QA surface for the launch window shrinks by roughly half the console.
- The dry-run gap list (failed-scan triage, health visibility) gets a permanent home instead of API spelunking.

**Launch effort: 2 days** (nav gating + smoke click-through). Operator Home v1: 3 days, Stage 2→3 package.
