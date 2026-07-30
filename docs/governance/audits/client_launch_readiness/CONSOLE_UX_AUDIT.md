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

## 5. What this buys

- Operator training time drops from "tour of 22 surfaces" to "one guided workflow plus 5 admin pages."
- Screen-shares during engagements only ever show live, populated, relevant surfaces — an enterprise-credibility gain at zero feature cost.
- QA surface for the launch window shrinks by roughly half the console.

**Effort: 2 days** (nav gating + one dashboard consolidation pass + smoke click-through). Everything else in this document is post-launch.
