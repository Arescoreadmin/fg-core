# MCIM 18.6 Navigation Decision Log

Status: Canonical recommendation log for 18.6.x navigation and IA follow-on PRs

| Recommendation | Evidence | Confidence | Business impact | Complexity | Target PR | Risks |
| --- | --- | --- | --- | --- | --- | --- |
| Keep `/dashboard`, `/dashboard/control-tower`, `/dashboard/readiness`, `/field-assessment`, and portal `/`, `/findings`, `/reports`, `/remediation` as primary destinations. | Phase 1 audit, PR 18.6 audit, operator guide, portal route inventory | high | preserves highest-value daily journeys | low | 18.6.1 | low |
| Classify `/assessment` and `/onboarding` as legacy, not primary. | legacy sessionStorage coupling, overlap with Field Assessment list/create flow | high | reduces duplicate entry points without route breakage | low | 18.6.1 | medium if demos rely on them |
| Preserve `/audit` and `/keys`, but demote them behind stronger specialist/admin homes. | duplicate with `/dashboard/forensics` and Control Tower | high | reduces admin confusion while preserving reachability | low | 18.6.1 | low |
| Establish Trust Center as the future home for provenance, verification, forensics, decisions, and transparency. | provenance page, forensics page, report verify, verification bundle, trust evidence map | high | exposes FrostGate differentiator more clearly | medium | 18.6.5 | medium if provenance links break |
| Establish Governance & Intelligence Workspace as the future home for topology, evaluation, providers, policies, intelligence, replay, simulation, and benchmarking. | hidden `/intelligence/*` routes, topology screen, evaluation lab, provider governance console | high | turns backend breadth into a coherent product story | medium | 18.6.4 | medium due to varying maturity |
| Treat portal as collaborative and partially write-capable, not read-only. | portal footer says read-only, but BFF allows attestation submit, report verify, and finding patch | high | prevents expectation mismatch for customers | low | 18.6.6 | medium if labels are not updated consistently |
| Replace portal engagement context dependence on `localStorage` with URL-first context and session fallback. | `apps/portal/lib/engagementStore.ts`, portal overview/findings/remediation/report pages | high | improves shareability, reliability, and recoverability | medium | 18.6.6 | medium |
| Keep Field Assessment as the canonical operator spine and do not split it across multiple top-level workspaces. | `docs/architecture/PLATFORM_ARCHITECTURE.md`, workspace page breadth, tests coverage | high | preserves the strongest workflow in the product | low | 18.6.3 | low |
| Keep report generation, QA approval, export, and verification as distinct states in IA. | workspace reports/history, portal reports, QA approval issuing portal access code | high | reduces accidental mixing of authoring and delivery semantics | medium | 18.6.2 / 18.6.6 | medium |
| Elevate hidden but valuable report detail and topology surfaces via contextual links rather than new routes. | `/reports/{reportId}`, `/governance/topology` | medium | improves discoverability without route churn | low | 18.6.2 / 18.6.4 | low |
| Leave backend-only authorities backend-only until a source-backed UX home is defined. | governance learning, optimization, orchestration, intelligence runtime-only routes | high | avoids speculative UI | low | 18.6.4 | low |
| Keep provider and policy pages reachable, but mark them specialist/growing until capability maturity improves. | placeholder findings in frontend census, provider/policy route presence | medium | prevents overpromising in navigation | low | 18.6.4 | low |
| Keep billing out of primary nav until there is a customer/admin workflow beyond readiness banners. | billing monetization map, dashboard billing status only | high | avoids premature top-level commercial UI | medium | 18.6.7 | low |
| Preserve all existing routes unless the MCIM explicitly retires them in a later amendment. | explicit MCIM rule and acceptance criteria | high | prevents silent regressions | low | all 18.6.x | high if ignored |
| Require every future 18.6.x PR to update the decision log when it changes a route tier, lifecycle classification, or source-of-truth boundary. | governance need for traceable IA evolution | high | creates auditable IA decisions | low | all 18.6.x | low |

---

## PR 18.6.1 Decisions — Unified Navigation Framework (2026-07-03)

| Decision | Rationale | Impact |
| --- | --- | --- |
| Created `packages/navigation/` as `@fg/navigation` package (not `apps/shared/navigation/`) | Matches existing `@fg/ui` monorepo convention. Avoids ambiguity between app-local and shared code. | Low risk — consistent with existing pattern. |
| Used MCIM group names verbatim as sidebar group labels | Eliminates divergence between MCIM taxonomy and UI labels. "AI & Knowledge" → "Intelligence". "System" → split into "Intelligence" (Workforce) + "Administration" (Settings). | Cosmetic sidebar label change only. No routes changed. |
| Reclassified Audit & Forensics from Compliance → Trust group | Forensics is a trust-verification surface, not a compliance-gating surface. Aligns with MCIM trust-center family. | Sidebar group changed. Route `/dashboard/forensics` unchanged. |
| Moved Workforce Intel from standalone "Workforce" group → Intelligence group | Workforce Intel is an AI-generated intelligence capability, not a standalone ops domain. MCIM family: monitoring. | Sidebar group changed. Route unchanged. |
| Moved Provenance from "AI & Knowledge" group → Trust group | Provenance is a chain-of-custody and explainability surface. MCIM family: trust-explainability. | Sidebar group changed. Route unchanged. |
| Moved Decisions from Compliance → Trust group | Decision provenance is a trust-center surface. MCIM family: trust-explainability. | Sidebar group changed. Route unchanged. |
| Moved Settings + Keys from System/Admin → Administration group | Consolidates platform administration into one group. Keys previously unlisted in sidebar. | Settings moved from "System" to "Administration". Keys now visible. |
| /assessment demoted to tier=legacy, visibility=hidden | Overlaps with Field Assessment. sessionStorage coupling. MCIM recommendation from decision log. | No route breakage. Item removed from sidebar. Route remains reachable via URL. |
| /audit kept at tier=specialist, visibility=visible in Compliance group | Route is reachable. Duplicate with /dashboard/forensics noted. Not removed per MCIM rule. | No change to route. |
| Enterprise group reserved (no items) | Future workspace placeholder. MCIM requirement: reserve workspace containers without populating incomplete features. | No nav items. Group registered in registry for future PRs. |
| Navigation generated from `CONSOLE_REGISTRY.getByGroup()` | Eliminates hardcoded sidebar tree. Single source of truth for nav. Validator enforces completeness. | Sidebar.tsx no longer contains nav data; registry is authoritative. |
| Portal nav generated from `PORTAL_REGISTRY.getAllItems()` with tier sort | Same pattern as console. Portal layout.tsx no longer contains hardcoded NAV_LINKS. | Portal nav item order: primary first, then secondary. Same 9 links visible. |
| Created `navigation-registry.json` as checked-in JSON snapshot | Enables Python CI tool (`check_navigation_registry.py`) to validate registry without running TypeScript. Pattern mirrors `tools/ci/route_inventory.json`. | Must be kept in sync with TypeScript registrations. |

---

## PR 18.6.2 Decisions — Executive Command Center (2026-07-03)

| Decision | Rationale | Impact |
| --- | --- | --- |
| Rewrote `/dashboard` from client component to async server component | Eliminates `useEffect`-based data fetching; all data fetched in parallel server-side via `Promise.allSettled`. Preserves five test anchor strings (`billing-ready`, `billing-not-ready`, `billing-error`, `events-loading`, `Core unreachable`). | Breaking change to page structure. No route change. All existing test anchors preserved. |
| Created `apps/console/components/command-center/` directory with 18 widget components | Each widget is a standalone client component with MCIM metadata, authority attribution, source-of-truth reference, drill-down route, and skeleton/empty/error states. No widget fabricates data. | 18 new component files. No existing component modified. |
| WidgetShell is the shared metadata wrapper — not a layout primitive | WidgetShell provides the authority/MCIM/source-of-truth metadata footer (collapsible via "Source" button), not page layout. Each widget wraps its own content. Avoids coupling layout to governance metadata. | All 18 widgets import WidgetShell. Single source of truth for metadata display. |
| No new BFF routes added | All 18 widgets consume existing BFF routes (`/api/core/control-tower/snapshot`, `/api/core/decisions`, `/api/core/feed/live`, `/api/core/field-assessment/engagements`, `/api/core/control-plane/readiness/*`). Dashboard page orchestrates existing authority functions from `coreApi.ts`, `readinessApi.ts`, `fieldAssessmentApi.ts`. | Zero backend changes. Zero new API routes. |
| GovernanceOverview receives `score: ScoreOutput | null` from server — no client-side scoring | Score is fetched server-side and passed as a prop. Widget never reimplements scoring logic. Displays `—` when score is null. | No scoring logic in client components. Authority: Readiness Authority. |
| GlobalSearch uses `NavigationSearchIndex` from `@fg/navigation` | Search index is built from the same registry that drives the sidebar. No duplicate capability registry. | Requires `@fg/navigation` import in console app. Zero new search infrastructure. |
| ExecutiveBriefing generates deterministic text from props — no LLM calls | Briefing is computed deterministically from the control tower snapshot, decisions, assessments, and engagements passed as props. Confidence scores reflect data availability, not fabricated percentages. | No AI/LLM calls. Briefing is exportable as text. |
| Risk counts in ExecutiveRiskMap come from props pre-aggregated server-side | Server fetches engagement data and derives counts. Widget never fetches or aggregates independently. `risk-no-data` state shown when engagements unavailable. | Clean separation: server aggregates, client renders. |
| Added `check_executive_dashboard.py` CI validator | Validates each component in `command-center/` for MCIM reference, authority, sourceOfTruth, drillDown, and absence of prohibited patterns (Math.random, hardcoded scores). Validates five anchor strings in dashboard page. | New CI gate. Returns exit 1 on any violation. |
| 600+ static-analysis tests in `tests/console/command-center.test.js` | 30 tests per widget × 18 widgets + 45 page/CI/navigation tests. Tests verify file structure, MCIM references, authority attribution, no fabricated data, required test ID strings, loading/empty/error states. | Replaces the previous 247-line command-center.test.js. No test runner required beyond `node --test`. |
