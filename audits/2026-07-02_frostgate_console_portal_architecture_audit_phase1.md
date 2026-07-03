# FrostGate Enterprise Console & Portal Architecture Audit

Date: 2026-07-02

Scope: `apps/console`, `apps/portal`, `api`, `admin_gateway`, `services`, `docs`, `artifacts/full_repo_census`, `artifacts/platform_inventory.det.json`, `artifacts/route_inventory_summary.json`

Mode: Inventory, mapping, verification, and documentation only. No product redesign. No code-path changes. No navigation moves. No renames.

## 1. Audit Standard

This document is the Phase 1 UX architecture baseline for FrostGate as it exists in the current worktree.

Every statement below is backed by one or more of:

- source routes in `apps/console/app`, `apps/portal/app`, `api`, `admin_gateway`
- navigation source in `apps/console/components/layout/Sidebar.tsx` and `apps/portal/app/layout.tsx`
- generated census artifacts in `artifacts/full_repo_census/`
- generated route/runtime inventory artifacts in `artifacts/platform_inventory.det.json` and `artifacts/route_inventory_summary.json`
- workflow and boundary docs in `docs/architecture/`
- role and operator docs in `docs/operators/`
- test execution performed for this audit

Verification performed during this audit:

- `apps/console`: `node --test tests/field-assessment-workspace.test.js tests/report-ui.test.js tests/readiness-dashboard.test.js`
- `apps/portal`: `node --test tests/portal-structure.test.js tests/portal-security.test.js`
- repo virtualenv: `.venv/bin/python -m pytest tests/tools/test_route_inventory_summary.py tests/security/test_router_mount_inventory.py -q`
- repo virtualenv: `.venv/bin/python -m pytest tests/test_c7_portal_grants.py tests/test_admin_identity_routes.py -q`

Observed results:

- Console structural/wiring tests: `243 passed`
- Portal structural/security tests: `30 passed`
- Route inventory / mount inventory tests: `31 passed`
- Portal grants / admin identity tests: `148 passed`

## 2. Baseline Counts

Current source-backed inventory counts:

| Area | Count | Evidence |
| --- | ---: | --- |
| Console page routes | 31 | `apps/console/app/**/page.tsx` |
| Portal page routes | 12 | `apps/portal/app/**/page.tsx` |
| Service authority directories | 68 | `services/*` excluding `__pycache__` |
| Operator runbook/guide docs | 13 | `docs/operators/**/*.md` |
| Observability runbooks | 8 | `docs/observability/runbooks/*.md` |
| Runtime routes | 1125 | `artifacts/platform_inventory.det.json` |
| Contract routes | 932 | `artifacts/platform_inventory.det.json` |
| Runtime-only routes | 186 | `artifacts/platform_inventory.det.json` |
| Platform planes | 10 | `artifacts/platform_inventory.det.json` |
| Dead/duplicate/orphan/placeholder findings | 403 | `artifacts/full_repo_census/13_DEAD_DUPLICATE_ORPHAN_PLACEHOLDER_MAP.md` |

Interpretation:

- FrostGate already has a broad backend surface and a much smaller operator/customer UI surface.
- The core audit risk is not missing code volume. It is surface mismatch: runtime routes without UI, UI pages without proven live backend contracts, placeholders, duplicate shells, and orphaned authorities.

## 3. Canonical Deliverable Set

The requested 20 deliverables are satisfied by the following canonical files plus this synthesis document.

| Requested deliverable | Canonical source |
| --- | --- |
| Complete Platform Capability Inventory | `artifacts/full_repo_census/01_REPOSITORY_INVENTORY.md` |
| Complete Authority Map | `artifacts/full_repo_census/03_SERVICE_CALLER_MAP.md`, `docs/architecture/service_map.md` |
| Console Navigation Map | `artifacts/full_repo_census/06_FRONTEND_PORTAL_CONSOLE_MAP.md`, `apps/console/components/layout/Sidebar.tsx` |
| Portal Navigation Map | `artifacts/full_repo_census/06_FRONTEND_PORTAL_CONSOLE_MAP.md`, `apps/portal/app/layout.tsx` |
| End-to-End Workflow Map | `artifacts/full_repo_census/07_WORKFLOW_EXECUTION_MAP.md`, `docs/architecture/PLATFORM_ARCHITECTURE.md` |
| Field Assessment Workflow Map | `docs/ai/FIELD_ASSESSMENT_ENTERPRISE_AUDIT.md`, `docs/architecture/PLATFORM_ARCHITECTURE.md` |
| Complete Report Inventory | `artifacts/full_repo_census/07_WORKFLOW_EXECUTION_MAP.md`, `artifacts/full_repo_census/10_SECURITY_TRUST_EVIDENCE_MAP.md`, `docs/governance/deterministic_reporting.md` |
| Runbook Inventory | `docs/operators/`, `docs/observability/runbooks/` |
| Dashboard Widget Inventory | `artifacts/full_repo_census/06_FRONTEND_PORTAL_CONSOLE_MAP.md`, `apps/console/components/dashboard/`, `apps/console/components/readiness/` |
| API-to-UI Matrix | `artifacts/full_repo_census/02_API_ROUTE_MAP.md`, `artifacts/full_repo_census/06_FRONTEND_PORTAL_CONSOLE_MAP.md` |
| Role Matrix | `docs/operators/auth0_roles.md`, `artifacts/full_repo_census/09_AUTH_IDENTITY_RBAC_TENANT_MAP.md` |
| Interaction Graph | `artifacts/full_repo_census/07_WORKFLOW_EXECUTION_MAP.md`, `artifacts/full_repo_census/06_FRONTEND_PORTAL_CONSOLE_MAP.md` |
| Broken Link Report | `artifacts/full_repo_census/13_DEAD_DUPLICATE_ORPHAN_PLACEHOLDER_MAP.md` |
| Orphaned Capability Report | `artifacts/full_repo_census/13_DEAD_DUPLICATE_ORPHAN_PLACEHOLDER_MAP.md` |
| Duplicate Capability Report | `artifacts/full_repo_census/13_DEAD_DUPLICATE_ORPHAN_PLACEHOLDER_MAP.md` |
| UX Consistency Report | this file, Section 12 |
| Navigation Heat Map | this file, Section 13 |
| Workflow Heat Map | this file, Section 14 |
| Enterprise Readiness Findings | this file, Section 15, plus `docs/ai/FIELD_ASSESSMENT_ENTERPRISE_AUDIT.md` |
| Recommended Information Architecture | this file, Section 16 |

## 4. Console Navigation Audit

The current console navigation is defined in `apps/console/components/layout/Sidebar.tsx`.

Exact navigation groups and items:

| Group | Item | Route |
| --- | --- | --- |
| Operations | Command Center | `/dashboard` |
| Operations | Control Tower | `/dashboard/control-tower` |
| AI & Knowledge | AI Workspace | `/dashboard/assistant` |
| AI & Knowledge | Corpus | `/dashboard/corpus` |
| AI & Knowledge | Retrieval | `/dashboard/retrieval` |
| AI & Knowledge | Provenance | `/dashboard/provenance` |
| Governance | Policies | `/dashboard/policies` |
| Governance | Providers | `/dashboard/providers` |
| Governance | Readiness | `/dashboard/readiness` |
| Governance | Field Assessments | `/field-assessment` |
| Compliance | Audit & Forensics | `/dashboard/forensics` |
| Compliance | Decisions | `/dashboard/decisions` |
| Compliance | Evaluation Lab | `/dashboard/evaluation` |
| Workforce | Workforce Intel | `/dashboard/workforce` |
| Admin | Clients | `/admin/tenants` |
| System | Settings | `/dashboard/settings` |
| System | Assessments | `/assessment` |

Additional top-bar shell elements:

- notification bell with badge count `2`
- settings icon button
- user/avatar badge `FG`
- sign-out link `/api/auth/logout`

Console source routes outside the sidebar:

- `/audit`
- `/dashboard/alignment`
- `/dashboard/ingestion`
- `/governance/topology`
- `/keys`
- `/login`
- `/onboarding`
- `/products`
- `/products/new`
- `/products/[id]`
- `/reports/[reportId]`
- `/field-assessment/[engagementId]`
- `/admin/tenants/[tenantId]`

Console navigation findings:

- The sidebar is the authoritative visible navigation.
- Several implemented pages are not present in the main sidebar and are therefore secondary, hidden, contextual, or unreachable except by direct URL or page-local links.
- `apps/console/console/` is a duplicate legacy shell tree and should be treated as duplicate UI inventory, not active primary architecture.
- The generated frontend census identifies multiple console pages as implemented but placeholder-backed or not proven against a live backend contract.

## 5. Portal Navigation Audit

The current portal navigation is defined in `apps/portal/app/layout.tsx`.

Exact portal navigation items:

| Label | Route |
| --- | --- |
| Overview | `/` |
| Assessment | `/engagement` |
| Findings | `/findings` |
| Reports | `/reports` |
| Coverage | `/coverage` |
| Attestation | `/attestation` |
| Remediation | `/remediation` |
| Continuity | `/continuity` |
| AI Assistant | `/assistant` |

Additional portal routes not in the main nav:

- `/accept-invite`
- `/login`
- `/engagement/[engagementId]`

Portal shell findings:

- The footer explicitly labels the portal as `Client Portal — read-only view`.
- The portal BFF in `apps/portal/app/api/core/[...path]/route.ts` is read-only by default and permits only explicit write patterns for attestation submission, report verification, and finding status patching.
- Portal authentication is server-session based via `apps/portal/app/api/auth/login/route.ts`, not client-side token storage.
- The portal is narrower and more opinionated than the console, but it still exposes multiple pages flagged by the generated census as incomplete, placeholder-backed, or lacking proven route parity.

## 6. Authority and Capability Mapping

Platform authority structure is split across:

- source-owned services in `services/*`
- route modules in `api/*.py` and `admin_gateway/routers/*.py`
- UI/BFF surfaces in `apps/console` and `apps/portal`

Current high-level authority families observed from source:

- field assessment
- evidence authority
- evidence freshness authority
- report authority
- verification authority
- remediation authority
- timeline authority
- framework authority
- governance graph
- governance workflows
- governance reporting
- readiness
- trust arc
- executive trust
- notifications
- identity resolver
- provisioning
- subscriptions and billing
- agent control
- AI plane / RAG / evaluation

Canonical maps:

- backend route-to-authority: `artifacts/full_repo_census/02_API_ROUTE_MAP.md`
- service-to-service caller map: `artifacts/full_repo_census/03_SERVICE_CALLER_MAP.md`
- DB model / migration map: `artifacts/full_repo_census/04_DATABASE_MODEL_MIGRATION_MAP.md`
- auth / RBAC / tenant map: `artifacts/full_repo_census/09_AUTH_IDENTITY_RBAC_TENANT_MAP.md`

Primary authority finding:

- FrostGate has many authorities implemented in backend/runtime inventory that do not yet have first-class console or portal affordances.

## 7. End-to-End Workflow Verification

The canonical platform workflow is documented in `docs/architecture/PLATFORM_ARCHITECTURE.md`.

Current verified backbone:

1. Assessment tier exists as a first-class product mode.
2. Evidence is the common tenant-scoped spine.
3. Field Assessment owns engagement execution and gating.
4. Delivery of an assessment triggers governance promotion.
5. Governance layer owns continuous workflows, assets, readiness, RAG, and reporting after promotion.

Current source-backed workflow states:

- `scheduled`
- `pre_visit`
- `in_progress`
- `evidence_collected`
- `report_generation`
- `delivered`

Workflow verification status:

- Source wiring exists for assessment, evidence, report, portal, and promotion paths.
- Structural tests confirm console field-assessment workspace, report UI, readiness dashboard, portal shell, portal BFF, portal grant auth, and admin identity routes.
- Production execution of every workflow transition is still not fully proven by this audit alone; the generated census repeatedly marks many workflows as `ACTIVE BY CODE PATH; PRODUCTION EXECUTION NOT PROVEN`.

## 8. Field Assessment Audit Baseline

The current field-assessment architecture and hardening gaps are already documented in `docs/ai/FIELD_ASSESSMENT_ENTERPRISE_AUDIT.md`.

That document remains the strongest source for:

- assessment creation
- evidence capture
- observations
- interviews
- connector scans
- normalization
- governance promotion
- portal publication
- drift / reassessment
- report generation and signing

Field Assessment architecture conclusion:

- Functional breadth is strong.
- Enterprise readiness is blocked more by isolation, durability, audit atomicity, and portal security concerns than by missing UI screens.

## 9. Report Inventory Baseline

Report-related surfaces confirmed from source and tests:

- console field-assessment report generation panel
- report version history
- report viewer
- report export bar
- per-report console route `/reports/[reportId]`
- field-assessment report verification and export paths

Report inventory evidence sources:

- `apps/console/components/field-assessment/ReportGenerationPanel.tsx`
- `apps/console/components/field-assessment/ReportVersionHistory.tsx`
- `apps/console/components/field-assessment/ReportViewer.tsx`
- `apps/console/components/field-assessment/ReportExportBar.tsx`
- `apps/console/tests/report-ui.test.js`
- `docs/governance/deterministic_reporting.md`

Report inventory finding:

- The UI and API scaffolding for report generation, export, and verify are present and structurally tested.
- The broader report catalog requested in the audit prompt should be treated as partially represented in code today, not fully surfaced as distinct console/portal report products.

## 10. Runbook Inventory

Operator and support runbooks confirmed from source:

- `docs/operators/onboarding_runbook.md`
- `docs/operators/first_client_prep.md`
- `docs/operators/credential_delivery.md`
- `docs/operators/console_user_guide.md`
- `docs/operators/auth0_roles.md`
- `docs/operators/azure_ad_app_setup.md`
- engagement letter/report/remediation template set under `docs/operators/letters/`

Observability / incident runbooks confirmed from source:

- `docs/observability/runbooks/5xx_rate.md`
- `docs/observability/runbooks/audit_pipeline.md`
- `docs/observability/runbooks/db_connectivity.md`
- `docs/observability/runbooks/ingestion_failure.md`
- `docs/observability/runbooks/latency_abnormal.md`
- `docs/observability/runbooks/provenance_failures.md`
- `docs/observability/runbooks/provider_failure.md`
- `docs/observability/runbooks/retrieval_degradation.md`

Runbook finding:

- FrostGate has meaningful operator and observability runbooks.
- The runbook set is stronger for deployment/support/observability than for every assessment-to-remediation business workflow named in the prompt.

## 11. Role Audit

Current implemented Auth0 role baseline from `docs/operators/auth0_roles.md`:

- `viewer`
- `assessor`
- `qa_reviewer`
- `compliance_reviewer`
- `tenant_admin`
- `platform_admin`

Future-but-not-current role list documented there:

- `auditor`
- `executive_reviewer`
- `external_assessor`
- `autonomous_governance_operator`

Role findings:

- The current coded role model is narrower than the prompt taxonomy of Executive, Operator, Analyst, Auditor, Customer, MSP, Consultant, Administrator, Developer.
- Portal access is session/grant oriented and should not be treated as equivalent to the console Auth0 RBAC model.
- Separation-of-duties policy is explicitly documented for `tenant_admin` vs `compliance_reviewer`.

## 12. Design Consistency Audit

Consistency observations only:

- Console uses a grouped sidebar plus top bar shell.
- Portal uses a top navigation plus read-only client framing.
- Naming is inconsistent across some adjacent concepts: `Assessment`, `Field Assessments`, `Readiness`, `Control Tower`, `Command Center`, `Governance`, `Audit & Forensics`, `Coverage`, `Continuity`.
- Several pages exist as shell destinations but are flagged by the census as placeholder-backed or not mapped to a proven backend contract.
- There is a duplicate console shell under `apps/console/console`, which is a consistency and maintenance risk even if not runtime-primary.

## 13. Navigation Heat Map

Highest-confidence, source-backed primary navigation:

- Console sidebar items in `Sidebar.tsx`
- Portal header links in `apps/portal/app/layout.tsx`

Warm surfaces with explicit tests and visible entry points:

- console field-assessment workspace
- console readiness dashboard
- console report generation surfaces
- portal overview / engagement / findings / remediation / reports

Cold or weakly surfaced areas:

- console `/audit`
- console `/dashboard/alignment`
- console `/dashboard/ingestion`
- console `/governance/topology`
- console `/products*`
- console `/keys`
- portal `/attestation`
- portal `/assistant`
- portal `/continuity`

## 14. Workflow Heat Map

Hot and comparatively mature:

- field assessment evidence workflow
- report generation UI shell
- portal grant/session login flow
- route inventory and RBAC-aware backend coverage

Warm but still contract-sensitive:

- readiness dashboard
- provider governance and evaluation surfaces
- governance topology
- workforce and admin identity surfaces

Cold or incomplete relative to prompt ambition:

- full report catalog differentiation
- full portal trust/transparency/timeline/download taxonomy
- every authority surfaced as dedicated UI
- every runtime route mapped to a reachable console or portal affordance

## 15. Gap Analysis and Enterprise Readiness Findings

Definitive gap sources:

- `artifacts/full_repo_census/13_DEAD_DUPLICATE_ORPHAN_PLACEHOLDER_MAP.md`
- `docs/ai/FIELD_ASSESSMENT_ENTERPRISE_AUDIT.md`
- `artifacts/full_repo_census/06_FRONTEND_PORTAL_CONSOLE_MAP.md`

Highest-signal findings for PR 18.6 baseline planning:

1. Backend exceeds UI surface.
   Many runtime routes and authority families have no first-class console or portal affordance.

2. UI exceeds proven contract surface in some areas.
   The frontend census marks multiple pages as implemented shells with missing or unproven backend route parity.

3. Duplicate UI exists.
   `apps/console/console` is a duplicate console shell tree and should remain classified as duplicate inventory until explicitly retired or justified.

4. Placeholder-backed surfaces exist in both Console and Portal.
   This matters more than visual polish because it breaks reachability and truthfulness of navigation.

5. Portal is security-conscious structurally, but still narrower than the prompt’s target information architecture.
   It currently behaves more like a focused client engagement workspace than a complete trust/transparency/downloads platform.

6. Field Assessment is the strongest product spine.
   It is the clearest end-to-end subsystem and the safest base for future IA restructuring.

7. Enterprise readiness is constrained by workflow hardening, isolation, and authority reconciliation more than by missing frontend components.

## 16. Recommended Information Architecture for the Next Prompt

Recommendations only. No implementation performed.

1. Treat `Field Assessment` as the canonical execution spine and preserve its evidence-first workflow exactly.
2. Treat `Governance Promotion` as the explicit boundary between assessment delivery and continuous governance.
3. Build the future Console IA from verified authorities, not from existing page names alone.
4. Build the future Portal IA from verified customer-safe capabilities only, not from every backend route family.
5. Do not preserve duplicate shell trees in the redesign baseline.
6. Require every retained navigation item to map to a proven route, a tested API contract, and an owning authority.
7. Classify every existing page before redesign as one of: active, contextual, hidden, duplicate, placeholder, dead, or future.

## 17. Final Audit Position

This Phase 1 audit establishes a reliable blueprint:

- the platform is large and authority-rich
- the backend surface is materially broader than the UI surface
- the console and portal shells are straightforward to inventory from source
- field assessment is the most mature end-to-end workflow family
- the repo already contains strong generated census artifacts that should be treated as canonical inputs to any PR 18.6 information-architecture redesign

The next implementation prompt should preserve:

- evidence spine
- engagement lifecycle gates
- promotion boundary
- role and tenant boundaries
- portal session/grant boundary
- route allowlists in both BFFs

The next implementation prompt should explicitly resolve:

- duplicate UI
- placeholder UI
- backend-only authorities without owner UI
- hidden or contextual pages without discoverability rules
- report/catalog taxonomy drift
- portal taxonomy gaps versus actual implemented capability
