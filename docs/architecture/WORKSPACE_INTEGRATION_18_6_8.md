# Workspace Integration & Demo Readiness — PR 18.6.8

**PR**: 18.6.8 — Workspace Integration & Demo Readiness  
**MCIM**: MCIM-18.6-WORKSPACE-INTEGRATION  
**Authority**: Navigation Authority  
**Source of Truth**: URL search parameters + workspace context keys  
**Date**: 2026-07-05  

---

## 1. Executive Summary

PR 18.6.8 delivers the cross-workspace integration layer for the FrostGate console. It does **not** introduce new backend authorities or data sources. Instead it provides:

- A URL-based context-preservation system that passes workspace state across navigation boundaries without browser-authoritative storage
- Seven integration components that handle metadata display, cross-workspace navigation, context bridging, empty states, loading states, demo mode indication, and workspace search
- Three lib modules that implement workspace context encoding, demo fixtures, and the navigation map
- A deterministic demo mode backed by static fixtures — no random data generation, no live API dependency

The integration layer is additive. Every existing workspace route remains valid. Authority ownership does not change. The components in this PR are presentational orchestration helpers, not new data authorities.

---

## 2. Workspace Model

The console exposes eleven workspaces. Each maps to a canonical route and owns a distinct domain.

| # | Workspace | Route | MCIM ID | Domain |
|---|---|---|---|---|
| 1 | Executive Intelligence Center | `/dashboard/executive` | MCIM-18.6.7-EXEC-INTEL | Strategic posture, risk, compliance, board summary |
| 2 | Executive Command Center | `/dashboard` | MCIM-18.6-CMD-CENTER | Operational dashboards, KPIs, situational awareness |
| 3 | Operations Workspace | `/workspace` | MCIM-18.6-OPS-WS | Live work queue, cases, decisions, delegation |
| 4 | Trust Center | `/trust-center` | MCIM-18.6-TRUST-CTR | Trust graph, scorecard, verification, benchmarks |
| 5 | Field Assessment | `/field-assessment` | MCIM-18.6-FIELD-ASSESS | Field engagements, evidence collection, operator flow |
| 6 | Assessment Reports | `/reports` | MCIM-18.6-REPORTS | Report generation, delivery, PDF export |
| 7 | Readiness | `/dashboard/readiness` | MCIM-18.6-READINESS | AI readiness score, framework gap analysis |
| 8 | Governance Intelligence | `/dashboard/alignment` | MCIM-18.6-ALIGNMENT | Framework alignment, policy coverage |
| 9 | Remediation | `/dashboard/forensics` | MCIM-18.6-FORENSICS | Findings, remediation roadmap, closure tracking |
| 10 | Customer Portal | `/portal` | MCIM-18.6-PORTAL | Customer-facing findings, reports, attestation |
| 11 | Engagement Portal | `/products` | MCIM-18.6-PRODUCTS | Legacy engagement catalog |

**executive-intelligence** (`/dashboard/executive`) is the primary entry for executive and board-level personas. It connects to Trust Center (`/trust-center`), Operations Workspace, Field Assessment, and Customer Portal via cross-workspace navigation.

---

## 3. Navigation Philosophy

Context travels exclusively through URL search parameters. No workspace state is written to `localStorage`, `sessionStorage`, or any other browser-authoritative store.

**Principles:**

- **URL is the single source of truth** for active workspace context. Sharing a URL reproduces the exact same view.
- **No browser-authoritative state** — `localStorage` and `sessionStorage` are forbidden in all workspace-integration components and lib files. The CI check enforces this.
- **Fail open on missing context** — when context keys are absent from the URL, components render their empty state with a `reason` and `nextAction` rather than a blank or broken view.
- **Deterministic rendering** — all workspace-integration components produce the same output for the same URL. No `Math.random()` calls.
- **Accessibility first** — all navigation elements carry `aria-label` and `data-mcim-id` attributes. Keyboard navigation is fully supported.

---

## 4. Context Preservation

Fifteen context keys travel via URL search parameters. They are defined in `WORKSPACE_CONTEXT_KEYS` in `apps/console/lib/workspaceContext.ts`.

| Key | Type | Purpose |
|---|---|---|
| `ws` | string | Active workspace identifier |
| `mcimId` | string | MCIM ID of the originating component |
| `engagementId` | string | Active engagement (field workspace) |
| `tenantSlug` | string | Tenant URL slug (never `tenant_id`) |
| `findingId` | string | Active finding reference |
| `reportId` | string | Active report reference |
| `remediationId` | string | Active remediation item |
| `attestationId` | string | Active attestation reference |
| `auditEventId` | string | Active audit event reference |
| `caseId` | string | Active operations case |
| `policyId` | string | Active governance policy |
| `providerId` | string | Active AI provider reference |
| `view` | string | Sub-view within the destination workspace |
| `returnTo` | string | URL to return to after completing an action |
| `demoMode` | `"1"` | Activates demo mode — served from fixtures |

**Encoding functions** (`workspaceContext.ts`):

- `parseWorkspaceContext(searchParams)` — reads a `URLSearchParams` object into a typed context record
- `buildWorkspaceUrl(workspace, context)` — constructs a fully-qualified console URL with all active context keys appended
- `mergeWorkspaceContext(base, override)` — merges two context records, with `override` winning on key collision
- `contextToParams(context)` — serialises a context record back to `URLSearchParams` for link construction

---

## 5. Naming Conventions

Workspace identifiers used in `WORKSPACE_NAV_MAP` and the `ws` context key follow these canonical names:

| Canonical `ws` value | Display name |
|---|---|
| `executive` | Executive |
| `operations` | Operations |
| `governance` | Governance |
| `intelligence` | Intelligence |
| `trust` | Trust |
| `compliance` | Compliance |
| `command-center` | Command Center |
| `remediation` | Remediation |
| `field` | Field Engagement |
| `admin` | Admin |
| `portal` | Customer Portal |

---

## 6. Interaction Patterns

### Cross-workspace navigation

`CrossWorkspaceNav` renders an accessible navigation landmark (`<nav aria-label="…">`). Each entry is a `WorkspaceLink` that calls `buildWorkspaceUrl` with the current context merged into the destination workspace context. Active workspace is indicated by `aria-current="page"`. The `data-mcim-id` attribute is present on every link.

### Empty states

`WorkspaceEmptyState` is the canonical empty-state component for all workspace-integration surfaces. It requires three props: `reason` (why data is absent), `dataRequired` (what context is needed), and `nextAction` (a link or callback to acquire that context). Bare "No Data" strings are forbidden — the CI check blocks them.

### Loading states

`WorkspaceLoadingState` renders skeleton placeholders using Tailwind's `animate-pulse` class. It accepts a `workspace` prop to label the loading region for accessibility. The `mcimId` prop is required so the loading state can be identified in telemetry.

---

## 7. Cross-Workspace Flows

### Executive → Operations (drill-down)

```
/console/executive?ws=executive
  → user clicks finding cluster
  → CrossWorkspaceNav builds URL with ws=operations&caseId=…&returnTo=/console/executive
  → /console/operations?ws=operations&caseId=…&returnTo=…
```

### Operator → Remediation (from governance policy breach)

```
/console/governance?ws=governance&policyId=…
  → user clicks remediation action
  → buildWorkspaceUrl(operations, { ws: 'remediation', policyId, remediationId, returnTo })
  → /console/remediation?ws=remediation&policyId=…&remediationId=…&returnTo=…
```

### Customer journey (portal)

```
/portal → customer clicks finding
  → portal BFF resolves engagementId from session (server-side)
  → /portal/findings?findingId=… (no cross-console link — portal is isolated)
```

Portal components never receive console workspace context keys. The `ws` key is console-only.

---

## 8. Demo Mode

Demo mode renders the console using static fixtures instead of live API data. It is activated by appending `?demoMode=1` to any console URL, or by the `DemoModeIndicator` toggle.

### Fixtures (`apps/console/lib/demoFixtures.ts`)

| Constant | Content |
|---|---|
| `DEMO_MODE_ACTIVE` | Boolean flag — `true` when `demoMode=1` is present |
| `DEMO_TENANT_ID` | Placeholder tenant slug (not a real `tenant_id`) |
| `DEMO_ENGAGEMENTS` | Array of 3 representative field engagements |
| `DEMO_FINDINGS` | Array of findings across severity levels |
| `DEMO_REPORTS` | Array of delivered and draft reports |
| `DEMO_REMEDIATIONS` | Array of remediation items at various stages |
| `DEMO_EXECUTIVE_METRICS` | Executive dashboard metric snapshot |
| `DEMO_TRUST_SCORE` | Trust score record with component breakdown |

All fixture data is **static and deterministic**. `Math.random` is banned in `demoFixtures.ts` and enforced by CI.

### Enabling demo mode

Navigate to any console URL and append `?demoMode=1`. The `DemoModeIndicator` component renders a visible banner (`data-demo-mode="active"`) so users can confirm they are in demo mode. The banner includes a dismissal link that strips `demoMode` from the URL.

---

## 9. Accessibility

All workspace-integration components target WCAG 2.1 AA.

| Requirement | Implementation |
|---|---|
| Navigation landmark | `<nav aria-label="Workspace navigation">` in `CrossWorkspaceNav` |
| Active page | `aria-current="page"` on the active workspace link |
| Metadata decorative content | `aria-hidden="true"` on decorative metadata spans |
| Search combobox | `role="combobox"`, `aria-expanded`, `aria-controls` in `WorkspaceSearch` |
| Keyboard navigation | `ArrowUp` / `ArrowDown` cycle through search results; `Enter` selects; `Escape` dismisses |
| Loading state | `aria-busy="true"` on the loading container; skeleton items are `aria-hidden` |
| Demo banner | Visible text "Demo Mode" — not icon-only |

---

## 10. MCIM Compliance

Every workspace-integration component declares the standard MCIM constant set.

| Constant | Required value |
|---|---|
| `mcimId` | `MCIM-18.6-WS-[NAME]` (passed as prop or declared inline) |
| `data-mcim-id` | Present on the root element of navigation components |
| `data-workspace-metadata` | Present on `WorkspaceMetadata` root element |
| `data-demo-mode` | `"active"` or `"inactive"` on `DemoModeIndicator` |

The integration layer does not own a `sourceOfTruth` endpoint — context is derived from URL parameters. Components declare `sourceOfTruth: 'url-params'` where required by the MCIM model.

---

## 11. Component Reference

| File | MCIM ID | Primary attribute | Purpose |
|---|---|---|---|
| `WorkspaceMetadata.tsx` | `MCIM-18.6-WS-METADATA` | `data-workspace-metadata` | Displays active workspace context as collapsible metadata |
| `CrossWorkspaceNav.tsx` | `MCIM-18.6-WS-NAV` | `data-mcim-id`, `aria-label` | Accessible cross-workspace navigation rail |
| `WorkspaceContextBridge.tsx` | `MCIM-18.6-WS-BRIDGE` | — | Reads URL params, populates `WorkspaceContext`, exposes `useWorkspaceContext` |
| `WorkspaceEmptyState.tsx` | `MCIM-18.6-WS-EMPTY` | `mcimId` prop | Contextual empty state with reason, required data, and next action |
| `WorkspaceLoadingState.tsx` | `MCIM-18.6-WS-LOADING` | `mcimId` prop | Skeleton loading state with `animate-pulse` |
| `DemoModeIndicator.tsx` | `MCIM-18.6-WS-DEMO` | `data-demo-mode` | Demo mode banner; strips `demoMode` param on dismiss |
| `WorkspaceSearch.tsx` | `MCIM-18.6-WS-SEARCH` | `role="combobox"`, `aria-expanded` | Keyboard-navigable workspace search with `groupByWorkspace` grouping |
| `index.ts` | — | `WORKSPACE_INTEGRATION_VERSION` | Barrel export; declares integration version constant |

---

## 12. CI Validation

`tools/ci/check_workspace_integration.py` enforces the following on every CI run:

### File existence (8 component files + 3 lib files + 1 arch doc)

All paths under `apps/console/components/workspace-integration/` and `apps/console/lib/` listed in this document must exist. The architecture doc at `docs/architecture/WORKSPACE_INTEGRATION_18_6_8.md` must exist.

### Content contracts (per-file token checks)

Each component file must contain its required tokens (attributes, function names, prop names). The full token list is defined in `COMPONENT_REQUIRED` and `LIB_REQUIRED` in the script.

### Forbidden patterns (component + demo fixtures)

| Pattern | Reason |
|---|---|
| `Math.random()` | Non-deterministic — breaks demo mode and snapshot tests |
| `sessionStorage` | Browser-authoritative state — forbidden by navigation philosophy |
| `localStorage` | Browser-authoritative state — forbidden by navigation philosophy |
| `dangerouslySetInnerHTML` | XSS vector |
| `tenant_id` | Direct tenant ID exposure — use `tenantSlug` |
| `No Data` | Empty state without context — use `WorkspaceEmptyState` |
| `Math.random` in `demoFixtures.ts` | Fixtures must be fully deterministic |

### Navigation registry

`packages/navigation/navigation-registry.json` must contain either version `18.6.8` or the slug `workspace-integration`. Missing both is an error; having one but not the other is a warning.

### Exit codes

- **0** — all checks passed (warnings are acceptable)
- **1** — one or more errors
