# Command Center Authority — PR 18.6.3 Operations Workspace

**MCIM Reference:** MCIM-18.6-CMD-CENTER  
**Status:** Implemented  
**Date:** 2026-07-03

---

## 1. Investigation Drawer Model

The `InvestigationDrawer` is a reusable investigation panel used by all command-center widgets. It is a separate component from `WidgetShell` to prevent coupling between layout and investigation concerns.

### Design decisions

- **Not a modal** — renders as a `<div>` with `role="complementary"` and `aria-label="investigation-drawer"` as a collapsible aside panel.
- **Not part of WidgetShell** — widgets opt in by rendering the drawer conditionally based on user interaction.
- **Focus management** — when opened, focuses the close button via `useRef` + `useEffect`.
- **Empty state** — when `investigationItems` is empty, renders `aria-label="investigation-empty"` with text "No related records available".

### Props

| Prop | Type | Description |
|------|------|-------------|
| `widgetName` | `string` | Display name of the source widget |
| `mcimId` | `string` | MCIM ID to show in metadata table |
| `authority` | `string` | Authority name |
| `capability` | `string` | Capability name |
| `sourceOfTruth` | `string` | Source-of-truth path |
| `refreshPolicy` | `string` | Refresh policy |
| `confidence` | `number?` | Optional confidence 0–1 |
| `lastUpdated` | `string?` | Optional ISO timestamp |
| `drillDown` | `string` | Drill-down route |
| `investigationItems` | `InvestigationItem[]?` | Optional list of related records |
| `open` | `boolean` | Whether the drawer is open |
| `onClose` | `() => void` | Close handler |

### InvestigationItem

```ts
interface InvestigationItem {
  label: string;
  value: string;
  href?: string;
}
```

---

## 2. Universal Drilldown Model

Each widget has a `drillDown` constant pointing to the authoritative surface for that domain:

| Widget | drillDown |
|--------|-----------|
| OperationalHealthMatrix | `/dashboard/control-tower` |
| AuthorityMap | `/dashboard` |
| CorrelationGraph | `/dashboard` |
| ReplaySeam | `/dashboard/evaluation` |
| FutureReservedPanels | `/dashboard` |
| InvestigationDrawer | `/dashboard` (default, overridden by caller) |

---

## 3. Action Center Model

The action model for 18.6.3 is read-only. No widgets in this PR trigger write actions.

Action types (reserved for future):
- **Investigate**: opens `InvestigationDrawer` for any widget
- **Export**: downloads briefing or health data as text
- **Navigate**: follows `drillDown` route to authoritative surface

Authority delegation rules:
- All displayed data authority is attributed to the sourcing authority (Operational Health Authority, Navigation Authority, etc.)
- `InvestigationDrawer` inherits authority from its parent widget via props

---

## 4. Explainability Chain

The explainability chain from raw data to widget display:

```
Raw Authority Data (API)
  → Source of Truth (/api/core/control-tower/snapshot)
    → Evidence (chain_integrity, agents, connectors, keys, lockers)
      → Verification (CI checks, nil-safe access)
        → Decision (health status: ok/warning/error/unknown)
          → Widget (OperationalHealthMatrix badge + label)
```

No widget in this PR generates synthetic or inferred data without explicit source attribution.

---

## 5. Correlation Graph Model

The `CorrelationGraph` component renders relationships between governance entities as a list (not canvas, not SVG).

### Node types

| Type | Description |
|------|-------------|
| `authority` | A governance authority (Control Tower, Compliance, etc.) |
| `connector` | An external system connector |
| `agent` | A governance agent |
| `assessment` | A field assessment engagement |
| `decision` | A governance decision |

### Edge types

| Label | Description |
|-------|-------------|
| `governs` | Authority governs an entity |
| `depends-on` | Entity depends on another |
| `produces` | Entity produces an artifact |
| `reviews` | Entity reviews another entity |

### Determinism rules

Nodes are sorted by `type` then `id` for deterministic rendering. This ensures:
- Same props → same visual output
- No position randomness
- No floating-point layout instability
- Accessible via screen readers in a consistent order

---

## 6. Widget Metadata Contract

Every widget (except `InvestigationDrawer` which is not a widget shell) must declare:

```ts
const MCIM_ID = 'MCIM-18.6-{CAPABILITY}';  // required
const AUTHORITY = '{Authority Name}';          // required
const sourceOfTruth = '/api/core/...';         // required
const drillDown = '/dashboard/...';            // required
```

And must:
- Import `WidgetShell` and wrap content in it
- Pass all four constants to `WidgetShell` props
- Use `'use client'` directive
- Not contain `Math.random`, `dangerouslySetInnerHTML`, `localStorage`, `sessionStorage`
- Not use `'destructive'` as a Badge variant
- Not contain hardcoded fake metrics (= 97, = 98, = 99)

---

## 7. Future Panels Policy

`FutureReservedPanels` lists 10 reserved capabilities. Rules:

1. All panels are `aria-disabled="true"` and `disabled` — no interactions
2. All panels show "Capability reserved — not available"
3. No fake data, no mock metrics, no placeholder timelines
4. Panels are isolated from primary navigation — no nav items point to future panels
5. Adding a new panel requires adding an entry to `FUTURE_CAPABILITIES` array
6. Activating a capability requires removing it from `FutureReservedPanels` and building a real component
7. No capability transitions from "future" to "active" within a single PR without full authority documentation

---

## 8. Testing Strategy

Static-analysis-first: all tests in `tests/console/command-center-actions.test.js` read source files and assert on structure — no runtime execution, no DOM rendering, no network calls.

Categories:
1. **File existence** — each new component file exists
2. **Directive checks** — `'use client'` present
3. **MCIM contract** — MCIM_ID, AUTHORITY, sourceOfTruth, drillDown constants
4. **Accessibility** — aria-label, aria-expanded, tabIndex, role attributes
5. **Prohibited patterns** — Math.random, dangerouslySetInnerHTML, localStorage, sessionStorage, 'destructive' variant
6. **No fake data** — no hardcoded percentages, no fabricated records
7. **Widget registry** — WidgetShell imported and used
8. **Dashboard integration** — new sections present in page.tsx
9. **CI script** — check_command_center_authority.py structure and content

Tests aim for 700+ assertions across 700+ individual `test()` calls. Each assertion is atomic and minimally scoped.
