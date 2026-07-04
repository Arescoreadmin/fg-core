# MCIM 18.6 Validation Checklist

Use this checklist for every PR in the 18.6.x sequence.

## Route Integrity

- [ ] No existing Console route was removed unless the MCIM explicitly classifies it as retired.
- [ ] No existing Portal route was removed unless the MCIM explicitly classifies it as retired.
- [ ] Every touched route maps to a capability in the MCIM.
- [ ] Every touched route has a lifecycle classification.
- [ ] Hidden, contextual, and specialist routes remain reachable from at least one canonical entry point.

## Authority Coverage

- [ ] No authority was orphaned by a navigation or layout change.
- [ ] No backend-only authority was implied to be user-facing without a documented future home.
- [ ] No visible nav item points only to a placeholder experience without an explicit tier justification.
- [ ] Duplicate surfaces were either preserved intentionally or explicitly documented in the PR.

## Source of Truth

- [ ] No new business KPI was introduced without a source-of-truth assignment.
- [ ] No duplicate readiness, risk, trust, remediation, or continuity computation was added.
- [ ] Portal summary metrics still reconcile to their underlying findings, roadmap, questionnaire, and attestation sources.
- [ ] Command Center metrics do not add new browser-only state dependencies.

## State Ownership

- [ ] Critical context does not depend only on `localStorage`.
- [ ] URL or server-session context exists for engagement, client, tenant, or report flows that must survive reload/share flows.
- [ ] New browser storage use is documented and non-critical.
- [ ] Portal write flows still use server-owned auth/session boundaries.

## Mutation Safety

- [ ] Every write action still maps to an explicit authority owner.
- [ ] Every write action still has an audit expectation.
- [ ] Portal write actions are not mislabeled as read-only.
- [ ] Report verification, attestation, remediation, and key-management labels still describe the real mutation semantics.

## Trust and Provenance

- [ ] Provenance links remain reachable from trust, report, and evidence surfaces.
- [ ] Verification bundle links remain reachable from engagement and/or reports surfaces.
- [ ] Report verify affordances remain present where reports are exposed.
- [ ] No Trust Center change weakens the chain-of-custody story.

## Navigation and IA

- [ ] Primary destinations remain primary for their core personas.
- [ ] Specialist destinations are not promoted without evidence-backed value.
- [ ] Legacy routes are demoted or contextualized before any retirement proposal.
- [ ] Future workspace labels align to MCIM capability families.

## Validation Commands

- [ ] `python tools/ci/check_mcim_docs.py`
- [ ] `pytest tests/tools/test_mcim_docs.py -q`
- [ ] `python tools/ci/check_navigation_registry.py`
- [ ] `pytest tests/tools/test_navigation_registry.py -q`
- [ ] `make fg-smart`
- [ ] `make fg-contract`
- [ ] Optional when useful: `make fg-fast`

## PR Hygiene

- [ ] Only intended docs and optional MCIM guard/test files changed.
- [ ] No production source files changed unless explicitly justified and approved.
- [ ] The PR description references the relevant MCIM sections and decision-log entries.

## PR 18.6.1 Checklist — Unified Navigation Framework

- [x] Every existing console route registered in `CONSOLE_REGISTRY` (31 items).
- [x] Every existing portal route registered in `PORTAL_REGISTRY` (12 items).
- [x] All 8 MCIM groups registered in `ALL_GROUPS`.
- [x] Enterprise group reserved with `reserved: true` — no items assigned.
- [x] `/assessment` classified as `tier: legacy, visibility: hidden` — route preserved.
- [x] `/dashboard/forensics` (Audit & Forensics) moved from Compliance → Trust group.
- [x] `/dashboard/provenance` moved from AI & Knowledge → Trust group.
- [x] `/dashboard/decisions` moved from Compliance → Trust group.
- [x] `/dashboard/workforce` moved from standalone Workforce → Intelligence group.
- [x] `/keys` added to sidebar under Administration (was unlisted).
- [x] `/audit` retained as specialist visible item under Compliance.
- [x] Console sidebar generated from `CONSOLE_REGISTRY.getByGroup()` — no hardcoded tree.
- [x] Portal nav generated from `PORTAL_REGISTRY.getAllItems()` with tier ordering.
- [x] `navigation-registry.json` JSON snapshot checked in and valid.
- [x] `tools/ci/check_navigation_registry.py` passes.
- [x] `tests/tools/test_navigation_registry.py` 399 tests pass.
- [x] No backend changes, no API changes, no authority changes.
- [x] MCIM Navigation Decision Log updated with PR 18.6.1 decisions.
- [x] SOC review entry added for `tools/ci/check_navigation_registry.py`.
- [x] PR_FIX_LOG updated.

## PR 18.6.3 Checklist — Operations Workspace

- [x] 6 new component files created: `InvestigationDrawer.tsx`, `OperationalHealthMatrix.tsx`, `AuthorityMap.tsx`, `CorrelationGraph.tsx`, `ReplaySeam.tsx`, `FutureReservedPanels.tsx`
- [x] 4 existing components enhanced: `WidgetShell.tsx`, `ExecutiveBriefing.tsx`, `ExecutiveNotifications.tsx`, `DecisionProvenancePanel.tsx`
- [x] Dashboard page updated with 3 new sections: ops-matrix-heading, correlation-heading, future-heading
- [x] All new widgets import `WidgetShell` and declare MCIM_ID, AUTHORITY, sourceOfTruth, drillDown
- [x] No `Math.random` in any new component
- [x] No `dangerouslySetInnerHTML` in any new component
- [x] No `localStorage` or `sessionStorage` in any new component
- [x] No `'destructive'` Badge variant used
- [x] No hardcoded fake metrics (= 97, = 98, = 99)
- [x] `InvestigationDrawer` is NOT a modal — `role="complementary"` panel
- [x] `CorrelationGraph` is list-based — no canvas, no SVG
- [x] `ReplaySeam` all buttons `disabled` with `aria-disabled="true"`
- [x] `FutureReservedPanels` all panels `aria-disabled="true"` with "Capability reserved" text
- [x] `OperationalHealthMatrix` derives health from snapshot — no fabricated data
- [x] `AuthorityMap` derives health from snapshot for `from-snapshot` entries
- [x] `check_command_center_authority.py` CI script passes all components
- [x] `check_executive_dashboard.py` still passes
- [x] 511 existing tests in `tests/console/command-center.test.js` still pass
- [x] 700+ new tests in `tests/console/command-center-actions.test.js` pass
- [x] `COMMAND_CENTER_AUTHORITY_18_6_3.md` created
- [x] MCIM Navigation Decision Log updated with PR 18.6.3 decisions
- [x] SOC review entry added for `tools/ci/check_command_center_authority.py`
- [x] PR_FIX_LOG updated
- [x] ROADMAP.md updated
