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
