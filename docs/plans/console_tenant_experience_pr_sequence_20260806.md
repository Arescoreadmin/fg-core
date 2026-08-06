# Console Tenant Experience PR Sequence - 2026-08-06

## PR 1

PR identifier: CTE-PR1  
Title: Fix console invitation 403 root cause  
Objective: Restore authorized tenant-scoped console invitations without broadening tenant API keys.  
Exact scope: BFF/Core authority path for console invitation only; stable error mapping; regression tests.  
Expected files/components: `apps/console/app/api/core/[...path]/route.ts`, console BFF tests, `api/workforce.py` or new tenant-admin wrapper route if chosen, focused Core tests.  
Authority owner: Core identity/Console BFF.  
Tests: authorized invite succeeds; missing `admin:write` 403; missing `identity.scim` 403; route tenant is authoritative; UI receives stable error.  
Gates: targeted tests, `git diff --check`, route/contract gate if routes change, PR_FIX_LOG if source changes.  
Risks: accidentally making tenant portal keys admin-capable.  
Rollback: feature flag or revert BFF route mapping; no schema rollback.  
Dependencies: exact authority route decision.  
Effort: 1-2 days.  
Customer value: restores required admin onboarding.  
Moat contribution: least-privilege invitation authority.  
Required before RC1: Yes.

## PR 2

PR identifier: CTE-PR2  
Title: Canonical tenant-context contract for tenant admin actions  
Objective: Define and enforce one tenant authority path across BFF and Core.  
Exact scope: shared route/header/body contract; reject payload tenant/client overrides in tenant admin wrappers; add mismatch audit codes.  
Expected files/components: BFF proxy, Core tenant admin route handlers, tests for mismatch rejection, docs/contract updates if applicable.  
Authority owner: Platform security/Core API.  
Tests: route A/body B rejected; stale browser tenant rejected; unscoped key rejected; internal admin path requires route tenant.  
Gates: authority gates, route inventory, contract diff if route changes.  
Risks: breaking legacy direct API callers if old route behavior changes in place.  
Rollback: keep legacy routes; disable wrapper flag.  
Dependencies: PR 1 route pattern.  
Effort: 1-2 days.  
Customer value: prevents tenant ambiguity.  
Moat contribution: explainable authority boundary.  
Required before RC1: Yes if any tenant admin mutation remains in RC1.

## PR 3

PR identifier: CTE-PR3  
Title: Tenant-scoped engagement selector API  
Objective: Provide an operator-safe list of engagements owned by the selected tenant.  
Exact scope: read-only BFF/Core path for tenant engagements; response includes human-readable name/status and immutable ID.  
Expected files/components: BFF proxy rule or new admin tenant endpoint, Core engagement list wrapper around `services/field_assessment/store.py`, tests, OpenAPI update if new route.  
Authority owner: Field Assessment/Core API.  
Tests: tenant A list excludes tenant B; unauthorized role 403; empty state; pagination/search if implemented.  
Gates: targeted tests, contract/route inventory.  
Risks: duplicating existing field-assessment list semantics.  
Rollback: keep hidden behind selector flag.  
Dependencies: PR 2 tenant context contract.  
Effort: 1-2 days.  
Customer value: removes raw engagement ID typing.  
Moat contribution: tenant-scoped resource selection.  
Required before RC1: Yes if portal access is included in RC1.

## PR 4

PR identifier: CTE-PR4  
Title: Portal grant form redesign and authority validation  
Objective: Remove editable Client ID and require server-validated owned engagement.  
Exact scope: portal access modal, BFF payload simplification, Core server-side engagement ownership validation.  
Expected files/components: tenant page portal tab, Core portal grant route/wrapper, `services/portal_grant_service.py` caller validation, tests.  
Authority owner: Portal/Core API and Console UX.  
Tests: forged engagement ID rejected; body client mismatch rejected/ignored safely; grant metadata tenant/client consistent; email delivery remains compatible.  
Gates: portal grant tests, route inventory, PR_FIX_LOG.  
Risks: raw grant credential flow remains less ideal than named-user invitations.  
Rollback: feature flag to old modal; validation remains safe if retained.  
Dependencies: PR 2 and PR 3.  
Effort: 2-3 days.  
Customer value: safer portal access issuance.  
Moat contribution: tenant isolation proof.  
Required before RC1: Yes if portal access creation is launch-critical.

## PR 5

PR identifier: CTE-PR5  
Title: Console invitation UX redesign  
Objective: Make invitation flow tenant-explicit and role-explainable.  
Exact scope: modal tenant read-only row, role descriptions, success/pending/delivery status, stable errors.  
Expected files/components: `apps/console/app/admin/tenants/[tenantId]/page.tsx` or extracted components, tests.  
Authority owner: Console UX.  
Tests: tenant name/ID displayed; no tenant field submitted; 403 renders actionable state; keyboard/accessibility basics.  
Gates: frontend tests, `npm test` if scoped.  
Risks: changing UI before authority route stable.  
Rollback: component revert.  
Dependencies: PR 1.  
Effort: 1-2 days.  
Customer value: lowers onboarding friction.  
Moat contribution: visible least-privilege context.  
Required before RC1: Yes after PR 1.

## PR 6

PR identifier: CTE-PR6  
Title: Cross-tenant enforcement and regression suite  
Objective: Lock down bypass paths across invitations, grants, lists, and revocations.  
Exact scope: tests first; minimal fixes only for failures found.  
Expected files/components: Core security tests, BFF proxy tests, possible test fixtures.  
Authority owner: Security/Core API.  
Tests: all tenant isolation tests listed in redesign plan.  
Gates: security tests, authority gates, RLS tests if touched.  
Risks: broad test setup cost.  
Rollback: tests can be narrowed; fixes revert independently.  
Dependencies: PR 1-4.  
Effort: 2-3 days.  
Customer value: confidence before commercial launch.  
Moat contribution: evidence-backed tenant isolation.  
Required before RC1: Yes for flows included in RC1.

## PR 7

PR identifier: CTE-PR7  
Title: Invitation lifecycle status and audit UX  
Objective: Surface pending/sent/accepted/expired/revoked states and audit proof.  
Exact scope: lifecycle table, resend/revoke eligibility, audit/request ID display.  
Expected files/components: Console tenant page, identity/portal lifecycle endpoints if missing, tests.  
Authority owner: Identity/Console UX.  
Tests: issue, resend, accept, expire, revoke, delivery failure, audit display.  
Gates: targeted tests, contract update if new endpoints.  
Risks: scope creep into full identity governance product.  
Rollback: hide lifecycle UI behind flag.  
Dependencies: PR 1 and PR 5; optional Unified Invitation Authority alignment.  
Effort: 2 days.  
Customer value: operational clarity.  
Moat contribution: auditability and Trust but Verify.  
Required before RC1: No, unless launch walkthrough requires lifecycle proof.

## PR 8

PR identifier: CTE-PR8  
Title: Terminology, accessibility, and polish  
Objective: Align labels and modal behavior with enterprise operator expectations.  
Exact scope: wording, empty states, dialog accessibility, responsive layout, no nav count increase.  
Expected files/components: Console tenant page/components, maybe navigation aliases only.  
Authority owner: Console UX/design system.  
Tests: a11y/keyboard checks; nav visible item count <=9; responsive modal.  
Gates: frontend tests, visual review if available.  
Risks: cosmetic churn during launch freeze.  
Rollback: component revert.  
Dependencies: PR 5 and PR 4.  
Effort: 1-2 days.  
Customer value: lower cognitive load.  
Moat contribution: professional enterprise experience.  
Required before RC1: No, except critical error/tenant-context labels.

## Recommended sequence

1. CTE-PR1
2. CTE-PR2
3. CTE-PR3
4. CTE-PR4, if portal access remains in RC1
5. CTE-PR5
6. CTE-PR6
7. CTE-PR7
8. CTE-PR8

The smallest safe first PR is CTE-PR1. It restores the blocked workflow while preserving Core's `admin:write` and `identity.scim` enforcement.
