# Tenant Identity & Administration Platform — PR Sequence

**Date:** 2026-08-06  
**Branch:** plan/tenant-identity-administration-platform-20260806  
**Status:** PLANNING ARTIFACT — launch freeze active; no runtime changes  
**Authority:** jcosat

This document provides the canonical PR execution sequence for the Tenant Identity & Administration Platform roadmap integration. It absorbs the existing `console_tenant_experience_pr_sequence_20260806.md` CTE-PR1 through CTE-PR8 into H0 and H1 horizons, and defines the H2 authority consolidation sequence.

All H0 PRs are bounded by the launch freeze. Only production defects discovered during C4 execution are permitted before RC1.

---

## Horizon 0 — RC1 Launch Repair

### H0-PR1 (formerly CTE-PR1)

**PR ID:** H0-PR1  
**Title:** Fix console invitation 403 root cause  
**Horizon:** H0 — RC1 Launch Repair  
**Objective:** Restore authorized tenant-scoped console invitations without broadening tenant API keys.

**Exact scope:**
- Identify the correct BFF authority path for console invitation to Core `POST /workforce/users`
- BFF must use operator-class authority (`admin:write` + `identity.scim`) for this write, not tenant portal API key
- Add stable error mapping: 403 must return actionable detail, not raw HTTP status
- Add regression tests for the fixed path

**Non-goals:**
- Do not widen tenant API-key permissions
- Do not create global admin shortcut
- Do not build invitation UX redesign (H1-PR1)
- Do not build lifecycle status UI (H1-PR2)

**Authority owner:** Core identity / Console BFF  
**Expected files/components:**
- `apps/console/app/api/core/[...path]/route.ts` — BFF authority selection for workforce/users
- `api/workforce.py` — no change expected (Core correctly enforces)
- Possibly a new BFF admin endpoint or a wrapper route for tenant admin writes
- Focused Core tests and BFF proxy tests

**API/contract impact:** BFF internal credential selection only; no public API change  
**Persistence impact:** None  
**Audit impact:** Invitation attempt events should emit from existing audit points  

**Tests:**
- Authorized invite succeeds with correct operator credentials
- Tenant portal API key → 403 (Core enforcement preserved)
- Missing `admin:write` → 403
- Missing `identity.scim` → 403
- Route tenant is authoritative (does not come from request body)
- BFF returns structured error with `detail` and `code`, not raw 403

**Gates:** Targeted tests; `git diff --check`; route/contract inventory if routes change; PR_FIX_LOG if source changes  
**Dependencies:** None — first in sequence  
**Migration/compatibility:** None  
**Rollback:** Revert BFF route mapping; no schema rollback  
**Effort:** 1–2 days  
**Customer value:** Restores required admin onboarding workflow  
**Moat contribution:** Least-privilege invitation authority; correct operator/tenant boundary  
**Required before RC1:** Yes — blocks T9  
**Required before first design-partner self-administration:** Yes

---

### H0-PR2 (formerly CTE-PR2)

**PR ID:** H0-PR2  
**Title:** Canonical tenant-context contract for tenant admin actions  
**Horizon:** H0 — RC1 Launch Repair  
**Status:** IMPLEMENTED / VALIDATING — 2026-08-07; branch `fix/h0-pr2-canonical-tenant-authority` (not yet committed or merged)
**Objective:** Enforce one tenant authority path across BFF and Core; reject payload tenant/client overrides.

**What shipped:**
- `resolve_authoritative_tenant(request, actor_ctx, route_tenant_id)` added to `api/auth_scopes/resolution.py` — single canonical resolver wrapping `bind_tenant_id()` with explicit actor_ctx.tenant_id cross-check
- 3 new `IdentityEventType` members with explicit taxonomy: `TENANT_CONTEXT_VERIFIED` (all agree), `STALE_TENANT_SESSION` (actor session claims different tenant than route), `RESOURCE_TENANT_MISMATCH` (reserved for downstream object-ownership checks). `identity.auth.tenant_mismatch` remains the bind_tenant_id key/route event — not reused here.
- All 9 POST/PUT mutation routes in `api/admin_identity.py` migrated from bare `bind_tenant_id()` to `resolve_authoritative_tenant()`
- Unit tests (resolver helper) + integration test (real route dependency stack) in `tests/security/test_resolve_authoritative_tenant.py`

**Exact scope:**
- Shared route/header/body contract: tenant comes from route or trusted header, not mutation payload
- Reject payload tenant/client overrides in tenant admin wrappers
- Add audit event codes for tenant mismatch rejections
- Document the canonical contract for H1 consumers

**Non-goals:**
- Do not redesign the BFF proxy entirely
- Do not implement new tenant admin routes (H1-PR5)
- Do not break legacy direct API callers in this PR

**Authority owner:** Platform security / Core API  
**Expected files/components:**
- BFF proxy (`apps/console/app/api/core/[...path]/route.ts`) — tenant stripping/validation
- Core tenant admin route handlers — mismatch rejection
- Tests for mismatch scenarios
- Contract documentation update if applicable

**API/contract impact:** Behavior change: payload tenant fields stripped or rejected  
**Persistence impact:** None  
**Audit impact:** New `TENANT_MISMATCH` audit event code  

**Tests:**
- Route tenant A / body tenant B → body B rejected
- Stale browser tenant (session switched) → rejected
- Unscoped key → rejected
- Internal admin path requires route tenant match

**Gates:** Authority gates; route inventory; contract diff  
**Dependencies:** H0-PR1 route pattern  
**Effort:** 1–2 days  
**Required before RC1:** Yes, if any tenant admin mutation remains in RC1 scope

---

### H0-PR3 (formerly CTE-PR3)

**PR ID:** H0-PR3  
**Title:** Tenant-scoped engagement selector API  
**Horizon:** H0 — RC1 Launch Repair  
**Objective:** Provide an operator-safe list of engagements owned by the selected tenant; replace raw engagement ID typing.

**Exact scope:**
- Read-only BFF/Core path for tenant-owned engagements
- Response includes human-readable name, status, and immutable ID
- Server-side ownership validation: only engagements with `tenant_id = route_tenant` are returned
- No engagement from another tenant is visible

**Non-goals:**
- Do not implement full portal access UI (H1-PR8)
- Do not implement pagination/search unless trivially available from existing store

**Authority owner:** Field Assessment / Core API  
**Expected files/components:**
- BFF proxy rule or new admin tenant endpoint
- Core engagement list wrapper around `services/field_assessment/store.py`
- Tests for cross-tenant exclusion
- OpenAPI update if new route

**API/contract impact:** New read route for tenant-scoped engagement list  
**Persistence impact:** None  
**Audit impact:** None for read; no audit event needed for list  

**Tests:**
- Tenant A engagement list excludes tenant B engagements
- Unauthorized role → 403
- Empty state returns empty list
- All returned engagements have tenant_id = route_tenant

**Gates:** Targeted tests; contract/route inventory  
**Dependencies:** H0-PR2 tenant context contract  
**Effort:** 1–2 days  
**Required before RC1:** Yes, if portal access creation is included in T10

---

### H0-PR4 (formerly CTE-PR4)

**PR ID:** H0-PR4  
**Title:** Portal grant form and server-side engagement ownership validation  
**Horizon:** H0 — RC1 Launch Repair  
**Objective:** Remove editable Client ID from portal grant form; require server-validated owned engagement; fix API-001 (browser-supplied authority-bearing identifiers).

**Exact scope:**
- Portal access modal: remove editable `client_id` field
- BFF payload simplification: `client_id` derived from route/session tenant, not body
- Core server-side revalidation: `engagement_id` must belong to route tenant before grant creation
- `services/portal_grant_service.py`: add ownership check before credential issuance

**Non-goals:**
- Do not redesign the full portal access lifecycle (H1-PR8)
- Do not implement named-user invitation from this surface (H1-PR8)
- Raw grant credential flow remains acceptable for H0; named-user path is stronger but deferred

**Authority owner:** Portal / Core API and Console UX  
**Expected files/components:**
- Console tenant page portal tab (remove `client_id` input)
- BFF proxy for `/portal/grants`
- Core portal grant route / `services/portal_grant_service.py` — ownership validation
- Tests for forged engagement ID rejection

**API/contract impact:** `client_id` removed from grant creation request body  
**Persistence impact:** None  
**Audit impact:** `ENGAGEMENT_NOT_FOUND` / `ENGAGEMENT_TENANT_MISMATCH` error codes  

**Tests:**
- Forged engagement_id (belongs to other tenant) → rejected
- Body client_id override → rejected or ignored safely
- Grant metadata is tenant/client consistent
- Email delivery remains compatible

**Gates:** Portal grant tests; route inventory; PR_FIX_LOG  
**Dependencies:** H0-PR2 and H0-PR3  
**Effort:** 2–3 days  
**Required before RC1:** Yes, if portal access creation is a T10 requirement

---

### H0-PR5 (formerly CTE-PR6)

**PR ID:** H0-PR5  
**Title:** Cross-tenant enforcement and regression suite  
**Horizon:** H0 — RC1 Launch Repair  
**Objective:** Prove tenant isolation holds across invitations, grants, lists, and revocations; catch any bypass paths introduced during H0-PR1 through H0-PR4.

**Exact scope:**
- Tests first: write cross-tenant test scenarios before writing any fixes
- Test invitations: tenant A cannot invite into tenant B
- Test grants: tenant A cannot create grants for tenant B engagements
- Test lists: tenant A cannot list tenant B users or engagements
- Test revocations: tenant A cannot revoke tenant B sessions
- Minimal fixes only for failures found

**Non-goals:**
- Do not implement new features in this PR
- Do not run the full 21,466 test suite (that is the launch gate suite)
- Do not add RLS tests unless an RLS gap is found (existing RLS coverage is strong)

**Authority owner:** Security / Core API  
**Expected files/components:**
- Core security tests (new cross-tenant test file or additions to `tests/security/test_identity_administration_isolation.py`)
- BFF proxy tests
- Possibly test fixtures for multi-tenant setup

**API/contract impact:** None (test-only)  
**Persistence impact:** None  
**Audit impact:** None  

**Tests:**
- Cross-tenant invitation: all flows tested
- Cross-tenant engagement list: excluded
- Cross-tenant portal grant: rejected
- Cross-tenant session revocation: rejected
- Cross-tenant user list: excluded

**Gates:** Security tests; authority gates; RLS tests if touched  
**Dependencies:** H0-PR1 through H0-PR4  
**Effort:** 2–3 days  
**Required before RC1:** Yes

---

## Horizon 1 — First Design-Partner Self-Administration

**Start condition:** RC1 tagged; design partner scheduled or active.

**Stop condition (non-negotiable):** H1 stops as soon as the first design partner can securely self-administer routine users and portal access without FrostGate founder intervention. Not all ten PRs are required. Before starting any PR in this list, re-evaluate: is the exit criterion already met? If yes, stop. If a PR is unnecessary after observing real use, skip it. If two PRs can be merged without losing independent reviewability, merge them. Customer evidence controls scope; the list does not.

### H1-PR1 (formerly CTE-PR5)

**PR ID:** H1-PR1  
**Title:** Console invitation UX redesign  
**Horizon:** H1 — First Design-Partner Self-Administration  
**Objective:** Make the invitation flow tenant-explicit and role-explainable; implement wireframe from `console_tenant_experience_wireframes_20260806.md`.

**Exact scope:**
- Invitation modal: tenant name and ID displayed read-only
- No tenant field submitted in invitation payload
- Role descriptions visible (as planned in wireframes)
- 403 renders actionable denial state with request ID
- Success state shows pending/delivery status, expiration, audit event ID

**Non-goals:**
- No full invitation lifecycle table (H1-PR2)
- No invitation management (resend/revoke UI) — H1-PR2
- No full tenant admin surface — H1-PR6

**Authority owner:** Console UX  
**Expected files/components:**
- `apps/console/app/admin/tenants/[tenantId]/page.tsx` or extracted components
- Frontend tests

**Tests:**
- Tenant name/ID displayed
- No tenant field submitted
- 403 renders actionable state
- Keyboard/accessibility basics

**Gates:** Frontend tests; `npm test` if scoped  
**Dependencies:** H0-PR1 (authority fix must be in place)  
**Effort:** 1–2 days  
**Required before first design-partner self-administration:** Yes

---

### H1-PR2 (formerly CTE-PR7)

**PR ID:** H1-PR2  
**Title:** Invitation lifecycle status and audit UX  
**Horizon:** H1 — First Design-Partner Self-Administration  
**Objective:** Surface pending/sent/accepted/expired/revoked invitation states; expose audit proof and request IDs to operators.

**Exact scope:**
- Lifecycle table: recipient, type, status, sent, expires, actions
- Resend and revoke eligibility based on invitation state
- Audit/request ID display
- Identity lifecycle endpoints if missing

**Non-goals:**
- Do not build full audit history surface (H1-PR10)
- Do not begin Unified Invitation Authority (H2-PR1)
- Scope creep into full identity governance product must be rejected

**Authority owner:** Identity / Console UX  
**Expected files/components:**
- Console tenant page (lifecycle table)
- Identity/portal lifecycle endpoints if missing from existing authority files
- Tests

**Tests:**
- Issue → resend → accept → expire → revoke flow
- Delivery failure state
- Audit/request ID displayed

**Gates:** Targeted tests; contract update if new endpoints  
**Dependencies:** H1-PR1; optionally H2-PR1 alignment point  
**Effort:** 2 days  
**Required before first design-partner self-administration:** Yes (operators need lifecycle visibility)

---

### H1-PR3 (formerly CTE-PR8)

**PR ID:** H1-PR3  
**Title:** Terminology, accessibility, and polish  
**Horizon:** H1 — First Design-Partner Self-Administration  
**Objective:** Align labels with enterprise operator expectations; no navigation count increase.

**Exact scope:**
- Wording alignment: Tenant vs Client (keep "Clients" in nav; use "Tenant ID" as secondary label)
- Empty states
- Dialog accessibility
- Responsive layout
- Nav visible item count ≤ 9

**Non-goals:**
- No visual redesign of the whole Console
- No new nav items

**Authority owner:** Console UX / design system  
**Expected files/components:**
- Console tenant page/components
- Navigation (no count increase)

**Tests:**
- A11y/keyboard checks
- Nav item count ≤ 9
- Responsive modal

**Gates:** Frontend tests; visual review  
**Dependencies:** H1-PR1 and H1-PR2  
**Effort:** 1–2 days  
**Required before first design-partner self-administration:** Partially (critical error/context labels yes; cosmetic polish no)

---

### H1-PR4

**PR ID:** H1-PR4  
**Title:** Tenant administrator identity and session authority  
**Horizon:** H1 — First Design-Partner Self-Administration  
**Objective:** Establish the `tenant_admin` role as a fully functional session principal that can authenticate via Auth0 org and receive a tenant-bound governed session.

**Exact scope:**
- Verify `tenant_admin` role authentication flow through Admin Gateway (existing `require_governed_session()`)
- Confirm Auth0 org membership → Core `tenant_users` membership binding works for `tenant_admin` principals
- Verify `auth_version` and `membership_version` enforcement for `tenant_admin` sessions
- Tests: tenant_admin session issues, revokes, version-bumps correctly
- Confirm SoD invariant: `tenant_admin` ≠ `compliance_reviewer` (existing test; add to new tenant_admin smoke suite)

**Non-goals:**
- Do not build tenant admin UI (H1-PR6)
- Do not implement new permission model (existing `tenant_rbac.py` is sufficient)
- Do not add `tenant_operator` or `tenant_auditor` unless design partner specifically requests

**Authority owner:** Core identity / Admin Gateway  
**Expected files/components:**
- `api/tenant_rbac.py`, `api/actor_context.py` — verify, do not change unless gaps found
- New `tests/test_tenant_admin_session_authority.py`
- Possibly `api/admin_identity.py` for tenant_admin invite/accept flow

**API/contract impact:** No new routes expected; validation of existing flows  
**Persistence impact:** None  
**Audit impact:** Confirm audit events for tenant_admin session issuance/revocation  

**Tests:**
- Tenant admin authenticates; receives governed session
- Tenant admin session has correct tenant scope
- Tenant admin cannot access another tenant's data
- SoD: tenant_admin is not compliance_reviewer
- auth_version bump invalidates session

**Gates:** Targeted tests; authority gate if permissions change  
**Dependencies:** H0-PR1 (invitation fix); H1-PR1 (invitation UX)  
**Effort:** 1–2 days  
**Required before first design-partner self-administration:** Yes

---

### H1-PR5

**PR ID:** H1-PR5  
**Title:** Tenant user administration APIs  
**Horizon:** H1 — First Design-Partner Self-Administration  
**Objective:** Provide tenant-admin-scoped API routes for user listing, invitation, role change, disable, and reactivation.

**Exact scope:**
- Tenant-scoped endpoints gated by `tenant_admin` role (not `platform_admin`):
  - `GET /admin/tenants/{tenant_id}/users` — list users with membership/invitation status
  - `POST /admin/tenants/{tenant_id}/invitations` — invite user to tenant
  - `PATCH /admin/tenants/{tenant_id}/users/{user_id}` — change role, disable, reactivate
  - `DELETE /admin/tenants/{tenant_id}/users/{user_id}/sessions` — revoke all sessions
  - `POST /admin/tenants/{tenant_id}/users/{user_id}/password-reset` — initiate IdP-mediated password reset
  - `POST /admin/tenants/{tenant_id}/invitations/{invitation_id}/resend` — resend pending invitation
- All routes: route tenant is authoritative; payload cannot override
- All routes: target resource tenant_id revalidated server-side
- All routes: audit events emitted

**Non-goals:**
- Do not build UI (H1-PR6)
- Do not implement custom roles
- Do not implement SCIM
- Do not create new invitation system (use existing `admin_identity.py` / `TenantInvitation` or extend it)

**Authority owner:** Core identity / Platform security  
**Expected files/components:**
- New tenant admin router: `api/tenant_admin.py` or extensions to `api/admin_identity.py`
- `api/tenant_rbac.py` — `tenant_admin` permission checks
- Auth0 adapter for password reset initiation
- Tests

**API/contract impact:** New admin tenant routes (not public; requires admin session)  
**Persistence impact:** None new; uses existing `tenant_users`, `tenant_invitations`, `tenant_identity_audit_events`  
**Audit impact:** All mutations emit audit events  

**Tests:**
- Tenant admin can list users in own tenant
- Tenant admin cannot list users in another tenant
- Tenant admin can invite new user
- Tenant admin cannot change platform_admin roles
- Role change emits audit event
- Disable user invalidates session (via auth_version bump)
- Password reset does not expose credentials to tenant admin

**Gates:** Targeted tests; route inventory; PR_FIX_LOG; authority gate  
**Dependencies:** H1-PR4; H0-PR2 (canonical tenant context)  
**Effort:** 3–5 days  
**Required before first design-partner self-administration:** Yes

---

### H1-PR6

**PR ID:** H1-PR6  
**Title:** Tenant administration user interface  
**Horizon:** H1 — First Design-Partner Self-Administration  
**Objective:** Surface tenant user administration through the Console tenant detail page (Console users tab).

**Exact scope:**
- Console users tab: user list with membership/invitation status, role badges, action menu
- Actions: invite, resend invitation, change role, disable, reactivate, revoke sessions
- All actions delegated to H1-PR5 APIs
- Tenant context read-only throughout
- Error states: permission denied, tenant mismatch, user not found

**Non-goals:**
- No custom role builder
- No bulk user management
- No CSV export

**Authority owner:** Console UX  
**Expected files/components:**
- `apps/console/app/admin/tenants/[tenantId]/page.tsx` — Console users tab implementation
- BFF proxy routes for H1-PR5 APIs
- Tests

**Tests:**
- User list renders correctly
- Invite action triggers invitation flow
- Action menu state matches user status
- Permission denied state rendered correctly

**Gates:** Frontend tests; BFF proxy tests  
**Dependencies:** H1-PR5; H1-PR1; H1-PR2  
**Effort:** 2–4 days  
**Required before first design-partner self-administration:** Yes

---

### H1-PR7

**PR ID:** H1-PR7  
**Title:** Tenant-scoped engagement selection (full UI)  
**Horizon:** H1 — First Design-Partner Self-Administration  
**Objective:** Replace raw engagement ID typing with a searchable, tenant-scoped engagement selector throughout the Console.

**Exact scope:**
- Engagement selector component backed by H0-PR3 API
- Searchable; shows name, status, and ID
- Only returns engagements owned by route tenant
- Used in portal access creation flow and any other engagement-referencing action

**Non-goals:**
- No engagement creation from this surface
- No cross-tenant engagement visibility

**Authority owner:** Console UX / Field Assessment  
**Expected files/components:**
- Engagement selector component
- Integration into portal access modal
- Tests

**Tests:**
- Selector only shows tenant-owned engagements
- Search filters correctly
- Empty state when no engagements

**Gates:** Frontend tests  
**Dependencies:** H0-PR3; H1-PR6  
**Effort:** 2 days  
**Required before first design-partner self-administration:** Yes

---

### H1-PR8

**PR ID:** H1-PR8  
**Title:** Portal access lifecycle administration  
**Horizon:** H1 — First Design-Partner Self-Administration  
**Objective:** Allow tenant admin to create, view, and revoke portal access for recipients within their tenant.

**Exact scope:**
- Portal access tab: recipient, engagement, access type, status, expiration, revoke action
- Grant creation: uses engagement selector (H1-PR7); no raw client_id entry
- Revoke action: delegated to existing portal grant revocation path
- Named-user invitation path: connect to H1-PR5 invitation flow for named-user portal access

**Non-goals:**
- No bulk access grant
- No access review workflow (H3)

**Authority owner:** Portal / Console UX  
**Expected files/components:**
- Console tenant page Portal access tab
- BFF proxy for portal grant lifecycle
- Tests

**Tests:**
- Portal access list shows tenant-scoped grants only
- Grant creation rejects cross-tenant engagements
- Revoke removes access

**Gates:** Portal grant tests; route inventory  
**Dependencies:** H1-PR5; H1-PR7; H0-PR4  
**Effort:** 2–3 days  
**Required before first design-partner self-administration:** Yes

---

### H1-PR9

**PR ID:** H1-PR9  
**Title:** Password reset, session revocation, and account disablement  
**Horizon:** H1 — First Design-Partner Self-Administration  
**Objective:** Implement IdP-mediated password reset, server-side session revocation, and account disablement for tenant administrators.

**Exact scope:**
- Password reset: trigger Auth0 password-change email; no FrostGate operator visibility into credentials
- Session revocation: use existing `revoke_all_for_subject()` from `api/identity_authority/authority.py`; bump `auth_version`
- Account disablement: set `tenant_users.status = disabled`; bump `auth_version`; Auth0 block via adapter
- Reactivation: set `tenant_users.status = active`; Auth0 unblock
- All actions from H1-PR5 API endpoints; H1-PR6 UI surfaces them

**Non-goals:**
- No direct credential management by FrostGate operators
- No operator-readable password path

**Authority owner:** Core identity / Auth0 adapter  
**Expected files/components:**
- Auth0 adapter extensions for password reset, block, unblock
- `api/tenant_admin.py` endpoints (or `api/admin_identity.py` extensions)
- Tests

**Tests:**
- Password reset initiates Auth0 flow; no credential returned to caller
- Session revocation invalidates existing tokens
- Disablement blocks re-authentication
- Reactivation restores access

**Gates:** Targeted tests; Auth0 adapter tests  
**Dependencies:** H1-PR5; H1-PR4  
**Effort:** 2–3 days  
**Required before first design-partner self-administration:** Yes

---

### H1-PR10

**PR ID:** H1-PR10  
**Title:** Tenant identity audit and lifecycle evidence surface  
**Horizon:** H1 — First Design-Partner Self-Administration  
**Objective:** Surface tenant-scoped identity and access audit history to tenant administrators.

**Exact scope:**
- Audit history tab on Console tenant detail page
- Reads from `tenant_identity_audit_events` (RLS-gated, append-only, hash-linked)
- Shows: event type, principal, target, timestamp, request ID, event ID
- Scoped to route tenant; no cross-tenant leakage
- Filter by event type

**Non-goals:**
- No cross-tenant audit
- No platform-level audit surface (platform_admin only)
- No raw token/secret display

**Authority owner:** Audit / Console UX  
**Expected files/components:**
- Console tenant page Audit history tab
- BFF proxy for tenant audit events
- Core endpoint: `GET /admin/tenants/{tenant_id}/identity-events`
- Tests

**Tests:**
- Audit events are tenant-scoped
- Cross-tenant events not visible
- Event hash chain integrity noted

**Gates:** Targeted tests; route inventory  
**Dependencies:** H1-PR5; H1-PR6  
**Effort:** 2–3 days  
**Required before first design-partner self-administration:** Yes

---

## Horizon 2 — Identity Authority Platform Consolidation

**Start condition:** RC1 tagged; design partner active; H1 exit criteria met.

### H2-PR1

**PR ID:** H2-PR1  
**Title:** Unified Invitation Authority foundation  
**Horizon:** H2 — Identity Authority Platform Consolidation  
**Objective:** Establish one canonical authority service that handles all identity invitations regardless of type (console user, portal shared, portal named-user). This is the non-negotiable first P1-01 PR.

**Exact scope:**
- `InvitationAuthority` service with canonical invitation lifecycle
- Accepts: invitation type, recipient, tenant, role/grant parameters, expiration policy
- Emits: canonical invitation events to unified audit pipeline
- Wraps: existing `admin_identity.py` console invitation path, `portal_user_authority.py` named-user path
- Does not replace: existing paths immediately (compatibility wrapper strategy)
- One API, one audit trail, one notification pipeline per invitation
- Idempotency and replay protection

**Non-goals:**
- Do not retire legacy paths in this PR (H2-PR5)
- Do not implement SCIM or federation

**Authority owner:** Platform identity / Core  
**Expected files/components:**
- `api/invitation_authority/` new package
- `InvitationAuthority` service
- Canonical invitation event types
- Tests

**API/contract impact:** New unified invitation route; legacy routes remain temporarily  
**Persistence impact:** May require new canonical invitation table or unified view  
**Audit impact:** Unified invitation audit events  

**Gates:** Targeted tests; PR_FIX_LOG; route inventory; authority gate  
**Dependencies:** H1 exit criteria met; RC1 tagged  
**Effort:** 3–5 days

---

### H2-PR2

**PR ID:** H2-PR2  
**Title:** Membership Authority consolidation  
**Objective:** One `MembershipAuthority` service; Core authoritative for membership state; Auth0 org as provider adapter.

**Expected files/components:**
- `api/membership_authority/` new package
- Consolidates: `tenant_users` membership operations from `admin_identity.py`, `workforce.py`, and H1-PR5 endpoints
- Auth0 as membership-events provider; Core as governance authority

**Dependencies:** H2-PR1  
**Effort:** 3–5 days

---

### H2-PR3

**PR ID:** H2-PR3  
**Title:** Role and permission authority consolidation  
**Objective:** One `RoleAuthority` service; explicit role grant tracking; formalize SoD invariants as authority rules.

**Dependencies:** H2-PR2  
**Effort:** 3–5 days

---

### H2-PR4

**PR ID:** H2-PR4  
**Title:** Credential and session authority consolidation  
**Objective:** One `SessionAuthority` formalization; existing `identity_authority/authority.py` formalized; shared revocation semantics; session/credential audit chain.

**Dependencies:** H2-PR3  
**Effort:** 2–3 days

---

### H2-PR5

**PR ID:** H2-PR5  
**Title:** Legacy invitation and grant path retirement  
**Objective:** Retire legacy console/portal invitation and grant paths after all consumers have migrated to canonical authorities. No unsafe payload authority preserved for compatibility.

**Note:** Do not begin until H2-PR1 through H2-PR4 are complete and all consumers confirmed migrated.

**Dependencies:** H2-PR1 through H2-PR4; all consumers migrated  
**Effort:** 2–3 days

---

## Recommended Execution Sequence

```
TODAY
  H0-PR1  →  H0-PR2  →  H0-PR3  →  H0-PR4  →  H0-PR5
                                                    │
                                            T9 rerun
                                            T10 run
                                            T13 run
                                            T8 run
                                            RC1 tag
                                                    │
                                            [parallel: L14 / design partner scheduling]
                                                    │
                                    H1-PR1  H1-PR2  H1-PR3
                                            │
                                    H1-PR4  H1-PR5
                                            │
                                    H1-PR6  H1-PR7  H1-PR8  H1-PR9  H1-PR10
                                            │
                                    [Design partner self-administers]
                                            │
                                    H2-PR1 (Unified Invitation Authority)
                                    H2-PR2  H2-PR3  H2-PR4  H2-PR5
                                            │
                                    [H3: evidence-backed enterprise expansion only]
```

**Smallest safe RC1 boundary:** H0-PR1 + H0-PR2 + H0-PR5 (if T10 skips portal grant creation using existing gold path grants).

**Full RC1 boundary:** H0-PR1 through H0-PR5 (if portal access creation is included in T10).

**First design-partner self-administration boundary:** H0 complete + H1-PR1 through H1-PR10 complete.

**Authority consolidation boundary:** H0 + H1 complete + RC1 tagged + design partner active.
