# Tenant Identity & Administration Platform — Roadmap Integration

**Date:** 2026-08-06  
**Branch:** plan/tenant-identity-administration-platform-20260806  
**Status:** PLANNING ARTIFACT — under launch freeze; no runtime code changes  
**Authority:** Founder (jcosat)

---

## Executive Decision

The Tenant Identity & Administration Platform is a bounded sub-epic of **P1-01 Identity Authority Platform**.

It is not a standalone product. It is not a complete IAM system. It is the minimum-viable authority layer that allows FrostGate to serve enterprise clients without requiring founder intervention for routine identity and portal access management.

The work is divided into four delivery horizons:

- **Horizon 0 (H0):** RC1 launch repair — restore blocked console invitation workflow; close T9/C4; do not begin platform build.
- **Horizon 1 (H1):** First design-partner self-administration — tenant admin can manage users and portal access without FrostGate founder intervention.
- **Horizon 2 (H2):** Identity Authority Platform consolidation — converge duplicate invitation and lifecycle paths into canonical authorities (Unified Invitation Authority first).
- **Horizon 3 (H3):** Enterprise identity expansion — only after customer evidence exists.

**Non-negotiable:** The existing P1-01 canonical principle stands. Exactly one authority handles all identity invitations regardless of type. Unified Invitation Authority remains the first P1-01 PR.

**RC1 impact:** Conditionally blocked. T9 cannot complete until H0-PR1 (Fix console invitation 403) ships and T9 reruns successfully.

---

## Why This Belongs Under P1-01

P1-01 (Identity Authority Platform) was defined in ROADMAP.md as:

> "Unified identity control plane covering all identity types FrostGate manages. Design principle (non-negotiable): exactly one authority handles all identity invitations regardless of type. First PR: Unified Invitation Authority."

The Tenant Identity & Administration Platform is the first bounded delivery stream inside P1-01 that has a hard customer dependency. Without it:

- FrostGate operators must manually manage all tenant users.
- The console invitation workflow is broken (AUTH-001 P0, per `docs/audits/console_tenant_ux_authority_audit_20260806.md`).
- T9 cannot pass.
- C4 is conditionally blocked.
- The first design partner cannot self-administer their tenant.

It belongs under P1-01 because it shares the same non-negotiable design principles: one invitation authority, one audit trail, one notification pipeline, tenant-authoritative context, fail-closed semantics.

**It does not replace P1-01.** P1-01 remains the parent epic. Unified Invitation Authority remains first. This stream adds a parallel delivery column: Tenant Administration Surface, which is the first consumer of those canonical authorities.

---

## Current State (Repository Evidence, 2026-08-06)

**From `docs/governance/status/EXECUTION_STATE.md`:**
- Platform status: YELLOW → GREEN (C1 CLOSED)
- Platform freeze: ACTIVE
- C4 outstanding: T8 / T9 / T10 / T13 — runbooks done, awaiting operator execution
- T9 is effectively blocked: console invitation 403 root cause (AUTH-001) discovered during pre-T9 audit
- No open PRs; next action is H0-PR1 to unblock T9
- Launch confidence: 97%
- Estimated RC1: 2026-08-08 to 2026-08-10

**From `docs/audits/console_tenant_ux_authority_audit_20260806.md`:**

| Finding | Severity | Description |
|---|---|---|
| AUTH-001 | P0 | Console invitation 403: BFF uses tenant API-key path for Core write requiring `admin:write` + `identity.scim` |
| API-001 | P1 | Portal grant accepts browser-supplied `client_id` and `engagement_id` without server-side ownership validation |
| API-002 | P1 | BFF classifies `/portal/grants` as admin-gateway; Core does not recognize it as such |
| CTX-001 | P1 | Scoped modals do not repeat tenant context |
| UX-001 | P1 | 403 rendered as raw HTTP status, not actionable error |
| IA-001 | P2 | Mixed terminology (client/tenant/workforce) in console |
| AUDIT-001 | P2 | Missing audit event for invitation attempt/failure |
| A11Y-001 | P2 | Accessibility improvements needed |
| MOAT-001 | P2 | Audit evidence and request IDs not exposed to operators |

**From existing implementation (via grep evidence):**

- `api/identity/store.py`, `api/admin_identity.py`: `TenantInvitation` model exists; invitation lifecycle management is implemented
- `api/actor_context.py`, `api/tenant_rbac.py`: `tenant_admin` role exists with SoD enforcement (does not inherit compliance authority)
- `api/actor_context.py`: `platform_admin` receives `ALL_PERMISSIONS`, bypasses scope guards
- `api/workforce.py`: All endpoints require `admin:write` scope + `identity.scim` capability
- `api/identity_authority/authority.py`: Session revocation (`revoke_session`, `revoke_all_for_subject`, `is_session_revoked`) is implemented
- `api/tenant_identity_authority.py`: `provision_tenant_organization` exists; one Auth0 org per tenant
- Migration `0099`: RLS on all identity governance tables including `tenant_users`
- Migration `0169_tenant_identity_bindings.sql`: binding and events tables with append-only trigger
- `api/portal_user_authority.py`: Portal invitation and session lifecycle is implemented (separate from tenant_users)

**From `ROADMAP.md`:**
- P1-01 is deferred until after Design Partner Onboarding
- Design principle is non-negotiable: one invitation authority
- First PR is Unified Invitation Authority

**Existing CTE planning artifacts (all in `docs/plans/`):**
- `console_tenant_experience_redesign_plan_20260806.md`
- `console_tenant_experience_pr_sequence_20260806.md` (CTE-PR1 through CTE-PR8)
- `console_tenant_experience_wireframes_20260806.md`

This roadmap integration absorbs the CTE PR sequence into H0 (RC1 launch repair) and H1 (design-partner self-administration), renames them with H-prefixed identifiers, and adds the H2/H3 platform horizon.

---

## Problem Statement

FrostGate platform operators currently must:

1. Manually manage all console user invitations (broken at AUTH-001).
2. Create portal access grants by typing raw client IDs and engagement IDs (no server-side ownership validation per API-001).
3. Remain the single point of contact for any identity or access change inside a client tenant.

This is unsustainable at scale and blocks the first design partner from self-administering their tenant.

The root causes are:

1. **Authority routing mismatch:** BFF uses tenant portal API keys for a Core write that requires operator-class authority (`admin:write` + `identity.scim`). Core correctly fails closed. BFF incorrectly forwards tenant keys to an admin-only endpoint.
2. **Missing payload validation:** Portal grant creation accepts browser-supplied authority-bearing identifiers without revalidating ownership against the route tenant.
3. **Missing tenant administration surface:** No tenant-admin-scoped administration UI or API exists for routine tenant management without platform_admin authority.

---

## Target Operating Model

1. FrostGate platform operator creates a tenant (existing, proven IA-1).
2. FrostGate platform operator invites the first tenant administrator (H0 fix + H1 build).
3. Tenant administrator accepts invitation, enrolls credentials/MFA via Auth0 organization flow, receives tenant-bound session (H1).
4. Tenant administrator logs into tenant administration surface (H1).
5. Tenant administrator manages their tenant without FrostGate founder intervention (H1 exit criterion).
6. Ordinary portal users access only explicitly granted tenant resources (existing for portal_users; H0 strengthens portal grant authority).
7. No tenant identity can view, mutate, infer, or administer another tenant (existing RLS + session model; H0 adds regression proof).
8. FrostGate platform operators retain platform-level authority but are not required for routine tenant administration after H1.
9. Console, tenant-admin, and portal onboarding converge toward one canonical invitation and identity lifecycle authority (H2 Unified Invitation Authority).
10. Every identity and access action is auditable, explainable, revocable, and tenant-scoped (continuous, strengthened each horizon).

---

## Platform / Tenant / Portal Authority Boundaries

### Platform Console

**Users:** FrostGate platform operators, platform support, founder.

**Responsibilities (current + planned):**
- Create/suspend/deprovision tenants
- Bootstrap initial tenant administrator invitation
- Platform support and investigation (read-only by default; break-glass for mutations)
- Global policy and configuration
- Platform-level audit
- Key management (system keys)
- Billing and licensing (L14 / future)

**Authority class:** `platform_admin` / `platform_support` (distinct roles; support gets read-only by default)

**Not permitted:**
- Viewing another tenant's operational data without explicit audit trail
- Issuing mutations inside a tenant without operator-class authority and audit event

### Tenant Administration Surface

**Users:** Tenant administrators, tenant operators.

**Responsibilities (H1):**
- Invite and manage console users within tenant
- Assign and modify tenant roles
- Create and revoke portal access
- Tenant-scoped engagement selection (only owned engagements)
- Resend invitations
- Initiate password reset flows (IdP-mediated; no operator visibility into passwords)
- Revoke sessions
- Disable and reactivate users
- Manage portal credentials and access lifecycle
- Review tenant-scoped audit evidence

**Authority class:** `tenant_admin` (existing SoD-constrained role); `tenant_operator` (future)

**Not permitted:**
- Viewing another tenant's data
- Modifying platform-level configuration
- Breaking out of tenant scope via payload manipulation
- Accessing compliance review authority (SoD invariant, from `api/tenant_rbac.py`)

### End-User Portal

**Users:** Portal users (named-user, shared-credential).

**Responsibilities:**
- View assessments, reports, evidence, findings
- Remediation tracking
- Document center
- Profile and security settings
- Only explicitly granted resources within their tenant

**Authority class:** `portal_user` (existing; separate identity population per PR #577)

**Not permitted:**
- Platform or tenant administration
- Cross-tenant resource access
- Any mutation without explicit grant

---

## Canonical Identity Lifecycle

```
PLATFORM OPERATOR
    │
    ├─► create_tenant()
    │       → tenant record, Auth0 org, credential set
    │
    ├─► invite_tenant_admin()           [H0 fix; H1 surface]
    │       → TenantInvitation (pending)
    │       → notification email
    │
TENANT ADMIN CANDIDATE
    │
    ├─► accept_invitation(token)
    │       → Auth0 enrollment (credentials + MFA)
    │       → identity binding: Auth0 sub → tenant_users membership
    │       → session issued
    │
TENANT ADMIN (active)
    │
    ├─► invite_user(email, role)        [H1]
    │       → TenantInvitation (pending)
    │       → notification
    │
    ├─► manage_portal_access()          [H0 partial; H1 full]
    │       → portal grant or named-user invitation
    │       → engagement ownership validated server-side
    │
    ├─► revoke_session(user)            [H1]
    │       → auth_version bump → immediate invalidation
    │
    ├─► disable_user(user)              [H1]
    │       → membership_status = disabled → session invalid
    │
    ├─► initiate_password_reset(user)   [H1]
    │       → Auth0 password-change flow → no operator visibility
    │
    └─► review_audit_history()          [H1]
            → tenant_identity_audit_events (RLS-gated, append-only)

PORTAL USER
    │
    ├─► accept_invitation(token)        [existing: portal_user_authority.py]
    │       → portal_users enrollment
    │       → session issued
    │
    ├─► access_resources()              [existing; H0 strengthens ownership guard]
    │
    └─► session_revoked → locked out    [existing]
```

All state transitions emit audit events to the appropriate append-only, RLS-gated event table.

---

## Role Model

Minimal role model; no custom role builder before customer demand.

| Role | Scope | Permissions |
|---|---|---|
| `platform_admin` | Global | ALL_PERMISSIONS (existing `actor_context.py`) |
| `platform_support` | Global read | Read-only platform scope; explicit break-glass for mutations (H1) |
| `tenant_admin` | Tenant-bound | Invite/manage users; roles; portal access; audit view (existing SoD; H1 surface) |
| `tenant_operator` | Tenant-bound | Portal access management; no role changes (H1, if needed) |
| `tenant_auditor` | Tenant-bound | Read-only audit access (H1 or H2 depending on demand) |
| `portal_user` | Grant-bound | Access granted resources only (existing) |

SoD invariant (from `api/tenant_rbac.py`): `tenant_admin` does not inherit `compliance_reviewer` permissions. This invariant must not be weakened.

---

## Canonical Authorization Predicate — Tenant Administration

```
ALLOW IF:
  authenticated human principal (Auth0 JWT, RS256, verified JWKS)
  AND active tenant membership (tenant_users.status = active)
  AND required role/permission for action
  AND route_tenant = session_tenant (route authoritative; payload cannot override)
  AND target_resource.tenant_id = route_tenant (server-side revalidation)
  AND action permitted by role policy
  AND principal session not revoked (auth_version validated)
  AND membership not disabled
```

**Per-action application:**

| Action | Required permission | Tenant check | Target revalidation | Auth0 operation |
|---|---|---|---|---|
| Invite user | `admin:write` + `identity.scim` | Route tenant | N/A | Auth0 org invite |
| Resend invitation | `admin:write` | Route tenant | Invitation.tenant_id | Resend via IdP |
| Change role | `admin:write` | Route tenant | Membership.tenant_id | None |
| Password reset initiation | `admin:write` | Route tenant | Membership.tenant_id | Auth0 password-change flow |
| Revoke session | `admin:write` | Route tenant | Session.tenant_id | Auth0 session revoke |
| Disable/reactivate user | `admin:write` | Route tenant | Membership.tenant_id | Auth0 block/unblock |
| Create portal access | `admin:write` | Route tenant | Engagement.tenant_id (server-side) | None |
| Revoke portal access | `admin:write` | Route tenant | Grant.tenant_id | None |
| Select engagement | `admin:read` | Route tenant | Engagement.tenant_id | None |
| View audit history | `admin:read` | Route tenant | Events.tenant_id (RLS) | None |

**Platform-admin exception path:** `platform_admin` role bypasses scope guards (existing behavior in `api/actor_context.py`). All platform_admin mutations must emit audit events. Platform_admin should not be the routine path for tenant administration.

**Platform-support limitations:** Read-only by default. Explicit mutation authority requires a break-glass workflow with audit. Not implemented in H0/H1 — use platform_admin until H2.

**Auth0 vs Core source of truth during migration:**
- Core (`tenant_users`) is authoritative for membership status, role assignments, session revocation, and audit.
- Auth0 org is authoritative for OIDC identity operations (invitation acceptance, credential enrollment, MFA, password reset).
- Conflicts resolve in favor of Core: a disabled Core membership rejects the session even if Auth0 org is active.
- Eventual target: Auth0 org is a provider adapter; Core owns all governance state.

---

## Delivery Horizons

---

### Horizon 0 — RC1 Launch Repair

**Purpose:** Restore required launch workflows without beginning the full platform epic. Unblock T9. Close C4. Reach RC1.

**Exit criterion:** T9 PASS (console invitation end-to-end); T10 PASS (portal UX); T13 PASS (deletion drill); LDR updated; v1.0.0-rc1 tagged.

**What belongs here:**
- Fix console invitation authority-routing mismatch (AUTH-001 P0)
- Preserve `admin:write` and `identity.scim` enforcement (do not widen tenant keys)
- Provide route-authoritative tenant context
- Add stable actionable error mapping (UX-001 P1)
- Show selected tenant read-only in invitation modal (CTX-001 P1)
- Portal access authority containment (API-001 P1) — only if portal access is included in T10
- Cross-tenant regression test suite
- Focused fixes only; no platform feature build

**PRs (from `docs/plans/console_tenant_experience_pr_sequence_20260806.md`, renamed):**

| PR ID | Maps to | Title | RC1-required |
|---|---|---|---|
| H0-PR1 | CTE-PR1 | Fix console invitation 403 root cause | Yes — blocks T9 |
| H0-PR2 | CTE-PR2 | Canonical tenant-context contract | Yes — if any admin mutation in RC1 |
| H0-PR3 | CTE-PR3 | Tenant-scoped engagement selector API | Yes — if portal access in T10 |
| H0-PR4 | CTE-PR4 | Portal grant form and server-side ownership validation | Yes — if portal access in T10 |
| H0-PR5 | CTE-PR6 | Cross-tenant enforcement regression suite | Yes |

**What does NOT belong in H0:**
- Tenant admin self-administration surface (H1)
- Unified Invitation Authority (H2)
- Password reset / session revocation UI (H1)
- Invitation lifecycle status UI (H1)
- Terminology/accessibility polish (H1, except launch-critical labels)

**T9 gate:** H0-PR1 must merge and pass targeted tests before T9 re-runs. T9 re-run is required after H0-PR1 to close C4.

**T10 gate:** H0-PR3 and H0-PR4 must merge before T10 if portal access creation is exercised during T10. If the T10 walkthrough skips portal grant creation (using an existing grant from the Gold Path), H0-PR3/PR4 can be deferred to H1.

**C4 status:** Conditionally blocked. T9 cannot complete without H0-PR1. Once H0-PR1 merges and T9 passes, C4 unblocks for T10 and T13.

**RC1 tagging:** After all C4 gates pass and LDR is updated.

**Explicitly disabled launch workflows:** If H0-PR4 is not completed before T10, the portal grant creation UI should be disabled or hidden during T10 rather than walked through with unvalidated authority. Do not attempt T10 portal access creation without server-side engagement ownership validation.

---

### Horizon 1 — First Design-Partner Self-Administration

**Purpose:** Allow the first client to manage their tenant without FrostGate founder intervention.

**Start condition:** RC1 tagged; design partner scheduled or active.

**Stop condition (non-negotiable):** H1 stops as soon as the first design partner can securely self-administer routine users and portal access without FrostGate founder intervention. Not all ten PRs are required. Each PR is evaluated before starting against the stop condition. If the exit criterion is already met, H1 closes — remaining PRs are deferred to H1-extension or H2. Do not ship PRs to match a roadmap count.

**Exit criterion (first design partner self-administration):**
- Tenant admin can invite, manage, disable, and reactivate users
- Tenant admin can create and revoke portal access
- Tenant admin cannot escape tenant scope
- Password reset is IdP-mediated with no operator visibility into credentials
- Session revocation invalidates access immediately
- Lifecycle and audit status are visible to tenant admin
- FrostGate founder intervention is not required for routine management

**PRs (candidate sequence — evaluate each before starting):**

| PR ID | Maps to | Title |
|---|---|---|
| H1-PR1 | CTE-PR5 | Console invitation UX redesign (read-only tenant, role descriptions, stable errors) |
| H1-PR2 | CTE-PR7 | Invitation lifecycle status and audit UX |
| H1-PR3 | CTE-PR8 | Terminology, accessibility, and polish |
| H1-PR4 | new | Tenant administrator identity and session authority |
| H1-PR5 | new | Tenant user administration APIs |
| H1-PR6 | new | Tenant administration user interface |
| H1-PR7 | new | Tenant-scoped engagement selection (full UI) |
| H1-PR8 | new | Portal access lifecycle administration |
| H1-PR9 | new | Password reset, session revocation, account disablement |
| H1-PR10 | new | Tenant identity audit and lifecycle evidence surface |

**Sequencing discipline:** Before starting any H1 PR beyond the current one, re-evaluate: does the design partner already meet the exit criterion? If yes, stop. If a PR seems unnecessary after observing real use, skip it. If two PRs can be merged without losing independent reviewability, merge them. Customer evidence controls scope; the list does not.

**Note on H1-PR4 through H1-PR10:** These are new PRs not in the existing CTE sequence. They require separate scoping from repository evidence before starting. Do not begin H1-PR4 until RC1 is tagged and design-partner timeline is confirmed.

**Role model additions in H1:**
- `tenant_operator` if operations demand it (defer until design partner specifically requests it)
- `tenant_auditor` if audit access is specifically requested

**What does NOT belong in H1:**
- Custom role builder
- SCIM provisioning
- SSO federation (beyond what Auth0 org already provides)
- Groups and sub-admin delegation
- Service accounts or machine identities
- Multi-tenant federation
- Device trust

**Commercial value of H1:**
- Removes founder bottleneck for routine client management
- Reduces cost of first engagement (no manual access coordination)
- Increases price floor: multi-user tenant management is enterprise-table-stakes
- Required for client to operate independently between engagement cycles

---

### Horizon 2 — Identity Authority Platform Consolidation

**Purpose:** Converge duplicate invitation and lifecycle paths into canonical authorities. Reduce parallel systems. This is the main P1-01 delivery horizon.

**Start condition:** RC1 tagged; at least one design partner active; H1 exit criteria met.

**First PR (non-negotiable per ROADMAP.md):** Unified Invitation Authority — exactly one authority handles all identity invitations regardless of type (console user, portal shared, portal named-user).

**Scope:**

| Authority | Current state | H2 target |
|---|---|---|
| Invitation Authority | Three paths: `admin_identity.py` (console), `portal_user_authority.py` (named-user), `portal_grant_service.py` (shared) | One canonical `InvitationAuthority` service; all paths converge |
| Membership Authority | `tenant_users` (Core); Auth0 org membership (IdP) | One `MembershipAuthority` service; Core authoritative; Auth0 as provider |
| Role Authority | `tenant_rbac.py` + `actor_context.py` | One `RoleAuthority` service; explicit grant tracking |
| Credential Authority | `api_key.py` + Auth0 OIDC | `CredentialAuthority`; existing credential service extended |
| Session Authority | `identity_authority/authority.py` | `SessionAuthority`; existing revocation logic formalized |
| Portal Access Authority | `portal_grant_service.py` + `portal_user_authority.py` | `PortalAccessAuthority`; engagement ownership canonical |
| Audit Authority | `tenant_identity_audit_events` + `portal_user_audit_events` | Unified audit chain; shared notification pipeline |

**PRs:**

| PR ID | Title |
|---|---|
| H2-PR1 | Unified Invitation Authority foundation |
| H2-PR2 | Membership Authority consolidation |
| H2-PR3 | Role and permission authority consolidation |
| H2-PR4 | Credential and session authority consolidation |
| H2-PR5 | Portal Access Authority consolidation |
| H2-PR6 | Shared notification pipeline (expiration, revocation, delivery retry, idempotency) |
| H2-PR7 | Legacy invitation and grant path retirement |
| H2-PR8 | Authority ownership documentation and ADR updates |

**Compatibility strategy:** Wrap legacy paths; do not break direct callers immediately. Retire old paths in H2-PR7 only after all consumers have migrated. Do not preserve unsafe payload authority for compatibility.

**Commercial value of H2:**
- Eliminates parallel identity systems that cause authority drift
- Creates auditable, explainable governance evidence for every identity action
- Reduces engineering maintenance burden
- Positions FrostGate as a trust infrastructure platform, not an assessment tool with bolted-on IAM

---

### Horizon 3 — Enterprise Identity Expansion

**Purpose:** Add advanced enterprise capabilities only after customer evidence supports them.

**Start condition:** Customer evidence required. Minimum: one active design partner whose operating need explicitly requires the capability. No H3 work before H2 exit criteria are met.

**Candidate capabilities:**

| Capability | Evidence status |
|---|---|
| SSO federation expansion (beyond Auth0 org) | Likely future requirement — no current customer demand |
| SCIM provisioning | Likely future requirement — common enterprise ask |
| Custom roles / policy composition | Speculative — no customer demand yet |
| Groups and delegated sub-admins | Speculative |
| Device and session management (beyond session revocation) | Speculative |
| MFA policy management (beyond Auth0 org defaults) | Likely future requirement |
| Service accounts | Likely future requirement for API integrations |
| Machine identities | Speculative |
| AI agent identities | Speculative — important for FrostGate AI plane but not customer-driven yet |
| Cross-tenant federation | Explicitly deferred — no legitimate use case established |
| JIT provisioning | Likely future requirement with SSO customers |
| Lifecycle automation (auto-disable on inactivity) | Evidence-backed in enterprise contexts; defer until first such request |
| Access reviews | Speculative — high effort, specialty IAM feature |
| Separation-of-duties policy composition | Speculative — current SoD is hardcoded; custom SoD is enterprise niche |
| Privileged access workflows (PAM) | Speculative — not FrostGate's core differentiation |

**Classification rules:**
- **Evidence-backed:** Customer has specifically requested this or operating data shows the need. Start only after H2 is stable.
- **Likely future requirement:** Common enterprise pattern; plan for extension points but do not build.
- **Speculative:** Do not build until repeated customer demand. Document as out-of-scope.
- **Explicitly deferred:** Do not accept scope without executive decision.

---

## Launch Impact

| Item | Status | Notes |
|---|---|---|
| T9 (console UX) | Blocked pending H0-PR1 | Console invitation 403 must be fixed first |
| T10 (portal UX) | Conditional | If portal grant creation is in T10 scope, requires H0-PR3/PR4 |
| T13 (deletion drill) | Not blocked | Can run independently |
| T8 (incident drill) | Not blocked | Can run independently |
| C4 | Conditionally blocked | T9 cannot close without H0-PR1 |
| RC1 tag | Conditional | After all C4 gates pass |
| L14 / design partner scheduling | Not blocked | Founder track; no engineering dependency; can run in parallel |

---

## Design-Partner Impact

The first design partner (target 2026-08-27, per execution state) needs:

1. **Before or at engagement start:** H0-PR1 through H0-PR5 (RC1 repair) — restores invitation and portal access authority.
2. **Before design partner can self-administer:** H1-PR1 through H1-PR10 — delivers tenant admin surface.

The design-partner engagement can start with FrostGate founder managing identity manually if H1 is not complete. The goal is to have H1 complete before or during the first renewal or second engagement.

Do not delay design-partner scheduling for H1 completion. H1 is post-RC1 work. Schedule the design partner; build H1 in parallel.

---

## Dependencies

```
Auth0 org provisioning (IA-1, done) → H0-PR1 (invitation authority fix)
    → H0-PR2 (tenant context contract)
    → H0-PR3 (engagement selector API)
    → H0-PR4 (portal grant ownership validation)
    → H0-PR5 (cross-tenant regression)
    → T9 rerun
    → T10 run
    → T13 run
    → T8 run
    → RC1 tag
    → L14 / design partner
    → H1-PR1...H1-PR10 (tenant admin surface)
    → H2-PR1 (Unified Invitation Authority)
    → H2-PR2...H2-PR8 (authority consolidation)
    → H3 (evidence-backed enterprise expansion)

Existing systems (no change required):
- tenant_users (Core, RLS, append-only audit)
- portal_user_authority.py (portal named-user lifecycle)
- identity_authority/authority.py (session revocation)
- tenant_identity_authority.py (Auth0 org provisioning)
- tenant_identity_policy.md (policy foundation, migration 0099)
```

---

## Risks

| Risk | Likelihood | Impact | Mitigation | Owner | Horizon | Stop/go |
|---|---|---|---|---|---|---|
| Scope explosion into full IAM | High | High | Revenue discipline; H3 start condition (customer evidence required); no custom role builder before repeated demand | Founder | H1-H3 | Stop if H1 exceeds 3 months without a customer asking for more |
| Duplicate invitation systems | High | Medium | H2-PR1 (Unified Invitation Authority) is non-negotiable first H2 PR; no new invitation paths in H0/H1 | Platform security | H2 | Stop if H1 adds a fourth invitation path |
| Auth0/Core source-of-truth conflict | Medium | High | Core wins for governance state; Auth0 is provider adapter; documented in authority predicate | Platform security | H0-H2 | Stop if any Core membership rejection is ignored because Auth0 says active |
| Tenant admin privilege escalation | Medium | Critical | SoD invariant in `tenant_rbac.py`; test coverage (MV-1 through MV-15); H0-PR5 regression suite | Platform security | H0 | Stop on any cross-tenant access proof |
| Platform support overreach | Low | High | Platform support = read-only by default; break-glass requires explicit audit; no omnipotent support path in H0/H1 | Platform security | H1 | Stop if support mutations bypass audit |
| Cross-tenant confused deputy | Medium | Critical | Route-authoritative tenant; server-side ownership revalidation; H0-PR5 regression suite | Platform security | H0 | Stop on any cross-tenant confusion |
| Stale sessions after role changes | Medium | Medium | `auth_version` mechanism (MV series tests); membership_version bump on role change | Platform security | H0 | Stop if version bump is bypassed |
| Password reset abuse | Low | Medium | IdP-mediated only; no direct credential mutation by operators; rate limiting via Auth0 | Platform security | H1 | Stop if any operator-readable credential path is added |
| Portal access bypass | Medium | High | Engagement ownership validation (H0-PR3/PR4); server-side revalidation required before T10 | Platform security | H0 | Stop if engagement_id accepted from body without server-side ownership proof |
| Engagement ownership mismatch | Medium | High | H0-PR3 (server-side engagement list); H0-PR4 (grant validation) | Field Assessment authority | H0 | Stop if cross-tenant engagement access is proven |
| Legacy route compatibility | Medium | Medium | Wrap-then-retire strategy; do not break direct callers; retire in H2-PR7 | Platform security | H2 | Stop if unsafe payload authority preserved for compatibility |
| Audit inconsistency | Low | Medium | Append-only triggers; hash-linked events; shared audit pipeline in H2 | Audit authority | H2 | Stop if mutation has no audit event |
| Notification retry/idempotency | Low | Low | H2-PR6 shared notification pipeline; current path: fire-and-forget acceptable for H0/H1 | Platform ops | H2 | No stop condition in H0/H1 |
| Launch delay from H0 scope | Medium | High | H0 scope is tightly bounded; 5 PRs; ~8-12 days of effort | Founder | H0 | Stop if H0 exceeds 12 days from today |
| Commercial work displacement | Low | Medium | L14 is founder track; no engineering dependency; parallel path | Founder | H0 | No stop condition |

---

## Anti-Overengineering Guardrails

1. **Do not move H1 work before RC1** unless required by T9/T10 safety or first-client contract.
2. **Do not begin H2** until RC1 is tagged and design partner is scheduled or active.
3. **Do not begin H3** until customer evidence exists.
4. **No custom role builder** before repeated customer demand.
5. **No shared credentials** for tenant administrators.
6. **No direct password management** by FrostGate operators or tenant admins.
7. **No new invitation path** in H0 or H1 without H2 Unified Invitation Authority alignment plan.
8. **No omnipotent Console keys** — do not widen tenant API keys; do not create global admin shortcut keys.
9. **No global admin fallback** for routine tenant operations.
10. **No speculative federation, SCIM, or device trust** before revenue and customer evidence.

---

## Commercial Value and Moat Contribution

**H0 — RC1 repair:**
- Customer problem: Operators cannot invite console users; portal access issuance is unsafe.
- Reduces founder/operator labor: Yes — removes manual workaround.
- Revenue required: Yes — required for RC1 and first client engagement.
- Moat: Minimal — this is defect repair. Moat contribution is indirect (trust credibility at launch).

**H1 — Design-partner self-administration:**
- Customer problem: Every identity change requires founder intervention.
- Reduces founder/operator labor: Yes — significantly. Founders do not need to manage user access between engagement cycles.
- Increases price or retention: Yes — self-service administration is enterprise-table-stakes.
- Enterprise trust: Yes — tenant admins can see and govern their own identity state.
- Defensible governance evidence: Yes — every identity action is auditable, tenant-scoped, explainable.
- Required for first revenue: Not technically, but required before second engagement without founder labor.
- Required for scale: Yes — cannot scale to 5+ clients without tenant self-administration.

**H2 — Authority consolidation:**
- Customer problem: Invitation paths are inconsistent; audit evidence is fragmented across systems.
- Reduces founder/operator labor: Yes — eliminates parallel systems that cause divergent behavior.
- Enterprise trust: High — unified audit trail for all identity actions is a compliance expectation.
- Moat: Medium-high — unified invitation + membership + session authority connected to engagement evidence creates a governance record that commodity IAM cannot replicate.
- FrostGate differentiator: Identity actions are connected to assessment scope, engagement ownership, evidence lifecycle, and audit evidence chains. This is not commodity IAM.

**H3 — Enterprise expansion:**
- Revenue required: No until evidence exists.
- Moat: Varies — SCIM and SSO are commodity; custom roles tied to assessment scope are differentiated.

**Core commercial thesis validation:**
> "Tenant-owned identity lifecycle management reduces FrostGate operating cost, removes founder bottlenecks, improves enterprise readiness, and turns identity administration into auditable governance evidence."

- H0: Reduces cost (defect repair); does not yet create governance evidence.
- H1: Removes bottlenecks; creates lifecycle visibility.
- H2: Turns every identity action into tamper-evident governance evidence — this is where the thesis is validated.
- H3: Extends the evidence chain into enterprise scenarios.

**Where FrostGate's identity authority is differentiated (not commodity IAM):**
- Identity actions that emit evidence connected to engagement ownership
- Tenant-scoped engagement selection as part of access issuance
- Session revocation connected to assessment scope
- Audit evidence tied to assessment lifecycle (not just login events)
- Invite-through-portal-access lifecycle as a single governance chain

---

## Existing Roadmap Entries — Reconciliation

| Entry | Action | Reason |
|---|---|---|
| `P1-01: Identity Authority Platform` | Retain; add TIAP as sub-epic | TIAP is the first bounded delivery stream inside P1-01 |
| `First PR: Unified Invitation Authority` | Retain; promote to H2-PR1 | Non-negotiable; unchanged |
| `CTE-PR1 through CTE-PR8` | Absorb into H0 (PR1-PR5) and H1 (PR6-PR10) | Renamed with H-prefix for clarity; content unchanged |
| `DB startup ordering barrier` | No change — stays in backlog | Unrelated to identity administration |
| `IA-1: Client Organization Provisioning` | Complete; no change | Foundation for H0/H1 |

---

## Final Decisions

1. **Does Tenant Identity & Administration remain under P1-01?** Yes.
2. **Is Unified Invitation Authority still first?** Yes — H2-PR1. Unchanged.
3. **What is the exact next canonical PR?** H0-PR1 — Fix console invitation 403 root cause (CTE-PR1).
4. **Which PRs block RC1?** H0-PR1, H0-PR2, H0-PR5; H0-PR3/H0-PR4 block RC1 only if portal access is included in T10.
5. **Which PRs block first design-partner self-administration?** H1-PR1 through H1-PR10.
6. **Which work is intentionally post-launch?** H1-PR4 through H1-PR10 (new tenant admin surface); all H2 and H3 work.
7. **Which existing roadmap entries are superseded or renamed?** None superseded; CTE-PR1–PR8 absorbed into H0/H1 with H-prefix renaming.
8. **Is C4 blocked, conditionally blocked, or passable after the launch repair?** Conditionally blocked — T9 cannot pass without H0-PR1. T8 and T13 can run now.
9. **Can L14 and design-partner outreach continue in parallel?** Yes — founder track, no engineering dependency.
10. **What is the smallest launch-safe boundary?** H0-PR1 + H0-PR2 + H0-PR5 (with T10 using existing portal grants, not creating new ones).
11. **What is the first revenue-safe self-administration boundary?** H1 complete: tenant admin can invite, manage, and revoke access without founder intervention.
12. **What prevents this from becoming an overbuilt IAM platform?** Anti-overengineering guardrails §14; H3 start condition (customer evidence required); no custom role builder; no speculative federation; revenue discipline applied at each horizon.
13. **How does this strengthen FrostGate's governance moat?** H2 Unified Invitation Authority connects every identity action to the audit chain, engagement ownership, and evidence lifecycle — differentiating FrostGate from commodity IAM.
14. **What must never be delegated to tenant administrators?** Platform-level configuration, billing, global key management, cross-tenant visibility, compliance review authority (SoD invariant).
15. **What must no longer require FrostGate founder intervention?** After H1: console user invitation, role assignment, portal access creation and revocation, session revocation, user disablement/reactivation, password reset initiation.

---

## Validation Record

| Check | Result |
|---|---|
| `git diff --check` | PASS — no trailing whitespace or mixed line endings |
| Markdown structure | PASS — all sections present per task specification |
| Plan guard (no runtime code) | PASS — no routes, migrations, permissions, UI components, or tests created |
| Paste-garbage guard | PASS — no binary artifacts, placeholder text, or truncated sections |
| PR_FIX_LOG enforcement | SKIP — planning document only; no source changes; `scripts/ci/enforce_pr_fix_log.sh` not triggered |
| Roadmap/status schema | PASS — EXECUTION_STATE.md update in separate artifact; no false completions |
| Repository evidence cited | PASS — all claims cite exact file paths and symbols from repository inspection |
| Horizon 0 scope bounded | PASS — no H1+ work in H0 |
| No duplicate invitation paths created | PASS — no new invitation system created; existing paths preserved |
| Unsafe payload authority | PASS — no compatibility exception created for body-supplied tenant override |
| Conflict analysis | PASS — see Appendix: Open PR Conflict Analysis |

---

## Appendix: Open PR Conflict Analysis

Open PRs in ROADMAP.md reviewed against H0/H1/H2 sequence. Conflicts and sequencing requirements documented below. All H0/H1 authors must read this section before beginning work.

---

### Conflict 1: PR 10 (#446) — Enterprise Identity Consolidation vs H0-PR1 / H1-PR4

**PR 10 scope:** `IdentityResolver`, `_bind_membership()` in `auth_dispatch.py`, `require_governed_session()`, portal named-user OIDC flow, `POST /portal/identity/login`.

**Conflict:** H0-PR1 touches `auth_dispatch.py` BFF credential selection. H1-PR4 verifies `require_governed_session()` for `tenant_admin` principals. PR 10 modifies both files.

**Status:** Likely partially superseded. PR #577 (merged 2026-07-25, Portal Named-User Identity Authority) covers the portal named-user flow. T4 COMPLETE (2026-08-04) proves portal named-user works in production. PR 10's Auth0 OIDC hardening may have been absorbed into the IA-1 sequence (#601-607).

**Resolution required before H0-PR1 starts:**
- Confirm whether PR 10 (#446) branch has been merged, closed, or superseded by the launch candidate commit (`1bcddc16`).
- If not merged: do not merge PR 10 before RC1; it is H1-class work. Annotate ROADMAP.md accordingly.
- If merged: no conflict (foundational elements are in place).

**Risk:** If H0-PR1 modifies the same auth dispatch paths as an unmerged PR 10, cherry-pick conflicts will arise.

---

### Conflict 2: PR 11 (P1.1) — Membership Versioning vs H1-PR9

**PR 11 scope:** `membership_version BIGINT` on `tenant_users` (migration 0117); `MembershipVersionService.bump_version()`; session version embedding and validation.

**Conflict:** H1-PR9 (password reset, session revocation, disablement) depends on `auth_version`/`membership_version` being in place for immediate invalidation.

**Status:** T4 COMPLETE evidence confirms session revocation works (`DELETE /portal/named-sessions/{id}` and `D-T6-007` confirmed fixed). PR #577 and the IA-1 sequence established the revocation infrastructure. PR 11 may have been partially implemented via different mechanism.

**Resolution required before H1-PR9 starts:**
- Confirm that `membership_version` column exists on `tenant_users` in production (migration 0117 or equivalent).
- If not: H1-PR9 must include this mechanism or depend on the merged form of PR 11.
- If already merged/implemented differently: H1-PR9 builds on existing foundation without conflict.

---

### Conflict 3: PR-01a / PR-01a.1 — FIAP Identity Governance vs H0-PR1 / H0-PR2

**PR-01a scope:** New `api/identity_governance/` package (12 modules); migration 0148 (5 tables); `IdentityLifecycleManager`, `SessionEvaluator`, `ConditionalAccessPolicyEngine`, `DeviceTrustRegistry`, `BreakGlassAuthority`, etc.

**PR-01a.1 scope:** Wires `apply_governance_checks()` into `get_actor_context()` (same function H0-PR2 may touch for canonical tenant-context enforcement).

**Conflict:** PR-01a.1 modifies `get_actor_context()` in `api/deps.py` or equivalent. H0-PR2 (canonical tenant-context contract) also modifies tenant binding logic in the same request path. If PR-01a.1 merges before H0-PR2, the tenant-context changes will have a different base.

**Classification:** PR-01a and PR-01a.1 are H3-class work (device trust, conditional access policy engine, digital twins, break-glass workflows). None of this is RC1-critical. All functionality is behind feature flags.

**Resolution — non-negotiable:**
- PR-01a and PR-01a.1 MUST NOT merge before RC1 under the platform freeze.
- If these branches exist, annotate ROADMAP.md with `🚫 deferred — H3; blocked until after RC1 tag`.
- H0-PR2 author must inspect these branches for `get_actor_context()` modifications and ensure H0-PR2 does not create a divergent base.

---

### Conflict 4: PR #519 — Phase 5 Governance + Admin Enforcement vs H0-PR1

**PR #519 scope:** 83 injections across 7 files including `admin_identity.py` (P1 enforcement). Legacy scope fallback extended to cover `admin:write/read`.

**Conflict:** H0-PR1 also touches `admin_identity.py` invitation routes and the `admin:write` enforcement path. If PR #519 is not merged, H0-PR1 must handle the same enforcement gaps independently. If PR #519 is already merged (launch candidate `1bcddc16`), it provides the enforcement foundation for H0-PR1.

**Status:** Uncertain. PR #519 shows `🔄 open (feat/phase5-p0p1-governance-admin-enforcement)` but the launch candidate is `1bcddc16` which is commit `c11c4300` post-backup fix. Need to confirm whether `feat/phase5` was merged into `main` before the launch candidate.

**Resolution required before H0-PR1 starts:**
- Run `git log main --oneline | grep -i "phase5\|#519"` to confirm merge status.
- If not merged: H0-PR1 must be written against main without assuming PR #519's injection pattern.
- If merged: H0-PR1 builds on the injected enforcement cleanly.

---

### Conflict 5: CTE-PR Sequence vs H0/H1 Sequence (Doc-Level Only)

**Conflict:** `docs/plans/console_tenant_experience_pr_sequence_20260806.md` defines CTE-PR1 through CTE-PR8. This document is now superseded by H0-PR1 through H0-PR5 and H1-PR1 through H1-PR3 (which absorb the same scope with H-prefix renaming).

**Risk:** If engineering teams track both sequences, work will be double-counted or confused.

**Resolution:**
- `console_tenant_experience_pr_sequence_20260806.md` and `console_tenant_experience_redesign_plan_20260806.md` remain as reference material (they contain useful scope detail for H0-PR1 through H0-PR5).
- The authoritative execution sequence is `tenant_identity_administration_pr_sequence_20260806.md`.
- Add a deprecation notice to the CTE docs noting they are absorbed. (Founder action; not a runtime change.)

---

### Conflict 6: P1.2 / P1.3 / P1.4 / P1.5 — Capability and Billing vs H0/H1 Migrations

**PR P1.2-P1.5 scope:** New DB tables via migration 0118 (`tenant_subscriptions`, `policy_bundles`, `capabilities`, etc.). These are commercial authorization architecture PRs.

**Conflict:** H0 and H1 PRs add no new migrations. H2-PR1 (Unified Invitation Authority) may need a new canonical invitation table. The migration sequence must not conflict: 0118 (P1.2, if unmerged) must be explicitly sequenced relative to any H0-H2 migrations.

**Classification:** P1.2–P1.5 are commercial/entitlement architecture PRs. No direct conflict with identity administration authority. They do not touch `workforce.py`, `admin_identity.py`, or BFF credential selection.

**Resolution:** Confirm P1.2–P1.5 merge status. If unmerged and on separate branches, coordinate migration numbering with H2-PR1 author. No blocking conflict for H0.

---

### Conflict 7: PR feat/identity-assurance-trust-engine vs H1/H2

**Scope:** Multi-provider identity assurance ladder (Keycloak, Entra, Okta, Google Workspace, Ping, Auth0), migration 0153, 177 tests.

**Classification:** H3. Device/session assurance levels are explicitly deferred. Custom provider adapters are speculative until customer evidence.

**Resolution:** Do not merge before H2 is complete and customer evidence exists. Annotate as H3-deferred in ROADMAP.md.
