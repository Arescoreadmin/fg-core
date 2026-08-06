# Tenant Identity & Administration Platform — Definition of Done and Launch Gates

**Date:** 2026-08-06  
**Branch:** plan/tenant-identity-administration-platform-20260806  
**Status:** PLANNING ARTIFACT — launch freeze active; no runtime changes  
**Authority:** jcosat

This document defines the acceptance criteria for each delivery horizon of the Tenant Identity & Administration Platform.

---

## RC1 Acceptance (Horizon 0 Complete)

All criteria must be met before `v1.0.0-rc1` is tagged and before C4 is considered closed.

### Identity Authority Repair

| # | Criterion | Verification |
|---|---|---|
| RC1-I1 | Platform operator can send a console user invitation that succeeds end-to-end (no 403) | T9 walkthrough passes invitation step |
| RC1-I2 | Invitation uses operator-class authority (`admin:write` + `identity.scim`), not tenant portal API key | Code review of BFF credential selection in H0-PR1 |
| RC1-I3 | Core's `admin:write` and `identity.scim` enforcement is unchanged | Existing enforcement tests pass; no new bypass added |
| RC1-I4 | Route tenant is the authoritative tenant context for all admin mutations | H0-PR2 test suite passes |
| RC1-I5 | Payload `tenant_id` / `client_id` cannot override route tenant in admin mutations | Cross-tenant override test in H0-PR5 |
| RC1-I6 | 403 renders as actionable denial (not raw HTTP status) with request ID | T9 walkthrough; UX state check |
| RC1-I7 | Invitation attempt emits audit event with tenant_id, actor, timestamp | Audit event inspection post-T9 |

### Portal Access Authority

| # | Criterion | Verification | Condition |
|---|---|---|---|
| RC1-P1 | Portal grant creation does not accept browser-supplied `client_id` as authority | H0-PR4 server-side ownership validation | Required if portal access creation is in T10 scope |
| RC1-P2 | `engagement_id` in portal grant is validated against route tenant ownership before grant issuance | H0-PR3/H0-PR4 test suite | Required if portal access creation is in T10 scope |
| RC1-P3 | Portal grant with forged engagement ID (cross-tenant) is rejected by Core | H0-PR5 regression test | Required if portal access creation is in T10 scope |

**If T10 does not exercise portal grant creation:** RC1-P1 through RC1-P3 may be deferred to H1-PR8, provided the T10 walkthrough uses only pre-existing grants from the Gold Path engagement.

### Cross-Tenant Isolation Proof

| # | Criterion | Verification |
|---|---|---|
| RC1-X1 | No cross-tenant user list leakage in admin routes | H0-PR5 test suite |
| RC1-X2 | No cross-tenant invitation (invite user into wrong tenant) possible | H0-PR5 test suite |
| RC1-X3 | No cross-tenant portal grant (grant access to wrong tenant engagement) possible | H0-PR5 test suite |
| RC1-X4 | Session from tenant A cannot access tenant B resources | Existing RLS + H0-PR5 confirmation |

### T9 Rerun Gate

| # | Criterion |
|---|---|
| RC1-T9 | T9 console UX walkthrough reruns after H0-PR1 merges and all of the above RC1-I criteria pass |
| RC1-T9 | T9 passes the invitation step: invitation sent, delivery acknowledged, no 403 |
| RC1-T9 | Console navigation ≤ 9 items (verified; 8 items at launch per audit) |

---

## First Design-Partner Self-Administration Acceptance (Horizon 1 Complete)

All criteria must be met before the first design partner operates independently without FrostGate founder intervention.

### Tenant Administrator Identity

| # | Criterion | Verification |
|---|---|---|
| H1-A1 | Tenant admin can authenticate via Auth0 org OIDC and receive a tenant-bound governed session | H1-PR4 test suite |
| H1-A2 | Tenant admin session is scoped to exactly one tenant; cannot access another tenant | H1-PR4 + H1-PR5 isolation tests |
| H1-A3 | Tenant admin session is invalidated immediately upon `auth_version` bump | Existing `membership_version` tests; H1-PR9 disablement test |
| H1-A4 | Tenant admin does not inherit `compliance_reviewer` authority (SoD invariant) | Existing SoD tests preserved; H1-PR4 smoke suite |

### Tenant User Administration

| # | Criterion | Verification |
|---|---|---|
| H1-B1 | Tenant admin can list users in their tenant | H1-PR5 API test |
| H1-B2 | Tenant admin cannot list users in another tenant | H1-PR5 isolation test |
| H1-B3 | Tenant admin can invite a new user with a specified role | H1-PR5 API test; H1-PR6 UI test |
| H1-B4 | Tenant admin can resend a pending invitation | H1-PR5 API test |
| H1-B5 | Tenant admin can change a user's permitted tenant role (within tenant_admin permission) | H1-PR5 API test |
| H1-B6 | Tenant admin cannot assign `platform_admin` or `compliance_reviewer` to any user | H1-PR5 permission guard test |
| H1-B7 | Tenant admin can disable a user; disabled user cannot authenticate | H1-PR9 test |
| H1-B8 | Tenant admin can reactivate a disabled user | H1-PR9 test |

### Password Reset (IdP-Mediated)

| # | Criterion | Verification |
|---|---|---|
| H1-C1 | Tenant admin can initiate a password reset for a tenant user | H1-PR9 API test |
| H1-C2 | Password reset is Auth0-mediated; no credential is returned to tenant admin or FrostGate operator | H1-PR9 test: response contains no credential |
| H1-C3 | Password reset does not expose the current password or its hash to any FrostGate surface | Code review of Auth0 adapter in H1-PR9 |

### Session Revocation

| # | Criterion | Verification |
|---|---|---|
| H1-D1 | Tenant admin can revoke all sessions for a user in their tenant | H1-PR9 API test |
| H1-D2 | Session revocation invalidates the user's active sessions immediately (auth_version bump) | Existing revocation tests; H1-PR9 verification |
| H1-D3 | Revoked session cannot be used to authenticate | Existing session validation tests |

### Portal Access Administration

| # | Criterion | Verification |
|---|---|---|
| H1-E1 | Tenant admin can create portal access for a recipient using only tenant-owned engagements | H1-PR8 test |
| H1-E2 | Engagement selector shows only engagements owned by the tenant admin's tenant | H1-PR7 UI test; H0-PR3 API test |
| H1-E3 | Tenant admin cannot create portal access referencing an engagement from another tenant | H1-PR8 isolation test |
| H1-E4 | Tenant admin can revoke portal access | H1-PR8 test |
| H1-E5 | Revoked portal access is rejected on next access attempt | Existing portal grant revocation tests |

### Audit and Lifecycle Visibility

| # | Criterion | Verification |
|---|---|---|
| H1-F1 | Tenant admin can view identity and access audit history scoped to their tenant | H1-PR10 test |
| H1-F2 | Audit events from another tenant are not visible | H1-PR10 isolation test (RLS) |
| H1-F3 | Every identity/access mutation in H1 emits an audit event | Per-PR audit event tests |
| H1-F4 | Audit events include actor, target, timestamp, request ID, and event type | Audit event schema check |

### Founder Intervention Not Required

| # | Criterion | Verification |
|---|---|---|
| H1-G1 | FrostGate founder does not need to execute any step for routine tenant user management after initial tenant bootstrap | Operational walkthrough with design partner |
| H1-G2 | FrostGate founder does not need to execute any step for routine portal access management | Operational walkthrough with design partner |
| H1-G3 | FrostGate founder does not need to execute any step for password reset or session revocation | Operational walkthrough with design partner |

---

## Enterprise Expansion Acceptance (Horizon 3)

Enterprise expansion capabilities may not enter implementation until all three conditions are met:

| # | Criterion |
|---|---|
| H3-A1 | At least one current paying customer has explicitly requested the capability with documented use case |
| H3-A2 | H2 authority model is stable (no open architectural debt in invitation, membership, session, or audit authorities) |
| H3-A3 | Lifecycle metrics (session volume, invitation volume, user count, support requests) show the need is not addressable by simpler means |

Examples of capabilities subject to H3-A1 through H3-A3:
- Custom role builder
- SCIM provisioning
- SSO federation beyond Auth0 org defaults
- Groups and delegated sub-admins
- Device trust
- Advanced MFA policy management
- Machine identities
- Service accounts

No H3 capability may enter the H1 or H2 scope without an explicit founder decision citing customer evidence.

---

## Non-Waivable Security Conditions (All Horizons)

These conditions are non-waivable regardless of launch pressure or design-partner timelines:

| # | Condition | Stop/go |
|---|---|---|
| SEC-1 | Tenant isolation exposure proven (any cross-tenant data access) | Immediate stop; no first client engagement until resolved |
| SEC-2 | Tenant payload override of route authority | Immediate stop |
| SEC-3 | Admin credential in BFF response or client-visible surface | Immediate stop |
| SEC-4 | Password or credential hash accessible to FrostGate operator or tenant admin | Immediate stop |
| SEC-5 | New invitation system created in parallel with existing systems (no H2 Unified Invitation Authority alignment) | Must not ship without H2-PR1 predecessor or documented migration plan |
| SEC-6 | `platform_admin` authority granted to `tenant_admin` or `portal_user` | Immediate stop; SoD invariant violation |
| SEC-7 | Session revocation bypass (revoked session accepted by Core) | Immediate stop |

---

## Validation Summary

| Artifact | Status |
|---|---|
| `docs/plans/tenant_identity_administration_platform_roadmap_20260806.md` | CREATED — planning document only |
| `docs/plans/tenant_identity_administration_pr_sequence_20260806.md` | CREATED — planning document only |
| `docs/architecture/tenant_identity_authority_capability_map_20260806.md` | CREATED — planning document only |
| `docs/governance/tenant_identity_administration_acceptance_20260806.md` | CREATED — this document |
| `docs/governance/status/EXECUTION_STATE.md` | UPDATED — T9 blocker and H0-PR1 added |
| `ROADMAP.md` | UPDATED — P1-01 expanded with TIAP sub-epic and H0 sequence |
| `git diff --check` | PASS |
| Runtime code changes | NONE |
| Schema changes | NONE |
| Migration files | NONE |
| PR_FIX_LOG | NOT REQUIRED — planning documents only |
