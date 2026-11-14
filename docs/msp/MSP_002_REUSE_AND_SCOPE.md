# MSP-002 reuse and scope audit

**Base:** `main` `ee1a31e12` (MSP-001 #872 and RBAC P17 #873 merged). No open PRs at start.
**Authorization:** founder-authorized on 2026-11-14. It is recorded in `customer_one/roadmap_authority.yaml` `next_sequence` without claiming Freeze Law criteria (1) or (2).

The rule for this PR: reuse every supported existing component, and build only what is missing. MSP-001 remains the only relationship and delegation authority.

## Capability reuse

| Existing capability | Canonical owner | Reuse strategy | Gap | Implementation decision |
|---|---|---|---|---|
| MSP relationship lifecycle (propose, approve, suspend, resume, revoke) | `api/msp.py`, `api/msp_authority.py`, migration 0206 | The console calls these routes unchanged. | None | No new lifecycle code and no new table. Transitions stay compare-and-set. |
| Delegated access decision (role ∩ approved ∩ ceiling) | `resolve_actor_access`, `list_actor_customers`, `MSP_DELEGABLE_PERMISSIONS` | The portfolio is built only from `list_actor_customers`. Each summary section is gated on the per-customer effective permission set. | No per-customer summary data | Add a read-only `GET /admin/msp/portfolio`. Authority stays in `msp_authority.py`. |
| Customer discovery and context selection | `GET /admin/msp/customers`, `POST /admin/msp/customers/{id}/context` | The console uses the context route as-is. It is a validated, audited navigation step that grants nothing. | None | Unchanged |
| Relationship list for both parties | `GET /admin/msp/relationships` | Reused for pending, suspended and expiring counts and the customer approval queue. | No display names for the counterparty. No bounded paging. | Additive fields: `counterparty_display_name` and `limit`/`offset`. The MSP sees a customer's name only after that customer has approved, so the tenant-id oracle is not widened. |
| Relationship audit history | Identity audit chain (`tenant_identity_audit_events`, `verify_identity_audit_chain`) | Read only the caller's own chain. | `/admin/identity/tenants/{id}/timeline` is unfiltered, and it exposes subjects and emails. | Add `GET /admin/msp/relationships/{id}/events`. It projects only the acting party, shows subjects for the caller's own side only, and reports the chain verification result. |
| Assessment lifecycle summary | `services/field_assessment/store.py` `list_engagements` (the sanctioned data-access layer, tenant-scoped, `MAX_PAGE_SIZE` 100) | Called per authorized customer under that customer's RLS context, gated on `assessment.read`. | None | Counts by canonical `EngagementStatus`, latest activity, and `truncated` when the sample hit the page bound. |
| Outstanding findings summary | `services/field_assessment/store.py` `list_findings_for_tenant` | Same, gated on `finding.read` | None | Counts of `open` and `acknowledged` findings by severity, `truncated`, and latest activity |
| Governance posture score | `api/admin_identity.py` `governance-score` | **Not reused** | The logic is inline in the route, not a service. It returns `score: 0` and grade `F` when data is absent, and it is identity-governance specific. | **Deferred.** No governance score is shown, so none is invented. |
| Console authentication | `apps/console/auth.ts` (NextAuth / Auth0) | Reused | None | Unchanged |
| Console-to-Core identity transport | BFF gateway delegation (`X-FG-Named-User-Sub` plus an HMAC delegation proof v3, verified by `_verify_delegation_proof` and `_verify_delegated_tenant_human_authority`) | `admin/msp` joins the delegated-actor path families in `isTenantAdminCorePath`. | Not wired for `admin/msp` | BFF allowlist covers GET and POST only. `PUT` (platform designation) is never proxied. |
| Console role policy | `apps/console/lib/consoleAccess.js` (`CORE_API_POLICIES`, `CONSOLE_ROUTE_AUDITS`) | Add one core API policy (`admin/msp`, `tenant_admin` plus internal roles) and two route audits. | None | `navVisible: false`. Pages are linked from the tenant admin's own-organization page. |
| Typed API client pattern | `SafeResult<T>` clients (for example `lib/readinessApi.ts`) | Same pattern in `lib/mspApi.ts` | None | Never throws. Never sends a tenant id. |
| UI components | `components/ui` (`Button` with `loading` blocks duplicate submits, `Badge`, `Card`, `Checkbox`), `@radix-ui/react-dialog` (already a dependency) | Reused | None | No new dependency and no new design system |
| Console navigation registry | `packages/navigation/navigation-registry.json` (bound to the MCIM 18.6 docs and checkers) | Not changed | Adding an entry requires MCIM document updates. | **Deferred.** Pages are reachable from `/admin/tenants/[tenantId]`. |
| Frontend tests | `node --test` (static and source contract tests plus pure-module behaviour) | Same tooling. Pure logic lives in `lib/mspConsole.js` and is tested behaviourally. | No React rendering harness in the repo | No new test dependency |
| Legacy MSP delegation | `services/cp_msp_delegation.py` and `/control-plane/v2/delegation*` | Kept as non-authoritative records | It is still required by `tools/ci/check_control_plane_v2_invariants.py`. | **Not removed.** A regression proves a legacy record grants no MSP portfolio, context or control-plane access. Removal is a separate change to a CI invariant. |

## Scope boundaries

**In scope:**

- the portfolio API;
- relationship display names and paging;
- relationship history;
- the BFF wiring;
- the MSP operator page (`/msp`);
- the customer approval page (`/partners`);
- tests, documentation and the synthetic first-client demonstration.

**Out of scope:**

- MSP write access to customer data;
- MSP billing;
- white label;
- benchmarks and CGIN;
- a governance score;
- console access for non-admin MSP staff (see below);
- navigation registry entries;
- deleting the legacy delegation code.

**Console constraint, verified in code.** The BFF's `tenant_human` delegation is accepted only for a unique, active, bound `tenant_admin` of the session tenant (`_verify_delegated_tenant_human_authority`).

- Through the console, MSP operators are therefore the MSP tenant's `tenant_admin`s, and approvers are the customer's `tenant_admin`.
- Non-admin MSP staff can still use the API with a tenant-bound credential.
- Console access for them requires widening Core's delegation verifier, which is a separately reviewed change.
