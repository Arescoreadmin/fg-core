# MSP-002 — Multi-client portfolio and customer approval console

**Status:** implemented; not deployed.
**Builds on:** MSP-001 (`api/msp_authority.py`, `api/msp.py`, migration 0206). That remains the only relationship and delegation authority.
**Scope audit:** `docs/msp/MSP_002_REUSE_AND_SCOPE.md`.
**Security model:** `docs/msp/MSP_002_SECURITY_MODEL.md`.
**Operator guide:** `docs/msp/MSP_002_OPERATOR_GUIDE.md`.

**Competitive Gap Widened [MOAT-WIDENING].** Partner programs in compliance-automation tools (Vanta, Drata, Secureframe) and GRC suites typically give a partner standing access to client workspaces. FrostGate now gives MSPs a working multi-client console in which three things hold for every customer:

- the customer approved the access;
- the scope is limited to named capabilities and a time window;
- every read is recorded in the customer's own audit chain.

The consent and access history compounds into the customer's governance record, which cannot be reconstructed elsewhere.

## What was added

| Layer | Addition |
|---|---|
| Core API | `GET /admin/msp/portfolio`; `GET /admin/msp/relationships/{id}/events`; `limit`/`offset` and `counterparty_display_name` on `GET /admin/msp/relationships` |
| Core composition | `api/msp_portfolio.py`. It is not an authority: it summarizes a page of customers already authorized by `list_actor_customers`. |
| Core transport fix | `_bind_console_gateway_tenant` runs first on every MSP route except platform designation (see below). |
| Audit | One new event type: `tenant.msp.portfolio_summary_accessed`. It is written to the customer's chain. |
| Console BFF | `admin/msp/{relationships,customers,portfolio}` allowed for GET and POST only, as delegated named-actor calls. `PUT` designation is never proxied. |
| Console UI | `/msp` (MSP operator) and `/partners` (customer approval). Both are linked from the organization page `/admin/tenants/[tenantId]`. |
| Schema | None. Migration 0206 is reused unchanged. |

## Console transport (why the dependency fix was needed)

The console BFF has no tenant key for these routes. It sends:

- the admin gateway machine credential;
- the named user's Auth0 subject;
- an HMAC delegation proof (v3) that binds the request id, the session's own tenant, the method, the path, the subject and `tenant_human`.

Core does three things inside `bind_tenant_id`:

- verifies the proof (`_verify_delegation_proof`);
- requires the subject to be that tenant's unique, active, bound `tenant_admin` (`_verify_delegated_tenant_human_authority`);
- verifies the tenant lifecycle.

Only after that does the actor resolver build the named human's `ActorContext` from DB roles.

MSP-001 routes resolved the actor before anything called `bind_tenant_id`. Propose worked only because its `require_capability` dependency binds first. List, approve, suspend, resume and revoke therefore returned 403 `MSP_ACCESS_DENIED` from the console. Customer approval in the console was impossible.

MSP-002 adds `_bind_console_gateway_tenant` as the first dependency on all ten GET and POST MSP routes. It reuses `api.entitlements._ensure_admin_gateway_tenant_bound`, so the order has one implementation:

1. authenticate the gateway;
2. verify the delegation proof;
3. verify the tenant-human authority;
4. verify the tenant lifecycle;
5. build the actor;
6. check scopes, permission and capability;
7. run the route.

For tenant-bound credentials it does nothing. `tests/security/test_msp_002_console_transport.py` drives exactly the BFF's headers.

## Endpoints

| Route | Caller | Authority |
|---|---|---|
| `GET /admin/msp/portfolio?limit=1..50&offset>=0` | MSP member (`admin:read`, `msp.multi_tenant`) | `resolve_msp_membership` + `list_actor_customers` (DB role ∩ approved capabilities ∩ `MSP_DELEGABLE_PERMISSIONS`), on every request |
| `GET /admin/msp/relationships?limit=1..200&offset>=0` | `tenant_admin` of either party | MSP-001 (`check_tenant_admin_authority`) |
| `GET /admin/msp/relationships/{id}/events` | `tenant_admin` of either party | MSP-001 party check. Reads only the caller's own chain. |
| All MSP-001 routes | Unchanged semantics | Unchanged. They gained only the transport binder. |

## UI routes

| Route | Audience | Backend |
|---|---|---|
| `/msp` | An MSP tenant's `tenant_admin` | `portfolio`, `relationships`, `customers/{id}/context`, `relationships` (POST), `relationships/{id}/revoke` |
| `/partners` | A customer tenant's `tenant_admin` | `relationships`, `relationships/{id}/{approve,suspend,resume,revoke}`, `relationships/{id}/events` |

Both routes have `routeAudit` entries in `lib/consoleAccess.js` (`CLIENT_ADMIN_ROLES`, `navVisible: false`). The navigation registry is unchanged, because adding an entry requires MCIM document updates.

## Portfolio data lineage

| Field | Source | Gate |
|---|---|---|
| Customer list, `effective_permissions`, `expires_at`, `relationship_id` | `msp_service_relationships` through `list_actor_customers` | Authorized relationship |
| `display_name` | `tenants.display_name` (`tenant_kind_and_name`; active tenants only) | Authorized relationship |
| `assessment.engagements_by_status`, `observed`, `truncated`, `last_activity_at` | `services/field_assessment/store.list_engagements` (newest 100; canonical `EngagementStatus`) | `assessment.read` delegated |
| `findings.outstanding_by_severity`, `outstanding_total`, `observed`, `truncated`, `last_activity_at` | `services/field_assessment/store.list_findings_for_tenant` (newest 100). Outstanding means status `open` or `acknowledged`. | `finding.read` delegated |
| Governance posture | **Not provided.** No canonical, absent-safe governance summary exists: the identity `governance-score` returns 0/F on missing data. | — |

**Section states:**

| State | Meaning |
|---|---|
| `available` | Data was read. |
| `not_authorized` | The capability was not delegated. No data is returned. |
| `not_configured` | No records exist yet. Never a zero score. |
| `unavailable` | The read failed. The error is not echoed. |

`stale` and `unknown` are not used, because no source in scope carries freshness metadata. When `truncated` is true, the counts cover only the 100 most recent records, and the console says so.

## Failure behaviour

- Each section of each customer is read separately: `set_tenant_context(customer)`, then the read, then the caller's context is restored.
- On an exception the session is rolled back and that section becomes `unavailable`. Other sections and other customers are unaffected (test 16). The rollback is safe because nothing has been written yet; audit events are emitted after all reads.
- On Postgres each read runs under a `statement_timeout` of 5 seconds, set transaction-locally.

## Pagination and performance

- **Stable order:** customer tenant id.
- **Page size:** 25 by default, 50 at most.
- **Queries per page:** 2 bounded queries per customer that has delegated the matching capabilities, plus one audit write per customer read.
- **Why no batching across customers:** each read runs under that customer's own RLS context, which rules out a cross-tenant query.
- **No cache.** Authority is re-evaluated on every request, so revocation applies to the next request.
- `list_actor_customers` loads the MSP's approved relationships before paging, which is linear in the number of relationships. Server-side keyset paging is future work if MSPs grow past hundreds of customers.

## Legacy delegation (Phase 10)

`services/cp_msp_delegation.py` and `/control-plane/v2/delegation*` remain as non-authoritative records. Nothing reads them in an access decision. Test 26 proves a legacy record grants no portfolio or context access. Removing them would change `tools/ci/check_control_plane_v2_invariants.py` (check 18), which is a CI invariant change, so removal is deferred.

## Deployment requirements

The same as MSP-001, plus the console:

- migration 0206 applied;
- `FG_INTERNAL_GATEWAY_SECRET` configured;
- an `msp.multi_tenant` bundle on each MSP tenant;
- MSP admins onboarded as bound `tenant_admin`s of the MSP tenant;
- the console BFF configured with `FG_GATEWAY_DELEGATION_SECRET_CURRENT` (already required in production by the existing delegated routes).

There is no new service, container, environment variable, dependency or infrastructure.

## Rollback

1. Revert the PR. The console pages, the BFF rules and the two read routes disappear.
2. The MSP-001 routes lose the transport binder. They keep working with tenant-bound credentials, but not from the console.
3. No schema change. `tenant.msp.portfolio_summary_accessed` events stay in customer chains and remain verifiable.

## Recommended next PR

**MSP-006, partner billing and usage attribution.** The portfolio now produces the attributable `portfolio.summary` and `context.resolve` events that billing needs.

Before a paid MSP, also address:

- console access for non-admin MSP staff (a reviewed widening of Core's delegation verifier);
- invitation codes in place of raw customer ids.
