# MSP-001 — MSP organizations, customer-approved relationships, delegated authority

**Status:** implemented; not deployed.
**Authority:** `api/msp_authority.py`, the only MSP authority.
**Schema:** `migrations/postgres/0206_msp_service_relationships.sql`, mirrored by `api/db_models_msp.py`.
**Routes:** `api/msp.py`.
**Audit:** `docs/msp/MSP_001_CAPABILITY_AUDIT.md`.

## Operating model

```
FROSTGATE PLATFORM ──designates──▶ MSP organization (an ordinary customer tenant)
                                      │ staff = tenant_users of the MSP tenant
                                      │
              proposes ───────────────┤
                                      ▼
                         msp_service_relationships (MSP, customer)
                                      ▲
      approves / suspends / resumes / revokes ── customer tenant_admin
```

This hierarchy is an authorization and commercial relationship. It is not data nesting:

- Customer tenants stay independent: their own rows, their own RLS and audit chain, their own evidence.
- An MSP never owns customer records.
- A customer may use several MSPs, and an MSP may serve many customers.
- A pair may have at most one open relationship at a time; this is enforced by a partial unique index.
- An MSP can never relate to itself (database CHECK). Relationships do not chain, so cycles and inherited authority cannot exist.

## Lifecycle

| Stored status | Derived status shown to callers | Who moves it |
|---|---|---|
| — → `proposed` | `proposed` | MSP `tenant_admin` (`POST /admin/msp/relationships`) |
| `proposed` → `approved` | `approved` before `effective_at`; `active` from `effective_at`; `expired` from `expires_at` | Customer `tenant_admin` who holds no MSP membership |
| `approved` → `suspended` | `suspended` | Customer `tenant_admin` |
| `suspended` → `approved` | as above; an expired window stays expired | Customer `tenant_admin` |
| `proposed` / `approved` / `suspended` → `revoked` (terminal) | `revoked` | Customer **or** MSP `tenant_admin` |

`active` and `expired` are never stored, so expiry needs no scheduler.

Every approval expires: at most 366 days, and the default is the maximum. `effective_at` may not be in the past.

Transitions are compare-and-set on `(id, status, version)`. A stale or concurrent writer gets 409 `MSP_RELATIONSHIP_INVALID_TRANSITION`.

Idempotency rules:

| Operation | Behaviour |
|---|---|
| Propose again, same capabilities, still pending | 200, `created: false` |
| Propose again, any other open relationship for the pair | 409 `MSP_RELATIONSHIP_EXISTS` |
| Propose after revocation | New relationship |
| Revoke again | 200, `changed: false` |
| Re-designate with the same status | 200, `changed: false` |
| Approve twice | 409 (approval is not idempotent) |

## Authorization rule

```
effective(actor, M, C) = ROLE_PERMISSIONS[actor's DB role in M]
                       ∩ relationship(M, C).authorized_capabilities
                       ∩ MSP_DELEGABLE_PERMISSIONS
```

The result is empty, and access is denied, unless all of these hold:

1. M is a platform-designated MSP organization with status `active`.
2. The actor has an active, `bound` `tenant_users` row in M with a principal. JWT and API-key role claims are ignored.
3. The relationship (M, C) is customer-approved, not suspended or revoked, and `effective_at <= now < expires_at`.
4. The requested permission is in the intersection.
5. The caller's tenant is M, taken from the bound credential via `resolve_authoritative_tenant`. Header or body tenant values cannot change it.

It is an intersection, never a union: an MSP `tenant_admin` holds `key.manage`, `user.invite` and other permissions in M, and none of them reach C (test 11b).

**Delegation ceiling** (`MSP_DELEGABLE_PERMISSIONS`). MSP-001 allows read-only delegation:

- allowed: `assessment.read`, `finding.read`, `evidence.read`, `scan.read`, `report.read`, `bundle.read`, `governance.read`;
- never delegable: approvals, consent, key, user, tenant, risk, actor, platform or any write permission.

Widening the ceiling is a reviewed code change.

**Self-approval is impossible**:

- The approver must be the *customer's* canonical `tenant_admin`. MSP-side callers get 403 `MSP_APPROVAL_REQUIRES_CUSTOMER`.
- The approver must not be the proposer.
- The approver's principal must hold no active membership in the MSP tenant. Otherwise the result is 403 `MSP_SELF_APPROVAL_DENIED`.
- The customer may narrow the requested capabilities, never widen them.

**Platform authority** is the internal admin gateway, plus `admin:write`, plus `platform.admin`, exactly as for tenant provisioning. The platform can:

- designate a customer tenant as an MSP;
- suspend an MSP: the kill switch, which denies every relationship of that MSP on the next check.

The platform can never approve a relationship: it has no customer `tenant_admin` row (test 21).

**Uniform denial.** No relationship, pending, suspended, revoked, expired, capability not delegated, and no such tenant all return the same 404 `MSP_CUSTOMER_NOT_FOUND`. No tenant ids, subjects or capabilities are echoed in errors.

## Multi-client context (API contract)

| Route | Purpose |
|---|---|
| `GET /admin/msp/customers` | Only customers where the caller currently has a non-empty effective permission set, with that set and the expiry. No global listing. |
| `POST /admin/msp/customers/{id}/context` | Validates and audits the selection, and returns the effective permissions and `valid_until`. It **grants nothing and issues no token**; `revalidation: every_request`. |

Every future MSP data route must call `resolve_actor_access` on every request. That is how suspension, revocation, expiry, membership removal and partner suspension take effect on the next request without cache invalidation.

## Revocation contract (bounded)

The authority reads the database on every call and has no cache.

**MSP-001 has no MSP background jobs or queued work.** Any future MSP job must:

1. carry `(msp_tenant_id, customer_tenant_id, relationship_id)`, never a captured `DelegatedAccess`;
2. call `resolve_actor_access` or `resolve_credential_access` immediately before each unit of customer work, and stop on denial;
3. keep per-customer state keyed by customer tenant.

Test 16 proves a previously obtained `DelegatedAccess` does not survive revocation on re-check. Until a job path exists, the maximum revocation latency for MSP-001 is one request.

## Control-plane v2 MSP scope (re-based)

`control-plane:msp:read` and `control-plane:msp:admin` are now a gate, not an authority.

**Cross-tenant reads.** A credential bound to M may read customer C's control-plane data only when `resolve_credential_access(M, C, "governance.read")` succeeds. Otherwise it gets the same 404 as any foreign tenant.

**Unfiltered queries** see M only; there is no more global listing.

**`control_plane_msp_delegations`** records are non-authoritative and grant nothing.

## Audit

Events go to the existing per-tenant identity audit hash chain (`tenant_identity_audit_events`). Relationship events are written to **both** parties' chains, so the customer sees every MSP action that concerns it. The event types are:

- `tenant.msp.organization_designated`
- `tenant.msp.organization_suspended`
- `tenant.msp.relationship_proposed`
- `tenant.msp.relationship_approved`
- `tenant.msp.relationship_suspended`
- `tenant.msp.relationship_resumed`
- `tenant.msp.relationship_revoked`
- `tenant.msp.context_resolved`

Each event binds:

- the actor (`actor_user_id`, `membership_id`);
- the MSP, the customer and the relationship;
- the capabilities in effect, the operation and the result;
- the correlation id (`request_id`);
- the timestamp (`created_at`).

The chain verifies with `verify_identity_audit_chain` (test 19).

Each chain write runs under that tenant's RLS context, and the caller's context is restored afterwards.

## Schema and isolation

| Table | Row visible to | Notes |
|---|---|---|
| `msp_organizations` | The MSP tenant | Platform writes under the target tenant's context. |
| `msp_service_relationships` | Either party (`tenant_id` = customer, or `msp_tenant_id`) | `FORCE ROW LEVEL SECURITY`, with no empty-context bypass. |

The migration is additive only.

Constraints:

- one open relationship per pair;
- distinct parties;
- approved and suspended rows carry approver, time, capabilities and `effective_at`;
- revoked rows carry who revoked and when;
- `expires_at > effective_at`.

## Compatibility

| Area | Effect |
|---|---|
| Customer tenants, users, evidence, reports and assessments | Unchanged. MSP-001 opens no MSP path into customer data, and existing routes still deny MSP credentials (tests 12–14). |
| Control-plane v2 | A `control-plane:msp:*` credential now needs an approved relationship for cross-tenant reads, and no longer receives a global listing. The one existing test that relied on the old behaviour now seeds an approved relationship. |
| Contracts | OpenAPI component schemas for the three request bodies were added by `make fg-contract`. The `/admin/msp/*` paths are control-plane only, like `/admin/tenants/*`. Authority markers were refreshed with `make contract-authority-refresh`. |
| Identity audit | Eight new event types and six new safe detail keys. No schema change. |

## Rollback

1. Revert the PR. The routes disappear, and control-plane v2 returns to scope-only behaviour (the unsafe behaviour; see the audit).
2. Migration 0206 is additive. Its tables may stay in place, and nothing reads them after the revert.
3. If they must be removed: `DROP TABLE msp_service_relationships; DROP TABLE msp_organizations;` after exporting the rows.
4. Audit events remain in the tenants' chains and remain verifiable.

## Next MSP workstreams

These are candidates, not approved work.

| Order | Workstream | Why this order | Reuses |
|---|---|---|---|
| 1 | **MSP-002 Portfolio view and console integration.** Read-only customer posture through `resolve_actor_access`; console UI for propose, approve and revoke; retire `control_plane_msp_delegations`. | The first thing a paying MSP needs, and it makes approval usable by real customers without API calls. | Control Tower snapshot, governance reads |
| 2 | **MSP-006 Partner billing and usage attribution.** | Revenue: wholesale billing of the MSP per managed customer. | Subscriptions, entitlements, Stripe (L14) |
| 3 | **MSP-003 MSP-guided onboarding and assessment orchestration.** Assessor actions under delegation (adds write capabilities to the ceiling with SoD). | Converts MSP channels into field assessments. | Field assessment, scan receipts (0203) |
| 4 | **MSP-007 Customer-facing evidence portal and managed reports.** | Customer-visible accountability for MSP work. | Portal truth, report proof |
| 5 | MSP-004 continuous governance monitoring; MSP-005 remediation and SLA | Recurring revenue | Continuous governance, remediation |
| 6 | MSP-008 white label; MSP-009 automation; MSP-010 benchmarks | Differentiation after traction | `msp.white_label`, CGIN |
