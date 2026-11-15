# MSP-002 security model

MSP-002 adds no authority. Every decision is made by MSP-001 (`api/msp_authority.py`) and the existing identity, tenancy and RBAC authorities, and it is made again on every request.

## Effective access

```
effective(actor, M, C) = ROLE_PERMISSIONS[actor's DB role in M]
                       ∩ relationship(M, C).authorized_capabilities   (customer-approved)
                       ∩ MSP_DELEGABLE_PERMISSIONS                    (read-only ceiling)
```

The result is non-empty only when every one of these holds at the moment of the request:

1. The actor is a verified identity. Through the console, this means a delegation proof (v3) binding subject, tenant, method and path.
2. The actor holds an active, `bound` `tenant_users` membership in M with a principal.
3. M is a platform-designated MSP organization with status `active`.
4. A relationship (M, C) exists, was approved by C, and is neither suspended nor revoked.
5. `effective_at <= now < expires_at`.
6. The capability requested is in the intersection.
7. The caller's tenant is M, taken from the verified credential. A header, query parameter or body field never supplies it.

Selecting a customer (`POST /admin/msp/customers/{id}/context`) validates and audits. It issues no token, changes no principal and grants nothing.

## Permission matrix

| Action | MSP `tenant_admin` | MSP non-admin member | Customer `tenant_admin` | Other customer roles | Platform |
|---|---|---|---|---|---|
| View portfolio | Console + API | API only (see below) | — | — | — |
| Summary section | Only if that customer delegated the capability | Same, ∩ the member's role | — | — | — |
| Propose | Yes | No | — | — | — |
| Approve, suspend, resume | No (`MSP_APPROVAL_REQUIRES_CUSTOMER`) | No | Yes, unless also an MSP member (`MSP_SELF_APPROVAL_DENIED`) | No (403) | No |
| Revoke | Yes (own relationships) | No | Yes | No | No |
| Relationship history | Own chain | No | Own chain | No | — |
| Designate or suspend an MSP | No | No | No | No | Internal gateway + `platform.admin` (never proxied by the console) |

**Console limit, verified:** Core accepts console (`tenant_human`) delegation only for the tenant's unique, active, bound `tenant_admin`.

## Tenant isolation guarantees

- **Caller identity.** The caller is always the session's own tenant. The BFF signs `X-Tenant-ID` from the session. Core re-checks the human against that tenant's DB membership. A proof naming another tenant, or reused for another path, is refused with 403 (transport tests).
- **Customer selection.** A customer id in a path (`customers/{id}/context`) is a target, never the caller. The BFF does not parse it as a tenant.
- **Customer data reads.** These happen only under that customer's RLS context, for a customer already in the actor's authorized set, and only for delegated capabilities. In the MSP's own context, Postgres forced RLS hides customer rows (CI probe `test_0206_msp_002_portfolio_reads_only_under_the_customer_context`).
- **No aggregation and no cache.** There is no cross-customer aggregation and no cache. Each customer's summary is computed from that tenant's rows alone (tests 13 and 33).
- **Uniform denial.** Any MSP-side refusal (no relationship, pending, suspended, revoked, expired, not delegated, or no such tenant) returns the same 404 `MSP_CUSTOMER_NOT_FOUND`.

## Information disclosure controls

- An MSP never learns a customer's display name before that customer approves (test 31).
- Relationship history shows the party that acted. It shows acting subjects only for the caller's own side, so neither party learns the other's people.
- Portfolio summaries carry counts and timestamps only: no titles, descriptions, engagement ids, client names or evidence.
- The console shows only mapped messages for known error codes and HTTP statuses, never server text (console test 31).

## Consent lifecycle

- MSP-001's state machine and compare-and-set are reused unchanged.
- A customer approves explicitly, in a confirmation dialog. It may narrow but never widen the request, for a period of 1 to 366 days.
- Suspension, resumption and revocation each require confirmation.
- Every mutation re-reads Core afterwards. A 409 tells the user the relationship changed and reloads it.

## Audit attribution

These events are written to the existing per-tenant identity hash chain:

| Event | Chains |
|---|---|
| `tenant.msp.relationship_proposed` | Both parties (MSP-001) |
| `tenant.msp.relationship_approved` | Both parties (MSP-001) |
| `tenant.msp.relationship_suspended` | Both parties (MSP-001) |
| `tenant.msp.relationship_resumed` | Both parties (MSP-001) |
| `tenant.msp.relationship_revoked` | Both parties (MSP-001) |
| `tenant.msp.context_resolved` | Both parties (MSP-001) |
| `tenant.msp.portfolio_summary_accessed` | The customer's chain, only when its data was actually read (MSP-002) |

Each event binds:

- the actor subject and membership;
- the MSP, the customer and the relationship;
- the capabilities used;
- the operation and the result;
- the correlation id and the timestamp.

The new events are added in the same transaction and verify with `verify_identity_audit_chain` (test 25; demonstration step 11). The UI calls the audited APIs; it emits no events of its own.

Nothing logs tokens, secrets, raw evidence or customer payloads. Server logs for an unavailable section record only the section name and relationship id.

## Residual risks

- **Tenant-id oracle.** A designated MSP admin can still test whether a customer id exists (MSP-001). The customer page shows its own organization id for sharing; invitation codes would remove both.
- **Truncation.** Summary counts cover only the 100 most recent records per source, and this is labelled in the UI. Relationship lists and relationship history are not truncated: the console follows every relationship page (failing closed past 10,000), and history filters by relationship in the database and pages back to the first event.
- **Legacy delegation.** The non-authoritative legacy delegation code still exists; it grants nothing.
- **Non-admin MSP staff** have no console path.
