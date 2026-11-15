# MSP-003 canonical authority audit

This is the authority map for MSP-003: partner-guided customer onboarding and assessment orchestration. It was written before any MSP-003 code. Every capability MSP-003 needs is mapped to the system that already owns it, and the system is reused, extended, repaired or deferred.

- **Base:** `origin/main` `295fde436` (MSP-006 merged)
- **Authorization:** `customer_one/roadmap_authority.yaml`, entry `MSP-003` (FOUNDER_AUTHORIZED)

## Authority map

| Capability | Canonical owner | Current API | Existing security boundary | Decision | Required extension |
|---|---|---|---|---|---|
| Tenant creation | `api/admin.py` `create_tenant` and the `tenants` registry | `POST /admin/tenants` | `platform.admin` and `admin:write` | REUSE | None. An MSP never creates a tenant. |
| Tenant lifecycle, activation, suspension | `tenants.lifecycle_state`, `api/tenant_lifecycle.py` | Platform tenant routes | Platform only | REUSE | MSP-003 reads `lifecycle_state` and fails closed on anything but `active`. |
| Tenant administration | TENANT-ADMIN-001 `check_tenant_admin_authority` | `/admin/tenants/{id}/…` | DB-canonical `tenant_admin` row and bound principal | REUSE | Every MSP-003 mutation calls it, for the MSP or the customer side. |
| Customer readiness | CLIENT-LIFECYCLE-001/002 `evaluate_client_lifecycle` | `GET /admin/tenants/{id}/lifecycle` | `user.invite` | REUSE | Onboarding progress after linking is derived from it, not stored. |
| Customer invitation (initial admin) | `api/tenant_admin.py` `invite_initial_admin` | `POST /admin/tenants/{id}/invite-initial-admin` | `platform.admin` | REUSE | None. MSP-003 never sends an invitation. |
| Human identity and membership | `tenant_users` and `fg_principals` | Tenant user routes | `require_tenant_admin` | REUSE | None. |
| MSP designation | MSP-001 `msp_organizations` | `PUT /admin/msp/organizations/{id}` | Internal admin gateway and `platform.admin` | REUSE | `msp_organization_active` is re-checked on every MSP-003 call. |
| MSP service relationships | MSP-001 `msp_service_relationships` | `/admin/msp/relationships…` | Customer-approved, expiring, read-only ceiling | REUSE | An existing customer's onboarding is the existing relationship proposal and approval. No second relationship table. |
| MSP consent and delegation (read) | MSP-001 `resolve_actor_access` and `MSP_DELEGABLE_PERMISSIONS` | Portfolio and context routes | Role ∩ customer approval ∩ static ceiling | REUSE | The ceiling stays read-only. MSP-003 does not widen it. |
| MSP consent and delegation (write) | None | None | None | EXTEND | New `msp_assessment_grants`. Each row is one customer-approved, expiring, single-assessment write grant (see below). |
| New-customer onboarding | None. MSP-led tenant creation is not authorized anywhere. | None | None | EXTEND | New `msp_onboarding_requests`, a request-and-review record. The platform provisions through the canonical routes, then links. |
| Engagement creation | `services/field_assessment/store.create_engagement` and the `create_engagement_route` audit sequence | `POST /field-assessment/engagements` | `assessment.create`, the caller's own tenant | EXTEND | The route body becomes `create_engagement_with_audit`, which both the existing route and the MSP initiation call. One creation path. |
| Workflow progression | `VALID_ENGAGEMENT_TRANSITIONS` and the FA status routes | `POST …/engagements/{id}/status` | Customer-tenant permissions | REUSE | MSP-003 exposes no engagement status mutation. MSP progress is the canonical status, read-only. |
| Assignment (assessor) | `fa_engagements.assessor_id` | Create route | `assessment.create` | REUSE | The assessor is part of the customer-approved scope. |
| Readiness, execution, evidence | FA scan, evidence and readiness routes | `/field-assessment/…` | Customer-tenant permissions and the existing gates | REUSE | Unchanged, and never reachable through MSP authority. |
| QA approval | `qa_approve_report_route` (SoD) | `POST …/reports/{id}/qa-approve` | `qa_reviewer`, independent of the assessor | REUSE | Unchanged. The MSP cannot call it. |
| Report qualification, Result Truth Gate | `report_proof` and the report gates | Report routes | Existing gates | REUSE | Unchanged. |
| Governed delivery | GOV-DELIVERY-001 and the QA auto-advance to `delivered` | QA approve | Existing gates | REUSE | Unchanged. |
| MSP billing attribution | MSP-006 `msp_payer_assignments`, `resolve_payer` and the delivery producer | `/admin/msp/billing/…` | Platform-created payer assignment | REUSE | Initiation requires `resolve_payer(...) == RESOLVED` as its product-entitlement check. Charges still come only from the canonical delivery. |
| Product entitlement | `api/entitlements.py` `check_capability` and MSP-006 payer assignments | `require_capability` | Per-tenant capability | REUSE | `msp.multi_tenant` stays on the MSP side, as in MSP-001. The customer-side commercial authority for an MSP-initiated assessment is the MSP-006 payer assignment for `assessment.delivered`. No new capability name. |
| Audit | Identity audit hash chain `emit_identity_audit_event`, via `emit_msp_audit`; FA `emit_engagement_audit_event` | Relationship history route | Per-tenant chain under RLS | EXTEND | `emit_msp_audit` gains an optional `extra` mapping (grant, engagement, previous and new state). New `tenant.msp.*` event types are registered in `api/identity/store.py`. |
| Console transport | MSP-002 BFF allowlist and `_CONSOLE_BIND` | `/api/core/admin/msp/…` | Delegated named human of the session tenant | EXTEND | Two prefixes are proxied: `admin/msp/assessments` and `admin/msp/onboarding`. Platform review routes live under `admin/msp/platform/…`, which is never proxied. |
| Customer Portal | `api/portal.py` and the portal grants | Portal routes | Portal grants | REUSE (unchanged) | None. Customer approval happens in the Console's `/partners` page, where tenant administrators already approve relationships. |

## Why there are two new tables

**`msp_assessment_grants`.** MSP-001 approval covers read-only capabilities for the life of a relationship, up to 366 days. Rule 16 forbids deriving MSP write access from that approval. A write grant needs properties that a relationship approval cannot express:

- one exact assessment scope (type and assessor);
- a short expiry (at most 90 days, and never beyond the relationship);
- single use: at most one engagement per grant, with the engagement id unique in the database;
- its own approve, reject, revoke and withdraw lifecycle, independent of the relationship.

Extending the relationship's capability ceiling would make the write right as long-lived and as broad as the read right. A separate scoped grant keeps the ceiling read-only. Effective authority is the intersection of these checks, all made at the time of the call:

1. MSP designation active
2. the actor is the MSP's canonical tenant_admin
3. relationship active
4. grant approved, unexpired and unused
5. customer tenant active
6. payer resolves
7. scope comes only from the grant

**`msp_onboarding_requests`.** No canonical record exists for "an MSP referred an organization that is not yet a tenant". Tenant creation and invitations are platform-only, and they stay that way. The request is a review queue owned by the MSP tenant. The platform provisions through the canonical routes, then links the request to the new tenant id. From then on, every stage is derived from canonical state rather than stored:

- the tenant's lifecycle;
- client lifecycle, for invited versus accepted;
- the MSP-001 relationship.

## Duplication avoided

- No second tenant registry, onboarding platform, lifecycle or invitation sender.
- No second engagement engine or status set. Orchestration stores only the grant and its engagement link; the engagement status is always read from `fa_engagements`.
- No new RBAC engine or permission names. Initiation needs the canonical `assessment.create`, granted per assessment by the customer. Progress needs the canonical `assessment.read`, already delegable.
- No new audit ledger, billing path or Portal.

## Deferred

| Item | Deferred to |
|---|---|
| MSP staff acting as assessors inside a customer tenant (scans, evidence) | A future milestone with its own SoD review |
| MSP evidence sharing and managed reporting | MSP-007 |
| MSP-led tenant creation (self-service) | Not authorized; it stays platform-reviewed |
| Customer action reminders and notifications | Shown as derived `next_actions`; delivery channels deferred |
