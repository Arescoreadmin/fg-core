# MSP-001 capability audit

Base: `main` `e241e43b` (#871 merged), audited 2026-11-13 before any MSP-001 code was written.

**Question:** what does FrostGate already have for operating a partner (MSP, MSSP, consultancy) that manages several customer organizations?

**Short answer:** almost all of the identity, tenancy, RBAC, audit and entitlement building blocks exist and are reusable. Two things are missing:

- a customer-approved relationship between a partner and a customer;
- an authority that combines the existing blocks into one delegated-access decision.

The only MSP-specific mechanism already present, the control-plane v2 MSP scope, is **unsafe**. Any credential carrying `control-plane:msp:*` could read any tenant's control-plane data, with no relationship and no customer consent. It also had to be blocked, not reused.

## Roadmap authority

`tools/ci/check_customer_one_roadmap.py --work-item MSP-001` initially returned **BLOCKED**, because the item was absent from `next_sequence`. The founder explicitly authorized MSP-001 on 2026-11-13. It is recorded in `customer_one/roadmap_authority.yaml` with an honest Freeze Law basis:

- **Criteria (1) and (2) are not claimed.** No Customer-One blocker or contracted MSP customer was cited.
- **Criterion (3) is supported in part.** This work closes the cross-tenant read described below.

## Capability inventory

| # | Capability | Existing authority | Maturity | Reusable | Missing contract | Classification and action |
|---|---|---|---|---|---|---|
| 1 | Tenant administration | `api/tenant_admin.py`, `api/tenant_admin_authority.py` (TENANT-ADMIN-001) | Production-grade. DB-canonical `tenant_users` check, uniform denial, delegation ceiling. | Yes | Nothing for MSP | **REUSE.** `check_tenant_admin_authority` is the MSP-admin check (on the MSP tenant) and the customer-approver check (on the customer tenant). |
| 2 | Tenant lifecycle | `tenants.lifecycle_state`, `api/credential_authority.py` lifecycle policy | Production-grade | Yes | None | **REUSE.** Only `active` tenants can relate or be served. |
| 3 | Tenant registry and classification | `tenants` (0156), `tenant_kind` (0166), `api/tenant_authority.py` | Production-grade | Yes | No partner designation | **EXTEND.** A new `msp_organizations` designation is keyed by `tenants.tenant_id` and copies no tenant attributes. A new `tenant_kind` was rejected: kinds are exclusive, while an MSP is also a paying customer tenant; and partner suspension must not change tenant lifecycle. |
| 4 | Organization membership | `tenant_users` bound to `fg_principals` (PR-AUTH-001, HARD-002) | Production-grade | Yes | None | **REUSE.** MSP staff are ordinary members of the MSP tenant. No new membership table. |
| 5 | Delegated tenant administration | TENANT-ADMIN-001 (single tenant); `api/identity_governance/delegated_admin.py` (in-tenant admin levels) | Production-grade (single tenant) | Pattern only | Cross-organization delegation | **NEW.** Customer-approved `msp_service_relationships`. |
| 6 | RBAC and scopes | `ALL_PERMISSIONS`, `ROLE_PERMISSIONS` (`api/actor_context.py`); `require_scopes`, `require_permission` | Production-grade | Yes | Cross-tenant intersection | **REUSE.** Delegated capabilities *are* existing permission names. MSP staff roles are existing roles (`tenant_admin`, `assessor`, `viewer`, `client_*`). No new role or permission. |
| 7 | Canonical identity (Auth0, Entra, Keycloak-style OIDC) | `api/identity_authority/*`, `api/auth_dispatch.py`, `ActorContext` | Production-grade | Yes | None | **REUSE.** JWT role claims stay advisory; MSP decisions read the DB. |
| 8 | Tenant credential authority | `api/credential_authority.py`; `/admin/tenants/{id}/credentials` (platform only) | Production-grade | Yes | None | **REUSE.** MSP service credentials are ordinary platform-issued tenant credentials. |
| 9 | Multi-tenant assessment execution | Field assessment (`api/field_assessment.py`, `fa_*`), scan authorization receipts (0203) | Production-grade per tenant | Later | MSP actor on an engagement | **DEFER** to MSP-003. MSP-001 exposes no assessment route through MSP authority. |
| 10 | Field assessment engagements | `fa_engagements`, assessor and QA SoD | Production-grade | Later | Same | **DEFER** to MSP-003. |
| 11 | Autonomous AI governance | `api/governance_*`, agent phase 2 | Varies | Later | Same | **DEFER.** |
| 12 | Governance Control Tower | `api/control_tower_snapshot.py`, CGCT | Production-grade per tenant | Later | Portfolio view | **DEFER** to MSP-002. |
| 13 | Evidence ownership | `decision_evidence_artifacts` + owner-record authorization (#871) | Production-grade | Yes | None | **REUSE, unchanged.** MSP-001 never reads evidence. Offboarding leaves evidence customer-owned (test 20). |
| 14 | Audit and provenance | `tenant_identity_audit_events` hash chain (`emit_identity_audit_event`, `verify_identity_audit_chain`) | Production-grade | Yes | MSP event types and keys | **EXTEND.** 8 `tenant.msp.*` event types and 6 safe detail keys are added. No second ledger. |
| 15 | Subscription and billing | `subscription_contracts` and `subscription_items` (`parent_item_id`: "MSP parent subscription — design point"), Stripe (L14) | Partial (no MSP logic) | Later | Usage attribution | **DEFER** to MSP-006. See `MSP_COMMERCIAL_MODEL.md`. |
| 16 | Partner and reseller entitlements | `api/entitlements.py`: `msp.multi_tenant`, `msp.cross_tenant_reporting`, `msp.tenant_switching`, `msp.white_label` | Capability keys exist; only `msp.multi_tenant` and `msp.cross_tenant_reporting` were used (legacy delegation routes) | Yes | None | **REUSE.** `msp.multi_tenant` gates the MSP-side routes (propose, discovery, context). |
| 17 | Customer onboarding | `/admin/tenants` provisioning, invite-initial-admin | Production-grade | Yes | Relationship onboarding | **NEW** (relationship only): propose, approve, active. |
| 18 | Customer offboarding | Tenant lifecycle; workforce revoke | Production-grade | Yes | Relationship offboarding | **NEW** (relationship only): suspend, resume, revoke. |
| 19 | Tenant switching | None. Console tenant is credential-bound. | — | — | Validated context | **NEW**, contract only: `POST /admin/msp/customers/{id}/context` validates and audits, and grants nothing. |
| 20 | Platform impersonation and delegation | `platform.admin`, internal admin gateway, platform service principal (PSP) | Production-grade | Yes | Partner kill switch | **REUSE plus NEW.** Designation and suspension use the same gateway, scope and permission as tenant provisioning. |
| 21 | Service-to-service authorization | PSP (`api/platform_service_principal.py`), plane registry | Production-grade | Yes | None | **REUSE, unchanged.** |
| 22 | **Control-plane v2 MSP scope** | `api/control_plane_v2.py` `_resolve_msp_tenant`; `services/cp_msp_delegation.py`; `control_plane_msp_delegations` | **Unsafe** | **No** | Customer consent | **BLOCKED and re-based.** See below. |

## Reuse map

| MSP-001 need | Implemented with |
|---|---|
| Who is the MSP? | `tenants` row (kind `customer`) plus `msp_organizations` designation |
| Who are its staff? | `tenant_users` rows in the MSP tenant (active, bound, with principal) |
| Who may propose or end relationships for the MSP? | `check_tenant_admin_authority(MSP tenant)` |
| Who may approve, suspend or resume for the customer? | `check_tenant_admin_authority(customer tenant)`, plus a separation-of-duties (SoD) check: no membership in the MSP |
| What can be delegated? | Existing permission names, capped by `MSP_DELEGABLE_PERMISSIONS` (read-only) |
| What can a staff member use? | `ROLE_PERMISSIONS[DB role]` ∩ approved capabilities ∩ ceiling |
| Caller tenant | `resolve_authoritative_tenant` (credential-bound) |
| Commercial gate | `require_capability("msp.multi_tenant")` |
| Audit | `emit_identity_audit_event` on both parties' chains |
| Platform authority | `require_internal_admin_gateway` + `admin:write` + `platform.admin` |

## Finding: control-plane v2 MSP scope (pre-existing cross-tenant read)

On `main` `e241e43b`, `_resolve_msp_tenant` allowed a credential bound to tenant M that carries `control-plane:msp:read` (or `:msp:admin`) to:

- read **any** tenant's control-plane commands, ledger, ledger verification, ledger anchors, heartbeats and evidence bundle, by passing `?tenant_id=<any>`;
- receive a **global** listing across all tenants, by passing no filter.

No delegation record, relationship or customer consent was consulted. `MSPDelegationService.check_delegation` exists but is never called. Delegation records are created by the MSP itself, for any target tenant, without customer approval, and persistence silently falls back to an in-memory store.

Reproduced on unmodified `main` with a synthetic credential:

- `GET /control-plane/v2/ledger?tenant_id=cust-1` returned **200**;
- with no filter it returned `tenant_scope: "global"`.

**Exposure:**

- **Data:** operational control-plane metadata (commands, ledger events, heartbeats). Not decision evidence or reports.
- **Who could exploit it:** a holder of a platform-issued credential with the MSP scope. Credential issuance requires `platform.admin`.

**MSP-001 action:**

- The scope remains a gate, never an authority.
- Cross-tenant access additionally requires `resolve_credential_access`: an active MSP organization, plus an active, customer-approved relationship delegating `governance.read`.
- Without one, the response is the same 404 used for any foreign tenant.
- An unfiltered MSP query sees only its own tenant.

The legacy delegation records stay as they are, and are documented in code as **non-authoritative**; a test proves a record alone grants nothing. Retiring them is left to MSP-002.

## Other observations (not changed)

- **Legacy scope-to-platform mapping.** `admin:write` and `admin:read` API keys map to `platform_admin` permissions through the legacy scope mapping (`api/identity_providers/api_key.py`). MSP-001 therefore puts its only platform route behind the internal admin gateway, like tenant provisioning. Relationship approval never relies on platform permission: it requires a DB-canonical customer `tenant_admin`.
- **Pre-existing test failure.** `tests/test_h14_rbac.py::test_P17_critical_permissions_are_governance_or_platform` fails on unmodified `main` (`scan.emergency_stop.platform` is marked critical). It is outside `fg-fast` and `fg-security`, but `fg-full` runs every test, so the full-suite shards will report it independently of this PR. Out of scope here.
