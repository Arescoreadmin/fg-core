# FrostGate Authorization & Compliance Plan

**Version:** 1.0  
**Created:** 2026-07-07  
**Owner:** Jason Cosat  
**Authority:** This document is the single source of truth for authorization hardening and regulated-industry compliance readiness.  
**Related:** `ENTERPRISE_PLAN.md` (product strategy), `AUDIT_TRACKER.md` (open security findings), `H14_RBAC_GAP_REPORT.md` (RBAC gap baseline), `ROADMAP.md` (PR tracking)

---

## How to Use This Document

- Update status inline when work ships. Every status change must reference a PR or commit.
- Do not close a phase until **all** exit criteria are checked off.
- Track which items are blockers for a regulated-industry sale in the **Bank/Medical Readiness** track — these run in parallel with the RBAC phases but have independent exit criteria.
- Status key: ✅ Done · 🟡 Partial · 🔴 Not Started · ⏸ Deferred · 🔄 In Progress

---

## Quick Status Overview

| Track | Phase | Status | Blocking? |
|-------|-------|--------|-----------|
| RBAC | 1. Capability Model | 🟡 Partial | No |
| RBAC | 2. Backend Authority | 🟡 Partial | **Yes — H14 open** |
| RBAC | 3. Object-Level Auth | 🔴 Not Started | Yes |
| RBAC | 4. Client-Safe DTOs | 🟡 Partial | Yes |
| RBAC | 5. Authz Audit Logging | 🟡 Partial | Yes |
| RBAC | 6. Entitlements/Licensing | 🔴 Not Started | No |
| RBAC | 7. Policy Registry | 🔴 Not Started | No |
| RBAC | 8. Legacy Removal | 🔴 Not Started | Blocked on 2–7 |
| Bank/Medical | MFA & Identity Proofing | 🟡 Partial | Yes |
| Bank/Medical | Privileged Access & Break-Glass | 🔴 Not Started | Yes |
| Bank/Medical | Access Reviews & Deprovisioning | 🔴 Not Started | Yes |
| Bank/Medical | Encryption At Rest & In Transit | 🟡 Partial | Yes |
| Bank/Medical | Data Retention & Secure Disposal | 🟡 Partial | No |
| Bank/Medical | Vulnerability Management & Patch SLAs | 🔴 Not Started | No |
| Bank/Medical | Incident Response & Disaster Recovery | 🔴 Not Started | Yes |
| Bank/Medical | Vendor/Third-Party Risk | 🔴 Not Started | No |
| Bank/Medical | Privacy Controls, BAA & Data Classification | 🟡 Partial | Yes |
| Bank/Medical | Change Management & Test Evidence | 🟡 Partial | No |
| Bank/Medical | Independent Audit & Penetration Testing | 🟡 Partial | Yes |

---

## Track 1 — RBAC Execution Phases

### Phase 1 — Capability Model

**Owner:** Backend platform  
**Status:** 🟡 Partial  
**Last Updated:** —  
**PR:** —

**What is done:**
- 24 explicit named permissions in `api/actor_context.py` (`ALL_PERMISSIONS` frozenset)
- 6 role → permission bundles (`ROLE_PERMISSIONS` dict)
- Deny-by-default: unknown roles resolve to empty permission set
- Existing permissions follow `resource.action` naming convention

**What is missing:**
- [ ] `CAPABILITY_REGISTRY` dict in `api/actor_context.py` — maps each permission to `{display_name, description, risk_level}`, preventing undocumented additions
- [ ] Unit test asserting `ALL_PERMISSIONS == set(CAPABILITY_REGISTRY.keys())` — CI fails on sprawl

**Exit Criteria:**
- [ ] Every privileged action maps to a named, registered capability with documented risk level
- [ ] CI fails if a permission is added without a registry entry

**Key Files:** `api/actor_context.py`

---

### Phase 2 — Backend Authority

**Owner:** Core/backend  
**Status:** 🟡 Partial (~25% complete)  
**Last Updated:** —  
**PR:** —  
**Open Finding:** H14 in `AUDIT_TRACKER.md` (🔴 Open)

**What is done:**
- `require_permission()` FastAPI dependency exists in `api/actor_context.py`
- `ActorContext` dataclass with JWT-sourced actor fields (not request-body spoofable)
- SoD invariants defined (tenant_admin ≠ compliance_reviewer)
- 5 critical routes hardened in H14: `qa-approve`, `risk-acceptance`, `exception-grant`, `evidence-delete`, `baseline-pin`
- Auth dispatch pattern in `api/auth_dispatch.py` resolves Auth0 / Entra / API key

**What is missing:**
- [ ] ~74 governance mutation routes in `api/field_assessment.py` still use `Depends(verify_api_key_detailed)` (scope-only) — need `Depends(require_permission("X:Y"))` per route
- [ ] Service routes under `services/*/router.py` need same audit and hardening
- [ ] Structured `AuthzDecision(allowed: bool, reason: str, capability: str)` return so denials are machine-readable, not bare 403s
- [ ] `admin_gateway` middleware auth does not call core `require_permission()` — gateway and API can disagree on access

**Exit Criteria:**
- [ ] All mutation routes protected by `require_permission()` — verified by automated AST scan
- [ ] UI/gateway cannot grant access the backend would deny
- [ ] Every 403 response includes a structured machine-readable reason
- [ ] CI fails if a new mutation route ships without a `require_permission` dependency

**Key Files:** `api/actor_context.py`, `api/auth_dispatch.py`, `api/field_assessment.py`, `admin_gateway/middleware/auth.py`

---

### Phase 3 — Object-Level Auth

**Owner:** Core/backend + data layer  
**Status:** 🔴 Not Started  
**Last Updated:** —  
**PR:** —

**What is done:**
- SoD invariant "assessor cannot approve own findings" is documented in `api/actor_context.py`
- Tenant isolation enforced at application layer (tenant_id predicate on all queries)
- `FaGovernanceEvent` table records actor_subject per decision

**What is missing:**
- [ ] `api/object_auth.py` — `check_object_ownership(actor, object_id, table, tenant_id)` to verify tenant_id on object matches actor's tenant before any mutation
- [ ] `check_approval_eligibility(actor, finding_id)` — queries `FaGovernanceEvent` to reject self-approval; hooked into approve/reject routes
- [ ] Division-scoped access: add `division_id` to `ActorContext` so per-division checks avoid extra DB calls
- [ ] Integration test suite: cross-tenant access attempt (must fail), same-actor self-approval attempt (must fail), different-actor approval (must pass)

**Exit Criteria:**
- [ ] A request with valid tenant auth but wrong object tenant gets 403, not 200 or 404
- [ ] An actor who created a finding cannot approve it — enforced at route layer, not documentation only
- [ ] Same role receives different answers for different objects when ownership rules differ

**Key Files:** new `api/object_auth.py`, `api/field_assessment.py`, `api/db_models_governance_event.py`

---

### Phase 4 — Client-Safe DTOs

**Owner:** API layer  
**Status:** 🟡 Partial  
**Last Updated:** —  
**PR:** —

**What is done:**
- Pydantic response models exist per route
- `api/middleware/portal_scope.py` middleware identifies portal-scope requests
- Portal grant model hardened (C7 fix) — per-engagement grants, server-side sessions

**What is missing:**
- [ ] `api/dto/base.py` — three base classes: `InternalDTO`, `ClientDTO`, `PortalDTO`; sensitive fields decorated with `@internal_only` excluded from client/portal tiers
- [ ] `redact(actor: ActorContext) -> ClientDTO` method on internal response models — routes call this before returning
- [ ] Middleware assertion: portal-scope requests (`X-FG-Portal-Session`) can only receive `PortalDTO` instances — server-side enforcement, not UI masking
- [ ] Audit of highest-sensitivity routes first: governance decisions, findings with evidence, signed reports

**Exit Criteria:**
- [ ] Sensitive fields (internal IDs, raw scores, audit metadata, actor emails) never appear in portal responses
- [ ] Automated test asserts that `PortalDTO` serialization excludes all `@internal_only` fields
- [ ] A portal-scoped token cannot receive an `InternalDTO` response — enforced by middleware, not route discipline

**Key Files:** new `api/dto/`, `api/middleware/portal_scope.py`, `api/field_assessment.py`

---

### Phase 5 — Authz Audit Logging

**Owner:** Platform security  
**Status:** 🟡 Partial (~60% complete)  
**Last Updated:** —  
**PR:** —

**What is done:**
- `SecurityAuditLog` ORM model in `api/db_models.py` with HMAC chain (`chain_id`, `prev_hash`, `entry_hash`)
- Structured JSON logging via `api/logging_config.py` with `SecretRedactionFilter`
- `request_id` propagated via `RequestContextFilter` in `api/observability/log_context.py`
- `AuditAtomicityService` ensures audit events commit in the same transaction as mutations (H13 fix)

**What is missing:**
- [ ] `capability: str` column on `SecurityAuditLog` (Alembic migration 0083)
- [ ] `decision: str` column (`"allow"` / `"deny"`) on `SecurityAuditLog`
- [ ] `decision_reason: str` column on `SecurityAuditLog`
- [ ] `require_permission()` must emit an audit event for **every** allow decision, not only denies
- [ ] Verify `request_id` flows from tracing middleware into every audit event row

**Exit Criteria:**
- [ ] Every authz decision (allow and deny) has a row in `SecurityAuditLog` with: actor, tenant, resource, action, capability, decision, reason, request_id
- [ ] Given a request_id, the full decision chain is reconstructable from logs alone
- [ ] Audit log does not contain PII beyond what is necessary (no full JWT payloads, no request bodies)

**Key Files:** `api/db_models.py` (SecurityAuditLog), `api/actor_context.py`, `api/observability/log_context.py`, new migration 0083

---

### Phase 6 — Entitlements/Licensing

**Owner:** Product/backend  
**Status:** 🔴 Not Started  
**Last Updated:** —  
**PR:** —

**What is done:**
- Nothing. No tenant-level feature licensing exists today.

**What is missing:**
- [ ] `TenantEntitlement` ORM model: `(tenant_id, feature_key, enabled, expires_at)` — Alembic migration 0084
- [ ] `api/entitlements.py` with `check_entitlement(tenant_id, feature_key)` — Redis-cached with TTL to avoid per-request DB hit
- [ ] `require_entitlement("feature_key")` FastAPI dependency, composable with but independent of `require_permission()`
- [ ] Seed existing tenants with all entitlements enabled (opt-out model at launch)
- [ ] Admin route to manage entitlements per tenant (admin_gateway)

**Design constraint:** Entitlement checks must never be merged into RBAC logic. A role grants a capability; a license grants the right to use a feature. These are separate denial reasons.

**Exit Criteria:**
- [ ] A tenant with valid role and permission can still be denied if their subscription does not include the feature module
- [ ] Entitlement denial returns a distinct error code from permission denial
- [ ] Existing tenants are not broken at launch (opt-out seeding verified in staging)

**Key Files:** new `api/entitlements.py`, `api/db_models.py`, new migration 0084

---

### Phase 7 — Policy Registry

**Owner:** Platform/security + CI  
**Status:** 🔴 Not Started  
**Last Updated:** —  
**PR:** —

**What is done:**
- `authority_manifest.yaml` at repo root exists — examine whether it overlaps before creating new registry

**What is missing:**
- [ ] `policy/route_registry.yaml` — versioned list of every route with `method`, `path`, `capability_required`, `sensitivity` (low/medium/high/critical), `dto_tier` (internal/client/portal)
- [ ] `scripts/check_route_registry.py` — reflects FastAPI routes at import time, diffs against registry, fails CI if any `high`/`critical` route is unregistered
- [ ] CI gate wired into Makefile and GitHub Actions — must be a PR blocker, not advisory

**Exit Criteria:**
- [ ] Every route with `sensitivity: high` or `sensitivity: critical` has a registry entry before it can merge
- [ ] CI fails on any unregistered high/critical route — confirmed in a test PR
- [ ] Registry is versioned; changes require review

**Key Files:** new `policy/route_registry.yaml`, new `scripts/check_route_registry.py`, `Makefile`, `.github/workflows/ci.yml`

---

### Phase 8 — Legacy Removal

**Owner:** Platform/backend  
**Status:** 🔴 Not Started — **Blocked on Phases 2–7**  
**Last Updated:** —  
**PR:** —

**What must be removed:**
- [ ] All remaining `Depends(verify_api_key_detailed)` on mutation routes (replaced by `require_permission()` in Phase 2)
- [ ] Legacy role → scope fallback in `api/identity_providers/api_key.py`
- [ ] Any hardcoded scope bypass paths identified during Phase 2 audit

**Prerequisite:** 30-day deprecation notice in API responses (`X-FG-Deprecation` header) before removal, to avoid breaking existing API key clients silently.

**Exit Criteria:**
- [ ] `verify_api_key_detailed` is not called by any mutation route
- [ ] A request to a mutation route without a valid `ActorContext` returns 403 — no legacy fallback
- [ ] Integration test suite asserts that unmapped and unknown access fails closed

**Key Files:** `api/identity_providers/api_key.py`, `api/auth.py`, `api/auth_scopes/`

---

## Track 2 — Bank/Medical-Grade Compliance

These requirements are **necessary but not sufficient** from the RBAC phases above. They represent independent compliance domains that must be addressed for HIPAA (medical) and FFIEC/NIST SP 800-53 Rev. 5 (banking) readiness.

---

### 1. MFA and Strong Identity Proofing

**Status:** 🟡 Partial  
**Last Updated:** —  
**PR:** —

**What is done:**
- Auth0 integration (`api/identity_providers/auth0.py`) — Auth0 supports MFA
- `TenantIdentityConfig.sso_enforced` flag exists in `api/db_models_identity.py`
- Session management with timeout in `admin_gateway/auth/session.py`

**What is missing:**
- [ ] Confirm Auth0 MFA is enforced (not optional) for all tenant identity modes — check Auth0 org policy
- [ ] `sso_enforced = True` must block password-only auth paths for SSO-configured tenants
- [ ] Verify that API key auth paths cannot bypass MFA-protected console routes
- [ ] Document identity assurance levels (IAL) per tenant tier for regulated sales

**Exit Criteria:**
- [ ] All human-actor console sessions require MFA — enforceable at tenant level
- [ ] API key paths documented as machine-to-machine (not human); human impersonation via API key blocked

---

### 2. Privileged Access Management and Break-Glass Controls

**Status:** 🔴 Not Started  
**Last Updated:** —  
**PR:** —

**What is done:**
- `admin_gateway` provides separate surface for platform admin operations
- Non-root container confirmed (POST_PT_AUDIT.md control #2)

**What is missing:**
- [ ] Formal definition of "privileged roles" (tenant_admin, governance_admin at minimum) with elevated logging
- [ ] Break-glass procedure: time-limited emergency escalation with mandatory audit trail and mandatory post-event review
- [ ] Privileged session recording or audit-only mode for break-glass access
- [ ] Automatic deprovisioning of break-glass grants after TTL

**Exit Criteria:**
- [ ] Break-glass access leaves a non-repudiable audit trail
- [ ] No standing privileged access for platform operators — just-in-time only
- [ ] Break-glass events trigger an alert to a designated reviewer

---

### 3. Periodic Access Reviews and Deprovisioning SLAs

**Status:** 🔴 Not Started  
**Last Updated:** —  
**PR:** —

**What is done:**
- `tenant_role_audit` table is append-only — provides history of role assignments
- `TenantMembership` model in `admin_gateway/identity/models.py` with `status` field

**What is missing:**
- [ ] Access review workflow: scheduled review prompt (configurable interval, e.g. 90 days) with owner sign-off
- [ ] Deprovisioning SLA: define maximum time from termination event to access revocation (e.g. 24h for standard, 1h for privileged)
- [ ] Orphaned account detection: API keys and memberships with no last-use activity past SLA threshold flagged for review
- [ ] Admin dashboard showing pending reviews and SLA status

**Exit Criteria:**
- [ ] Every tenant membership has a documented review date
- [ ] Stale access (no activity past SLA) is automatically flagged and queued for deprovisioning
- [ ] Access review completions are auditable

---

### 4. Encryption At Rest and In Transit

**Status:** 🟡 Partial  
**Last Updated:** —  
**PR:** —

**What is done:**
- HTTPS enforced via security headers (`api/middleware/security_headers.py`) — HSTS present
- Secure cookie flags set (`admin_gateway/middleware/session_cookie.py`)
- POST_PT_AUDIT.md confirms no default secrets in repo

**What is missing:**
- [ ] Confirm PostgreSQL encryption at rest is enabled in production (`deploy/` Kubernetes configs and managed DB config)
- [ ] Confirm blob/object storage (Vercel Blob) is encrypted at rest — verify provider SLA
- [ ] Document key management: who holds encryption keys, rotation schedule, key escrow policy
- [ ] Confirm Redis data is not persisted unencrypted (Redis AOF/RDB on encrypted volume or Redis encryption-at-rest)
- [ ] mTLS between internal services (API ↔ admin_gateway ↔ NATS ↔ Redis) — or document why not required

**Exit Criteria:**
- [ ] Written confirmation of encryption at rest for every data store used in production
- [ ] Key rotation documented and tested
- [ ] All data in transit between services uses TLS 1.2+ — verified by network scan

---

### 5. Data Retention and Secure Disposal

**Status:** 🟡 Partial  
**Last Updated:** —  
**PR:** —

**What is done:**
- `contracts/dpa_template.md` exists — DPA template started
- Evidence model has retention policy field (per P1 Evidence Provenance Ledger ROI item in `AUDIT_TRACKER.md`)
- Soft-delete pattern used in FA (deleted_at columns)

**What is missing:**
- [ ] Retention policy engine: automated enforcement of retention schedules per data classification
- [ ] Secure disposal procedure: cryptographic erasure or verified overwrite for tenant offboarding
- [ ] Tenant offboarding runbook: steps to purge all tenant data within SLA after contract termination
- [ ] Data classification registry: PII, ePHI, financial data, assessment findings — each with retention period and disposal method

**Exit Criteria:**
- [ ] Every data type has a documented retention period and disposal method
- [ ] Tenant offboarding can be executed with a documented, auditable procedure
- [ ] Retention enforcement is automated — not a manual checklist

---

### 6. Vulnerability Management and Patch SLAs

**Status:** 🔴 Not Started  
**Last Updated:** —  
**PR:** —

**What is done:**
- CI pipeline exists (`.github/workflows/ci.yml`)
- `requirements.txt` pins dependencies

**What is missing:**
- [ ] Automated dependency scanning in CI (Dependabot, `pip-audit`, or Snyk) — alerts on CVEs in pinned packages
- [ ] Patch SLA policy: Critical CVE ≤ 48h, High ≤ 7 days, Medium ≤ 30 days
- [ ] Container image scanning (Trivy or equivalent) in the release workflow
- [ ] Process for tracking CVEs in production until patched (issue tracker label or dedicated board)

**Exit Criteria:**
- [ ] CI blocks merges on Critical/High CVEs in dependencies
- [ ] Container images scanned on every release build
- [ ] SLA policy documented and SLA breach triggers escalation

---

### 7. Incident Response and Disaster Recovery

**Status:** 🔴 Not Started  
**Last Updated:** —  
**PR:** —

**What is done:**
- Docker + Kubernetes deployment infrastructure exists (`deploy/`)
- Structured logging and OpenTelemetry tracing in place for incident forensics
- `admin_gateway/middleware/audit.py` records activity

**What is missing:**
- [ ] Incident Response Plan: classification (P0/P1/P2/P3), communication tree, escalation paths, SLAs for containment/eradication/recovery
- [ ] Disaster Recovery Plan: RTO and RPO targets, backup schedule, restore procedure, failover runbook
- [ ] Runbook for: data breach, credential compromise, service outage, tenant data loss
- [ ] IR plan tested: tabletop exercise or drill at least annually
- [ ] Security contact published (responsible disclosure / security@ contact)

**Exit Criteria:**
- [ ] IR plan documented and reviewed by a stakeholder outside engineering
- [ ] DR plan tested — restore from backup verified in a non-production environment
- [ ] RTO and RPO commitments are contractually documentable

---

### 8. Vendor and Third-Party Risk Management

**Status:** 🔴 Not Started  
**Last Updated:** —  
**PR:** —

**What is done:**
- Third-party providers identified: Auth0, PostgreSQL (managed), NATS, Redis, Vercel Blob, Anthropic (AI), OpenAI (audio transcription — see H6)
- `contracts/` directory exists

**What is missing:**
- [ ] Vendor inventory: every third-party service with data access documented (name, data types accessed, SOC 2 / ISO 27001 cert status, BAA availability)
- [ ] BAA executed with any vendor that processes ePHI (HIPAA requirement)
- [ ] Subprocessor list for DPA — required by GDPR and most enterprise DPAs
- [ ] Annual review of vendor security posture (SOC 2 Type II report review)
- [ ] OpenAI usage (H6) — audio recordings sent to OpenAI bypass provider governance; must be remediated before any medical or legal engagement

**Exit Criteria:**
- [ ] Vendor inventory complete and reviewed
- [ ] BAA in place for any HIPAA-relevant vendors
- [ ] H6 (OpenAI audio bypass) resolved before regulated-industry go-live

---

### 9. Privacy Controls, BAA/Contracting, and Data Classification

**Status:** 🟡 Partial  
**Last Updated:** —  
**PR:** —

**What is done:**
- `contracts/dpa_template.md` exists
- `contracts/README.md` covers basic contract guidance
- Assessment covers HIPAA, SOC 2, ISO 27001 frameworks — platform understands the domain

**What is missing:**
- [ ] BAA template for healthcare customers — required before any ePHI processing
- [ ] Data classification policy: define tiers (Public, Internal, Confidential, Restricted/ePHI) with handling rules per tier
- [ ] Privacy notice / privacy policy linked from portal
- [ ] GDPR/CCPA compliance documentation if serving EU or California residents
- [ ] Data subject request (DSR) workflow: erasure, portability, access requests

**Exit Criteria:**
- [ ] BAA template reviewed by legal and executable for healthcare customers
- [ ] Data classification policy covers all data types handled by FrostGate
- [ ] DSR workflow exists and is documented

---

### 10. Change Management and Test Evidence

**Status:** 🟡 Partial  
**Last Updated:** —  
**PR:** —

**What is done:**
- Alembic migrations for every schema change — versioned, sequential
- 6,347+ tests documented in `ENTERPRISE_PLAN.md`
- CI pipeline gates merges on test pass
- `POST_PT_AUDIT.md` is an example of structured evidence for a completed control assessment
- `AUDIT_TRACKER.md` references PR numbers for closed findings

**What is missing:**
- [ ] Change management procedure: every production change requires a PR, reviewer approval, and CI pass — formalize as written policy, not just practice
- [ ] Test evidence packaging: for a compliance audit, demonstrate that tests cover the specific controls being attested — map tests to control IDs
- [ ] Configuration change log: infrastructure/environment changes outside git (Kubernetes config, managed DB, DNS) are not tracked — introduce a change log
- [ ] Release notes or change log generated per release for auditor consumption

**Exit Criteria:**
- [ ] Written change management policy exists and is pointed to in contracts
- [ ] Compliance auditor can be given a package: "here are the tests that cover control X, here are the run results"
- [ ] No production changes outside the tracked change process

---

### 11. Independent Audit and Penetration Testing

**Status:** 🟡 Partial  
**Last Updated:** —  
**PR:** —

**What is done:**
- `POST_PT_AUDIT.md` — internal post-pentest audit completed, all Critical/High findings resolved, confidence score 90
- `AUDIT_TRACKER.md` — structured internal security audit with finding tracking
- `artifacts/SOC_AUDIT_GATES.md`, `artifacts/SOC_AUDIT_STAGE0.md`, `artifacts/SOC_AUDIT_STAGE1.md`, `artifacts/SOC_AUDIT_STAGE2_PATCHPLAN.md` — SOC 2 audit preparation underway
- Open findings still present (H11, H12, H14, H15, PI17–PI20 in `AUDIT_TRACKER.md`)

**What is missing:**
- [ ] External penetration test by an independent third party (internal PT does not satisfy bank/medical requirements)
- [ ] Resolve open High findings before external PT: H11 (drift RLS), H12 (scan job durability), H14 (console RBAC), H15 (evidence immutability)
- [ ] SOC 2 Type II readiness: Type I is a point-in-time assertion; Type II requires 6+ months of operating evidence — start the observation period
- [ ] HIPAA Security Rule risk assessment by a qualified assessor (required before accepting ePHI)
- [ ] Penetration test scope to include: API auth bypass, tenant crossover, IDOR, privilege escalation, SSRF (C5 fixed — verify in PT)

**Exit Criteria:**
- [ ] External PT report with no Critical or High findings unresolved
- [ ] SOC 2 Type II audit initiated (observation period started)
- [ ] All AUDIT_TRACKER.md open High findings resolved before external PT

---

## Phase Dependency Map

```
Phase 1 (Capability Model)
    └── Phase 2 (Backend Authority)           ← H14 open finding
            ├── Phase 3 (Object-Level Auth)
            ├── Phase 4 (Client-Safe DTOs)
            ├── Phase 5 (Audit Logging)
            └── Phase 6 (Entitlements)        ← independent track
Phase 7 (Policy Registry)                     ← can start after Phase 2
Phase 8 (Legacy Removal)                      ← blocked on 2–7

Bank/Medical items run in parallel with RBAC phases.
Items 1, 4, 9, 11 are blockers for a regulated-industry first engagement.
Items 6, 7, 8 can be prepared in parallel without blocking product work.
```

---

## Regulated-Industry Go/No-Go Checklist

Before handing credentials to a bank or medical facility, all of the following must be ✅:

**Authorization (RBAC Track):**
- [ ] Phase 2 complete — all mutation routes behind `require_permission()`
- [ ] Phase 3 complete — object-level ownership and self-approval SoD enforced
- [ ] Phase 5 complete — every authz decision logged with capability and reason

**Identity & Access:**
- [ ] MFA enforced for all human console access
- [ ] No standing privileged access — break-glass procedure in place

**Data & Privacy:**
- [ ] Encryption at rest confirmed for all production data stores
- [ ] Data classification policy and BAA template ready (medical: BAA executed before any ePHI)
- [ ] H6 (OpenAI audio bypass) resolved

**Audit & Assurance:**
- [ ] All AUDIT_TRACKER.md High findings resolved (H11, H12, H14, H15)
- [ ] External penetration test completed with no unresolved Critical/High findings
- [ ] Incident response plan documented and reviewed

---

*Update this document when any phase status changes. Reference the PR that changed it.*
