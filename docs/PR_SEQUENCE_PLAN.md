# FrostGate — PR Sequence Plan
# PR6 · ECE · PR7A · PR7B · PR7C · PR7D

**Author:** Jason Cosat  
**Date:** 2026-06-10  
**Branch:** `claude/exciting-rubin-tldiit`  
**Quality target:** 9.5 / 10  
**Authority:** This document is the delivery plan for the next six PRs.  
`SYSTEM.md` and `BLUEPRINT_STAGED.md` remain authoritative for system-level decisions.

---

## Execution Order

```
PR6 (RBAC)
  ↓
ECE (Evidence Correlation Engine)
  ↓
PR7A (Commercial Event Ledger)
  ↓
PR7B (Rating Engine)
  ↓
PR7C (Chargeback & Analytics)
  ↓
PR7D (Invoicing)
```

**Why this order:**
- PR6 establishes `evidence:read/write`, `rbac:*`, `audit:export` scopes that gate every downstream route
- ECE requires governed evidence lifecycle (PR6 RBAC) but not commercial infrastructure
- PR7A–D are strictly sequential: ledger → rating → chargeback → invoicing
- ECE can ship before or after PR7A with no hard dependency; placing it before PR7A keeps commercial work clean

---

## Moat Dimensions (referenced throughout)

| Symbol | Moat |
|--------|------|
| **D** | Data — accumulates and compounds with each engagement |
| **S** | Switching cost — painful to leave once embedded |
| **I** | Integration depth — deep wiring to identity, finance, compliance systems |
| **N** | Network effect — benchmarks get smarter as more clients join |
| **R** | Regulatory lock-in — outputs become part of clients' audit evidence packages |

---

---

# PR6 — Governed RBAC + Permission Delegation Engine

**Depends on:** PR1–PR4 (Identity Foundation, merged)  
**Blocks:** ECE, PR7A–D (all downstream routes need RBAC scopes)  
**Migration:** 0099

---

## Mission

Build the enterprise RBAC foundation that connects tenant identity governance to deterministic permission delegation. Role selection must be meaningful, deterministic, auditable, and future-proof from day one.

**Hard rule:** Admin Gateway remains the only authority for tenant session issuance. RBAC decides what a governed identity can *do* after session issuance. RBAC must never become an alternate session authority.

---

## Security Doctrine

After PR6 the following must be true — no exceptions:

- Role selection never creates a session
- Role selection never activates membership by itself
- Permissions are server-authored only
- Console displays and requests role changes; it does not calculate authority
- `tenant_id` query/body values are not authorization authority
- Auth0/IdP roles are not trusted unless explicitly mapped through Frostgate policy
- JWT claims are authentication context, not final authorization authority
- Every role assignment is tenant-scoped
- Every effective permission set is explainable

---

## Commit 1 — Data Model (migration 0099)

**File:** `api/db_models_rbac.py`

### Tables

**`role_templates`**
```
id, tenant_id (nullable = global), role_key, display_name, description,
category, identity_type_allowed (JSON array → see identity_type_registry),
is_system, is_assignable, risk_level (low/medium/high/critical),
version, created_at, updated_at, disabled_at
```

**`permission_bundles`**
```
id, tenant_id (nullable), bundle_key, display_name, description,
version, is_system, created_at, updated_at, disabled_at
```

**`permissions`**
```
id, permission_key (unique, CHECK format: ^[a-z_]+:[a-z_]+$),
display_name, description, domain, action, resource,
risk_level, is_system, created_at, updated_at
```

**`role_template_permissions`**
```
id, role_template_id FK, permission_id FK, source (seed/custom/delegated),
created_at
UNIQUE(role_template_id, permission_id)
```

**`membership_role_assignments`**
```
id, tenant_id, membership_id FK, role_template_id FK,
assigned_by, assignment_reason,
approval_state (pending/active/approval_required/revoked/expired),
effective_at, expires_at, revoked_at,
delegation_chain_json (JSON array of {actor_id, actor_role, assigned_at}),
created_at, updated_at
INDEX(tenant_id, membership_id), INDEX(tenant_id, approval_state)
```

**`rbac_audit_events`**
```
id, tenant_id, event_type, actor_id, membership_id, role_template_id,
permission_key, payload_json, previous_hash, event_hash,
delegation_depth (int), created_at
Append-only — UPDATE/DELETE triggers (same pattern as governance_decisions)
```

**`rbac_delegation_policies`** *(Moat upgrade — I/R)*
```
id, tenant_id, grantor_role_key, grantee_role_key,
allowed_target_roles (JSON array),
effective_from, effective_to (nullable),
policy_version, authored_by, created_at
```
Evaluated through OPA at `:8181`. Tier-customizable. Machine-readable for SOC 2 evidence.

**`identity_type_registry`** *(Moat upgrade — future-facing)*
```
id, type_key (varchar 64), display_name, description,
can_have_interactive_session (bool),
can_receive_human_roles (bool),
requires_approval_for_elevated_roles (bool),
is_system, created_at
```
Seeded with 5 types. Adding `agi_provider` or `autonomous_swarm` = one INSERT, no migration.

**RLS:** All tenant-scoped tables enforce row-level security matching existing `fa_*` table pattern.

---

## Commit 2 — Permission Seed + Role Template Seed

**File:** `api/identity/rbac_seed.py`

Idempotent — `INSERT ... ON CONFLICT DO NOTHING`. Called from startup after migrations.

### 35 Canonical Permissions

| Domain | Actions |
|--------|---------|
| identity | read, write, admin |
| rbac | read, write, admin |
| tenant | read, write, admin |
| assessment | read, write, admin |
| evidence | read, write, admin |
| governance | read, write, admin |
| report | read, write, admin |
| audit | read, export |
| risk | read, write |
| drift | read, write |
| connector | read, write, admin |
| rag | read, write, admin |
| agent | read, write, admin |
| system | read |

No wildcards. No `*:*`. Every permission is explicit.

### 13 System Role Templates

| Role | identity_type_allowed | risk_level | Notable permissions |
|------|-----------------------|-----------|---------------------|
| owner | [human] | critical | all non-system |
| tenant_admin | [human] | high | tenant:admin, identity:write, rbac:write, all:read |
| identity_admin | [human] | high | identity:admin, rbac:read |
| security_admin | [human] | high | governance:admin, drift:write, connector:admin |
| compliance_manager | [human] | medium | governance:write, assessment:write, evidence:write |
| risk_manager | [human] | medium | risk:write, assessment:read, governance:read |
| auditor | [human] | medium | audit:read, audit:export, all:read — no write |
| analyst | [human] | low | assessment:read, report:read, risk:read |
| assessor | [human] | low | assessment:write, evidence:write, report:read |
| viewer | [human] | low | *:read only |
| service_operator | [human, service] | medium | connector:write, agent:read |
| agent_operator | [human, agent] | medium | agent:write, rag:write |
| workload_operator | [human, workload] | medium | connector:read, system:read |

---

## Commit 3 — RBAC Engine

**File:** `api/identity/rbac_policy.py`

```python
list_role_templates(db, tenant_id) -> list[RoleTemplateRow]
get_role_template(db, role_key_or_id, tenant_id) -> RoleTemplateRow | None
validate_role_assignment(db, actor_ctx, membership_id, role_template_id, tenant_id) -> ValidationResult
assign_role(db, actor_ctx, membership_id, role_template_id, tenant_id, reason) -> MembershipRoleAssignment
revoke_role(db, actor_ctx, assignment_id, tenant_id, reason) -> None
materialize_effective_permissions(db, membership_id, tenant_id) -> list[str]
materialize_session_scopes(db, membership_id, tenant_id, identity_type) -> list[str]
detect_rbac_drift(db, tenant_id) -> list[DriftItem]
score_rbac_governance(db, tenant_id) -> GovernanceScore
verify_delegation_allowed(actor_ctx, target_role, tenant_id) -> bool
verify_separation_of_duties(db, membership_id, new_role_key, actor_ctx) -> SoDResult
get_delegation_lineage(db, assignment_id) -> list[DelegationHop]
```

**`materialize_session_scopes` is the only path that produces session scopes.** No other function, route, or request field may influence what scopes a session receives.

Active assignment criteria: `approval_state='active'` AND `effective_at <= now` AND `(expires_at IS NULL OR expires_at > now)` AND `revoked_at IS NULL`.

**Drift detection — 10 categories:**
1. Role assignment references missing role template
2. Role template references missing permission
3. Disabled role still has active assignments
4. Expired assignment still marked active
5. Identity type incompatible with role
6. Assignment exists with no audit trail entry
7. Effective scopes differ from expected bundle
8. Permission key no longer in registry
9. Tenant mismatch between assignment and role template
10. Stale role version (assignment references version N, current is N+2+) *(Moat upgrade — D)*: Role assigned >90 days ago with no exercised high-risk permissions → `ROLE_NEVER_EXERCISED` drift type

**Governance score factors (9):**
1. Assignments have audit trail
2. Roles map to known permissions
3. No incompatible identity types
4. No expired active assignments
5. No disabled active roles
6. No orphaned assignments
7. No SoD violations
8. Least-privilege coverage
9. High-risk roles require approval

---

## Commit 4 — RBAC Audit Events

**File:** `api/identity/rbac_audit.py`

```
RBAC_ROLE_ASSIGNED
RBAC_ROLE_REVOKED
RBAC_ROLE_ASSIGNMENT_REJECTED
RBAC_ROLE_ASSIGNMENT_EXPIRED
RBAC_PERMISSION_MATERIALIZED
RBAC_SESSION_SCOPES_MATERIALIZED
RBAC_DRIFT_DETECTED
RBAC_SOD_VIOLATION
RBAC_DELEGATION_DENIED
```

`RBAC_AUDIT_ALLOWLIST` dict maps each event type to permitted payload keys. Keys outside the allowlist are silently dropped before write. No secrets, no tokens, no auth headers in any payload.

Hash chain: `event_hash = SHA-256(previous_hash + event_type + payload_json + created_at)` per tenant.

---

## Commit 5 — Admin API Routes

**File:** `api/admin_rbac.py`

```
GET    /admin/rbac/tenants/{tenant_id}/roles
GET    /admin/rbac/tenants/{tenant_id}/permissions
GET    /admin/rbac/tenants/{tenant_id}/memberships/{membership_id}/roles
POST   /admin/rbac/tenants/{tenant_id}/memberships/{membership_id}/roles
DELETE /admin/rbac/tenants/{tenant_id}/memberships/{membership_id}/roles/{assignment_id}
GET    /admin/rbac/tenants/{tenant_id}/effective-permissions
GET    /admin/rbac/tenants/{tenant_id}/drift
GET    /admin/rbac/tenants/{tenant_id}/governance-score
GET    /admin/rbac/tenants/{tenant_id}/audit-summary
GET    /admin/rbac/tenants/{tenant_id}/compliance-export   ← Moat upgrade (R/S)
```

**`/compliance-export`** returns: current role templates, permission bundles, all active assignments with full delegation lineage, SoD policy summary, delegation boundary matrix, last 90-day audit event counts. Signed with `FG_REPORT_SIGNING_KEY`. Format: JSON or CSV. Includes in client SOC 2 / ISO 27001 evidence packages.

All routes: enforce `tenant_id` from actor context (not request body/query), require proper scopes, audit all mutations, return structured `RBACErrorResponse` with `error_code`.

**SoD error codes:**
- `SOD_SELF_ASSIGN_FORBIDDEN`
- `SOD_INCOMPATIBLE_ROLES`
- `SOD_APPROVAL_REQUIRED`
- `SOD_IDENTITY_TYPE_FORBIDDEN`

---

## Commit 6 — Session Scope Materialization Wire-up

**File:** `api/auth_dispatch.py` (targeted diff)

Single change: find session issuance path, replace static scope assignment with:

```python
scopes = materialize_session_scopes(db, membership_id, tenant_id, identity_type)
```

Empty scopes = session denied or minimal read-only per policy. No silent grant.
Emits `RBAC_SESSION_SCOPES_MATERIALIZED` with permission count (not the permission list).

---

## Commit 7 — Invitation Role Delegation Integration

**File:** `api/admin_identity.py` (targeted diff)

1. Invitation creation accepts `role_template_id` (required when tenant RBAC-enabled)
2. `validate_role_assignment(..., approval_state='pending')` called on create
3. On membership binding → `assign_role()` activates assignment
4. On revoke/expiry → `revoke_role()` on pending assignment + audit event
5. `delegation_chain_json` populated at assignment time

---

## Commit 8 — Tests

| File | Series | Count |
|------|--------|-------|
| `tests/test_rbac_policy.py` | M/A/I/S/D/SoD/DR/SC | 40+ |
| `tests/test_rbac_postgres_hardening.py` | migration replay, RLS, seed idempotency | 15+ |
| `tests/test_rbac_admin_routes.py` | route integration, auth enforcement | 20+ |

Critical test assertions:
- `materialize_session_scopes` is the only path producing session scopes
- Auth0 claims do not inject scopes
- POST body cannot inject scopes
- Disabled/revoked/expired assignments excluded
- SoD codes fire correctly
- Delegation boundary enforced server-side
- `compliance-export` is signed and contains delegation lineage

---

## Commit 9 — Console RBAC Governance UI

**Files:**
- `apps/console/app/governance/rbac/page.tsx`
- `apps/console/components/rbac/RoleTemplatesPanel.tsx`
- `apps/console/components/rbac/PermissionBundlePanel.tsx`
- `apps/console/components/rbac/MembershipRolePanel.tsx`
- `apps/console/components/rbac/RbacDriftScorePanel.tsx`
- `apps/console/lib/rbacApi.ts`

**Five panel tabs:** Role Templates · Permission Bundles · Membership Assignments · Invitation Role Selection · RBAC Drift/Score

**Hard rules:**
- No `localStorage`/`sessionStorage` authority
- No `tenant_id` in query params for auth
- No permission calculation in frontend
- No `dangerouslySetInnerHTML`
- All states handled: loading / error / empty / not-yet-run

Existing `InviteUserModal` updated: role selector dropdown populated from `GET .../roles` filtered by identity type. Backend validation error displayed inline.

---

## Commit 10 — Docs + ROADMAP

- `docs/architecture/rbac_governance.md` — role templates, permission bundles, session scope materialization, delegated admin, SoD, drift/score, identity type registry, future agent/workload RBAC
- `ROADMAP.md` — PR6 row added to Active Identity Foundation table
- `docs/ai/PR_FIX_LOG.md` — log entry

---

## PR6 Success Gate

```
[ ] migration 0099 replays cleanly on empty DB
[ ] seed is idempotent
[ ] materialize_session_scopes is the ONLY path setting session scopes
[ ] disabled/revoked/expired assignments excluded
[ ] Auth0 claims do not inject scopes (tested)
[ ] POST body cannot inject scopes (tested)
[ ] SoD violations return structured error codes
[ ] delegation boundary enforced server-side
[ ] compliance-export is signed and contains delegation lineage
[ ] identity_type_registry table seeded with 5 types
[ ] all pytest suites pass
[ ] npm test + typecheck + build pass
[ ] make fg-fast passes
[ ] ROADMAP.md updated
```

---

---

# ECE — Evidence Correlation Engine

**Depends on:** PR6 (RBAC scopes gate all correlation routes)  
**Blocks:** nothing hard, but should precede PR7 series  
**Migration:** 0100

---

## Mission

Build the data accumulation engine that makes FrostGate's moat. Every completed engagement feeds a persistent evidence relationship graph. Correlation clusters, strength scores, and longitudinal patterns compound with each client and each reassessment.

From `ENTERPRISE_PLAN.md`:
> *"The moat is not the questionnaire UI or the PDF. It is a data accumulation engine that compounds with every completed engagement: Asset → Evidence → Control → Finding → Remediation → Outcome → Drift → Reassessment → Outcome"*

ECE is the infrastructure that makes that loop real.

---

## What Already Exists (do not duplicate)

| Component | Location |
|-----------|----------|
| `FaEvidenceLink` graph edges | `api/db_models_field_assessment.py` |
| `EvidenceLifecycleService` | `services/field_assessment/evidence_lifecycle.py` |
| `find_root_cause_candidates()` | `services/connectors/drift/correlation.py` — promote to engine |
| `GovernanceGraphNode/Edge` | `api/db_models_governance_graph.py` — query layer |
| `FaEngagementAuditEvent` | `api/db_models_field_assessment.py` — emit to |
| Verification bundle | `services/verification_bundle/` — add correlation component |
| `DurableJobService` | `services/durable_jobs/` — async execution |

---

## Commit 1 — Data Model (migration 0100)

**File:** `api/db_models_correlation.py`

**`evidence_correlation_clusters`**
```
id, tenant_id, engagement_id,
cluster_key (SHA-256 of sorted finding_ids — deterministic),
cluster_type (varchar 64, CHECK against known values — NOT an enum),
finding_ids (JSON array, ordered),
evidence_node_ids (JSON array),
shared_evidence_count, strength_score (decimal 0–1),
confidence (low/medium/high),
pattern_label (plain-language detected pattern name),
regulatory_citations (JSON array of {framework, citation, requirement_text}),  ← Moat upgrade (R)
feature_vector_json (JSON — versioned numerical representation),               ← Moat upgrade (D)
created_at, refreshed_at
INDEX(tenant_id, engagement_id), INDEX(tenant_id, cluster_type)
```

**`evidence_strength_scores`**
```
id, tenant_id, engagement_id, finding_id,
raw_score (decimal 0–1), factor_breakdown (JSON),
evidence_count, linked_scan_count, linked_observation_count,
linked_document_count, linked_questionnaire_count,
freshness_penalty, source_diversity_score,
lifecycle_state (collected/locked/legal_hold),
sector (varchar 64),               ← Moat upgrade (N) — benchmark data collection
benchmark_consent (bool default false),
computed_at
UNIQUE(tenant_id, engagement_id, finding_id)
```

**`evidence_longitudinal_nodes`** *(Moat upgrade — D/S)*
```
id, tenant_id,
canonical_finding_key (SHA-256 of domain+control_id+finding_type — deterministic),
first_seen_engagement_id, last_seen_engagement_id,
recurrence_count, avg_strength_score_at_detection,
avg_days_to_remediation, remediation_held_count, regression_count,
last_cluster_type, last_regulatory_citations (JSON),
created_at, updated_at
UNIQUE(tenant_id, canonical_finding_key)
```

**`evidence_longitudinal_edges`** *(Moat upgrade — D)*
```
id, tenant_id,
source_node_id FK, target_node_id FK,
relationship_type (co_occurs/causal/resolved_together/regressed_together),
observation_count, confidence, first_seen_at, created_at, updated_at
UNIQUE(tenant_id, source_node_id, target_node_id, relationship_type)
```

**`external_evidence_submissions`** *(Moat upgrade — I)*
```
id, tenant_id, engagement_id,
source_type (pen_test/audit_firm/regulatory_exam/third_party_attestation/api_push),
source_name, source_reference,
evidence_payload (JSON), artifact_hash,
submitted_by, submitted_at, reviewed_at, review_status (pending/accepted/rejected),
linked_finding_ids (JSON array)
```

**`correlation_audit_events`**
```
id, tenant_id, engagement_id, event_type, actor_id, payload_json, created_at
Append-only
```

**Why `cluster_type` is VARCHAR not enum:** new correlation strategies are added without schema migrations. Same pattern as `FaAiVendorGovernanceRecord.target_type`.

---

## Commit 2 — Evidence Strength Scorer

**File:** `services/correlation/strength.py`

```python
@dataclass
class StrengthFactors:
    evidence_count: int           # raw FaEvidenceLink count
    source_diversity: float       # unique source types / total (0–1)
    freshness: float              # reuses existing confidence.py decay table
    lifecycle_weight: float       # collected=0.7, locked=1.0, legal_hold=1.0
    scan_coverage: float          # scan-backed links / total
    observation_coverage: float
    questionnaire_coverage: float

def compute_strength_score(db, finding_id, engagement_id, tenant_id) -> EvidenceStrengthScore
    # Weights: evidence_count 30% (log-scaled, saturates at 10), source_diversity 20%,
    #          freshness 20%, lifecycle_weight 15%, scan_coverage 15%
    # Returns score + per-factor breakdown for explainability

def bulk_compute_strength(db, engagement_id, tenant_id) -> list[EvidenceStrengthScore]
    # Upsert to evidence_strength_scores
```

**Feature vector generation** (stored in `evidence_correlation_clusters.feature_vector_json`):
```json
{
  "vector_version": "1.0",
  "finding_count": 3,
  "shared_evidence_ratio": 0.67,
  "avg_strength": 0.72,
  "temporal_spread_hours": 2.4,
  "source_diversity": 0.5,
  "cascade_depth_max": 2,
  "sector": "community_bank",
  "assessment_type": "HIPAA"
}
```
Stored now. ML model trained later when corpus reaches 500+ engagements. Cannot be reconstructed retroactively.

**Integration:** verification bundle service adds `evidence_strength` component when correlation has been run.

---

## Commit 3 — Correlation Cluster Engine

**File:** `services/correlation/engine.py`

### Five Strategies

**Strategy 1: Shared Evidence**
Findings sharing ≥1 identical `FaEvidenceLink` (same `source_ref` or `artifact_id`). Signals: not independent findings — same root artifact cited across multiple. Fix the shared root = multiple findings resolve.

**Strategy 2: Temporal Clustering**
Evidence links created within a configurable window (default 300s) across different findings. Signals: bulk import, automated scan, coordinated manual entry. Relevant context for audit review.

**Strategy 3: Systemic Pattern Detection**
`GovernanceGraphEdge` traversal to find strongly-connected finding subgraphs (≥3 findings). Signals: systemic control failure, not isolated incidents. Promotes existing `find_root_cause_candidates()` to full cross-finding analysis.

**Strategy 4: Cascade Impact Analysis**
Given a finding, traverse `GovernanceGraphEdge` to depth ≤3. Returns: if this finding's evidence is removed, how many other findings lose evidential support? Output: `{direct_dependents, transitive_dependents, cascade_risk: low/medium/high}`.

**Strategy 5: Duplicate Evidence Detection**
`FaEvidenceLinks` where `source_ref` or artifact hash is identical within the same finding = redundant. Same hash across different findings = shared evidence (Strategy 1).

### Aggregate

```python
def run_full_correlation(db, engagement_id, tenant_id) -> CorrelationReport
    # 1. Run all 5 strategies
    # 2. Deduplicate overlapping clusters
    # 3. Attach regulatory_citations to each cluster
    # 4. Generate feature_vector_json for each cluster
    # 5. Upsert to evidence_correlation_clusters
    # 6. Update evidence_longitudinal_nodes + edges
    # 7. Emit audit event + NATS events
    # 8. Return full CorrelationReport
    
    # Cardinality checks inline:
    #   findings with 0 evidence links → under-evidenced (flagged in report)
    #   findings with >20 links from same source → over-cited (flagged in report)
```

**NATS event emission** *(Moat upgrade — I)*:
- `evidence.correlation.cluster_detected` — new cluster found
- `evidence.correlation.strength_degraded` — finding dropped below 0.4 threshold
- `evidence.correlation.under_evidenced` — finding has 0 links

Downstream consumers (alerting, drift engine, auto-remediation) react without polling.

---

## Commit 4 — Longitudinal Graph Updater

**File:** `services/correlation/longitudinal.py` *(Moat upgrade — D/S)*

```python
def update_longitudinal_graph(db, tenant_id, engagement_id, clusters, strength_scores) -> None
    # Called at end of run_full_correlation()
    # For each finding in completed engagement:
    #   Compute canonical_finding_key = SHA-256(domain + control_id + finding_type)
    #   Upsert evidence_longitudinal_nodes (increment recurrence_count)
    #   Update avg_strength_score_at_detection, last_cluster_type, last_regulatory_citations
    # For each co-occurring finding pair in shared/systemic clusters:
    #   Upsert evidence_longitudinal_edges (increment observation_count)

def compute_reassessment_delta(db, tenant_id, prev_engagement_id, curr_engagement_id) -> ReassessmentDelta
    # Compares cluster sets between engagements
    # Returns: resolved_clusters, regressed_clusters, new_clusters, held_clusters
    # resolved: canonical_finding_key in prev, not in curr
    # regressed: remediation_held=True in prev, recurred in curr
    # held: remediation confirmed, not in curr
    # Updates remediation_held_count, regression_count on longitudinal_nodes
```

After 5 engagements: FrostGate knows which finding types co-occur in community banks. After 50: sector norms. After 200: recurrence prediction. No competitor can replicate this without the same client base.

---

## Commit 5 — Remediation Confidence Integration

**File:** `services/correlation/remediation_confidence.py`

```python
def compute_remediation_confidence(db, finding_id, engagement_id, tenant_id) -> RemediationConfidence
    # Combines: evidence_strength_score + cascade_impact + cluster membership
    # Output:
    #   confidence_level: low/medium/high
    #   rationale: [plain-language factors]
    #   recommended_action: fix_first | fix_with_cluster | needs_more_evidence | low_priority
```

**Integration:** `services/field_assessment/remediation.py` — add `correlation_confidence` as 10% additive weight to existing priority score. Graceful if correlation not yet run (factor omitted, not error).

---

## Commit 6 — External Evidence Ingestion Protocol

**File:** `api/external_evidence.py` *(Moat upgrade — I)*

```
POST /engagements/{engagement_id}/external-evidence
     require_permission("evidence:write")
     Accepts: source_type, source_name, source_reference, evidence_payload, linked_finding_ids
     Validates payload against source_type schema
     Stores in external_evidence_submissions
     Queues for correlation engine inclusion on next run

GET  /engagements/{engagement_id}/external-evidence
     require_permission("evidence:read")
     Returns paginated list with review_status
```

Pen test firms, audit firms, regulatory examiners can push evidence into FrostGate via API. FrostGate becomes the system of record for *all* evidence — not just what it collected. This is the architecture that enables MSSP partnerships and Big 4 audit firm integration.

---

## Commit 7 — Async Execution via DurableJobService

**File:** `api/correlation.py`

`POST .../correlation/run` creates a `DurableJob` (existing `DurableJobService` from PR fix 50) and returns `202 Accepted` with `job_id`. Engine runs async with retry/dead-letter semantics.

Large engagements (50+ findings, 500+ evidence links) need graph traversal time that will exceed request timeouts in synchronous mode.

```
POST /engagements/{engagement_id}/correlation/run           → 202, job_id
GET  /engagements/{engagement_id}/correlation/status        → job status
GET  /engagements/{engagement_id}/correlation/clusters      → require_permission("evidence:read")
GET  /engagements/{engagement_id}/correlation/clusters/{id}
GET  /engagements/{engagement_id}/correlation/findings/{finding_id}/strength
GET  /engagements/{engagement_id}/correlation/findings/{finding_id}/cascade
GET  /engagements/{engagement_id}/correlation/summary
GET  /engagements/{engagement_id}/correlation/report
GET  /engagements/{engagement_id}/correlation/reassessment-delta?prev_engagement_id=...
```

All routes: `engagement_id` validated against actor's `tenant_id`. Not-yet-run state handled gracefully (`correlation_not_run: true`, not 500).

---

## Commit 8 — Regulatory Evidence Mapping

**File:** `services/correlation/regulatory_mapping.py` *(Moat upgrade — R)*

```python
REGULATORY_CITATION_MAP: dict[str, list[Citation]] = {
    "mfa_gap": [
        Citation("HIPAA", "§164.312(d)", "Person or entity authentication"),
        Citation("NIST_AI_RMF", "GOVERN 1.2", "Policies maintained for AI risk"),
        Citation("SOC2", "CC6.1", "Logical access controls"),
    ],
    "admin_consent_scope": [...],
    "shadow_ai": [...],
    # ... all finding types mapped
}

def attach_regulatory_citations(clusters: list[CorrelationCluster]) -> list[CorrelationCluster]
    # Maps cluster's pattern_label / finding types to regulatory citations
    # Stored in evidence_correlation_clusters.regulatory_citations
```

An auditor reviewing a SOC 2 filters "show me all clusters satisfying CC6.1." FrostGate becomes the evidence management system for the audit itself. At that point the client cannot migrate to a new vendor without regenerating all their audit evidence.

---

## Commit 9 — Console UI

**Files:**
- `apps/console/components/correlation/CorrelationPanel.tsx` — 5-tab panel
- `apps/console/components/correlation/EvidenceStrengthBadge.tsx` — inline badge in `FindingCard`
- `apps/console/components/correlation/ClusterCard.tsx`
- `apps/console/components/correlation/CascadeImpactTree.tsx`
- `apps/console/lib/correlationApi.ts`

**Tabs:** Clusters · Evidence Strength · Cascade Map · Systemic Patterns · Run Correlation

**Existing UI integration:**
- `FindingCard`: `EvidenceStrengthBadge` next to severity chip
- Remediation roadmap panel: `correlation_confidence` indicator next to priority score
- Report viewer: correlation summary section when bundle has correlation component

---

## Commit 10 — Tests + Docs

| File | Series | Count |
|------|--------|-------|
| `tests/test_correlation_engine.py` | C/S/R/I/A/E/V | 35+ |
| `tests/test_correlation_routes.py` | route integration, auth, not-run state | 20+ |

- `docs/architecture/evidence_correlation_engine.md`
- `ROADMAP.md` — ECE row added to Phase 3 table

---

## ECE Success Gate

```
[ ] migration 0100 replays cleanly
[ ] run_full_correlation produces deterministic cluster_key
[ ] longitudinal_nodes updated after each completed engagement
[ ] reassessment_delta correctly identifies resolved/regressed/new
[ ] feature_vector_json stored on every cluster
[ ] regulatory_citations populated for known finding types
[ ] external evidence ingestion accepted and queued
[ ] NATS events emitted on cluster_detected / strength_degraded / under_evidenced
[ ] async job via DurableJobService, 202 response
[ ] tenant isolation enforced (no cross-tenant reads)
[ ] remediation priority score includes correlation_confidence
[ ] verification bundle includes evidence_strength component
[ ] all tests pass
[ ] ROADMAP.md updated
```

---

---

# PR7A — Commercial Event Ledger

**Depends on:** PR6 (RBAC scopes), ECE (optional but cleaner after ECE)  
**Blocks:** PR7B, PR7C, PR7D  
**Migration:** 0101

---

## Mission

Every billable, auditable, and analytically significant action in the system emits a commercial event. The ledger is append-only, immutable, hash-chained, and multi-dimensional. The event is a fact. The price is a policy (PR7B). The chargeback is an analysis (PR7C). The invoice is a rendering (PR7D).

---

## Commit 1 — Data Model (migration 0101)

**File:** `api/db_models_commercial.py`

**`commercial_event_schema_registry`** *(Moat upgrade — future-facing)*
```
id, event_type (varchar 128, unique), display_name,
description, unit_default, attribution_fields (JSON),
version, deprecated_at, created_at
```
New event types registered via admin API. Engine validates against registry. Adding `agent_decision_logged` or `rag_query_executed` = one INSERT, no code deploy.

**`commercial_events`**
```
id, tenant_id, event_class (commercial/consumption/revenue),
event_type (validated against schema_registry),
occurred_at (indexed),

— Attribution —
user_id, membership_id, workspace_id, agent_id, connector_id,
engagement_id, finding_id, report_id,

— Chargeback dimensions (for PR7C) —
department, cost_center, matter_number, project_code, business_unit,

— Quantity —
quantity (decimal), unit,

— Benchmark (Moat upgrade — N) —
sector (varchar 64),
benchmark_consent (bool default false),

— Reseller (Moat upgrade — I) —
reseller_tenant_id (varchar 128, nullable),

— Metadata —
source_service, metadata_json,

— Immutability —
previous_hash, event_hash, created_at

Append-only — UPDATE/DELETE triggers (governance_decisions pattern)
```

**`consumption_event_details`**
```
id, commercial_event_id FK,
model_id, input_tokens, output_tokens, total_tokens,
duration_seconds, memory_mb, cpu_units, created_at
```

**`revenue_event_details`**
```
id, commercial_event_id FK,
catalog_id, rule_id FK, rule_version, rule_snapshot_json,  ← Moat upgrade (S)
rate_key, unit_price, quantity, subtotal, currency (ISO 4217),
billing_period_start, billing_period_end,
invoice_id (nullable, FK added in PR7D),
calculated_by (service + git sha),                          ← Moat upgrade (S)
created_at
```

`rule_snapshot_json` stores the exact pricing rule config at calculation time. Customer disputes a charge 6 months from now — you replay the exact calculation with the exact rule that was active.

---

## Commit 2 — Commercial Event Service

**File:** `api/commercial/ledger.py`

```python
emit_commercial_event(db, tenant_id, event_type, attribution, quantity, unit, metadata) -> CommercialEvent
emit_consumption_event(db, commercial_event_id, model_id, tokens, duration) -> ConsumptionEventDetail
get_event_ledger(db, tenant_id, filters) -> Page[CommercialEventRow]
get_ledger_summary(db, tenant_id, period) -> LedgerSummary
get_sector_usage_benchmarks(db, sector, metric) -> BenchmarkResult  ← Moat upgrade (N)
```

`emit_commercial_event` is fire-and-forget from callers — if ledger write fails, logs warning but does not fail the originating request.

**`get_sector_usage_benchmarks`**: queries only `benchmark_consent=true` rows. Returns p25/p50/p75 for metric across sector. Never returns tenant-identifiable data. After 50 clients this is real data. After 200 it is a defensible product.

**Integration points** (emit at existing callsites):
- `POST /engagements` → `assessment_started`
- Report finalization → `report_generated`
- `ai_query_log` write (PR36) → `ai_query` with token counts
- Connector scan job start → `connector_run`
- Report PDF export → `report_export`

---

## Commit 3 — NATS Event Bus Integration

*(Moat upgrade — I)*

Every `emit_commercial_event` call publishes to NATS JetStream subject `commercial.event.created` with event class, type, tenant_id, event_id. No PII in the event.

Downstream consumers (PR7B rating engine, alerting, benchmark aggregator) subscribe — no polling loops.

---

## Commit 4 — Admin + Reseller Routes

**File:** `api/admin_commercial.py`

```
GET  /admin/commercial/tenants/{tenant_id}/events
GET  /admin/commercial/tenants/{tenant_id}/summary
GET  /admin/commercial/tenants/{tenant_id}/benchmarks?sector=community_bank&metric=connector_runs_per_engagement
GET  /admin/commercial/resellers/{reseller_tenant_id}/portfolio-summary   ← Moat upgrade (I)
```

**Portfolio summary** — aggregated across managed tenants: event counts by type, revenue by tenant, chargeback rollup. Enables MSSP channel partnerships without custom billing code.

---

## Commit 5 — Tests + Docs

- `tests/test_commercial_ledger.py` — hash chain, tenant isolation, immutability trigger, attribution dimensions, benchmark query excludes non-consenting tenants
- `ROADMAP.md` updated

---

---

# PR7B — Rating Engine

**Depends on:** PR7A (events to rate)  
**Blocks:** PR7C, PR7D  
**Migration:** 0102

---

## Mission

Transform commercial events into revenue values. The event is a fact. The pricing rule is a policy. They are always separate. A rule change does not alter historical events.

---

## Commit 1 — Data Model (migration 0102)

**File:** `api/db_models_commercial.py` (extend)

**`pricing_catalogs`**
```
id, tenant_id (nullable = global), catalog_key, display_name,
effective_from, effective_to (nullable),
is_active, is_system, version, created_at, updated_at
```

**`pricing_rules`**
```
id, catalog_id FK, rule_key, display_name,
pricing_model (fixed_fee/hourly/consumption/tiered/subscription/outcome_based),
applies_to_event_type,
fixed_fee_config (JSON),
hourly_config (JSON),
consumption_config (JSON),
tiered_config (JSON),
subscription_config (JSON),
outcome_config (JSON),     ← Moat upgrade (D)
priority (lower = evaluated first),
is_active, created_at, updated_at
```

**`credit_ledger`** *(Moat upgrade — S)*
```
id, tenant_id, credit_type (prepaid/promotional/adjustment),
amount_cents, currency, source_invoice_id FK (nullable),
applied_at, expires_at, created_at
```

**`credit_applications`** *(Moat upgrade — S)*
```
id, tenant_id, credit_ledger_id FK, revenue_event_detail_id FK,
amount_applied_cents, created_at
```

---

## Seeded Global Pricing Catalog

| Rule key | Model | Config |
|----------|-------|--------|
| quick_assessment | fixed_fee | $999 |
| extended_assessment | fixed_fee | $7,500 |
| ai_workspace_tokens | consumption | $0.002/token |
| remediation_hourly | hourly | $150/hr |
| connector_tier_1 | tiered | 0–10 free, 11–50 $10/run, 51+ $7/run |
| intelligence_subscription | subscription | $5,000/month |
| control_subscription | subscription | $7,500/month |
| findings_remediated_outcome | outcome_based | base $500 + $150/finding resolved, cap $5,000 | ← Moat upgrade |

---

## Commit 2 — Rating Engine Service

**File:** `api/commercial/rating.py`

```python
def rate_event(db, commercial_event) -> RevenueEventDetail | None
    # Resolution order: tenant-specific active rule → global active rule → unrated (not error)
    # Checks credit_ledger before writing revenue_event_detail
    # Stores rule_version + rule_snapshot_json + calculated_by on every rated event
    
def rate_period(db, tenant_id, period_start, period_end) -> RatingSummary
    # Batch rates all unrated commercial events in period
    
def get_pricing_catalog(db, tenant_id) -> list[PricingRule]
    # Tenant-specific overrides + global fallback
```

**Outcome-based pricing** requires verified remediation data from `services/field_assessment/remediation.py`. Only applicable when finding has `remediated_at` set by QA-approved evidence. Cannot be gamed by self-reporting — evidence chain is the authority.

**Credit application:** before writing `revenue_event_detail`, check tenant's `credit_ledger` for available balance. Apply credits first, write `credit_application`, then write net revenue amount.

**NATS subscription:** rating engine subscribes to `commercial.event.created` and rates new events in near-real-time. No polling.

---

## Commit 3 — Admin Routes

```
GET  /admin/commercial/tenants/{tenant_id}/pricing-catalog
POST /admin/commercial/tenants/{tenant_id}/rate-period
GET  /admin/commercial/tenants/{tenant_id}/revenue-summary
POST /admin/commercial/tenants/{tenant_id}/credits          ← Moat upgrade (S)
GET  /admin/commercial/tenants/{tenant_id}/credits
```

---

## Commit 4 — Tests + Docs

- `tests/test_rating_engine.py` — rule resolution order, all 6 pricing models, outcome-based with evidence verification, credit application, pricing audit trail (rule_snapshot_json matches rule at time of calculation), dispute replay test
- `ROADMAP.md` updated

---

---

# PR7C — Chargeback & Analytics

**Depends on:** PR7B (rated events)  
**Blocks:** nothing hard; PR7D is independent  
**Migration:** none (uses existing tables)

---

## Mission

Answer: where did revenue come from, where did costs come from, what are the margins, and what is forecast. The chargeback model uses attribution dimensions already on `commercial_events` — no new tables needed for core chargeback.

---

## Commit 1 — Chargeback + Analytics Service

**File:** `api/commercial/chargeback.py`

```python
def get_chargeback_report(db, tenant_id, period, group_by) -> ChargebackReport
    # group_by: department | cost_center | matter_number | project_code | business_unit
    # Returns: dimension_value → {event_count, total_revenue, total_cost, margin}

def get_compliance_cost_allocation(db, tenant_id, period) -> ComplianceCostReport  ← Moat upgrade (R)
    # Groups chargeback by regulatory framework (HIPAA/SOC2/NIST/CMMC)
    # Derived from engagement assessment_type + commercial event engagement_id
    # Output per framework: event_count, total_cost, finding_count, remediation_cost
    # CFOs and Legal show boards exactly what HIPAA compliance costs vs SOC 2

def get_margin_report(db, tenant_id, period) -> MarginReport
    # Revenue (revenue_event_details) vs Cost (consumption_event_details × model pricing)
    # Gross margin per dimension

def get_forecast(db, tenant_id, horizon_days) -> ForecastReport
    # Linear extrapolation from 90-day rolling average
    # Confidence bands based on historical variance
    # Labeled "projection" — not a financial guarantee

def get_roi_summary(db, tenant_id) -> ROISummary  ← Moat upgrade (S)
    # spend_to_date: total FrostGate charges
    # findings_remediated: from remediation tracking
    # estimated_breach_cost_avoided: industry-standard formula (IBM Cost of Data Breach avg × NIST score delta)
    # estimated_fine_risk_reduced: HIPAA/GDPR fine exposure from regulatory flag coverage
    # roi_ratio: avoided_cost / spend
    # Everything labeled "estimated" with methodology disclosure
```

---

## Commit 2 — Admin Routes

```
GET /admin/commercial/tenants/{tenant_id}/chargeback
    ?group_by=department&period_start=...&period_end=...

GET /admin/commercial/tenants/{tenant_id}/compliance-cost     ← Moat upgrade (R)

GET /admin/commercial/tenants/{tenant_id}/margin

GET /admin/commercial/tenants/{tenant_id}/forecast
    ?horizon_days=30

GET /admin/commercial/tenants/{tenant_id}/roi-summary         ← Moat upgrade (S)
```

---

## Commit 3 — Console Analytics Panel

**Files:**
- `apps/console/components/commercial/ChargebackPanel.tsx`
- `apps/console/components/commercial/ComplianceCostPanel.tsx`
- `apps/console/components/commercial/ROISummaryCard.tsx`

**Chargeback panel:** Recharts bar chart, dimension switcher, period selector, margin summary card, forecast trend line (labeled "projection").

**Compliance cost panel:** framework rows (HIPAA / SOC 2 / NIST AI RMF / CMMC), cost per framework, finding count, remediation cost. Finance teams justify AI governance spend to boards.

**ROI card:** spend vs estimated avoided cost, roi_ratio prominent. All methodology disclosures inline. Primary renewal conversation tool.

All data server-fetched. No client-side aggregation.

---

## Commit 4 — Tests + Docs

- `tests/test_chargeback.py` — dimension grouping, framework cost allocation, margin calculation, forecast confidence bands, ROI formula
- `ROADMAP.md` updated

---

---

# PR7D — Invoicing

**Depends on:** PR7B (rated events), PR7C (optional for line item labels)  
**Blocks:** nothing  
**Migration:** 0103

---

## Mission

Render rated events into invoices. Push invoices to Stripe, QuickBooks, and Xero. Make every line item traceable to the engagement or action that generated it.

---

## Commit 1 — Data Model (migration 0103)

**File:** `api/db_models_commercial.py` (extend)

**`invoices`**
```
id, tenant_id,
invoice_number (tenant-scoped sequential, formatted FG-{year}-{seq}),
status (draft/finalized/sent/paid/void),
billing_period_start, billing_period_end,
subtotal, tax_amount, total, currency,
stripe_invoice_id (nullable), quickbooks_invoice_id (nullable), xero_invoice_id (nullable),
issued_at, due_at, paid_at, void_at,
created_at, updated_at
```

**`invoice_line_items`**
```
id, invoice_id FK,
commercial_event_id FK (nullable — manual lines have no event),
description,
regulatory_framework (nullable),   ← Moat upgrade (R) — line item shows which compliance framework
quantity, unit_price, subtotal, currency, created_at
```

**Back-reference:** `revenue_event_details.invoice_id` FK populated when line item is created.

---

## Commit 2 — Invoice Service

**File:** `api/commercial/invoicing.py`

```python
def generate_invoice(db, tenant_id, period_start, period_end) -> Invoice
    # 1. rate_period() — rates any unrated events
    # 2. Create invoice (status=draft)
    # 3. Create invoice_line_items from revenue_event_details
    #    — each line item gets regulatory_framework from engagement.assessment_type
    # 4. Apply available credits (credit_ledger)
    # 5. Return draft invoice

def finalize_invoice(db, invoice_id, tenant_id) -> Invoice
    # draft → finalized; no further line item changes; DB trigger enforces

def export_invoice_pdf(db, invoice_id, tenant_id) -> bytes
    # reportlab PDF matching Executive PDF export style
    # Line items show engagement name, connector runs, assessment type
    # Regulatory allocation section: what percentage maps to HIPAA vs SOC 2
    # Methodology disclosure for any estimated amounts

def export_invoice_csv(db, invoice_id, tenant_id) -> str
```

**Accounting provider protocol:**

```python
class AccountingProvider(Protocol):
    def push_invoice(self, invoice: Invoice) -> str: ...   # returns external_id
    def sync_status(self, external_id: str) -> str: ...    # returns current status

# Implementations:
# api/commercial/stripe_invoicing.py
# api/commercial/quickbooks.py
# api/commercial/xero.py
# Activated via INVOICE_ACCOUNTING_PROVIDER env var: stripe | quickbooks | xero
```

---

## Commit 3 — Admin Routes

```
POST /admin/commercial/tenants/{tenant_id}/invoices/generate
     body: {period_start, period_end}

GET  /admin/commercial/tenants/{tenant_id}/invoices
GET  /admin/commercial/tenants/{tenant_id}/invoices/{invoice_id}

POST /admin/commercial/tenants/{tenant_id}/invoices/{invoice_id}/finalize
POST /admin/commercial/tenants/{tenant_id}/invoices/{invoice_id}/push-to-stripe
POST /admin/commercial/tenants/{tenant_id}/invoices/{invoice_id}/push-to-accounting

GET  /admin/commercial/tenants/{tenant_id}/invoices/{invoice_id}/export/pdf
GET  /admin/commercial/tenants/{tenant_id}/invoices/{invoice_id}/export/csv
```

---

## Commit 4 — Tests + Docs

- `tests/test_invoicing.py` — generation, finalization immutability, credit application, PDF export, Stripe push, accounting provider protocol contract
- `ROADMAP.md` updated

---

---

# Full File Map

```
PR6 — RBAC
api/db_models_rbac.py
api/identity/rbac_policy.py
api/identity/rbac_audit.py
api/identity/rbac_seed.py
api/admin_rbac.py
api/auth_dispatch.py                      (modify — wire materialize_session_scopes)
api/admin_identity.py                     (modify — invitation role delegation)
api/db_migrations.py                      (modify — 0099)
api/main.py                               (modify — register routers)
apps/console/app/governance/rbac/page.tsx
apps/console/components/rbac/*.tsx        (5 components)
apps/console/lib/rbacApi.ts
tests/test_rbac_policy.py
tests/test_rbac_postgres_hardening.py
tests/test_rbac_admin_routes.py
docs/architecture/rbac_governance.md

ECE — Evidence Correlation Engine
api/db_models_correlation.py
api/correlation.py
api/external_evidence.py
api/db_migrations.py                      (modify — 0100)
api/main.py                               (modify)
services/correlation/__init__.py
services/correlation/strength.py
services/correlation/engine.py
services/correlation/longitudinal.py
services/correlation/remediation_confidence.py
services/correlation/regulatory_mapping.py
services/field_assessment/remediation.py  (modify — add correlation_confidence factor)
services/verification_bundle/bundle_service.py  (modify — add evidence_strength component)
apps/console/components/correlation/*.tsx (5 components)
apps/console/lib/correlationApi.ts
tests/test_correlation_engine.py
tests/test_correlation_routes.py
docs/architecture/evidence_correlation_engine.md

PR7A — Commercial Event Ledger
api/db_models_commercial.py               (new — ledger, schema_registry tables)
api/commercial/__init__.py
api/commercial/event_types.py
api/commercial/ledger.py
api/admin_commercial.py                   (new — partial)
api/db_migrations.py                      (modify — 0101)
api/main.py                               (modify)
tests/test_commercial_ledger.py

PR7B — Rating Engine
api/db_models_commercial.py              (extend — pricing, credit tables)
api/commercial/rating.py
api/commercial/credit.py
api/admin_commercial.py                  (extend — rating + credit routes)
api/db_migrations.py                     (modify — 0102)
tests/test_rating_engine.py

PR7C — Chargeback & Analytics
api/commercial/chargeback.py
api/admin_commercial.py                  (extend — analytics routes)
apps/console/components/commercial/ChargebackPanel.tsx
apps/console/components/commercial/ComplianceCostPanel.tsx
apps/console/components/commercial/ROISummaryCard.tsx
tests/test_chargeback.py

PR7D — Invoicing
api/db_models_commercial.py              (extend — invoice tables)
api/commercial/invoicing.py
api/commercial/stripe_invoicing.py
api/commercial/quickbooks.py
api/commercial/xero.py
api/admin_commercial.py                  (extend — invoice routes)
api/db_migrations.py                     (modify — 0103)
tests/test_invoicing.py
```

---

# Moat Upgrade Index

| Upgrade | PR | Moat | Why it matters |
|---------|----|------|----------------|
| OPA-backed delegation policy | PR6 | I/R | Machine-readable, auditable, tier-customizable |
| RBAC machine-readable export | PR6 | R/S | Embeds in client SOC 2 evidence packages |
| Role usage / never-exercised drift | PR6 | D | Surfaces dormant privilege before it becomes a breach |
| Identity type registry as DB table | PR6 | future | Add AGI/swarm identity types with one INSERT |
| Delegation lineage chain | PR6 | S/R | Regulator-ready 3-hop assignment provenance |
| Longitudinal evidence graph | ECE | D/S | Core compounding data asset |
| Reassessment delta | ECE | D/S | Shows what held and what regressed across engagements |
| Sector benchmark consent flag | ECE/PR7A | N | Collect now; benchmark product ships later |
| ML-ready feature vectors | ECE | D | Cannot reconstruct retroactively |
| NATS event emission | ECE/PR7A | I | Reactive downstream consumers without polling |
| External evidence ingestion | ECE | I | Makes FrostGate system of record for ALL evidence |
| Regulatory evidence mapping | ECE | R | Embeds in SOC 2 / HIPAA audit cycles |
| Event schema registry | PR7A | future | New event types without code deploys |
| NATS bus for ledger events | PR7A | I | Real-time event streaming for downstream consumers |
| Reseller portfolio view | PR7A | I | MSSP channel partnerships from day one |
| Outcome-based pricing | PR7B | D | Only possible because evidence chain proves remediation |
| Pricing audit trail / rule snapshot | PR7B | S | Dispute resolution, 6-month replay |
| Prepaid credit ledger | PR7B | S | 12-month switching cost at contract time |
| Compliance cost allocation | PR7C | R | Finance justifies spend by regulatory framework |
| ROI calculator | PR7C | S | Board-level renewal justification |
| Evidence-backed invoice line items | PR7D | R/S | Client can trace every charge to a specific engagement |

---

# Compounding Loop

```
Engagement completes
  ├─ Commercial events emitted                    (PR7A)
  ├─ Evidence strength computed                   (ECE)
  ├─ Correlation clusters with regulatory cites   (ECE)
  ├─ Feature vectors stored                       (ECE — for future ML)
  ├─ Longitudinal graph updated                   (ECE)
  ├─ RBAC audit exported to compliance package    (PR6)
  ├─ Invoice generated with evidence-backed lines (PR7D)
  ├─ Chargeback shows regulatory cost allocation  (PR7C)
  ├─ ROI calculator updated                       (PR7C)
  └─ Sector benchmark data point added            (PR7A — if consent)

Next reassessment (same client):
  ├─ Delta shows what held, what regressed
  ├─ Sector benchmark: "similar banks improved MFA coverage 40%"
  └─ Outcome-based pricing rewards remediation velocity

After 50 clients:
  ├─ Sector benchmarks are real, defensible data
  ├─ Feature vectors enable recurrence prediction
  ├─ Regulatory citation mapping validated against real audits
  └─ External evidence ingestion makes FrostGate the audit hub

At that point:
  A competitor copying the UI has nothing.
  They don't have the data, the audit chain,
  the client evidence packages, or the benchmark corpus.
```

---

*Last updated: 2026-06-10*
