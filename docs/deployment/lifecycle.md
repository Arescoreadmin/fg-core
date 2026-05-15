# Deployment Lifecycle Model

Reference for operators and integrators using the Deployment Manager (`/control-plane/deployments/`).

---

## Environment model

A **deployment environment** describes where a release lands. Environments are immutable descriptors — they are created once and their `env_type`, `region`, and `compliance_classification` never change.

| Field | Values | Notes |
|---|---|---|
| `env_type` | `local`, `dev`, `staging`, `production`, `tenant-dedicated`, `regulated` | Determines approval policy |
| `lifecycle_state` | `active`, `maintenance`, `decommissioned` | Deployments can only target `active` envs |
| `compliance_classification` | `standard`, `regulated`, `hipaa`, `fedramp`, `govcon` | Drives approval requirement |
| `tenant_id` | null or tenant ID | null = platform-level; non-null = tenant-dedicated, visible only to that tenant |

**Production-like environments** (`production`, `regulated`, `tenant-dedicated`) and **regulated classifications** (`hipaa`, `fedramp`, `govcon`) always require approval before a deployment can enter `deploying` state.

---

## Deployment states

```
pending
  ├─→ validating
  │     ├─→ deploying  (blocked until approval_granted_by is set on regulated envs)
  │     │     ├─→ healthy      (terminal-like; may degrade)
  │     │     ├─→ degraded
  │     │     └─→ failed       (terminal)
  │     └─→ failed
  ├─→ failed
  └─→ (no other transitions from pending)

healthy
  ├─→ degraded
  └─→ rolled_back    (terminal)

degraded
  ├─→ healthy
  ├─→ failed
  └─→ rolled_back
```

**Terminal states:** `failed`, `rolled_back`. No further transitions are permitted.

**`completed_at`** is set on first entry into `healthy`, `failed`, or `rolled_back`.

**`state_version`** increments by 1 on every state transition. The store enforces this with optimistic locking (`UPDATE WHERE state_version = expected_version`), so concurrent transitions on the same deployment return `DEPLOY-007 ConcurrentModificationError` rather than silently diverging.

---

## Approval gate

When `approval_required=true` on a deployment record, the `pending → deploying` transition is blocked until `approval_granted_by` is populated via `POST /control-plane/deployments/{id}/approval`.

| Approval action | `to_state` set | Effect |
|---|---|---|
| `granted` | — | Sets `approval_granted_by`, `approval_granted_at`, `approval_reason`, `approval_policy_version`; deployment may now proceed to `deploying` |
| `denied` | — | Stores `approval_reason` and `approval_policy_version`; does NOT set `approval_granted_by`; deployment remains blocked |

`approval_granted_at` timestamps the decision for SOX/HIPAA/GovCon evidence. `approval_policy_version` records which policy bundle was in force at the time of the decision — required for audit replay when policies are updated.

---

## Deployment spec snapshot

At creation, an optional `spec` block captures immutable deployment inputs:

| Field | Purpose |
|---|---|
| `image_digest` | SHA-256 of the container image or artifact bundle |
| `commit_sha` | Git commit SHA (40 or 64 hex chars) |
| `contract_hash` | SHA-256 of the active OpenAPI contract |
| `topology_hash` | SHA-256 of the topology descriptor |
| `policy_bundle_version` | Policy bundle version string |
| `migration_fingerprint` | Fingerprint of the migration set applied |

These fields are written once and never updated. They make rollback lineage authoritative: "rollback to v1.0.2" means "rollback to the exact image, contract, and migration set captured in that deployment's spec."

---

## Strategy governance

Deployment strategy is validated against environment type and compliance classification at creation time. The governance layer rejects forbidden combinations before any execution engine runs.

| Strategy | Forbidden env_types | Forbidden classifications |
|---|---|---|
| `direct` | `production`, `regulated` | `hipaa`, `fedramp`, `govcon` |
| `rolling` | none | none |
| `blue_green` | `local` | none |
| `canary` | `local` | `fedramp`, `govcon` |

Violations return `DEPLOY-009 StrategyGovernanceViolation` (HTTP 422).

---

## Classification policies

| Classification | Approval depth | Restricted strategies | Telemetry restricted | Export restricted |
|---|---|---|---|---|
| `standard` | 0 | none | no | no |
| `regulated` | 1 | `direct` | yes | no |
| `hipaa` | 1 | `direct` | yes | yes |
| `fedramp` | 2 | `direct`, `canary` | yes | yes |
| `govcon` | 2 | `direct`, `canary` | yes | yes |

`required_approval_depth` is a future hook for multi-stage approval workflows. Currently a single approval grants/denies. `telemetry_restricted` and `export_restricted` are flags that downstream systems (telemetry pipeline, artifact export) can check.

---

## Tamper-evident audit chain

Every `DeploymentEvent` carries two hash fields:

- `event_hash` — SHA-256 of canonical event fields: `event_id`, `deployment_id`, `event_type`, `actor`, `timestamp`, `from_state`, `to_state`, `previous_event_hash`
- `previous_event_hash` — `event_hash` of the prior event for this deployment

This forms a hash chain. If any historical event is modified, all subsequent `previous_event_hash` values become invalid, making tampering detectable without a separate signing service. Full cryptographic signing can be added later by wrapping `event_hash` with a KMS key.

---

## Rollback lineage

A rollback deployment links back to the deployment it replaced via `rollback_from_id`. This forms a linked list:

```
deploy-003 → rollback_from_id: deploy-002
deploy-002 → rollback_from_id: deploy-001
deploy-001 → rollback_from_id: null
```

The `GET /control-plane/deployments/{id}/rollback-lineage` endpoint traverses this chain (up to 20 hops, cycle-safe) and returns the full history in order from most recent to root. Each lineage entry includes the deployment's `spec` snapshot.

### Rollback safety constraints

The store enforces the following before allowing a `→ rolled_back` transition:

- The `rollback_from_id` target must exist
- The target must not be in `failed` state (rolling back to a known-broken deployment is prohibited)
- The target's `tenant_id` must match the current deployment's `tenant_id` (no cross-tenant rollbacks)

Violations return `DEPLOY-008 RollbackSafetyViolation` (HTTP 422).

---

## Health records

Health checks are recorded via `POST /control-plane/deployments/{id}/health`. Each record captures four independent probe results:

| Probe | Values |
|---|---|
| `readiness_result` | `pass`, `fail`, `skip`, `unknown` |
| `liveness_result` | `pass`, `fail`, `skip`, `unknown` |
| `smoke_test_result` | `pass`, `fail`, `skip`, `unknown` |
| `validation_result` | `pass`, `fail`, `skip`, `unknown` |

Health records are point-in-time snapshots. They do not automatically trigger state transitions — the caller is responsible for deciding whether to transition to `degraded` or `failed` based on results.

`expires_at` is an optional ISO 8601 timestamp for retention enforcement. Records past this timestamp may be archived or purged by the retention job. Recommended TTLs:

- CI smoke probes on short-lived deployments: 7 days
- Staging health checks: 30 days
- Production health records: 90 days (or per compliance policy)
- HIPAA/FedRAMP/GovCon: follow regulatory retention schedules (typically ≥7 years for audit records)

---

## Dry-run mode

Append `?dry_run=true` to any `POST /control-plane/deployments/{id}/transition` call. The response reports whether the transition is `allowed`, whether it is `blocked` (with reasons), whether `approval_required` is set, and whether `missing_approval_granted_by` would prevent execution. No state change, no event, no metric emission occurs.

---

## SLO metrics

The deployment store emits Prometheus metrics on every mutation:

| Metric | Type | Labels |
|---|---|---|
| `frostgate_deployment_transitions_total` | Counter | `strategy`, `env_type`, `from_state`, `to_state` |
| `frostgate_deployment_failures_total` | Counter | `strategy`, `env_type`, `compliance_classification` |
| `frostgate_deployment_rollback_total` | Counter | `strategy`, `env_type` |
| `frostgate_deployment_approval_decisions_total` | Counter | `decision` |
| `frostgate_deployment_duration_seconds` | Histogram | `strategy`, `env_type`, `terminal_state` |
| `frostgate_deployment_approval_wait_seconds` | Histogram | `decision` |
| `frostgate_deployment_health_probe_results_total` | Counter | `probe`, `result` |

---

## Tenant isolation

- Deployments and environments with `tenant_id=null` are **platform-level**: visible to any operator with `control-plane:read` scope.
- Deployments and environments with a non-null `tenant_id` are **tenant-dedicated**: list and get operations filter by the authenticated tenant's ID. Cross-tenant access returns 403.

---

## Required scopes

| Operation | Scope |
|---|---|
| List/get environments and deployments | `control-plane:read` |
| Create environments, deployments, health records | `control-plane:admin` |
| Transition state, record approval | `control-plane:admin` |

---

## Error codes

| Code | HTTP | Meaning |
|---|---|---|
| `DEPLOY-API-001` | 404 | Deployment not found |
| `DEPLOY-API-002` | 404 | Environment not found |
| `DEPLOY-API-003` | 409 | Invalid state transition |
| `DEPLOY-API-004` | 403 | Approval required before proceeding to deploying |
| `DEPLOY-API-005` | 422 | Invalid input |
| `DEPLOY-API-006` | 403 | Forbidden (tenant isolation violation) |
| `DEPLOY-API-007` | 409 | Concurrent modification — retry with fresh state_version |
| `DEPLOY-API-008` | 422 | Rollback safety violation |
| `DEPLOY-API-009` | 422 | Strategy governance violation |

---

## Operational assumptions

- Environments are long-lived; deployments are ephemeral per release.
- Do not delete environments. Set `lifecycle_state` to `decommissioned` instead.
- `deployment_policy_json` on environments is reserved for future policy enforcement; current store logic does not evaluate it.
- `artifact_hash` is informational; the store performs no integrity verification.
- Page size is capped at 200 on all list endpoints.
- `state_version` is opaque — do not store or compare it across deployments; it is only meaningful within a single deployment's lifecycle.
