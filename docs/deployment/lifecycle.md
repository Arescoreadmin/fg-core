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

---

## Approval gate

When `approval_required=true` on a deployment record, the `pending → deploying` transition is blocked until `approval_granted_by` is populated via `POST /control-plane/deployments/{id}/approval`.

| Approval action | `to_state` set | Effect |
|---|---|---|
| `granted` | — | Sets `approval_granted_by`; deployment may now proceed to `deploying` |
| `denied` | `failed` | Terminates the deployment; `rolled_back` event emitted |

Approval is evaluated at the `deploying` transition, not at deployment creation. An operator may grant or deny approval any time between `pending` and the attempted `deploying` transition.

---

## Rollback lineage

A rollback deployment links back to the deployment it replaced via `rollback_from_id`. This forms a linked list:

```
deploy-003 → rollback_from_id: deploy-002
deploy-002 → rollback_from_id: deploy-001
deploy-001 → rollback_from_id: null
```

The `GET /control-plane/deployments/{id}/rollback-lineage` endpoint traverses this chain (up to 20 hops, cycle-safe) and returns the full history in order from most recent to root.

---

## Audit trail

Every mutation emits a `DeploymentEvent` record to the `deployment_events` table. This table is **append-only**: Postgres rules prevent UPDATE and DELETE. Events are also written to the structured audit log (`frostgate.deployment.audit`).

Event types: `created`, `state_transition`, `health_recorded`, `rollback_initiated`, `approval_requested`, `approval_granted`, `approval_denied`, `metadata_updated`.

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

## Operational assumptions

- Environments are long-lived; deployments are ephemeral per release.
- Do not delete environments. Set `lifecycle_state` to `decommissioned` instead.
- The `deployment_policy_json` field on environments is reserved for future policy enforcement; current store logic does not evaluate it.
- `artifact_hash` is informational; the store performs no integrity verification.
- Page size is capped at 200 on all list endpoints.
