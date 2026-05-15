# Tenant Provisioning Lifecycle — Operator Reference

## Organization Lifecycle Model

Each organization progresses through a deterministic lifecycle managed by the provisioning subsystem. Transitions are validated against an allowlist before any DB write.

### States

| Status | Meaning |
|--------|---------|
| `pending` | Org created, no provisioning workflow started |
| `provisioning` | Active provisioning workflow running |
| `active` | Fully provisioned and activated; tenant live |
| `suspended` | Temporarily disabled; reversible |
| `archived` | Permanently decommissioned (terminal) |
| `failed` | Provisioning failed; eligible for retry |

### Transition Table

| From | To | Trigger |
|------|----|---------|
| `pending` | `provisioning` | `POST /organizations/{id}/provision` |
| `pending` | `failed` | internal error during start |
| `provisioning` | `active` | `POST /organizations/{id}/activate` (atomic gate) |
| `provisioning` | `failed` | `POST /workflows/{id}/fail` |
| `active` | `suspended` | `POST /organizations/{id}/suspend` |
| `active` | `archived` | future operator action |
| `suspended` | `active` | future operator action |
| `suspended` | `archived` | future operator action |
| `failed` | `provisioning` | `POST /organizations/{id}/provision` (retry path) |
| `archived` | — | terminal, no outbound transitions |

---

## Provisioning Workflow Model

Each provisioning attempt creates a new `ProvisioningWorkflow` record. Retries create a new record rather than mutating the failed one (retry_count increments from the prior workflow).

### States

| State | Meaning |
|-------|---------|
| `pending` | Workflow created but not yet running |
| `running` | Provisioning steps executing |
| `completed` | All steps succeeded; org ready for activation |
| `failed` | Provisioning stopped; org in `failed` state |
| `cancelled` | Operator-cancelled before completion (terminal) |

### Transition Table

| From | To | Notes |
|------|----|-------|
| `pending` | `running` | workflow starts |
| `pending` | `cancelled` | operator cancels before start |
| `running` | `completed` | `POST /workflows/{id}/complete` |
| `running` | `failed` | `POST /workflows/{id}/fail` |
| `running` | `cancelled` | operator cancels in progress |
| `completed` | — | terminal |
| `failed` | — | terminal (start a new workflow via retry) |
| `cancelled` | — | terminal |

---

## Onboarding State Model

`onboarding_state` tracks the human-facing onboarding progress, independent of the provisioning workflow state.

| State | Meaning |
|-------|---------|
| `not_started` | Org created, no provisioning attempted |
| `in_progress` | Provisioning workflow running |
| `pending_activation` | Workflow completed; awaiting explicit activation |
| `completed` | Org activated; onboarding complete |
| `failed` | Provisioning failed; onboarding stalled |

---

## Tenant Activation Model

Activation is an **atomic gate** — all preconditions must pass before the org transitions to `active`. If any precondition fails, an `ActivationPreconditionFailed` error is raised and no state change occurs.

### Activation Preconditions

1. **Org lifecycle status must be `provisioning`** — only orgs actively in provisioning can be activated. An org in `pending`, `failed`, `suspended`, or `archived` state is blocked.
2. **Completed provisioning workflow required** — there must be at least one workflow record in `completed` state for this org. A running or failed workflow blocks activation.
3. **Onboarding state must be `pending_activation` or `completed`** — the onboarding state is advanced to `pending_activation` when the workflow completes. An org still in `in_progress` or `not_started` state is blocked.
4. **Compliance gate (future hook)** — currently always passes. Reserved for regulated tier enforcement.

On successful activation:
- `lifecycle_status` transitions to `active`
- `activated_at` is set to `now()`
- `onboarding_state` advances to `completed`
- A `tenant_activated` audit event is emitted

---

## Environment Assignment Model

An org's `env_assignment_id` links it to a `DeploymentEnvironment` record. Assignment is a standalone operation that does not change `lifecycle_status`:

```
POST /control-plane/provisioning/organizations/{org_id}/environment
{"env_assignment_id": "<env_id>"}
```

The `environment_assigned` audit event is emitted. Assignment may happen at any lifecycle stage. Assignment does not trigger activation.

---

## Idempotency Behavior

Both `create_organization` and `start_provisioning_workflow` accept an optional `idempotency_key`. If a request is replayed with the same key:

- The existing record is returned unchanged.
- No new audit event is emitted.
- The HTTP response is identical to the original.

**Idempotency keys are tenant-scoped.** The lookup filters by `(tenant_id, idempotency_key)` — keys are only de-duplicated within the same tenant context. Two tenants may use the same idempotency key string without collision. Platform-level records (`tenant_id = null`) have a separate global idempotency namespace.

`activate_organization` is also idempotent: if the org is already in `active` state, the call returns the current state immediately without re-emitting an audit event or mutating the record.

Concurrent duplicate requests will serialize — the second receives the result of the first.

---

## Deterministic Retry Behavior

Retrying a failed provisioning workflow does **not** mutate the failed workflow record. Instead:

1. The failed org is validated to be in `failed` state.
2. A new `ProvisioningWorkflow` record is created with `retry_count = prev_retry_count + 1` and `parent_provisioning_id` pointing to the most recent failed workflow.
3. The org transitions back to `provisioning`.
4. A `provisioning_started` audit event is emitted with the retry count in `details`.

`parent_provisioning_id` is the direct parent in the retry chain. To traverse the full lineage, walk `parent_provisioning_id` links from the current workflow back to the original attempt. The chain terminates when `parent_provisioning_id` is `null`.

This design preserves full history of all attempts and supports lineage auditing.

---

## Orchestration Boundary

The current implementation is **synchronous** — all provisioning steps complete within the HTTP request/response cycle. The data model is designed for future async compatibility:

- `current_step` field tracks in-progress step name for async polling.
- `orchestration_metadata_json` is reserved for async scheduler state.
- `workflow_state = running` is the quiescent state for an in-progress async workflow.
- Callers should not assume `running → completed` is synchronous in future releases.

---

## Audit Model (Event Hash Chain)

Every provisioning mutation emits a `ProvisioningAuditEvent` before returning. Events are append-only and form a tamper-evident SHA-256 hash chain per organization:

- `event_hash`: SHA-256 of `{event_id, organization_id, event_type, actor, timestamp, outcome, previous_event_hash}`.
- `previous_event_hash`: hash of the immediately preceding event for this org (null for the first event).
- Any tampering with a prior event invalidates all subsequent hashes.

Events are never updated or deleted (enforced at DB level via Postgres `NO UPDATE / NO DELETE` rules on `provisioning_audit_events`).

Event types:

| Event | Trigger |
|-------|---------|
| `organization_created` | `create_organization` |
| `provisioning_started` | `start_provisioning_workflow` / retry |
| `provisioning_completed` | `complete_provisioning_workflow` |
| `provisioning_failed` | `fail_provisioning_workflow` |
| `tenant_activated` | `activate_organization` |
| `tenant_suspended` | `suspend_organization` |
| `environment_assigned` | `assign_environment` |
| `org_status_changed` | `transition_org_status` |

---

## Visibility and Isolation Guarantees

- **Platform-level orgs** (`tenant_id = null`): visible to any operator with sufficient scope.
- **Tenant-linked orgs** (`tenant_id = <id>`): visible only to requests whose auth context matches the owning `tenant_id`. Cross-tenant access returns 404.
- Tenant resolution is always from auth context (`_tenant_from_auth(request)`), never from the request body.
- All list endpoints apply the same tenant filter: `tenant_id = <auth tenant> OR tenant_id IS NULL`.

---

## API Error Codes

| Code | HTTP | Meaning |
|------|------|---------|
| `PROV-API-001` | 404 | Organization not found |
| `PROV-API-002` | 404 | Workflow not found |
| `PROV-API-003` | 409 | Invalid lifecycle or workflow transition |
| `PROV-API-004` | 422 | Activation precondition(s) not met |
| `PROV-API-005` | 422 | Invalid input |
| `PROV-API-006` | 403 | Forbidden |
| `PROV-API-007` | 409 | Concurrent modification (optimistic lock failure) |
| `PROV-API-008` | 409 | Duplicate slug |
| `PROV-API-009` | 409 | Duplicate idempotency key |

---

## Compensation and Rollback Boundaries

This subsystem is **fail-safe, not compensating**. When a provisioning step fails, the system stops and marks the org `failed`; it does not attempt to undo side effects that may have occurred before the failure point (e.g., DNS records created, environment capacity reserved).

This is intentional for MVP governance infrastructure. Compensation is the responsibility of the operator based on the audit trail:

1. Inspect `GET /organizations/{id}/history` to identify what succeeded.
2. Manually undo external side effects (e.g., release reserved env capacity).
3. Call `POST /organizations/{id}/provision` to start a fresh retry workflow.

**Out of scope for this release:** saga-style compensation transactions, partial rollback of env assignment, or automated deprovision-on-failure. When these are introduced, the `VALID_ORG_TRANSITIONS` FSM and `_emit_event` hook provide the correct extension points.

---

## Future Extensions

The following capabilities are explicitly **out of scope** in this release but are acknowledged as required for enterprise-grade lifecycle management:

| Capability | Extension point |
|-----------|----------------|
| Environment capacity governance (saturation, quotas, regulated occupancy) | `assign_environment` + new `ProvisioningEnvironmentRecord` table |
| Dry-run / eligibility pre-check before provisioning | New `GET /organizations/{id}/activation-eligibility` endpoint calling `check_activation_preconditions` read-only |
| Async orchestration (step-by-step, external scheduler) | `current_step` + `orchestration_metadata_json` fields already reserved |
| Event sequence counter for strict ordering guarantees | `event_sequence INTEGER` column on `provisioning_audit_events` |
| Tenant offboarding / retention hold / legal preservation | New `offboarding_state` column + `legal_hold_at` timestamp; `archived` is the current terminal state |
| GDPR right-to-erasure / tenant purge governance | Purge policy table; `archived` orgs eligible only after retention period |
| Prometheus metrics | Same pattern as `services.deployment.metrics` — add counters at store layer |

The `archived` state is currently terminal with no additional semantics. It **must not** be treated as a purge trigger — data retention and deletion will be governed by a future policy layer.

---

## SLO and Observability Notes

- All mutations are logged via `frostgate.provisioning.audit` logger at INFO level.
- Structured log fields include `audit_domain`, `event_type`, `organization_id`, `actor`, `outcome`, `event_hash` — suitable for SIEM ingestion.
- No metrics are emitted by the provisioning subsystem in this release (future hook: add Prometheus counters at store layer similar to `services.deployment.metrics`).
- `state_version` increments monotonically on every org state change — usable for polling/change-detection by downstream consumers.
