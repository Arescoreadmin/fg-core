# Identity Governance Foundation

The `api/identity_governance/` package sits on top of the Identity Authority
(`api/identity_authority/`) and provides the deterministic building blocks
for identity governance across FrostGate.

## What it provides

- **Lifecycle state machine** — governed transitions between subject states
  (`CREATED -> INVITED -> ACCEPTED -> ACTIVE -> SUSPENDED -> DISABLED ->
  ARCHIVED -> DELETED`).
- **Device trust registry** — deterministic risk scoring per device state.
- **Continuous session evaluation** — six-step pipeline that runs on every
  request.
- **Conditional access policy engine** — deterministic JSON policies with
  strict priority ordering.
- **Identity event timeline** — hash-chained, tenant-scoped events.
- **Identity graph** — deterministic snapshot with SHA-256 fingerprint.
- **Delegated administration** — boundary checks preventing escalation.
- **Break-glass workflow** — reason-required, approval-gated, self-expiring
  emergency access (max 4 hours).
- **Risk engine** — deterministic 0.0-1.0 scoring with explainable factors.
- **Identity digital twin** — deterministic tenant-scoped snapshot exporter.

## Lifecycle states

| State       | Can auth? | Valid successors                             |
|-------------|-----------|----------------------------------------------|
| `CREATED`   | no        | `INVITED`, `ACTIVE`, `DISABLED`              |
| `INVITED`   | no        | `ACCEPTED`, `DISABLED`, `ARCHIVED`           |
| `ACCEPTED`  | no        | `ACTIVE`, `SUSPENDED`, `DISABLED`            |
| `ACTIVE`    | yes       | `SUSPENDED`, `DISABLED`, `ARCHIVED`          |
| `SUSPENDED` | no        | `ACTIVE`, `DISABLED`, `ARCHIVED`             |
| `DISABLED`  | no        | `ARCHIVED`, `DELETED`                        |
| `ARCHIVED`  | no        | `DELETED`                                    |
| `DELETED`   | no        | (terminal)                                   |

Only `ACTIVE` subjects can authenticate. `IdentityLifecycleManager.transition`
enforces the transition matrix at every state change and requires a
non-empty `reason` and `actor`.

## Device states

See [`DEVICE_TRUST.md`](DEVICE_TRUST.md).

## Session evaluation flow

```
+------------------+   +----------------+   +----------------------+
| identity_state   | > | session_expiry | > | session_revocation   |
+------------------+   +----------------+   +----------------------+
             |                                                    |
             v                                                    v
+------------------+   +----------------+   +----------------------+
| device_state     | > |     mfa        | > |       risk           |
+------------------+   +----------------+   +----------------------+
```

The pipeline stops at the first non-`ALLOW` decision. All checks are pure
functions of the input `SessionEvaluationContext`, so evaluation is fully
deterministic.

Decisions: `ALLOW`, `DENY`, `STEP_UP_REQUIRED`, `REVOKE_SESSION`.

## Policy engine

Policies are `PolicyRecord` instances containing:

- `priority` (lower value = higher priority)
- `conditions` (all must match)
- `on_match` decision: `ALLOW`, `DENY`, `STEP_UP_REQUIRED`,
  `JUSTIFICATION_REQUIRED`, `APPROVAL_REQUIRED`

Ordering: policies are sorted `priority ASC, decision_strength DESC,
policy_id ASC`. **Deny overrides allow at the same priority.** No matching
policy => default `ALLOW`.

Supported condition kinds:

- `requires_mfa`
- `requires_role` (params: `role`)
- `requires_capability` (params: `capability`)
- `deny_suspended`
- `requires_break_glass_reason`
- `ip_allowlist` (params: `cidrs` — comma-separated exact IPs)
- `time_window` (params: `start_hour_utc`, `end_hour_utc`)

Unknown condition kinds never match.

## Persistence

Phase 1 is entirely in memory. Migration
`migrations/postgres/0148_identity_governance.sql` provisions the target
persistence tables so Phase 2 can add adapters without a schema change.

## Determinism guarantee

Every component in this package satisfies:

> Given the same inputs, always return the same outputs.

Timestamps are the sole non-deterministic field, and are excluded from the
graph and digital-twin fingerprints so identical structural content always
produces identical fingerprints.
