# Identity Authorization Mapping (PR-01a.1)

This document is the authoritative reference for how the four authorization
axes — permissions, capabilities, policies, and ownership — combine to
produce a runtime decision, and how step-up, device trust, and risk feed
into that decision.

## The four axes

| Axis | Source of truth | What it answers | Where enforced |
|---|---|---|---|
| **Permission** | `ActorContext.permissions` from `ROLE_PERMISSIONS` | "Can this actor perform this operation type at all?" | `require_permission(*)` in every route |
| **Capability** | `AuthorizationContext.capabilities` from `IdentitySubscription` | "Is the operation licensed for this tenant's tier?" | Capability guards on premium features |
| **Policy** | `ConditionalAccessPolicyEngine` deterministic JSON policies | "Do runtime conditions (IP, hour, MFA, break-glass) allow this?" | Runtime policy evaluation |
| **Ownership** | Route-level checks against `tenant_id`, `membership_id`, and resource ownership fields | "Does this actor own the resource they are addressing?" | Route logic + query filters |

Each axis is a hard gate. Missing any of the four denies the request.

## Read vs write inheritance

- **Read inheritance:** viewers inherit no other role's writes. `assessor`
  and `compliance_reviewer` inherit `viewer` reads plus their own writes.
  `qa_reviewer` inherits `viewer` reads only — it never inherits `assessor`
  writes.
- **Write inheritance:** none. Every write permission (`.create`,
  `.approve`, `.close`, `.grant`, `.accept`) is explicitly granted to
  exactly the roles that hold it. `tenant_admin` deliberately does NOT
  inherit any compliance or QA write.
- **Cross-boundary promotion:** `governance.promote` is separate from all
  compliance-decision permissions. Only `tenant_admin` and `platform_admin`
  hold it.

SoD invariants (from `api/actor_context.py`):

- `tenant_admin` does not inherit `compliance_reviewer` permissions.
- `compliance_reviewer` does not inherit `qa_reviewer` permissions.
- `assessor` does not have `finding.approve`.
- `bundle.generate` (assessor) is split from `bundle.approve` (qa_reviewer).

## Step-up behavior

When the SessionEvaluator returns `STEP_UP_REQUIRED`, the runtime maps the
`stopped_at_check` to a specific error code:

| stopped_at | Code | Meaning |
|---|---|---|
| `device_state` | `DEVICE_COMPROMISED` | Device flagged compromised; MFA re-verification required. |
| `mfa` | `MFA_STEP_UP_REQUIRED` | Tenant requires MFA and the current session lacks a fresh factor. |

Clients handling these codes should:

1. Preserve the pending request (do not retry blindly).
2. Redirect the user to the identity provider step-up flow.
3. Retry the original request with a session token that has
   `mfa_verified=True`.

Machine identities (API keys) can never satisfy a step-up requirement.
When a machine identity receives `MFA_STEP_UP_REQUIRED`, the operator
must rotate the credential to one bound to a different subject.

## Device trust fallback

The device trust registry stores caller-supplied `fingerprint_hash` and
`user_agent_hash` — never raw fingerprints. Trust state transitions:

`UNKNOWN → KNOWN → TRUSTED` (via registration + repeated usage)
`(any) → SUSPICIOUS → COMPROMISED → REVOKED` (via admin action or
automated detection).

Fallback semantics at request time (when
`FG_DEVICE_TRUST_ENFORCEMENT_ENABLED=1`):

- `REVOKED`: deny with `DEVICE_REVOKED`.
- `COMPROMISED`: step-up with `DEVICE_COMPROMISED`.
- `SUSPICIOUS`: contribute +0.35 to the risk score; SessionEvaluator
  reads the score.
- `UNKNOWN`: contribute +0.2 to the risk score.
- `KNOWN`, `TRUSTED`: no negative contribution.

## Risk thresholds

Risk score is a bounded 0.0–1.0 float assembled deterministically from four
contributors:

| Factor | Contribution |
|---|---|
| lifecycle `DISABLED`/`DELETED`/`ARCHIVED` | +0.9 |
| lifecycle `SUSPENDED` | +0.6 |
| device `COMPROMISED` | +0.5 |
| device `REVOKED` | +0.5 |
| device `SUSPICIOUS` | +0.35 |
| device `UNKNOWN` | +0.2 |
| tenant requires MFA and MFA not verified | +0.3 |
| any active break-glass grant | +0.2 |

Bands (from `api/identity_governance/risk.py`):

| Band | Score range | Session decision |
|---|---|---|
| LOW | `< 0.25` | ALLOW |
| MEDIUM | `< 0.50` | ALLOW (with observability) |
| HIGH | `< 0.75` | ALLOW (with elevated logging) |
| CRITICAL | `>= 0.75` | DENY (`POLICY_DENIED`) |

## Break-glass constraints

Break-glass grants are the only authorized way to temporarily elevate
above a role's normal permissions. They are:

- **Reason-required**: empty reason → `ValueError`.
- **Duration-bounded**: `0 < duration <= 14400s` (4 hours). Enforced at
  request time.
- **Approval-gated**: `PENDING → APPROVED → ACTIVE` only via an approver
  distinct from the requester. Self-approval is rejected.
- **Self-expiring**: `expires_at` computed at approval; reads past that
  time transition to `EXPIRED`.
- **Revocable at any time** by an admin — status → `REVOKED`, capability
  no longer effective.
- **Tenant-scoped**: cross-tenant approvals, revokes, and reads all raise
  `ValueError` (see `tests/security/test_identity_runtime_isolation.py`).
- **Cannot resurrect DELETED identities**: `IdentityLifecycleState.DELETED`
  has no successor in the lifecycle state machine; no break-glass path can
  transition out of it.

Only the following capabilities may be requested via break-glass in
Phase 1: `platform.admin`, `tenant.configure`, `key.manage`. Requesting
any other capability is a design smell — the correct fix is to update the
role definition.

## Composing the decision

A request is authorized iff **all** of the following are true:

1. `require_permission(*perms) succeeds`
2. Every required `capability` is present in `AuthorizationContext.capabilities`
3. The conditional access policy engine returns `ALLOW`
4. `SessionEvaluator.evaluate` returns `ALLOW`
5. Ownership check on the target resource succeeds

Any failure short-circuits with a machine-readable `IdentityErrorCode`.
`platform_admin` bypasses (1) and (2) via holding all permissions; it does
**not** bypass (3), (4), or (5). No wildcard permission ever exists — every
role expansion is explicit in `ROLE_PERMISSIONS`.

## What must never happen

- No global admin bypass.
- No wildcards in `ROLE_PERMISSIONS`.
- No test-only runtime behavior.
- No `noqa` / `type: ignore` to hide real permission checks.
- No raw device fingerprints stored anywhere.
- No PII, tokens, or tenant identifiers in error responses or metric
  labels.
- No cross-tenant reads or writes — enforced by construction in every
  repository.
