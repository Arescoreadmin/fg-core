# Identity Runtime Enforcement (PR-01a.1)

This document is the operational reference for wiring the FrostGate Identity
Authority Platform (FIAP) and Identity Governance foundation into the live
request path. It covers the request flow, feature flags, failure modes,
rollout plan, and rollback plan.

## Request path

Every request enters through the FastAPI `get_actor_context` dependency in
`api/auth_dispatch.py`. Governance enforcement runs at the tail of that
resolver — the resolution order is unchanged, and governance is a strict
add-on gated by feature flags.

```
+-------------------- HTTP request --------------------+
|                                                     |
|  auth middleware fills request.state.auth (API key) |
|                                                     |
+---------------------- get_actor_context -------------+
                    |
                    v
        FG_AUTH_ENABLED=0? --> dev bypass ActorContext (never in prod)
                    |
                    v
     Bearer token present?
                    | yes
                    v
     +--------------+-------------+
     | FG_IDENTITY_AUTHORITY_ENABLED=1                  |
     |   -> IdentityAuthority.authenticate_jwt          |
     |      -> CanonicalIdentity + AuthorizationContext |
     |      -> to_actor_context() adapter               |
     | else legacy Auth0 provider                       |
     +--------------+-----------------------------------+
                    |
                    v
     API key path (X-API-Key + tenant binding)
                    |
                    v
                Anonymous ActorContext
                    |
                    v
     _apply_governance_hooks(actor, request)
                    |
                    v
     apply_governance_checks (api/identity_governance/runtime.py)
       1. Skip if all flags off
       2. Skip for anonymous / dev_bypass
       3. FG_RISK_ENGINE_ENABLED  -> compute RiskScore
       4. FG_SESSION_EVALUATOR_ENABLED -> SessionEvaluator.evaluate
            - identity_state
            - session_expiry
            - session_revocation
            - device_state
            - mfa
            - risk
            -> non-ALLOW -> HTTPException with IdentityErrorCode
       5. FG_IDENTITY_TIMELINE_ENABLED -> emit LOGIN / decision events
       6. Emit metrics
                    |
                    v
             route handler runs
```

## Feature flags

All flags live in `api/config/identity_runtime.py`. Every one defaults to
`False`. Any value not in `{"1", "true", "yes", "on", "y"}`
(case-insensitive) resolves to `False`.

| Flag | Effect |
|---|---|
| `FG_IDENTITY_AUTHORITY_ENABLED` | Route JWT through FIAP `IdentityAuthority`. When off, legacy Auth0 provider is used. |
| `FG_SESSION_EVALUATOR_ENABLED` | Run `SessionEvaluator.evaluate` on every resolved actor. Non-ALLOW decisions raise a machine-readable error. |
| `FG_DEVICE_TRUST_ENFORCEMENT_ENABLED` | Consult `DeviceTrustRegistry` before allowing the session (reserved for follow-up). |
| `FG_RISK_ENGINE_ENABLED` | Compute `IdentityRiskEngine` score and record it in the metrics. |
| `FG_CONDITIONAL_ACCESS_ENABLED` | Consult `ConditionalAccessPolicyEngine` (reserved for follow-up). |
| `FG_BREAK_GLASS_RUNTIME_ENABLED` | Consult `BreakGlassAuthority` on capability denials. |
| `FG_IDENTITY_TIMELINE_ENABLED` | Emit best-effort events to the identity timeline. Never blocks. |
| `FG_IDENTITY_PERSISTENCE_ENABLED` | Use SQLAlchemy repositories backed by `migrations/postgres/0148_identity_governance.sql`. When off, in-memory repositories are used. |

## Order of evaluation

The SessionEvaluator runs six deterministic checks in a fixed order. The
first non-ALLOW check wins:

1. Identity lifecycle state
2. Session expiry
3. Session revocation
4. Device trust state
5. MFA requirement
6. Risk score band

## Failure modes

| Condition | HTTP | Code | Notes |
|---|---|---|---|
| Suspended identity | 403 | `IDENTITY_SUSPENDED` |
| Disabled identity | 403 | `IDENTITY_DISABLED` |
| Archived identity | 403 | `IDENTITY_ARCHIVED` |
| Deleted identity | 403 | `IDENTITY_DELETED` |
| Session expired | 403 | `SESSION_EXPIRED` |
| Session revoked | 401 | `SESSION_REVOKED` |
| Device revoked | 403 | `DEVICE_REVOKED` |
| Device compromised | 403 | `DEVICE_COMPROMISED` (STEP_UP branch) |
| MFA missing | 403 | `MFA_STEP_UP_REQUIRED` |
| Risk band critical | 403 | `POLICY_DENIED` |
| Governance evaluator error | 500 | `GOVERNANCE_UNAVAILABLE` (fail-closed) |

The error body is always `{"code": <IdentityErrorCode>, "message": <generic>}`
and may include a machine-readable `reason` (e.g. `"identity_state"`,
`"session_revocation"`) — never PII, never token content, never tenant
identifiers, never policy rule text.

## Fail-closed guarantees

The governance runtime helper wraps the entire evaluation in a try/except.
Any exception raised by the evaluator, the risk engine, or the repository
layer results in a 500 `GOVERNANCE_UNAVAILABLE` — the request never
continues in an unknown governance state.

Timeline emission is an explicit exception: it is best-effort and will
never block a request or propagate an exception. If the timeline chain is
broken or the writer fails, the request completes normally and the
failure is logged.

## Rollout plan

The recommended flag progression:

1. `FG_IDENTITY_AUTHORITY_ENABLED=1` — switch the JWT provider path.
2. `FG_IDENTITY_TIMELINE_ENABLED=1` — start emitting timeline events.
3. `FG_RISK_ENGINE_ENABLED=1` — start recording risk bands (no gating).
4. `FG_SESSION_EVALUATOR_ENABLED=1` — start enforcing session decisions.
5. `FG_DEVICE_TRUST_ENFORCEMENT_ENABLED=1` — enforce device state.
6. `FG_CONDITIONAL_ACCESS_ENABLED=1` — enforce conditional access.
7. `FG_BREAK_GLASS_RUNTIME_ENABLED=1` — enable break-glass path.
8. `FG_IDENTITY_PERSISTENCE_ENABLED=1` — swap to DB-backed repositories.

Each step should soak for at least one release cycle behind observability
review of the metrics in `api/identity_governance/metrics.py`.

## Rollback plan

Disable in reverse order. Every flag is independently reversible without
data loss because:

- Governance evaluation is stateless — turning off a flag stops the check
  immediately.
- Persistence tables (0148) are append-only or overwrite-only per record;
  switching back to in-memory just abandons the newest reads.
- The FIAP path and the legacy path share the `ActorContext` shape, so
  routes are unaware of which path served them.

If a runaway denial rate is observed, set
`FG_SESSION_EVALUATOR_ENABLED=0` and the runtime immediately reverts to
pre-PR-01a.1 behavior on the next request.

## Observability

- Metrics: see `api/identity_governance/metrics.py`. Labels are limited to
  low-cardinality classifications only — never subject, tenant, email, or
  route parameters.
- Logs: prefixed with `frostgate.identity_governance.runtime` or
  `frostgate.auth_dispatch`. Emit structured details; never token content
  or full subject values (only prefixes).

## Related files

- `api/config/identity_runtime.py`
- `api/identity_governance/runtime.py`
- `api/identity_governance/services.py`
- `api/identity_governance/error_codes.py`
- `api/identity_governance/metrics.py`
- `api/identity_governance/repositories/`
- `api/identity_authority/auth_context_adapter.py`
- `api/auth_dispatch.py`
