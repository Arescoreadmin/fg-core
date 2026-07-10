# FrostGate Identity Authority — Architecture

## Overview

The FrostGate Identity Authority Platform (FIAP) is the single canonical authentication and authorization subsystem for all FrostGate applications: console, portal, and API.

Prior to FIAP, authentication was split across three implementations:
- **Console:** NextAuth + Auth0 OIDC (Next.js)
- **Portal:** Custom HMAC session keyed to `PORTAL_PASSWORD` (shared secret)
- **API:** Auth0 JWT validation in `api/identity_providers/auth0.py` + API key middleware

FIAP unifies these into one authority that every request flows through.

---

## Component Map

```
Request
  │
  ▼
FastAPI Middleware (api key extraction → request.state.auth)
  │
  ▼
auth_dispatch.py / integration.py  ←── FastAPI dependency
  │
  ├─[Bearer JWT]──► IdentityAuthority.authenticate_jwt()
  │                      │
  │                      ▼
  │               IdentityProviderRegistry.resolve_jwt()
  │                      │
  │          ┌───────────┼───────────┐
  │          ▼           ▼           ▼
  │       Auth0       Entra      Google / GenericOIDC
  │       Provider   Provider    Provider
  │          │
  │          ▼
  │    CanonicalIdentity
  │          │
  │          ▼
  │    TenantResolver.resolve()
  │          │
  │     ┌────┴────────────────┐
  │     │ _resolve_by_membership    (TenantUser identity triple lookup)
  │     │ _resolve_by_hint          (API key binding / X-Tenant-Id header)
  │     └───────────────────────
  │          │
  │          ▼
  │    AuthorizationContext  (permissions, tenant_id, session_risk_score)
  │
  ├─[API Key]──► MachineIdentityAuthority
  │               (request.state.auth → CanonicalIdentity)
  │
  └─[Legacy]──► LegacySessionMigrator
                 (portal HMAC tokens → CanonicalIdentity)
```

---

## Data Flow

### JWT Authentication (Human User)

```
1. Client sends:  Authorization: Bearer <jwt>
2. integration.py calls  IdentityAuthority.authenticate_jwt(token)
3. IdentityProviderRegistry tries providers in order:
     Auth0 → Entra → Google → Generic OIDC
4. Matching provider validates RS256/ES256 signature via JWKS
5. Provider returns  CanonicalIdentity  (frozen, immutable)
6. TenantResolver queries  TenantUser  by (provider, issuer, subject)
7. Returns  AuthorizationContext  with resolved permissions
8. Audit event emitted (hash-chained to SecurityAuditLog)
9. Prometheus metrics recorded
```

### API Key Authentication (Machine)

```
1. Client sends:  X-API-Key: fg_live_<prefix>.<secret>
2. API key middleware validates HMAC, sets request.state.auth
3. MachineIdentityAuthority.authenticate_api_key_from_state()
4. Builds  CanonicalIdentity  with identity_type="machine"
5. TenantBinding from key's configured roles
6. Returns  AuthorizationContext
```

### Legacy Portal Session (Migration Path)

```
1. Portal sends legacy HMAC session cookie
2. PortalIdentityBridge.validate_portal_session()
3. Tries unified session format first (new sessions)
4. Falls back to  LegacySessionMigrator  (PORTAL_PASSWORD HMAC)
5. Returns  AuthorizationContext  with "portal_legacy" provider
```

---

## Core Data Models

### CanonicalIdentity (frozen dataclass)

The single identity representation flowing through the system.

| Field | Type | Description |
|-------|------|-------------|
| `subject` | `str` | Stable, provider-scoped user ID |
| `email` | `str` | Verified email address |
| `provider` | `IdentityProvider` | Which IdP authenticated this identity |
| `auth_context` | `AuthenticationContext` | MFA, AMR, auth time |
| `tenant_binding` | `Optional[TenantBinding]` | Resolved FrostGate tenant membership |
| `identity_type` | `Literal[human,machine,agent,service]` | Classification |
| `issued_at` / `expires_at` | `datetime` | Token validity window |

### AuthorizationContext (frozen dataclass)

The fully resolved context attached to each authenticated request.

| Field | Type | Description |
|-------|------|-------------|
| `identity` | `CanonicalIdentity` | The authenticated identity |
| `permissions` | `frozenset[str]` | Effective permissions (from roles) |
| `capabilities` | `frozenset[str]` | Licensed features (from subscription) |
| `tenant_id` | `Optional[str]` | Resolved tenant |
| `session_id` | `str` | Session ID for revocation |
| `session_risk_score` | `float` | 0.0–1.0 (always 0.0 in this release) |
| `correlation_id` | `str` | Request tracing |

---

## Provider Registry

Providers are tried in this order on every JWT authentication request:

| Priority | Provider | Env Vars Required |
|----------|----------|-------------------|
| 1 | Auth0 | `FG_AUTH0_DOMAIN` |
| 2 | Entra ID | `FG_ENTRA_TENANT_ID` + `FG_ENTRA_CLIENT_ID` |
| 3 | Google | `FG_GOOGLE_CLIENT_ID` |
| 4 | Generic OIDC | `FG_OIDC_ISSUER` + `FG_OIDC_CLIENT_ID` |

First configured provider that accepts the token wins. If a provider rejects
the token (`IdentityValidationError`), the next is tried. If a provider is
unreachable (`IdentityProviderError`), the error propagates immediately (no
silent fallthrough to the next provider).

---

## Session Management

Sessions are HMAC-SHA256 signed blobs using `FG_SESSION_SECRET`.

Token format: `base64url(json_payload).hmac_sha256_hex`

Payload fields: `v`, `sid`, `sub`, `email`, `tid`, `it`, `prov`, `mfa`, `dev`, `iat`, `exp`, `idle_exp`

Default TTLs:
- Absolute: 8 hours (`FG_SESSION_TTL_SECONDS`)
- Idle: 1 hour (`FG_SESSION_IDLE_TIMEOUT`)
- Refresh window: last 30 minutes of absolute TTL

Revocation is Redis-backed (`FG_REDIS_URL`) with in-memory dict fallback.

---

## Audit Chain

Every identity event is appended to a SHA-256 hash chain:

```
event_hash = SHA-256(prev_hash || event_id || timestamp || event_type || subject || tenant_id || details)
```

Chain is per-process (in-memory `_prev_hash`). Events are logged as
structured JSON and persisted to `SecurityAuditLog` when a DB factory is
available.

---

## Backwards Compatibility

### `api/auth_dispatch.py`

When `FG_IDENTITY_AUTHORITY_ENABLED=1`, JWT authentication routes through
`IdentityAuthority`. Otherwise the legacy Auth0-only path is used.

The `get_actor_context()` dependency continues to work unchanged for all
existing routes.

### `api/identity_providers/entra.py`

`EntraProvider.extract_actor()` now delegates to `EntraOIDCProvider` instead
of raising `NotImplementedError`.

### `CanonicalIdentity.to_actor_context()`

Every `CanonicalIdentity` can be converted to a legacy `ActorContext` for use
with existing `require_permission()` checks.

---

## Feature Flags

| Env Var | Default | Purpose |
|---------|---------|---------|
| `FG_IDENTITY_AUTHORITY_ENABLED` | `0` | Route JWT auth through FIAP |
| `FG_SESSION_SECRET` | random (warn) | HMAC secret for sessions |
| `FG_REDIS_URL` | (none) | Redis for distributed session revocation |
| `FG_SESSION_TTL_SECONDS` | `28800` | Absolute session TTL |
| `FG_SESSION_IDLE_TIMEOUT` | `3600` | Idle session timeout |
| `FG_MAX_CONCURRENT_SESSIONS` | `5` | Max sessions per user (advisory) |
| `FG_ENTRA_REQUIRE_MFA` | `0` | Enforce MFA for Entra tokens |
| `FG_ENTRA_ALLOWED_TENANTS` | (any) | Comma-separated allowed Entra tenant IDs |
| `FG_SESSION_EVALUATOR_ENABLED` | `0` | Run continuous session evaluation in `get_actor_context()` |
| `FG_DEVICE_TRUST_ENFORCEMENT_ENABLED` | `0` | Enforce device trust registry |
| `FG_RISK_ENGINE_ENABLED` | `0` | Compute and record identity risk score |
| `FG_CONDITIONAL_ACCESS_ENABLED` | `0` | Consult conditional access policy engine |
| `FG_BREAK_GLASS_RUNTIME_ENABLED` | `0` | Consult break-glass authority at runtime |
| `FG_IDENTITY_TIMELINE_ENABLED` | `0` | Best-effort timeline event emission from auth paths |
| `FG_IDENTITY_PERSISTENCE_ENABLED` | `0` | Use DB-backed governance repositories (0148 tables) |

## Runtime governance integration (PR-01a.1)

Governance evaluation is wired at the tail of `get_actor_context()` behind
the flags above. See:

- [`RUNTIME_ENFORCEMENT.md`](./RUNTIME_ENFORCEMENT.md) for the request
  flow, order of evaluation, failure modes, rollout plan, and rollback
  plan.
- [`AUTHORIZATION_MAPPING.md`](./AUTHORIZATION_MAPPING.md) for how
  permissions, capabilities, policies, ownership, step-up, device trust,
  risk, and break-glass combine.
- [`GOVERNANCE.md`](./GOVERNANCE.md) for the underlying stateless
  services.
