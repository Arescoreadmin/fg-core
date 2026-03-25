# FrostGate Canonical Authentication Boundary Contract

## 1) Boundary Principle (Hard)

**Admin-Gateway is the only human authentication boundary.**

- Human authentication (OIDC/session/cookie/CSRF/admin portal identity) is performed only at Admin-Gateway.
- Core services MUST NOT authenticate humans directly.
- Core services only authorize trusted service-to-service or key/token claims already validated by boundary components.

---

## 2) Required Request Flow

Canonical flow:

`browser -> console/BFF -> admin-gateway -> core`

**Meaning**
1. Browser traffic terminates at the Console/BFF presentation layer.
2. Console/BFF forwards only allowlisted operations to Admin-Gateway.
3. Admin-Gateway authenticates human actor and establishes tenant-scoped identity context.
4. Admin-Gateway forwards authorized calls to core with signed/trusted service identity headers/tokens.
5. Core performs authorization + tenant enforcement using forwarded trusted context.

---

## 3) Explicitly Forbidden Paths

- `console -> core` direct access for human-originated operations.
- Human session cookies or browser credentials accepted directly by core APIs as human auth.
- Core login endpoints for human identity establishment.
- Any fallback path that bypasses Admin-Gateway for admin actions.

---

## 4) Admin-Gateway Responsibilities

1. Human identity verification (OIDC/session lifecycle).
2. CSRF/session protections for browser-originated flows.
3. Actor and tenant context resolution.
4. Scope/role evaluation for admin operations.
5. Emitting auth and admin decision audit events.
6. Forwarding only least-privilege service calls to core.

---

## 5) Core Service Responsibilities

1. Trust only validated boundary/service context; reject ambiguous identity context.
2. Enforce tenant-bound authorization on all tenant data operations.
3. Reject missing tenant context for tenant-owned operations.
4. Emit audit events for authorization decisions and privileged state transitions.
5. Never run human interactive auth flows.

---

## 6) Role Separation (Console/BFF vs Admin-Gateway vs Core)

### Console/BFF
- Browser-facing application layer.
- Request shaping / allowlist / UX boundary.
- Must not independently become the trust authority.

### Admin-Gateway
- Sole human authentication and authorization authority.
- Session validation.
- Tenant and role enforcement.
- Policy checks.

### Core
- Machine-only service boundary.
- No direct human auth.

---

## 7) Request Context Contract (Gateway to Core)

Every forwarded admin/core call must contain:
- `tenant_id` (required unless explicit global-admin control operation)
- `actor_id` (human principal id as asserted by Admin-Gateway)
- `actor_type` (`human|service`)
- `scopes`/permissions
- `request_id`/trace id
- issued-at timestamp or equivalent replay-control metadata

Core must fail closed when this context is incomplete or invalid.

---

## 8) Explicit Scoping Note

The Console BFF may remain the browser-facing entrypoint.  
This does not make it the human authentication authority.  
Admin-Gateway remains the sole authority for human identity, session validation, and access control decisions.
