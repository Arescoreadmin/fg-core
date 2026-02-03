**Generated**: 2026-02-01
**Status**: Informational (non-authoritative). Canonical requirements live in `BLUEPRINT_STAGED.md`.
**Derived From**: Code analysis of auth/tenant/rate-limit flow.

┌─────────────────────────────────────────────────────────────────────────────┐
│ INCOMING REQUEST │
└─────────────────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. AUTH GATE (MIDDLEWARE) │
│ File: api/middleware/auth_gate.py:AuthGateMiddleware.dispatch() │
│ Action: Extract key → verify via auth_scopes.verify_api_key_detailed() │
│ Fail: 401 Unauthorized (missing) or 401 (invalid) │
│ INVARIANT: INV-001 - No unauthenticated access to protected routes │
└─────────────────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. API KEY VERIFICATION (SINGLE SOURCE OF TRUTH) │
│ File: api/auth_scopes.py:verify_api_key_detailed() │
│ INVARIANT: INV-001, INV-003 │
└─────────────────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. TENANT BINDING │
│ File: api/auth_scopes.py:bind_tenant_id() │
│ INVARIANT: INV-002 │
└─────────────────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. SCOPE ENFORCEMENT (Per-Endpoint) │
│ File: api/auth_scopes.py:require_scopes() │
│ INVARIANT: INV-005 │
└─────────────────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. RATE LIMIT (If enabled) │
│ File: api/ratelimit.py │
│ INVARIANT: INV-003 │
└─────────────────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 6. ENDPOINT HANDLER │
└─────────────────────────────────────────────────────────────────────────────┘
