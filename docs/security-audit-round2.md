# FrostGate Security Audit — Round 2

**Branch:** `claude/security-audit-fastapi-QYoAK`
**Prior audit HEAD (round 1):** `ce12212`
**Audit date:** 2026-02-21
**Auditor:** Claude (Sonnet 4.6 via Claude Code)

---

## Phase 0 — Git Baseline

```
Branch: claude/security-audit-fastapi-QYoAK
HEAD:    ce12212 (post round-1 patches)
Working tree: clean
```

Round-1 patches in `ce12212` covered FG-AUD-001 through FG-AUD-007 (P0/P1).
This round audits the remaining surface and new findings.

---

## Phase 1 — System Inventory

### 1A — Router Surface (`api/main.py`)

| Router | Conditional? | Auth mechanism |
|--------|-------------|----------------|
| 27 unconditional routers | No | `AuthGateMiddleware` + route `Depends(require_scopes(...))` |
| `ai_plane_extension_router` | `ai_plane_enabled()` env var | Same |
| UI routers (4x) | `ui_enabled()` | Bypassed in `AuthGateMiddleware` via `PUBLIC_PATHS_PREFIX["/ui"]`; route-level `require_scopes("ui:read")` |
| 4 compliance routers | `_optional_router()` silent import | Same |
| `admin_router` | `_should_mount_admin_routes()` | Same |
| `dev_events_router` | `_dev_enabled()` | Same |

**`build_contract_app()` (`api/main.py:755–816`):** Separate FastAPI app with 25 routers.
Has `app.state.auth_enabled = True` but **NO middleware stack** (no `AuthGateMiddleware`,
no `SecurityHeadersMiddleware`, no CORS, no DoS guard). Route-level deps only.

### 1B — Plane Separation

`services/*` imports from `api.*` (plane violation — services should not depend on API layer):

| File | Imports |
|------|---------|
| `services/audit_engine/engine.py:20-21` | `api.db`, `api.db_models` |
| `services/compliance_registry/registry.py:12-13` | `api.db`, `api.db_models` |
| `services/connectors/idempotency.py:11` | `api.db_models` |
| `services/connectors/oauth_store.py:14` | `api.db_models` |
| `services/connectors/policy.py:12` | `api.db_models` |
| `services/connectors/runner.py:11` | `api.db_models` |

No CI guard enforces this boundary.

### 1C — Outbound HTTP Call Sites

| File | Line | Client | `follow_redirects` | URL source |
|------|------|--------|-------------------|-----------|
| `admin_gateway/auth.py` | 200,212,280 | `httpx.AsyncClient` | `False` ✓ | OIDC config |
| `admin_gateway/auth/oidc.py` | 49,226,256,294 | `httpx.AsyncClient` | `False` ✓ | OIDC/JWKS |
| `admin_gateway/routers/admin.py` | 123,160 | `httpx.AsyncClient` | `False` ✓ (patched R2) | Config |
| `admin_gateway/audit.py` | 56 | `httpx.AsyncClient` | `False` ✓ (patched R2) | Config |
| `engine/pipeline.py` | 315 | `httpx.Client` | `False` ✓ (patched R2) | `FG_OPA_URL` env |
| `admin_gateway/routers/products.py` | 619 | `httpx.AsyncClient` | implicit `False` | User-controlled |
| `api/tripwires.py` | 134 | `httpx.AsyncClient` | `False` ✓ | Config |
| `api/tripwires.py` | 143 | `aiohttp.ClientSession` | — (aiohttp default follows) | Config |
| `api/security_alerts.py` | 355 | `httpx.AsyncClient` | `False` ✓ | Validated config |
| `services/federation_extension/service.py` | 107 | `urllib.request` + `_NoRedirect` | Blocked ✓ | `FG_FEDERATION_ISSUER` env |

### 1D — Auth / Tenant Binding

- `/ui/*` paths bypass `AuthGateMiddleware` (via `PUBLIC_PATHS_PREFIX["/ui"]`).
  Route-level `require_scopes("ui:read")` on the router provides real auth.
- `_require_ui_key()` (`api/ui.py:80–92`) is documented as "presence-only UX convenience gate" —
  checks key exists, does NOT cryptographically validate. Router dep is the actual guard.
- `AuthGateConfig.public_paths` property (`api/middleware/auth_gate.py:74–85`) was dead code —
  `_is_public()` uses `public_paths_exact`/`public_paths_prefix` fields, not the property.
  **Removed in this round (FG-AUD-014).**
- `/_debug/routes` auth failure returned HTTP 200 with `ok: false` — monitoring would miss
  unauthorized access. **Fixed in this round (FG-AUD-013).**
- `/stats/debug` is in `PUBLIC_PATHS_EXACT` but has `Depends(require_status_auth)` at route level;
  route-level auth check runs after middleware bypass.

### 1E — Agent Pipeline

- `agent/core_client.py` (primary): SSRF guard in `validate_core_base_url()`, DNS resolution,
  private-IP blocking, TLS fingerprint pinning via `FingerprintPinningAdapter`. Well-hardened.
- `agent/app/core_client.py` (legacy stub): simpler, no SSRF guard — used only by older tests.
- `agent/app/queue/sqlite_queue.py`: bounded queue (`max_size=50000`), dead-letter with cap,
  retry with exponential backoff. Terminal reasons (`auth_invalid`, `schema_invalid`,
  `payload_too_large`) cause immediate dead-letter. Sound design.
- `agent/app/queue/backoff.py:8`: `random.uniform` for jitter — non-cryptographic but
  appropriate for retry jitter. Not a security issue.

### 1F — Logging / Secret Hygiene

- `api/keys.py:175–183`: logs key creation with prefix, scopes, tenant — no raw key. ✓
- `api/key_rotation.py:384–387`: logs old/new prefix only. ✓
- `api/auth_scopes/resolution.py:164–188`: `_log_auth_event` logs key prefix (first 8 chars),
  tenant, reason — no raw key. ✓
- `api/middleware/exception_shield.py`: `_safe_detail()` strips URL credentials, control chars,
  and truncates to 256 chars. Prod env returns generic "error" for non-string details. ✓
- `admin_gateway/auth/oidc.py:355`: logs `InvalidTokenError` message only — no token content. ✓
- `api/tripwires.py:613,664`: canary key prefix logged, not the secret. ✓
- `admin_gateway/audit.py:66–`: `_redact_event()` redacts secrets before forwarding. ✓

**No raw secret/key/token material found in log output paths.**

### 1G — CI Guards Realness

Existing guards verified non-vacuous:
- `check_federation_jwt_signature_verification`: positive markers required; removing them fails gate.
- `check_authgate_unmatched_not_fail_open`: checks for `"unmatched_authed"` marker.
- `check_oidc_parse_id_token_not_demo`: AST-based, checks function body patterns.

Gaps identified:
- No guard for `admin_gateway/audit.py`, `admin_gateway/routers/admin.py`, `engine/pipeline.py`
  outbound redirect policy. **Added `check_outbound_clients_follow_redirects_false` in this round.**
- No guard for `/_debug/routes` auth swallowing. **Added `check_debug_routes_auth_not_swallowed`.**
- No guard for `AuthGateConfig.public_paths` dead property. **Added `check_authgate_config_no_dead_public_paths_property`.**
- No guard for `services/*` → `api.*` plane boundary violations.

---

## Phase 2 — Findings

### Previously reported and patched (Round 1, commit `ce12212`)

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| FG-AUD-001 | P0 | Federation JWT: no signature verification | PATCHED |
| FG-AUD-002 | P0 | Federation SSRF via attacker-controlled `iss` claim | PATCHED |
| FG-AUD-003 | P0 | OIDC `parse_id_token_claims` demo implementation | PATCHED |
| FG-AUD-004 | P1 | Admin proxy `timeout=None` — unbounded streaming | PATCHED |
| FG-AUD-005 | P1 | Missing `follow_redirects=False` in OIDC/JWKS clients | PATCHED |
| FG-AUD-006 | P1 | `AuthGateMiddleware` fail-open for unregistered routes | PATCHED |
| FG-AUD-007 | P1 | Rate limiter fail-open when Redis unavailable | PATCHED |

### New findings (Round 2)

---

#### FG-AUD-008 — P1 — `admin_gateway/audit.py:56`: Audit client missing `follow_redirects=False`

**File/line:** `admin_gateway/audit.py:56`
**Pre-patch (ce12212):** `httpx.AsyncClient(base_url=self.core_base_url, timeout=5.0)`
**Post-patch (this commit):** `httpx.AsyncClient(base_url=self.core_base_url, timeout=5.0, follow_redirects=False)`

**Exploit:** If `AG_CORE_BASE_URL` is compromised (config injection) or the server
returns a 3xx redirect to an internal endpoint, the audit client silently follows the
redirect and forwards authentication headers (`X-API-Key`) to the redirected destination.
This enables SSRF from the audit logging path with credential forwarding.

**Regression test:** `tests/security/test_audit_fg_aud_008_009_010_outbound_redirects.py::TestFgAud008AuditFollowRedirects`

---

#### FG-AUD-009 — P1 — `admin_gateway/routers/admin.py:123,160`: Proxy clients missing `follow_redirects=False`

**File/line:** `admin_gateway/routers/admin.py:123` (`_proxy_to_core`), `admin_gateway/routers/admin.py:160` (`_proxy_to_core_raw`)
**Pre-patch:** Both `httpx.AsyncClient` calls without `follow_redirects=False`
**Post-patch:** Both have `follow_redirects=False`

**Exploit:** Admin gateway proxies to `FG_CORE_BASE_URL`. A 3xx redirect from core
(or a compromised config) causes the proxy to follow the redirect, forwarding the
`X-API-Key` header and request body to an attacker-controlled destination.
Impact includes credential theft and SSRF chained through the proxy.

**Regression test:** `tests/security/test_audit_fg_aud_008_009_010_outbound_redirects.py::TestFgAud009AdminProxyFollowRedirects`

---

#### FG-AUD-010 — P2 — `engine/pipeline.py:315`: OPA client missing `follow_redirects=False`

**File/line:** `engine/pipeline.py:315`
**Pre-patch:** `httpx.Client(timeout=timeout)`
**Post-patch:** `httpx.Client(timeout=timeout, follow_redirects=False)`

**Exploit:** `FG_OPA_URL` is config-controlled, but if the OPA server issues a redirect
(e.g., misconfigured reverse proxy) and the redirect target is an internal service, the
policy engine forwards the decision payload containing full request details.
Lower severity than FG-AUD-008/009 because OPA URL is operator-controlled.

**Regression test:** `tests/security/test_audit_fg_aud_008_009_010_outbound_redirects.py::TestFgAud010OpaClientFollowRedirects`

---

#### FG-AUD-011 — P2 — `admin_gateway/routers/products.py:619`: TOCTOU DNS rebinding in health URL validation

**File/line:** `admin_gateway/routers/products.py:216–262` (`_validate_health_url`), `619` (httpx call)

**Exploit:** `_validate_health_url()` resolves the hostname at validation time and checks
the resolved IP against a private-IP blocklist. The actual `httpx.AsyncClient` request
fires separately after validation. A DNS TTL of 0 allows a rebinding attack:
1. Attacker registers domain with IP `1.2.3.4` (public) — passes validation.
2. Attacker changes DNS to `169.254.169.254` (AWS IMDS) — TTL 0 triggers re-resolution.
3. httpx request resolves to `169.254.169.254` — SSRF to metadata service.

**Residual risk:** Mitigated somewhat by the post-request redirect check at lines 623–635,
but the 3xx check does not prevent a direct connection (no redirect needed for TOCTOU).
Also: `httpx.AsyncClient(timeout=3.0)` has no explicit `follow_redirects=False` —
relies on httpx default (False since v0.20), fragile if httpx is downgraded.

---

#### FG-AUD-012 — P1 — `api/security/public_paths.py:16`: `/stats/debug` auth model confusion

**File/line:** `api/security/public_paths.py:16`, `api/main.py:681–715`

**Observation:** `/stats/debug` is listed in `PUBLIC_PATHS_EXACT`, bypassing
`AuthGateMiddleware`. The route itself has `Depends(require_status_auth)`, which provides
authentication at the route level. However, `require_status_auth` checks against
`FG_API_KEY` (global env key), NOT against the per-tenant HMAC-verified key DB.

**Risk:** In deployments where `auth_enabled=False` (or `FG_API_KEY` is absent/empty),
`require_status_auth` returns without checking any credentials (line 466-467 of main.py).
The endpoint then returns internal stats including `FG_DB_URL` contents, memory usage,
connection counts — potential reconnaissance data.

**Note:** Design appears intentional for operational monitoring but creates diverged auth model.

---

#### FG-AUD-013 — P2 — `api/main.py:717–746`: `/_debug/routes` auth failures return HTTP 200

**File/line:** `api/main.py:717–746`
**Pre-patch:** `require_status_auth(request)` wrapped in `try/except HTTPException` → returns
`{"ok": false, "error": "401: ...", "routes": []}` with HTTP 200.
**Post-patch:** `require_status_auth` called before `try` block — auth exceptions propagate as 401/403.

**Exploit:** Monitoring based on HTTP status codes would classify all access to `/_debug/routes`
as 200 OK, including unauthenticated probes. An attacker repeatedly probing the endpoint
generates no 4xx alerts. The routes list is empty on auth failure (no data leak), but
the HTTP 200 masks unauthorized access attempts in access logs and SIEM rules.

**Regression test:** `tests/security/test_audit_fg_aud_008_009_010_outbound_redirects.py::TestFgAud013DebugRoutesAuthNotSwallowed`

---

#### FG-AUD-014 — P2 — `api/middleware/auth_gate.py:74–85`: Dead `AuthGateConfig.public_paths` property

**File/line:** `api/middleware/auth_gate.py:74–85` (removed in this patch)
**Evidence:** `grep -n "public_paths"` shows `_is_public()` at line 89 uses
`config.public_paths_exact` and `config.public_paths_prefix` — the `@property public_paths`
is never called anywhere in the codebase.

**Risk:** The property hardcoded a stale, different set of paths (`/ui`, `/ui/token`, `/openapi.json`
without the full `PUBLIC_PATHS_EXACT` list). A developer reading `AuthGateConfig` would see
a `public_paths` property and mistakenly believe it controls the public path list, missing
the actual source of truth in `api/security/public_paths.py`. This creates confusion
during security reviews.

**Regression test:** `tests/security/test_audit_fg_aud_008_009_010_outbound_redirects.py::TestFgAud014NoDeadPublicPathsProperty`

---

#### FG-AUD-015 — P2 — `api/ui.py:80–92`: `_require_ui_key` is presence-only, not cryptographic

**File/line:** `api/ui.py:80–92`

**Observation:** The docstring explicitly states:
> "This only checks 'present'. Actual validation happens on API endpoints via require_api_key_always/require_scopes. UI is just a UX convenience gate."

Individual handlers call `_require_ui_key(request)` which returns without checking key
validity if auth is disabled. The router-level `require_scopes("ui:read")` dependency
runs BEFORE the handler and does perform cryptographic validation.

**Risk (defense-in-depth):** If the router-level dependency is ever accidentally removed,
individual handlers fall back to presence-only checking. Any non-empty string (e.g., `"x"`)
would pass the handler check. Developers reading handlers see `_require_ui_key` and may
believe full auth is enforced at the handler level.

**No patch made** — the router-level `require_scopes` provides real security; removing
`_require_ui_key` calls would be an API change outside this audit scope. Documented for awareness.

---

#### FG-AUD-016 — P2 — Plane boundary violations: `services/*` imports from `api.*`

**Files:**
- `services/audit_engine/engine.py:20–21` — imports `api.db`, `api.db_models`
- `services/compliance_registry/registry.py:12–13` — imports `api.db`, `api.db_models`
- `services/connectors/idempotency.py:11` — imports `api.db_models`
- `services/connectors/oauth_store.py:14` — imports `api.db_models`
- `services/connectors/policy.py:12` — imports `api.db_models`
- `services/connectors/runner.py:11` — imports `api.db_models`

**Risk:** The services plane imports from the API plane, creating upward dependency.
This means: (1) running services in isolation requires the full API layer; (2) SQLAlchemy
models are shared across plane boundaries making schema changes risky; (3) circular
import potential. No CI guard enforces this boundary.

---

#### FG-AUD-017 — P2 — `api/main.py:755–816`: `build_contract_app()` has no middleware stack

**File/line:** `api/main.py:755–816`

**Observation:** `build_contract_app()` creates a FastAPI app with 25 routers but
no middleware stack. Missing:
- `AuthGateMiddleware` — no central auth enforcement or tenant context population
- `SecurityHeadersMiddleware` — no HSTS, X-Frame-Options, CSP
- `CORSMiddleware` — no CORS policy
- `DoSGuardMiddleware` — no rate limit / request size enforcement
- `ResilienceGuardMiddleware` — no circuit breaker

`app.state.auth_enabled = True` is set but never consumed by any middleware (none is added).
Route-level `Depends(require_scopes(...))` provides per-route auth but without the tenant
context that `AuthGateMiddleware` would populate (`request.state.tenant_id`,
`request.state.tenant_is_key_bound`).

**Severity note:** This app is labeled `env: "contract"` and appears used for API contract
testing. If deployed in production, all requests bypass the central security middleware.

---

#### FG-AUD-018 — P2 — CI guards don't cover newly identified outbound HTTP sites

**Pre-patch:** `check_oidc_follow_redirects_disabled` only checked `admin_gateway/auth.py`
and `admin_gateway/auth/oidc.py`.
**Post-patch:** Added `check_outbound_clients_follow_redirects_false` covering
`admin_gateway/audit.py`, `admin_gateway/routers/admin.py`, `engine/pipeline.py`.

---

#### FG-AUD-019 — P3 — `api/tripwires.py:143–145`: `aiohttp` fallback path has no redirect control

**File/line:** `api/tripwires.py:143–145`

**Observation:** `api/tripwires.py` has a primary path using `httpx.AsyncClient(follow_redirects=False)` ✓,
but also an `aiohttp.ClientSession` fallback (triggered if httpx is unavailable). `aiohttp`
follows redirects by default (`allow_redirects=True`). The fallback path lacks explicit
redirect control.

**Risk:** Low — triggered only if httpx import fails (extreme edge case). But in that scenario,
the webhook outbound call could follow redirects to internal targets.

---

#### FG-AUD-020 — P3 — `api/ui.py:985–999`: `/ui/token` uses GET verb for state-changing cookie set

**File/line:** `api/ui.py:985–999`

**Observation:** `/ui/token` is a `GET` endpoint that sets a cookie (`response.set_cookie`).
GET requests are idempotent by convention; cookie-setting on GET bypasses CSRF protections
that POST endpoints would normally require (the `CSRFProtect` middleware at admin_gateway
wouldn't apply here).

**Residual risk:** `samesite="lax"` on the cookie prevents CSRF for cross-site navigation.
`httponly=True` prevents JS access. Cookie security is `secure=_is_prod()` — HTTP in dev.

---

## Phase 3 — Patch Summary (Round 2)

| ID | Severity | File | Change | Test |
|----|----------|------|--------|------|
| FG-AUD-008 | P1 | `admin_gateway/audit.py:56` | Added `follow_redirects=False` | `test_audit_fg_aud_008_009_010_outbound_redirects.py` |
| FG-AUD-009 | P1 | `admin_gateway/routers/admin.py:123,160` | Added `follow_redirects=False` to both clients | Same |
| FG-AUD-010 | P2 | `engine/pipeline.py:315` | Added `follow_redirects=False` | Same |
| FG-AUD-013 | P2 | `api/main.py:717–746` | Moved `require_status_auth` outside `try` block | Same |
| FG-AUD-014 | P2 | `api/middleware/auth_gate.py:74–85` | Removed dead `@property public_paths` | Same |
| FG-AUD-018 | P2 | `tools/ci/check_security_regression_gates.py` | Added 3 new CI guards | N/A (guards are their own tests) |

---

## Phase 4 — Residual Risk Model

### Closed risks (Rounds 1 + 2)

| Control | Mechanism | Regression proof |
|---------|-----------|-----------------|
| Federation JWT forgery | PyJWT RS256/ES256 verification via JWKS | `check_federation_jwt_signature_verification` CI guard |
| Federation SSRF | JWKS URL from `FG_FEDERATION_ISSUER` only; DNS rebinding guard; redirect blocked | `check_federation_ssrf_guard` CI guard |
| OIDC demo token parse | Real JWKS fetch + PyJWT signature verify; `verify_exp/iss/aud=True` | `check_oidc_parse_id_token_not_demo` CI guard |
| Admin proxy timeout DoS | Bounded `httpx.Timeout(connect=10, read=300, write=30, pool=10)` | Code review |
| Outbound redirect SSRF (OIDC, audit, proxy, OPA) | `follow_redirects=False` on all 9 outbound HTTP call sites | `check_oidc_follow_redirects_disabled` + `check_outbound_clients_follow_redirects_false` CI guards |
| Auth gate fail-open (unregistered routes) | `verify_api_key_detailed()` required for all unregistered routes | `check_authgate_unmatched_not_fail_open` CI guard |
| Rate limiter fail-open | `_fail_open_allowed()` gate; default fail-closed | `check_rate_limiter_not_hardcoded_fail_open` CI guard |
| Debug routes auth masking | `require_status_auth` propagates as 4xx | `check_debug_routes_auth_not_swallowed` CI guard |
| Misleading dead code (public_paths property) | Property removed | `check_authgate_config_no_dead_public_paths_property` CI guard |

### Residual risks (unpatched)

| ID | Severity | Risk | Recommended owner action |
|----|----------|------|--------------------------|
| FG-AUD-011 | P2 | TOCTOU DNS rebinding in product health URL check (`products.py:619`) | Resolve DNS once, pass resolved IP to httpx via custom transport; or use `FG_PRODUCT_HEALTH_HOST_ALLOWLIST` strictly |
| FG-AUD-015 | P2 | `_require_ui_key` presence-only check creates false assurance | Remove `_require_ui_key` calls from handlers since `require_scopes("ui:read")` router dep provides real auth |
| FG-AUD-016 | P2 | `services/*` → `api.*` plane violations (6 files) | Extract shared DB layer to a neutral `core.db` package; add CI plane boundary guard |
| FG-AUD-017 | P2 | `build_contract_app()` has no middleware stack | Add `AuthGateMiddleware`, `SecurityHeadersMiddleware`, CORS to contract app; or clearly document it is test-only and gate its deployment |
| FG-AUD-019 | P3 | `aiohttp` fallback in `api/tripwires.py` follows redirects | Add `allow_redirects=False` to aiohttp fallback; or remove fallback and hard-depend on httpx |
| FG-AUD-020 | P3 | `/ui/token` uses GET for cookie-setting | Change to POST; add CSRF token check consistent with rest of UI |
| FG-AUD-012 | P1 | `/stats/debug` public bypass + `require_status_auth` env-key-only | Require `verify_api_key_detailed()` for stats endpoints; or move out of `PUBLIC_PATHS_EXACT` |

### Threat model summary

| Threat actor | Attack surface | Current control | Residual gap |
|-------------|---------------|-----------------|-------------|
| External unauthenticated | All `/ui/*` | `require_scopes("ui:read")` router dep | None (auth enforced) |
| External unauthenticated | `/_debug/*` | `require_status_auth` (env-key-only) | In auth-disabled configs, fully open |
| Compromised config value | `AG_CORE_BASE_URL`, `FG_OPA_URL` | `follow_redirects=False` on all clients | DNS rebinding on product health URL (FG-AUD-011) |
| Malformed JWT / forged token | Federation service | JWKS signature verify, `FG_FEDERATION_ISSUER` env | None — fully closed |
| Rogue agent enrollment | `/agent/enroll` (public) | Agent-side attestation (out of scope) | Rogue agent could enroll |
| Cross-tenant data access | All tenant-scoped routes | `AuthGateMiddleware` + `bind_tenant_id()` | Contract app lacks middleware tenant context |
| DoS via large payloads | All routes | `RequestValidationMiddleware`, `DoSGuardMiddleware` | Contract app lacks both middleware |

### Risk acceptance log

| ID | Accepted by | Rationale |
|----|-------------|-----------|
| FG-AUD-011 | Requires owner review | TOCTOU window is narrow; exploit requires DNS control |
| FG-AUD-015 | Requires owner review | Router dep provides real auth; handler check is defense-in-depth |
| FG-AUD-016 | Requires owner review | Architectural refactor; no immediate exploit path identified |
| FG-AUD-017 | Requires owner review | Contract app appears test-only; confirm no production deployment |
| FG-AUD-019 | Requires owner review | Fallback triggered only if httpx unavailable |
| FG-AUD-020 | Requires owner review | `samesite=lax` mitigates most CSRF vectors |
| FG-AUD-012 | Requires owner review | Consider requiring per-tenant key for stats endpoints |
