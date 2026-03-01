# PR Fix Log (Strict)

## Purpose

This log records **completed, intentional fixes**.

Each entry documents **one issue and one resolution**.

If multiple issues were fixed, they **MUST be logged as separate entries**.

Entries in this log are **final** unless explicitly reversed.

---

## Rules (Mandatory)

AI reviewers **MUST**:

1. Treat each entry as resolved
2. Avoid reopening logged issues
3. Avoid suggesting alternative fixes
4. Avoid combining entries

This log overrides heuristics and “best practice” suggestions.

---

## Entry Format (Enforced)

Each entry MUST contain:

- Date
- Area
- Issue (single, specific)
- Resolution (single, specific)
- AI Notes (instructions, not commentary)

---

## Entries

---

### 2026-03-01 — Route Inventory Canonical Source

**Area:** CI · Route Inventory

**Issue:**  
Route inventory comparison used multiple discovery sources, causing inconsistent results.

**Resolution:**  
AST-derived route discovery was designated as the sole canonical inventory source.

**AI Notes:**  
- Do NOT suggest runtime app inspection as authoritative
- Do NOT recommend hybrid inventory sources

---

### 2026-03-01 — Route Inventory Runtime-Only Drift

**Area:** CI · Governance

**Issue:**  
`route-inventory-audit` failed on runtime-only routes not present in OpenAPI.

**Resolution:**  
Runtime-only drift was downgraded to warning-only behavior.

**AI Notes:**  
- Do NOT escalate runtime-only drift to failure
- Do NOT recommend adding internal routes to OpenAPI

---

### 2026-03-01 — Duplicate `contract_routes` Definitions

**Area:** CI · Tooling

**Issue:**  
Multiple `contract_routes()` definitions caused lint failures and ambiguity.

**Resolution:**  
All local definitions were removed; a single imported implementation remains.

**AI Notes:**  
- Do NOT reintroduce local `contract_routes()` helpers
- Always import from `tools.ci.plane_registry_checks`

---

## Reopening Policy

An issue listed here may only be revisited if:

- The underlying behavior changes
- A new regression is introduced
- A PR explicitly states intent to reverse the fix

Absent these conditions, the issue is **closed**.

---

### 2026-03-01 — FG_OIDC_SCOPES Missing from Production Auth Validation

**Area:** Admin-Gateway · Auth · Startup Validation

**Issue:**
`FG_OIDC_SCOPES` was absent from `AuthConfig` and from production boot validation. The mandatory production auth model (§3) requires it to be present, but the system would boot in production without it, silently using a hardcoded default scope list.

**Resolution:**
Added `oidc_scopes: Optional[str]` to `AuthConfig`, loaded from `os.getenv("FG_OIDC_SCOPES")` in `get_auth_config()`. Added validation error "FG_OIDC_SCOPES must be set in production" to `validate()` when `is_prod` and the field is unset. `_filter_contract_ctx_config_errors` updated to suppress this error only in contract-generation context. `OIDCClient.get_authorization_url` now uses `config.oidc_scopes_list` instead of hardcoded defaults.

**AI Notes:**
- Admin-Gateway auth boundary enforced: OIDC scopes are now a mandatory boot-time requirement in production.
- OIDC enforcement: production will hard-fail if `FG_OIDC_SCOPES` is absent.
- Startup hard-fail behavior: `build_app()` raises `RuntimeError` if `FG_OIDC_SCOPES` is missing in prod.
- Control Tower integration impact: none (OIDC config is Admin-Gateway–only).

---

### 2026-03-01 — Open Redirect in /auth/login and /auth/callback (return_to Not Validated)

**Area:** Admin-Gateway · Auth Router · Session Redirect

**Issue:**
`/auth/login` and `/auth/callback` accepted arbitrary `return_to` URLs without validation. Attackers could craft a login URL that redirects victims to an external phishing site after authentication. This violates the mandatory "Redirect allowlist enforced (no arbitrary return_to)" requirement.

**Resolution:**
Added `_is_safe_return_to(url)` — rejects any URL that is not a relative path starting with `/`, including protocol-relative (`//evil.com`) and absolute (`https://evil.com`) URLs. Added `_safe_return_to(url)` which returns the validated URL or the safe default (`/admin/me`). Applied to both the dev-bypass login path and the OIDC state-store path in the login handler, and to the callback handler's state-store retrieval (re-validated even after storage, to defend against state-store corruption).

**AI Notes:**
- Do NOT remove or bypass `_is_safe_return_to` validation.
- Do NOT add logic that allows absolute URLs (e.g., a configured allowlist of external domains) without a security review.
- Any `return_to` containing `://` or starting with `//` must be rejected.

---

### 2026-03-01 — Dev Bypass Not Restricted to Localhost Origins

**Area:** Admin-Gateway · Auth Middleware · Dev Bypass Security

**Issue:**
`AuthMiddleware._get_session` activated dev bypass based only on `FG_ENV` (environment check), without verifying that the request `Host` header is a loopback address. If a dev instance were accidentally exposed to a non-localhost network, any client could access it without authentication.

**Resolution:**
Added `_is_localhost_request(request)` to `AuthMiddleware` that checks the `Host` header against `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`. `testserver` (used by TestClient) is also accepted in non-prod-like environments (it is a synthetic test hostname with no external reachability). Bypass is now refused with 401 for any non-loopback `Host` even when `FG_DEV_AUTH_BYPASS=true` in dev mode.

**AI Notes:**
- Do NOT add additional hosts to the loopback allowlist without explicit justification.
- `testserver` exception is non-prod-like environments ONLY; it is blocked in prod-like (where bypass is already refused at config level).
- Do NOT bypass the `_is_localhost_request` check in production paths.

---

_Last updated: 2026-03-01_