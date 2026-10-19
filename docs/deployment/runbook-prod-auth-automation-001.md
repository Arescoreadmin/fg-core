# PROD-AUTH-AUTOMATION-001 — Production Authentication Verification Runbook

**Work item:** PROD-AUTH-AUTOMATION-001  
**Governance status:** CUSTOMER_ZERO_TRUST=NOT_PROVEN  
**Platform:** Next.js / Auth.js / Auth0 on Vercel  

---

## Mode A — Public Production Smoke (Automated)

Safe to run after every approved deployment. No credentials required.

```bash
python tools/testing/production/prod_smoke_001.py
```

With evidence artifact:
```bash
python tools/testing/production/prod_smoke_001.py --write-evidence
```

With Vercel deployment resolution (requires read-only API token):
```bash
VERCEL_TOKEN=<read-only-token> \
VERCEL_PROJECT_ID=<project-id> \
VERCEL_TEAM_ID=<team-id> \
python tools/testing/production/prod_smoke_001.py --write-evidence
```

### Mode A checks

| Check | Description | Expected |
|-------|-------------|----------|
| SMOKE-001 | Console root accessible | HTTP 200 |
| SMOKE-002 | Login page accessible | HTTP 200 |
| SMOKE-003 | Unauthenticated session endpoint | HTTP 200 JSON |
| SMOKE-004 | Dashboard redirects unauthenticated | 3xx → /login |
| SMOKE-005 | Vercel deployment SHA (if token present) | READY + SHA |
| SMOKE-006 | No sensitive fields in session response | No secrets leaked |

---

## Mode B — Authenticated Playwright Verification (Operator-Approved)

**NOT automatically enabled.** Requires explicit operator opt-in.  
**Never run against a real customer account.**

### Requirements

1. A dedicated synthetic identity in Auth0 with minimal privileges
2. A dedicated test tenant (not a customer tenant)
3. The synthetic identity must not have MFA required
4. All three activation env vars must be set

### Activation

```bash
FG_PROD_AUTH_TEST_ENABLED=true \
FG_PROD_TEST_EMAIL=<synthetic-identity@your-domain.com> \
FG_PROD_TEST_PASSWORD=<password> \
python tools/testing/production/auth_harness_001.py --write-evidence
```

Visible browser (for operator inspection):
```bash
FG_PROD_AUTH_TEST_ENABLED=true \
FG_PROD_TEST_EMAIL=<email> \
FG_PROD_TEST_PASSWORD=<password> \
python tools/testing/production/auth_harness_001.py --headless false
```

### Mode B checks

| Check | Description | Expected |
|-------|-------------|----------|
| AUTH-001 | Auth0 login page renders | Auth0 UL page or FrostGate /login |
| AUTH-002 | Auth.js session cookie established | Session cookie present after login |
| AUTH-003 | Session cookie security attributes | Secure=true, HttpOnly=true, SameSite |
| AUTH-004 | Authenticated /dashboard access | HTTP 200 on /dashboard |
| AUTH-005 | Unauthorized admin route rejected | 401/403 or redirect to /unauthorized |
| AUTH-006 | Logout clears session cookie | Session cookie absent after logout |
| AUTH-007 | Post-logout session endpoint empty | No user in session response |
| AUTH-008 | Post-logout /dashboard redirects | Redirect to /login |
| AUTH-009 | Auth0 SLO redirect issued | Auth0 /v2/logout observed |

### Dependency: install Playwright

```bash
pip install playwright
playwright install chromium
```

---

## Operator-Assisted Fallback

When Mode B cannot run (MFA required, CAPTCHA, Auth0 bot detection, or credentials not authorized), use this manual procedure.

### Pre-conditions

- Access to the production console at https://console.frostgate.ai
- A dedicated test account (do not use a real customer account)
- Record all observations with timestamps

### Step 1 — Login flow

1. Open https://console.frostgate.ai/login in a private browser window
2. Observe: FrostGate login page loads (HTTP 200)
3. Click "Sign in with Auth0"
4. Observe: Browser redirects to Auth0 Universal Login
5. Enter test account credentials
6. Observe: Successful login, browser redirected to /dashboard

**Record:** timestamp, URL sequence, HTTP status codes

### Step 2 — Session cookie inspection

1. Open browser developer tools → Application → Cookies → console.frostgate.ai
2. Locate `__Secure-authjs.session-token`
3. Verify:
   - Secure: ✓
   - HttpOnly: ✓
   - SameSite: Lax or Strict
4. Record exact cookie attributes

### Step 3 — Dashboard access

1. Navigate to https://console.frostgate.ai/dashboard
2. Observe: Dashboard renders (HTTP 200, no redirect)
3. Record: timestamp, HTTP status

### Step 4 — Unauthorized route rejection

1. Navigate to https://console.frostgate.ai/unauthorized or attempt access to an admin-only page
2. Observe: 401/403 response or redirect to /unauthorized
3. Record: HTTP status, URL

### Step 5 — Logout and session invalidation

1. Navigate to https://console.frostgate.ai/api/auth/logout
2. Observe: Browser redirects to Auth0 /v2/logout, then to /login
3. Verify session cookie `__Secure-authjs.session-token` is deleted (DevTools → Cookies)
4. Navigate to https://console.frostgate.ai/dashboard
5. Observe: Redirect to /login (session invalidated)
6. Navigate to https://console.frostgate.ai/api/auth/session
7. Observe: HTTP 200 JSON with no user field (or empty `{}`)

**Record:** all timestamps, cookie states, HTTP responses

### Evidence recording

Record observations in:
```
contracts/artifacts/identity/prod-auth-automation-001-auth-evidence.json
```

Update `AUTH-00x` check entries with:
- `result`: PASS / FAIL / NOT_PROVEN
- `observed`: what was actually observed
- `timestamp`: ISO 8601 UTC

---

## CI Integration

### Mode A (automatic after deployment)

Runs on every approved deployment via `.github/workflows/prod-auth-smoke.yml`.

Triggered automatically by:
- `workflow_dispatch` with `mode: smoke`
- After `fg-required` passes

### Mode B (operator-approved only)

Triggered manually via:
```bash
gh workflow run prod-auth-smoke.yml -f mode=authenticated
```

Requires repository secret `FG_PROD_TEST_EMAIL` and `FG_PROD_TEST_PASSWORD` to be set in GitHub Actions secrets.

**Mode B is never triggered automatically.**

---

## Secret storage

| Secret | Location | Description |
|--------|----------|-------------|
| `VERCEL_TOKEN` | GitHub Actions secret | Read-only Vercel token for deployment resolution |
| `VERCEL_PROJECT_ID` | GitHub Actions variable | Console project ID |
| `VERCEL_TEAM_ID` | GitHub Actions variable | Vercel team ID |
| `FG_PROD_TEST_EMAIL` | GitHub Actions secret | Synthetic test identity email |
| `FG_PROD_TEST_PASSWORD` | GitHub Actions secret | Synthetic test identity password |

Secrets are **never printed** in evidence artifacts or CI logs.

---

## Governance

- `CUSTOMER_ZERO_TRUST=NOT_PROVEN` — interactive authentication is NOT_PROVEN until Mode B passes
- `CUSTOMER_ZERO_ACCEPTANCE=BLOCKED` — not unblocked by this harness
- Evidence fingerprint must be recorded in governance artifacts after each run
- Any FAIL result blocks the corresponding governance gate until remediated
