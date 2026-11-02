# PROD-AUTH-AUTOMATION-001 — Production Authentication Verification Runbook

**Work item:** PROD-AUTH-AUTOMATION-001  
**Hardening:** MODE-B-PROOF-HARDENING-001  
**Governance status:** CUSTOMER_ZERO_TRUST=NOT_PROVEN  
**Platform:** Next.js / Auth.js / Auth0 on Vercel  

---

## Summary

Mode A (public smoke) verifies the Console is reachable and unauthenticated routes behave correctly.  
Mode B (authenticated) verifies a real actor can authenticate, receives correct authorization, and that denial paths are enforced. Mode B uses a fail-closed acceptance model: any required check that is NOT_PROVEN, BLOCKED, or FAIL prevents acceptance.

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

1. Dedicated synthetic identity in Auth0 with the appropriate role
2. Dedicated test tenant (not a customer tenant)
3. All three activation env vars must be set
4. If MFA is enabled on the account, operator-assisted verification is required for Strategy A; see §Strategy B below

### Actor Profiles

| Profile | Positive route | Key negative assertions |
|---------|---------------|------------------------|
| `internal_operator` | `/dashboard` | Admin route rejected |
| `client_executive` | `/dashboard/executive` | `/dashboard` denied, admin UI/API denied, cross-tenant denied |

### Activation — internal_operator

```bash
FG_PROD_AUTH_TEST_ENABLED=true \
FG_PROD_TEST_EMAIL=<operator-identity@your-domain.com> \
FG_PROD_TEST_PASSWORD=<password> \
python tools/testing/production/auth_harness_001.py \
  --actor-profile internal_operator \
  --write-evidence
```

### Activation — client_executive

```bash
FG_PROD_AUTH_TEST_ENABLED=true \
FG_PROD_TEST_EMAIL=frostgatetest@gmail.com \
FG_PROD_TEST_PASSWORD=<password> \
python tools/testing/production/auth_harness_001.py \
  --actor-profile client_executive \
  --write-evidence
```

Visible browser (for operator inspection):
```bash
FG_PROD_AUTH_TEST_ENABLED=true \
FG_PROD_TEST_EMAIL=<email> \
FG_PROD_TEST_PASSWORD=<password> \
python tools/testing/production/auth_harness_001.py \
  --actor-profile client_executive \
  --headless false
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | ACCEPTED — all required checks PASS |
| 1 | REJECTED_FAIL — one or more checks FAIL |
| 2 | BLOCKED — activation guard not satisfied or MFA prerequisite blocked |
| 3 | REJECTED_INCOMPLETE — NOT_PROVEN, missing, or empty evidence |
| 4 | Unrecoverable error (browser crash) |

### Independent evidence verification

After a run, independently verify the evidence fingerprint and acceptance decision:
```bash
python tools/testing/production/verify_evidence.py \
  contracts/artifacts/identity/prod-auth-client-executive-evidence.json
```

Exit 0 = ACCEPTED. Nonzero = not accepted (see exit code table above).

---

## Mode B checks — internal_operator

| Check | Description | Expected |
|-------|-------------|----------|
| AUTH-001 | Auth0 login page rendered | Auth0 UL page |
| AUTH-002 | Auth.js session cookie established | Session cookie present |
| AUTH-003 | Session cookie security attributes | Secure=true, HttpOnly=true, SameSite |
| AUTH-004 | /dashboard accessible (internal only) | HTTP 200 on /dashboard |
| AUTH-005 | Unauthorized admin route rejected | 401/403/405 or redirect |
| AUTH-006 | Logout clears session cookie | Cookie absent after logout |
| AUTH-007 | Post-logout session endpoint empty | No user in session |
| AUTH-008 | Post-logout protected route redirects | Redirect to /login |
| AUTH-009 | Auth0 SLO redirect issued | Auth0 /v2/logout observed |

## Mode B checks — client_executive

| Check | Description | Expected |
|-------|-------------|----------|
| AUTH-001 | Auth0 login page rendered | Auth0 UL page |
| AUTH-002 | Auth.js session cookie established | Session cookie present |
| AUTH-003 | Session cookie security attributes | Secure=true, HttpOnly=true, SameSite |
| CLIENT-001 | /dashboard/executive accessible | HTTP 200 on /dashboard/executive |
| CLIENT-002 | Tenant-scoped BFF read succeeds | HTTP 200 (requires tenant binding) |
| CLIENT-003 | /dashboard denied → /unauthorized | Redirect to /unauthorized |
| CLIENT-004 | Platform-admin UI denied | Redirect to /unauthorized |
| CLIENT-005 | Platform-admin API denied | HTTP 401 or 403 |
| CLIENT-006 | Cross-tenant Core API denied | HTTP 403 |
| CLIENT-007 | Forged/duplicate tenant context denied | HTTP 422 or 403 |
| AUTH-006 | Logout clears session cookie | Cookie absent after logout |
| AUTH-007 | Post-logout session endpoint empty | No user in session |
| AUTH-008 | Post-logout protected route redirects | Redirect to /login |
| AUTH-009 | Auth0 SLO redirect issued | Auth0 /v2/logout observed |

### Prerequisites for client_executive

CLIENT-002 and CLIENT-006 require the synthetic test identity to have a tenant binding
in the Core API (`portal_user_memberships` or `principal_tenant_bindings`). Without this
binding, these checks are marked BLOCKED and the run will not ACCEPT.

To establish the binding:
1. Create a synthetic test tenant in the development database
2. Create a principal_tenant binding for `frostgatetest@gmail.com` via Core API admin
3. Re-run the harness

---

## Strategy A: Unattended Automation

If the synthetic account has no MFA enabled and credentials are available as CI secrets:
```bash
gh workflow run prod-auth-smoke.yml \
  -f mode=authenticated \
  -f actor_profile=client_executive
```

If MFA is active, the harness will return exit code 3 (REJECTED_INCOMPLETE) and
mark AUTH-002 as BLOCKED. Use Strategy B.

---

## Strategy B: Operator-Assisted Verification

When MFA is required or automated login cannot complete, use this manual procedure.

**The synthetic account for FrostGate testing: `frostgatetest@gmail.com` has MFA enabled.**  
Strategy B is the authoritative verification path until MFA is resolved.

### Pre-conditions

- Access to the production console at https://console.frostgate.ai
- The `frostgatetest@gmail.com` synthetic test account (do not use a real customer account)
- Auth0 TOTP authenticator access for the synthetic account
- Record all observations with timestamps

### Step 1 — Login flow

1. Open https://console.frostgate.ai/login in a private browser window
2. Observe: FrostGate login page loads (HTTP 200)
3. Complete Auth0 login with synthetic account credentials
4. Complete MFA challenge
5. Observe: Successful login, browser redirected

**Record:** timestamp, URL sequence, HTTP status codes

### Step 2 — Session cookie inspection

1. Open browser DevTools → Application → Cookies → console.frostgate.ai
2. Locate `__Secure-authjs.session-token`
3. Verify: Secure=✓, HttpOnly=✓, SameSite=Lax or Strict
4. Record exact cookie attributes

### Step 3 — client_executive positive authorization

1. Navigate to https://console.frostgate.ai/dashboard/executive
2. Observe: Page renders successfully (HTTP 200)
3. Record: timestamp, HTTP status

### Step 4 — Negative authorization

1. Navigate to https://console.frostgate.ai/dashboard
2. Observe: Redirect to /unauthorized (NOT the dashboard)
3. Navigate to https://console.frostgate.ai/admin/tenants
4. Observe: Redirect to /unauthorized
5. Record: HTTP status and URL for each attempt

### Step 5 — Logout and session invalidation

1. Navigate to https://console.frostgate.ai/api/auth/logout
2. Observe: Browser redirects to Auth0 /v2/logout, then to /login
3. Verify session cookie is deleted (DevTools → Cookies)
4. Navigate to https://console.frostgate.ai/dashboard
5. Observe: Redirect to /login (session invalidated)
6. Navigate to https://console.frostgate.ai/api/auth/session
7. Observe: HTTP 200 JSON with no user field

**Record:** all timestamps, cookie states, HTTP responses

### Recording operator-assisted evidence

After completing the manual procedure, generate a local evidence record:

```bash
# Create evidence with operator_assisted mode
python - <<'EOF'
import json, sys
sys.path.insert(0, '.')
from tools.testing.production.evidence import (
    EvidenceRecord, CheckResult, EvidenceResult, finalize, write_evidence, now_iso
)
from pathlib import Path

r = EvidenceRecord(
    verification_profile="client_executive",
    test_execution_mode="operator_assisted",
    evidence_provenance="Operator-assisted manual verification; MFA completed by operator",
    console_origin="https://console.frostgate.ai",
    environment="production",
    required_check_manifest=[
        "AUTH-001","AUTH-002","AUTH-003","CLIENT-001","CLIENT-003","CLIENT-004",
        "AUTH-006","AUTH-007","AUTH-008"
    ],
)
# Fill in checks with PASS/FAIL/NOT_PROVEN based on observations above
r.checks = [
    CheckResult("AUTH-001","Login page rendered","Auth0 UL","Observed",EvidenceResult.PASS,now_iso()),
    CheckResult("AUTH-002","Session established","Session cookie","Observed",EvidenceResult.PASS,now_iso()),
    # ... add remaining checks
]
finalize(r)
write_evidence(r, Path("contracts/artifacts/identity/prod-auth-client-executive-evidence.json"))
print("Evidence written. Fingerprint:", r.evidence_fingerprint)
EOF
```

After writing evidence, run the independent verifier:
```bash
python tools/testing/production/verify_evidence.py \
  contracts/artifacts/identity/prod-auth-client-executive-evidence.json
```

---

## Dependency: install Playwright

```bash
pip install playwright
playwright install chromium
```

---

## CI Integration

### Mode A (automatic after deployment)

Triggered automatically by `.github/workflows/prod-auth-smoke.yml` after frostgate-core-ci passes.

### Mode B (operator-approved only)

```bash
gh workflow run prod-auth-smoke.yml \
  -f mode=authenticated \
  -f actor_profile=client_executive

# Or for internal_operator:
gh workflow run prod-auth-smoke.yml \
  -f mode=authenticated \
  -f actor_profile=internal_operator
```

**Mode B is NEVER triggered automatically.**

Evidence is uploaded as a CI artifact even when the job fails (so investigation is possible).  
The `verify_evidence` step is a distinct, hard-fail acceptance gate — it does not use
`continue-on-error`.

---

## Secret storage

| Secret | Location | Description |
|--------|----------|-------------|
| `VERCEL_TOKEN` | GitHub Actions secret | Read-only Vercel token |
| `VERCEL_PROJECT_ID` | GitHub Actions variable | Console project ID |
| `VERCEL_TEAM_ID` | GitHub Actions variable | Vercel team ID |
| `FG_PROD_TEST_EMAIL` | GitHub Actions secret | Synthetic test identity email |
| `FG_PROD_TEST_PASSWORD` | GitHub Actions secret | Synthetic test identity password |

Secrets are **never printed** in evidence artifacts or CI logs.  
Evidence fingerprints are computed server-side and must be independently verified.

---

## Governance

- `CUSTOMER_ZERO_TRUST=NOT_PROVEN` — Production Mode B is NOT_PROVEN until a complete
  run with ACCEPTED acceptance_decision is produced
- `CUSTOMER_ZERO_ACCEPTANCE=BLOCKED` — not unblocked by this harness alone
- Evidence fingerprint must be recorded in governance artifacts after each run
- Any FAIL result blocks the corresponding governance gate until remediated
- Simulation evidence (test_execution_mode=simulation) does NOT satisfy the production gate
- Operator-assisted evidence satisfies the gate only if all required checks are PASS

---

## Production Activation Checklist (client_executive)

Before claiming Mode B is satisfied for client onboarding:

- [ ] `frostgatetest@gmail.com` has `client_executive` role in Auth0
- [ ] Synthetic test tenant exists in Core database
- [ ] `frostgatetest@gmail.com` has a `principal_tenant_binding` in Core
- [ ] MFA is handled (either Strategy A unattended account or Strategy B manual)
- [ ] Run harness: exit code 0
- [ ] Run verifier: exit code 0 (acceptance_decision = ACCEPTED)
- [ ] Evidence fingerprint recorded in governance artifacts
- [ ] No raw credentials, cookies, or JWT payloads in evidence file
- [ ] Upload evidence as PR artifact
- [ ] `verify_evidence.py` passes in CI
