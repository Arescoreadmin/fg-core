# Secret Rotation Runbook

**For:** FrostGate operators performing secret rotation before a client engagement or after a suspected exposure.  
**Time to complete:** 30–90 minutes depending on which secrets are rotated.  
**DoD gate:** L12 — top-5 blast-radius secrets rotated; rotation procedure documented; Anthropic auto-recharge enabled.

---

## Secret Inventory — Top 5 by Blast Radius

| Rank | Name | Location | What it protects | Blast radius if leaked |
|------|------|----------|-----------------|----------------------|
| 1 | `FG_KEY_PEPPER` | Railway (API service) | HMAC-SHA256 key for all credential fingerprint lookups (portal keys, connector keys, agent device keys) | **Critical** — all existing credentials unlookable; must regenerate every portal key, connector key, and agent key after rotation |
| 2 | `FG_SIGNING_SECRET` | Railway (API service) + agent build env | Signs agent enrollment tokens and device key contracts | **High** — all enrolled agents must re-enroll after rotation |
| 3 | `FG_INTERNAL_GATEWAY_SECRET` | Railway (API + Console services) + Vercel (portal env) | Internal service-to-service auth between API, Console, and Portal | **High** — console and portal lose API access during the rotation window; rolling update required |
| 4 | `FG_REPORT_SIGNING_KEY` | Railway (API service) | HMAC over report records for tamper detection (audit integrity chain) | **Medium** — new reports unaffected; existing reports can no longer be re-verified with old key once rotated |
| 5 | `PORTAL_SESSION_SECRET` | Vercel (portal deployment) | Signs portal session cookies (OIDC flow) | **Low-medium** — immediately invalidates all active portal sessions; affected users must log in again |

### Additional secrets to inventory (not top 5 but relevant to July incident history)

| Name | Location | Notes |
|------|----------|-------|
| `FG_INTERNAL_AUTH_SECRET` | Railway (API service) | Legacy alias for `FG_INTERNAL_GATEWAY_SECRET`; the R6 migration (PR #553) standardised on the canonical name but the legacy var remains as a fallback — set both to the same new value during rotation |
| `FG_ACKNOWLEDGMENT_KEY` | Railway (API service) | Signs engagement acknowledgment tokens; rotate if shared in any incident channel |
| `RESEND_API_KEY` | Railway (Console + API) | Email delivery; if leaked, attacker can send email from FrostGate domain; rotate in Resend dashboard |
| `FG_API_KEY` | Railway (API service) | Console → API auth key; rotate if shared during debugging |

---

## Before You Start

- [ ] Take a pre-rotation database backup: `scripts/backup/fg_backup.sh backup --type pre-maintenance` with `FG_BACKUP_OPERATOR` set.
- [ ] Confirm API health: `GET /health` returns 200.
- [ ] Confirm no active client engagement is in progress — rotation causes brief disruption.
- [ ] Have the Railway dashboard open (API service → Variables) and Vercel dashboard open (portal project → Environment Variables).
- [ ] Have a local terminal ready to generate secrets (see §Generation below).
- [ ] Have the health endpoint ready to poll after each change.

---

## Generating New Secrets

Use one of these methods. Never reuse an existing value or set a value from memory.

```bash
# 64-byte hex (preferred for FG_KEY_PEPPER, FG_SIGNING_SECRET, FG_REPORT_SIGNING_KEY)
python3 -c "import secrets; print(secrets.token_hex(32))"

# 32-byte base64 (use for FG_INTERNAL_GATEWAY_SECRET, FG_INTERNAL_AUTH_SECRET)
python3 -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"

# 64-byte hex (use for PORTAL_SESSION_SECRET — must be long for cookie signing)
python3 -c "import secrets; print(secrets.token_hex(64))"
```

Generate each value in a private terminal session. Do not paste values into chat, tickets, or email.

---

## Rotation Procedures

Execute in this order. Lower blast radius first so any mistakes are recoverable before touching the most critical secrets.

---

### 1. PORTAL_SESSION_SECRET — Rotate First (Lowest Blast Radius)

**Effect:** All active portal sessions are immediately invalidated. Any user currently logged into the portal will be redirected to the login page on their next request.

**Steps:**

1. Generate new value: `python3 -c "import secrets; print(secrets.token_hex(64))"`
2. Open Vercel → portal project → Settings → Environment Variables.
3. Update `PORTAL_SESSION_SECRET` to the new value in all environments (Production + Preview).
4. Trigger a Vercel redeployment (or wait for next deploy).
5. After deploy: open the portal in an incognito window → confirm the login page renders → complete a login flow.
6. Confirm the old session (if any) no longer works.

**Health check:**
- `GET <portal-url>/` redirects to login (not a 500 or blank page) — PASS
- Login flow completes successfully — PASS

**Rollback:** Revert the Vercel env var to the previous value and redeploy.

---

### 2. FG_REPORT_SIGNING_KEY — Rotate Second

**Effect:** New reports are signed with the new key. Existing reports in the database retain their old signature; they can still be served but will no longer pass re-verification with the new key. Keep the old key value recorded in a secure notes document until the engagement history is archived or migrated.

**Steps:**

**Key type:** Ed25519. `FG_REPORT_SIGNING_KEY` is the 32-byte private seed (64-char hex). `FG_REPORT_SIGNING_PUBLIC_KEY`, if set, is the matching Ed25519 public key used by verification callers (`GET /signing/public-key`, `/verify`). `get_public_key_hex()` prefers `FG_REPORT_SIGNING_PUBLIC_KEY` over deriving from the private key, so if this var is set you **must** update it too — otherwise new reports sign with the new key but verification uses the old public key and all new reports fail the `/verify` endpoint.

1. Generate a new keypair. Run in a private terminal:
   ```bash
   python3 -c "
   from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
   import secrets
   seed = secrets.token_bytes(32)
   priv = Ed25519PrivateKey.from_private_bytes(seed)
   pub = priv.public_key().public_bytes_raw()
   print('PRIVATE_SEED:', seed.hex())
   print('PUBLIC_KEY:  ', pub.hex())
   "
   ```
2. Open Railway → API service → Variables.
3. Update `FG_REPORT_SIGNING_KEY` to the `PRIVATE_SEED` value.
4. Check if `FG_REPORT_SIGNING_PUBLIC_KEY` is set. If it is, update it to the `PUBLIC_KEY` value from the same keypair. If it is not set, skip this step (the API derives the public key from the private seed automatically).
5. Wait for Railway deploy to complete (check Railway deploy logs).
6. Verify a report using the new key: generate a test report on a `[TEST]` engagement, then call `GET /signing/public-key` → confirm the returned hex matches `PUBLIC_KEY` above. If the endpoint is unavailable, confirm report generation completed without error.
7. Record the old `FG_REPORT_SIGNING_KEY` value in a secure offline note labelled `FG_REPORT_SIGNING_KEY_PRE_<date>` — needed to verify pre-rotation reports against the old public key.

**Health check:**
- `GET /health` → 200 — PASS
- `GET /signing/public-key` returns the new public key hex — PASS
- Report generation on a test engagement completes without error — PASS

**Rollback:** Revert both `FG_REPORT_SIGNING_KEY` and `FG_REPORT_SIGNING_PUBLIC_KEY` (if set) to the old values; Railway redeploys.

---

### 3. FG_INTERNAL_GATEWAY_SECRET — Rotate Third (= R6 Deploy 2)

**Background:** The R6 gateway secret convergence (PR #553) introduced `FG_INTERNAL_GATEWAY_SECRET` as the canonical variable. The code resolves in order: `FG_INTERNAL_GATEWAY_SECRET` → `FG_INTERNAL_AUTH_SECRET` → `FG_ADMIN_GATEWAY_INTERNAL_TOKEN` → `FG_INTERNAL_TOKEN`. Until Deploy 2 is executed, the system still uses `FG_INTERNAL_AUTH_SECRET`. This rotation executes Deploy 2.

**Effect during rotation window:** Console and portal lose API access between when the API service redeploys and when console/portal are updated. Plan for a 2–3 minute window.

**Steps:**

1. Generate new value (base64): `python3 -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"`
2. Open Railway → API service → Variables.
3. Set `FG_INTERNAL_GATEWAY_SECRET` to the new value (do NOT delete `FG_INTERNAL_AUTH_SECRET` yet — the legacy fallback keeps the system working if the new var is somehow missed).
4. Also set `FG_INTERNAL_AUTH_SECRET` to the same new value (keeps the fallback in sync; eliminates any stale-old-value scenario).
5. Wait for Railway API deploy to complete.
6. Open Railway → Console service → Variables. Set `FG_INTERNAL_GATEWAY_SECRET` and `FG_INTERNAL_AUTH_SECRET` to the same new value.
7. Wait for Railway Console deploy.
8. Open Vercel → portal project → Environment Variables. Set `FG_INTERNAL_GATEWAY_SECRET` (and `FG_INTERNAL_AUTH_SECRET` if present) to the same new value. Redeploy.
9. After all three services are live: confirm console login works end-to-end.

**Health check:**
- `GET /health` on API → 200 — PASS
- Console login completes (Auth0 → console dashboard loads) — PASS
- `GET <portal-url>/` renders without 502/503 — PASS
- Create a test engagement in console → PASS

**Rollback:** Once `FG_INTERNAL_GATEWAY_SECRET` is set, the legacy `FG_INTERNAL_AUTH_SECRET` fallback is never consulted — the canonical var takes precedence. Rollback must restore or remove `FG_INTERNAL_GATEWAY_SECRET` on every consumer:
1. Railway API → revert `FG_INTERNAL_GATEWAY_SECRET` to the old value (or delete it to fall back to `FG_INTERNAL_AUTH_SECRET` if still set to the old value).
2. Vercel console → revert or delete `FG_INTERNAL_GATEWAY_SECRET`.
3. Revert `FG_INTERNAL_AUTH_SECRET` to the old value on both Railway API and Vercel console.
4. Wait for all services to redeploy; verify console login.

---

### 4. FG_SIGNING_SECRET — Rotate Fourth

**Effect:** `FG_SIGNING_SECRET` is enforced as a required production env var by startup validation and appears in the agent installer's secret-denylist (ensuring it never leaks into service command arguments). No runtime signing operation in the API consumes this value — agent credential fingerprinting uses `FG_KEY_PEPPER` (HMAC-SHA256). Rotating this value satisfies the required-env enforcement check and removes any exposure if the value was shared during incident recovery, but does not invalidate existing enrolled agents or portal credentials.

**Steps:**

1. Confirm no active field assessments are in progress.
2. Generate new value: `python3 -c "import secrets; print(secrets.token_hex(32))"`
3. Open Railway → API service → Variables. Update `FG_SIGNING_SECRET`.
4. Wait for Railway deploy. Verify `/health` → 200.

**Health check:**
- `GET /health` → 200 — PASS

**Rollback:** Revert Railway env var; no credential or session impact.

---

### 5. FG_KEY_PEPPER — Rotate Last (Highest Blast Radius)

**WARNING:** Rotating `FG_KEY_PEPPER` immediately invalidates ALL credential lookups stored in the database. Every portal key, connector key, and agent device key has its fingerprint stored as `HMAC-SHA256(secret_part, old_pepper)` in `tenant_credentials`. After rotation, none of them can be looked up by fingerprint — all authentications via `credential_authority.py` will return 404/invalid.

**Only rotate if:** the old pepper is confirmed or suspected to have been shared in any channel during incident recovery. If there is no evidence of exposure, the operational cost is severe enough to defer to a scheduled maintenance window with pre-planned key migration.

**Pre-conditions:**
- [ ] Active client count is zero.
- [ ] A fresh database backup exists (run `fg_backup.sh backup --type pre-maintenance` within the last 60 minutes).
- [ ] You have a count of all active credentials: `SELECT credential_type, COUNT(*) FROM tenant_credentials WHERE status = 'active' GROUP BY credential_type;`

**Steps:**

1. Generate new value: `python3 -c "import secrets; print(secrets.token_hex(32))"`
2. Open Railway → API service → Variables. Update `FG_KEY_PEPPER`.
3. Wait for Railway deploy. Verify `/health` → 200.
4. The old fingerprints in `tenant_credentials` are now orphaned. Credential lookups will fail with "invalid credential" or "not found".
5. Regenerate all active credentials:
   - **Portal keys:** in the console, revoke and reissue each active portal key.
   - **Connector keys:** revoke and reissue from the tenant admin panel.
   - **Agent device keys:** re-enroll each agent.
6. Verify each credential type can authenticate successfully.

**Health check:**
- `GET /health` → 200 — PASS
- Issue one portal key and authenticate with it — PASS
- Issue one connector key and authenticate — PASS
- All `fa_credential_store` rows have valid fingerprints (no orphaned rows from before rotation) — confirm count matches expected

**Rollback:** Revert Railway env var to old pepper; existing fingerprints immediately work again (no DB changes needed). Do NOT rotate credentials before confirming the rotation is permanent.

---

## Post-Rotation Checklist

Run through these after completing all planned rotations.

- [ ] `GET /health` on Railway API → 200.
- [ ] Console login (Auth0) → dashboard loads.
- [ ] Portal renders → login page accessible.
- [ ] Test engagement created and opened in console.
- [ ] Report generation on test engagement completes (AI executive summary generated).
- [ ] No Railway service restart loops (check deploy logs).
- [ ] `first_client_prep.md` §1 env var confirmation still passes for all rotated vars.
- [ ] Record completion in `docs/governance/status/L12_evidence_manifest.md`.

---

## Evidence Required for DoD L12

After completing the rotations planned for this cycle, fill in `docs/governance/status/L12_evidence_manifest.md`:
- Date and time of each rotation.
- Operator email.
- Which secrets were rotated (not the values — confirmation only).
- Health check results.
- Anthropic auto-recharge status (see §Anthropic Auto-Recharge below).

---

## Anthropic Auto-Recharge (T2 — FG-LR-013)

**Prerequisite for DoD L12.**

**Steps:**
1. Log in to `console.anthropic.com`.
2. Navigate to **Billing** → **Plans & Billing**.
3. Enable **Auto-recharge** with:
   - Trigger threshold: when balance drops below **$10**.
   - Recharge amount: **$50** per recharge.
   - Monthly cap: **$200** (prevents runaway cost if the API key is misused).
4. Confirm the current balance is ≥ $10 before the next engagement. If below, add credit manually.
5. Screenshot the billing panel showing auto-recharge enabled — attach or reference in `L12_evidence_manifest.md`.
6. Add a balance check line to `first_client_prep.md` §1 (already done in this PR — confirm the item is present before the engagement).

**Rotated RESEND_API_KEY (if applicable):**
If `RESEND_API_KEY` was shared during any incident recovery, rotate it in the Resend dashboard (resend.com → API Keys → Revoke + Create new) and update the Railway Console service variable.

---

## Scheduling Future Rotations

| Secret | Recommended rotation cadence |
|--------|------------------------------|
| `PORTAL_SESSION_SECRET` | Every 90 days, or immediately after any suspected portal compromise |
| `FG_REPORT_SIGNING_KEY` | Every 12 months; also before archiving engagement history |
| `FG_INTERNAL_GATEWAY_SECRET` | Every 90 days |
| `FG_SIGNING_SECRET` | Every 180 days, or after any agent security incident |
| `FG_KEY_PEPPER` | Only on confirmed exposure; require a maintenance window and full credential regeneration |

Document each rotation in `L12_evidence_manifest.md` with date, operator, and health-check results.
