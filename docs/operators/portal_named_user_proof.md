# Portal Named-User Production Proof — T4 Runbook

**For:** FrostGate operators executing the T4 launch-readiness proof.  
**DoD gate:** L1 — a real external identity completes invite → OIDC login → engagement pages → logout with Core-side session revocation, without engineering intervention.  
**Closes:** FG-LR-002  
**Time to complete:** 30–60 minutes.  
**Evidence manifest:** `docs/governance/status/L01_evidence_manifest.md`

---

## What you need before you start

- A **cold external email address** that can authenticate via Auth0 (Google, Microsoft, or any social provider configured on the Auth0 app). Must not be `admin@arescore.ai` or any operator address — it must be a genuinely external identity that has never touched this Auth0 tenant.
- The production API key (`FG_API_KEY` from Railway API → Variables) to issue the invitation.
- The tenant ID for the engagement you will use for the proof (from the console tenant list or Railway env `CORE_TENANT_ID`).
- An engagement ID (`engagement_id`) — use an existing `[T4-TEST]` engagement or create one.

---

## Pre-flight checklist

- [ ] `GET https://api.frostgate.ai/health` → 200.
- [ ] `https://app.frostgate.ai` renders the **OIDC sign-in panel only** — no password field, no demo tenant selector. If a password field appears, `NEXT_PUBLIC_FG_ENV` is not `prod` in Vercel.
- [ ] `RESEND_API_KEY` is set in Railway → Console service → Variables (for other email flows; not used for this proof's invite delivery but required for post-engagement email).
- [ ] `PORTAL_SESSION_SECRET` is set in Vercel → `app.frostgate.ai` → Environment Variables (rotated 2026-07-31).
- [ ] `CORE_TENANT_ID` in Vercel portal is the **client's own tenant ID** — not `default`, not `frostgate-internal`.
- [ ] `CORE_API_URL` points to the Railway API.
- [ ] `CORE_API_KEY` is set.
- [ ] Auth0 app `Allowed Callback URLs` includes `https://app.frostgate.ai/api/auth/oidc/callback`.

---

## Step 1 — Create or verify a test engagement

Log into `console.frostgate.ai` as operator. Create (or confirm) an engagement labelled `[T4-TEST]`.

Note the `engagement_id` UUID — visible in the console URL when you open the engagement, or from the Railway API response.

---

## Step 2 — Issue a portal invitation

The invitation endpoint requires `governance:write` scope. Use the operator API key from Railway → API service → `FG_API_KEY`.

**No automated email is sent for `pni1.` invitations** — the console email route does not yet have a `portal_invite` type (T14 credential delivery rewrite). You will deliver the accept-invite URL manually.

```bash
TENANT_ID="<your-tenant-id>"
ENGAGEMENT_ID="<engagement-uuid-from-step-1>"
EXTERNAL_EMAIL="<cold-external-email>"
API_KEY="<FG_API_KEY value>"

curl -s -X POST "https://api.frostgate.ai/portal/invitations" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -H "X-FG-Tenant-ID: $TENANT_ID" \
  -d "{
    \"email\": \"$EXTERNAL_EMAIL\",
    \"portal_role\": \"viewer\",
    \"engagement_id\": \"$ENGAGEMENT_ID\"
  }"
```

Expected response (HTTP 201):
```json
{
  "invitation_id": "<uuid>",
  "token": "pni1.<64-hex-chars>",
  "expires_at": "<ISO-8601>",
  "email": "<EXTERNAL_EMAIL>",
  "portal_role": "viewer",
  "engagement_id": "<uuid>"
}
```

Record `invitation_id` and `token` in the evidence manifest.

> The raw `pni1.` token is returned once and not recoverable. Copy it immediately.

---

## Step 3 — Construct and deliver the accept-invite URL

```
https://app.frostgate.ai/accept-invite?token=<pni1.token>&tenant_id=<TENANT_ID>
```

Deliver this URL to the cold external mailbox via any out-of-band channel (personal email, text message, Slack to yourself on the external account). The external user must open this URL in a browser where they are NOT already authenticated to `app.frostgate.ai`.

---

## Step 4 — External user accepts the invitation (OIDC flow)

As the external user:

1. Open the accept-invite URL in a fresh browser or incognito window.
2. The page shows a "Sign in to accept your invitation" button.
3. Click the button → Auth0 OIDC login page appears.
4. Authenticate with the external identity (Google, Microsoft, or email magic link).
5. Auth0 redirects to the portal OIDC callback.
6. The portal callback calls `POST /portal/invitations/{token}/accept` on Core, creates a `portal_user_sessions` row, and sets the `fg_portal_session` cookie (a `pnu1.` token).
7. Browser lands on the portal home page for the engagement.

**Evidence to capture:**
- [ ] Portal home page loads with the `[T4-TEST]` engagement visible.
- [ ] At least one engagement findings tab or page loads without error.

---

## Step 5 — Verify active session in Core

From a terminal with the operator API key, confirm the session exists and is `active` before logout:

```bash
# List portal user sessions for the tenant (admin endpoint)
curl -s "https://api.frostgate.ai/portal/named-users?tenant_id=$TENANT_ID" \
  -H "Authorization: Bearer $API_KEY" \
  -H "X-FG-Tenant-ID: $TENANT_ID"
```

Note the `portal_user_id` and `membership_id` in the response. Record them in the evidence manifest.

---

## Step 6 — External user logs out

In the portal browser session, click the logout button.

The portal BFF (`apps/portal/app/api/auth/logout/route.ts`) detects the `pnu1.` cookie, calls `DELETE /portal/named-sessions/self` on Core (with `AbortController` timeout), then clears the `fg_portal_session` cookie regardless of Core response (fail-open). The browser is redirected to the portal login page.

---

## Step 7 — Verify Core-side session revocation

Confirm the session was revoked in Core:

```bash
# Attempt to use the old session token — must be rejected
OLD_SESSION_TOKEN="pnu1.<the-token-that-was-in-the-cookie>"

curl -s -X GET "https://api.frostgate.ai/portal/engagement" \
  -H "X-FG-Portal-Session: $OLD_SESSION_TOKEN" \
  -H "X-FG-Tenant-ID: $TENANT_ID"
```

Expected: HTTP 401 with `SESSION_REVOKED` or similar rejection — **not** 200.

Alternatively, confirm via the audit log:

```bash
curl -s "https://api.frostgate.ai/portal/named-users/$PORTAL_USER_ID/audit-events?tenant_id=$TENANT_ID" \
  -H "Authorization: Bearer $API_KEY" \
  -H "X-FG-Tenant-ID: $TENANT_ID"
```

Look for a `portal_session_revoked` event timestamped after the logout.

---

## Post-proof cleanup

- [ ] Delete or archive the `[T4-TEST]` engagement in the console.
- [ ] Revoke the test portal invitation if it has not expired: `DELETE /portal/invitations/{invitation_id}`.
- [ ] Clear any test cookies from the external browser session.

---

## Evidence required for DoD L1

Fill in `docs/governance/status/L01_evidence_manifest.md` with:

- Date and time of each step.
- Operator email.
- External test identity email (can be redacted to domain only: `***@gmail.com`).
- `invitation_id` from step 2.
- `portal_user_id` and `membership_id` from step 5.
- Pre-logout session status (active).
- Post-logout confirmation (401 rejection or `portal_session_revoked` audit event).
- Engagement pages that loaded successfully.

L1 is PASS when all seven steps complete and the session revocation is confirmed in Core.

---

## Known gaps (not blockers for T4 proof)

- **No automated invitation email**: the console `/api/email` route does not have a `portal_invite` type; `pni1.` invite URLs must be delivered manually. T14 (credential delivery rewrite) will add this.
- **No synthetic monitor**: post-launch, a weekly synthetic login test should exercise this path automatically (noted in FG-LR-002 "ideal later state").
- **Onboarding runbook stale**: `docs/operators/onboarding_runbook.md` step 7 still references `PORTAL_PASSWORD` delivery. T14 will rewrite it for the named-user flow.
