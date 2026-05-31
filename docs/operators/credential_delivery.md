# Secure Credential Delivery — Portal Access

**For:** FrostGate operators handing portal access to a client after an engagement.  
**Rule:** Never send the URL and password in the same message, channel, or email thread.

---

## What you are delivering

| Credential | Value | Where it lives |
|------------|-------|---------------|
| Portal URL | `https://app.frostgate.ai` | Public — safe to send in any channel |
| Portal password | `PORTAL_PASSWORD` env var value | Sensitive — deliver via separate secure channel |

---

## Recommended delivery method

### Option A — 1Password Share Link (preferred)

1. Open 1Password → create a new Login item.
2. Set **Website:** `https://app.frostgate.ai`
3. Set **Password:** the `PORTAL_PASSWORD` value.
4. Click **Share** → set expiry to **7 days** → copy the share link.
5. Send the share link to the client in your report delivery email (letter #4).
6. In the email body, include the URL `https://app.frostgate.ai` and instruct them to retrieve the password from the share link.
7. The share link expires after first use or 7 days, whichever comes first.

**Why:** The password is never in email. The link can only be used once. After it expires, the credential is gone from 1Password Share too.

---

### Option B — Bitwarden Send

1. Open Bitwarden → **Send** → **New Send** → type: **Text**.
2. Paste the portal password as the text content.
3. Set **Deletion date:** 7 days from now.
4. Set **Maximum access count:** 3 (client + their IT person, with one spare).
5. Copy the Send link.
6. Send the Send link in your report delivery email alongside the portal URL.

**Why:** Same separation as Option A. Works without a paid 1Password plan.

---

### Option C — Verbal + written follow-up (minimum viable)

1. During the engagement session (while you are on video/in-person), say the password aloud.
2. Confirm the client wrote it down or added it to their password manager.
3. In the report delivery email, include only the portal URL — no password.
4. If the client loses the password, you can reset `PORTAL_PASSWORD` in Vercel and redeploy (takes ~2 min).

**When to use:** If the client does not have a password manager and you cannot use Options A or B. Acceptable for first client; not scalable.

---

## What NOT to do

- Do not paste the password in the same email as the portal URL.
- Do not send the password over SMS or WhatsApp alongside the URL.
- Do not include the password in the PDF report (it is not — the PDF is client-readable).
- Do not use a share link with no expiry.

---

## If the client loses the password

1. Generate a new strong password: `python3 -c "import secrets, string; print(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20)))"`
2. Update in Vercel: `vercel env rm PORTAL_PASSWORD production && vercel env add PORTAL_PASSWORD production`
3. Redeploy the portal: `vercel deploy --prod` from `apps/portal/`
4. Deliver the new password via Option A or B above.

---

## Timing

Send credentials with letter #4 (Report Delivery), within 24 hours of the engagement session. Do not send them before the report is ready — there is nothing to log in to yet.
