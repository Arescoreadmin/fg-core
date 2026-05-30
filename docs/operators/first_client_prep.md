# First-Client Pre-Engagement Checklist

**For:** FrostGate operators preparing for a client's first field assessment.  
**Time to complete:** ~15 minutes.  
**Deep-dive procedures:** see [`onboarding_runbook.md`](onboarding_runbook.md).

Run through every item below before the client meeting starts. Do not begin the engagement until all boxes are checked.

---

## 1. System Health Check

- [ ] Railway API is responding — open `https://api-production-6d47.up.railway.app/health` (or your Railway URL) and confirm a 200 response.
- [ ] Console is accessible — load `https://console.frostgate.ai` and confirm the login page renders without errors.
- [ ] Portal is accessible — load the portal URL and confirm the password prompt appears.
- [ ] Railway env vars confirmed (open Railway → API service → Variables):
  - [ ] `FG_MSAL_CLIENT_ID` is set and non-empty.
  - [ ] `FG_ACKNOWLEDGMENT_KEY` is set.
  - [ ] `FG_ANTHROPIC_API_KEY` is set.
  - [ ] `FG_REPORT_VERIFY_URL` is set (e.g. `https://console.frostgate.ai/verify`).
- [ ] Portal env vars confirmed (Vercel or your portal deployment → Environment Variables):
  - [ ] `PORTAL_PASSWORD` is set.
  - [ ] `PORTAL_SESSION_SECRET` is set.
  - [ ] `CORE_API_URL` points to the Railway API.
  - [ ] `CORE_API_KEY` is set.
  - [ ] `CORE_TENANT_ID` is set (typically `default`).

---

## 2. Azure AD App Registration

- [ ] You have the client's **Directory (tenant) ID** written down or on clipboard.
- [ ] The FrostGate app is registered in the **client's** Azure AD tenant (not your own tenant).
- [ ] The `FG_MSAL_CLIENT_ID` in Railway matches the **Application (client) ID** of that registration.
- [ ] All 15 delegated Microsoft Graph permissions are present on the app:
  - [ ] `User.Read.All`
  - [ ] `Directory.Read.All`
  - [ ] `Policy.Read.All`
  - [ ] `Application.Read.All`
  - [ ] `AuditLog.Read.All`
  - [ ] `Reports.Read.All`
  - [ ] `InformationProtectionPolicy.Read`
  - [ ] `AccessReview.Read.All`
  - [ ] `IdentityRiskyUser.Read.All`
  - [ ] `IdentityRiskEvent.Read.All`
  - [ ] `RoleEligibilitySchedule.Read.Directory`
  - [ ] `RoleAssignmentSchedule.Read.Directory`
  - [ ] `Sites.Read.All`
  - [ ] `Files.Read.All`
  - [ ] `DeviceManagementManagedDevices.Read.All`
- [ ] **Admin consent** has been granted for all permissions (green checkmarks in the API permissions blade).
- [ ] **Authentication → Advanced settings → Allow public client flows** is set to **Yes**.

> P2-gated permissions (AccessReview, IdentityRiskyUser, etc.) are safe on any tenant — connectors
> handle 403 gracefully. Add all 15 now so you never revisit this mid-engagement.

> If any of these are missing, complete them now via `docs/operators/azure_ad_app_setup.md` before proceeding.

---

## 3. Engagement Setup Dry Run

- [ ] Sign in to `console.frostgate.ai` with your operator account.
- [ ] Navigate to **Field Assessments** in the sidebar — the list loads without error.
- [ ] Create a test engagement (client name: `[TEST]`, any domain) — it saves and opens.
- [ ] Advance status from **Scheduled** → **In Progress** — the badge updates.
- [ ] Click the **Scans** tab — confirm all connector panels are visible:
  - [ ] MS Graph Core scan panel shows no `MSAL_NOT_CONFIGURED` error
  - [ ] DNS & Email Security panel is present
  - [ ] Web Security Headers panel is present
  - [ ] Network Scan panel is present
  - [ ] OAuth Inventory, OAuth Risk, Endpoint Inventory, Entra Governance, SharePoint panels present
- [ ] Click the **Questionnaire** tab (or scroll to it in the Scans tab) — 69 NIST AI RMF controls load.
- [ ] Delete the test engagement (or leave it with a `[TEST]` label — do not use it for the real engagement).

---

## 4. MS Graph Scan Readiness

- [ ] Confirmed with client: a **Global Administrator** or **Application Administrator** will be present (or available by phone/video) for the MS Graph scan authentication steps.
- [ ] You have the client's **Directory (tenant) ID** (format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).
- [ ] `https://microsoft.com/devicelogin` is reachable from the machine you will use during the engagement — open it now and confirm the page loads.
- [ ] You have a browser session ready that can authenticate into the client's Azure AD tenant (your admin credential or the client admin's device).
- [ ] You have the client's **primary domain** and any secondary domains for the DNS & Email scan.
- [ ] You have the client's **public-facing URLs** for the Web Security Headers scan.
- [ ] You have any known **external IP ranges or hostnames** for the Network Scan (if in scope).
- [ ] No-auth scans (DNS, Web Headers, Network) are ready to run before the client meeting — confirm you have the domain/URL/IP list.

---

## 5. Report Delivery Prep

- [ ] `FG_ANTHROPIC_API_KEY` is set in Railway (verified in Section 1) — AI executive summary generation will work.
- [ ] PDF export is functional — confirm `reportlab` is in `requirements.txt` and the Railway deployment is current. If unsure, check the Railway deploy logs for import errors.
- [ ] You have the portal URL written down — the exact URL you will send to the client.
- [ ] You have the `PORTAL_PASSWORD` value ready to share securely with the client.
- [ ] You know how you will deliver credentials (e.g. encrypted email, 1Password share link) — do not send the password in plaintext alongside the portal URL.

---

## 6. Auth0 / Access Control

- [ ] Sign out of the console completely, then sign back in — login completes successfully via Auth0.
- [ ] Sign out again and confirm the session is cleared — reloading `console.frostgate.ai` redirects back to the Auth0 login page (no auto-login from a stale session).
- [ ] Confirm no other operator sessions are left open on shared machines that could interfere.

---

## 7. Day-of Checklist

**Before the meeting** (no client required):

- [ ] Run DNS & Email Security scan — have client domain(s) ready.
- [ ] Run Web Security Headers scan — have public URLs ready.
- [ ] Run Network Scan if in scope — have IP/hostname list ready.
- [ ] All three no-auth scans show **Scan complete** in the Scans tab before the meeting starts.

**When the meeting starts:**

- [ ] `console.frostgate.ai` is open and you are signed in.
- [ ] The real engagement is created with the client's name and domain — status is **In Progress**.
- [ ] Client's **tenant ID** is on clipboard or written down.
- [ ] A browser tab is open to `https://microsoft.com/devicelogin` (or ready to open in seconds).
- [ ] The client admin who will authenticate MS Graph scans is confirmed present.
- [ ] Portal URL and password are ready to copy-paste at report delivery time.
- [ ] `onboarding_runbook.md` is open in a second window for step-by-step reference.
- [ ] You have ~75–90 minutes blocked:
  - No-auth scans (done pre-meeting): 5–10 min
  - MS Graph Core + OAuth Inventory + OAuth Risk: ~25 min (5 min each incl. auth)
  - Endpoint Inventory + Entra Governance + SharePoint: ~20 min
  - Questionnaire walkthrough: 20–40 min
  - Report generation + review: 3–5 min
  - Delivery: 5 min

---

*If any item above cannot be checked, resolve it before the meeting. Do not attempt a live engagement with unresolved system or permission gaps — the MS Graph device code window is only 15 minutes.*
