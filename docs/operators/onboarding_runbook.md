# Operator Onboarding Runbook

**For:** FrostGate operators running a client field assessment engagement.  
**Time:** ~30 minutes setup + scan time (scan itself takes 5–15 minutes).  
**Result:** Client receives a PDF report and portal access to track remediation.

---

## Overview — What you will do

```
1. One-time setup   — Azure AD app registration in client tenant
2. Create engagement — Name the client and set assessment type in console
3. Run scan         — MS Graph device-code scan (operator authenticates)
4. Fill questionnaire — NIST AI RMF controls: mark what scan couldn't see
5. Generate report  — AI executive summary + findings compiled into PDF
6. Deliver          — Transition to Delivered; share portal with client
```

---

## Prerequisites

Before starting, confirm you have:

- [ ] Access to `console.frostgate.ai` (operator login via Auth0)
- [ ] A user account with Global Administrator or Application Administrator role in the **client's Azure AD tenant**
- [ ] The following Railway environment variables set on the API service:
  - `FG_MSAL_CLIENT_ID` — from the Azure AD app registration (Step 1)
  - `FG_ACKNOWLEDGMENT_KEY` — generate once: `python3 -c "import secrets; print(secrets.token_hex(32))"`
- [ ] Portal deployed and accessible (note the portal URL for Step 6)
- [ ] Portal environment variables set:
  - `PORTAL_PASSWORD` — shared password you will give the client
  - `PORTAL_SESSION_SECRET` — generate: `openssl rand -base64 32`

---

## Step 1 — Register the Azure AD app (one-time per client)

**Skip this step** if you have already registered the FrostGate app in this client's Azure AD tenant. Reuse the existing `FG_MSAL_CLIENT_ID`.

See the full guide: [`docs/operators/azure_ad_app_setup.md`](azure_ad_app_setup.md)

Summary:
1. Sign in to [portal.azure.com](https://portal.azure.com) in the **client's tenant**
2. **Azure AD → App registrations → New registration**
   - Name: `FrostGate Assessment`
   - Account type: `This organizational directory only`
   - Redirect URI: leave blank
3. Copy the **Application (client) ID** → set as `FG_MSAL_CLIENT_ID` in Railway
4. Copy the **Directory (tenant) ID** → you will paste this in Step 3
5. **API permissions → Add → Microsoft Graph → Delegated:**
   `User.Read.All`, `Directory.Read.All`, `Policy.Read.All`, `Application.Read.All`,
   `AuditLog.Read.All`, `Reports.Read.All`, `InformationProtectionPolicy.Read`
6. Click **Grant admin consent**
7. **Authentication → Advanced settings → Allow public client flows → Yes → Save**

After setting `FG_MSAL_CLIENT_ID` in Railway, trigger a Railway redeploy.

---

## Step 2 — Create the engagement

1. Open `console.frostgate.ai` → sign in → **Field Assessments** in the sidebar
2. Click **New Engagement**
3. Fill in:

   | Field | What to enter |
   |-------|--------------|
   | Client name | Client's organisation name (e.g. `Volusia Community Bank`) |
   | Client domain | Their primary domain (e.g. `volusiabank.com`) |
   | Assessment type | Choose: `ai_governance`, `hipaa`, `soc2`, `cmmc`, or `comprehensive` |
   | Assessor | Your name or operator ID |
   | Scheduled date | Today or the agreed engagement date |

4. Click **Create**. The engagement opens with status **Scheduled**.

5. Advance the status to **In Progress**: in the engagement header, click the status badge → select **In Progress**.

---

## Step 3 — Run the MS Graph scan

1. In the engagement, click the **Scans** tab
2. In the **Run MS Graph Scan** panel:
   - Paste the **Directory (tenant) ID** from Step 1
   - Enter your name as Operator Name (shows on the signed receipt)
   - Enter `FrostGate` as Operator Org
   - Click **Run MS Graph Scan**
3. A device code appears (e.g. `ABC-123-XYZ`). You have 15 minutes.
4. Open `https://microsoft.com/devicelogin` in a browser signed in to the client's tenant
5. Enter the code → sign in → **Accept** the permissions
6. Watch the console status: `Waiting` → `Running` → `Importing` → **Scan complete**
7. Navigate to the **Findings** tab — normalised findings appear automatically

> If the scan times out or shows partial results, click **Run MS Graph Scan** again and re-authenticate. Findings from the first scan are preserved; the second scan adds or updates.

---

## Step 4 — Complete the NIST questionnaire

The MS Graph scan covers technical controls. The questionnaire captures what the scan cannot see: policies, training, governance decisions.

1. In the engagement, click the **Scans** tab → scroll to **NIST AI RMF Questionnaire**
   (or navigate to the **Questionnaire** section if shown in a separate tab)
2. Work through each of the 69 NIST AI RMF controls
3. For each control, set the status and add evidence notes:

   | Status | When to use |
   |--------|-------------|
   | `implemented` | Control is fully in place with documented evidence |
   | `partial` | Some elements in place, gaps remain |
   | `not_implemented` | Control not in place |
   | `not_applicable` | Control does not apply to this organisation |

4. Attach evidence links (policy docs, screenshots, meeting notes) where available
5. Click **Save** after each section — responses auto-link to related findings

> You do not need to complete all 69 controls in one session. Progress is saved. Complete as many as you have evidence for before generating the report.

---

## Step 5 — Review findings and advance status

1. Click the **Findings** tab
2. Review scan-generated findings — each shows severity, NIST control mapping, and plain-language explanation
3. Add any manual observations via **Add Observation** for gaps the scan and questionnaire did not capture
4. Attach supporting evidence links to key findings
5. Advance engagement status → **Evidence Collected**

   > The system enforces readiness gates before allowing this transition. If blocked, the status badge shows which gates are incomplete.

6. Advance status → **Report Generation**

---

## Step 6 — Generate the report

1. Click the **Reports** tab → **Generate Report**
2. The report compiles automatically:
   - AI executive summary (Claude, ~30–60 seconds)
   - Severity-sorted findings
   - Remediation roadmap (0–30 / 31–60 / 61–90 days)
   - NIST AI RMF coverage matrix
   - Evidence appendix with manifest hash
3. When status shows **Complete**, click **Download PDF**
4. Review the PDF before delivering to the client:
   - Check executive summary tone and accuracy
   - Verify finding counts match what you saw in the Findings tab
   - Confirm the disclaimer appears: *"aligned with, not certification to"*

> If the executive summary needs adjustment, you can regenerate the report. Each generation is versioned — previous versions are preserved in the Reports tab.

---

## Step 7 — Deliver and share the portal

1. Advance engagement status → **Delivered**

   This triggers automatic governance promotion — the engagement record, findings, and report are promoted to the governance asset registry.

2. Share portal access with the client:
   - Send the portal URL (e.g. `portal.frostgate.ai` or your deployment URL)
   - Send the shared portal password (the value of `PORTAL_PASSWORD`)
   - Include a brief note: *"Log in with this password to view your assessment findings, remediation roadmap, and download your report."*

3. In the portal the client can:
   - View the engagement overview and risk posture dashboard
   - Browse findings by severity with plain-language explanations
   - Download the PDF report
   - Mark findings as resolved with evidence notes (closed-loop remediation)
   - Submit NIST questionnaire attestations
   - Track continuity gaps and overdue items

---

## Step 8 — Monitor remediation (ongoing)

After delivery, the engagement moves to **Remediation** status automatically when the client begins marking findings resolved.

In the console:
- **Findings** tab shows which findings the client has marked resolved
- **Governance** tab shows attestations the client has submitted
- **Reports** tab allows you to regenerate a follow-up report reflecting remediation progress

For a formal re-assessment (e.g. 90 days later), create a new engagement for the same client and repeat this runbook. Historical engagements remain in the system for comparison.

---

## Status lifecycle reference

```
Scheduled → In Progress → Evidence Collected → Report Generation → Delivered
                                                                        │
                                                                        ▼
                                                              Remediation → Monitoring → Closed
```

Gated transitions (require readiness gates to pass): `Evidence Collected`, `Report Generation`, `Delivered`

Ungated transitions: `Scheduled → In Progress`, `Delivered → Remediation`, `Remediation → Monitoring`, `Monitoring → Closed`

---

## Environment variable checklist

Variables required before running any engagement. Set in Railway (API service).

| Variable | Purpose | How to generate |
|----------|---------|-----------------|
| `FG_MSAL_CLIENT_ID` | Azure AD app for MS Graph scan | From Step 1 app registration |
| `FG_ACKNOWLEDGMENT_KEY` | HMAC signing key for scan receipts | `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `FG_ANTHROPIC_API_KEY` | AI executive summary generation | Anthropic console |
| `FG_REPORT_VERIFY_URL` | Verification URL embedded in PDF | Set to `https://console.frostgate.ai/verify` or your domain |

Variables for the portal (set in the portal deployment environment):

| Variable | Purpose | How to generate |
|----------|---------|-----------------|
| `PORTAL_PASSWORD` | Client login password | Choose a strong password per engagement or per client |
| `PORTAL_SESSION_SECRET` | Session cookie signing | `openssl rand -base64 32` |
| `CORE_API_URL` | Backend API URL | `https://api-production-6d47.up.railway.app` |
| `CORE_API_KEY` | BFF authentication key | Same as `FG_API_KEY` in Railway |
| `CORE_TENANT_ID` | Tenant context | `default` |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Scan panel shows `MSAL_NOT_CONFIGURED` | `FG_MSAL_CLIENT_ID` not set in Railway | Add env var, redeploy Railway |
| Device code page shows `AADSTS65001` | Admin consent not granted | Repeat Step 1 → grant admin consent |
| Device code page shows `AADSTS7000218` | Public client flow not enabled | Step 1 → Authentication → Allow public client flows → Yes |
| Scan stuck at `Running` for > 15 min | Timeout | Re-run scan — partial findings are preserved |
| Status transition blocked | Readiness gates not met | Check gate status in the status badge tooltip |
| Report generation fails | `FG_ANTHROPIC_API_KEY` not set or quota exceeded | Check Railway env vars and Anthropic usage |
| PDF download returns 501 | `reportlab` not installed | Add `reportlab` to `requirements.txt` and redeploy |
| Portal login fails | `PORTAL_PASSWORD` or `PORTAL_SESSION_SECRET` not set | Add to portal deployment env vars |
| Field assessment 401 | `CORE_TENANT_ID` or `CORE_API_KEY` not set | Add to portal and console Vercel env vars |

---

*FrostGate — AI Governance for Regulated Industries*  
*See also: [`azure_ad_app_setup.md`](azure_ad_app_setup.md)*
