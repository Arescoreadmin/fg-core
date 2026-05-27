# Azure AD App Registration — MS Graph Scan Setup

**For:** FrostGate operators preparing a client environment for MS Graph scanning.  
**Prerequisite:** Global Administrator or Application Administrator role in the client's Azure AD tenant.

---

## What this does

The MS Graph scan uses an Azure AD app registration to authenticate via the
device-code flow. When the operator clicks **Run MS Graph Scan** in the console,
Azure prompts them to authenticate in a browser using a one-time code. The scan
runs under the operator's delegated identity — no service principal, no stored
credentials, no background service.

The app registration is created once per client tenant and reused for all
subsequent scans.

---

## Step 1 — Create the app registration

1. Sign in to [portal.azure.com](https://portal.azure.com) as a Global Administrator
   (or Application Administrator) in the **client's tenant**.

2. Navigate to **Azure Active Directory → App registrations → New registration**.

3. Fill in the form:
   - **Name:** `FrostGate Assessment` (or any name the client recognises)
   - **Supported account types:** `Accounts in this organizational directory only`
   - **Redirect URI:** leave blank

4. Click **Register**.

5. You land on the app's **Overview** page. Copy and save:
   - **Application (client) ID** → this becomes `FG_MSAL_CLIENT_ID`
   - **Directory (tenant) ID** → you will need this when initiating each scan

---

## Step 2 — Add API permissions

1. In the left sidebar click **API permissions → Add a permission → Microsoft Graph → Delegated permissions**.

2. Search for and add each permission below. All are **delegated** (not application).

   | Permission | Purpose |
   |---|---|
   | `User.Read.All` | Enumerate users, MFA registration state |
   | `Directory.Read.All` | Read directory objects (groups, roles, devices) |
   | `Policy.Read.All` | Read conditional access and auth policies |
   | `Application.Read.All` | Enumerate enterprise apps and OAuth consents |
   | `AuditLog.Read.All` | Read sign-in and audit logs |
   | `Reports.Read.All` | Read usage and MFA reports |
   | `InformationProtectionPolicy.Read` | Read sensitivity label policies |

3. After adding all seven, click **Grant admin consent for [tenant name]** at the
   top of the permissions list.

4. Confirm. All permissions should show a green tick and status **Granted for [tenant name]**.

> **Why delegated and not application permissions?**  
> Device-code flow authenticates the operator interactively. The scan runs under
> the operator's identity, so consent is tied to that session and automatically
> expires when the session ends. No long-lived credentials are stored.

---

## Step 3 — Enable the public client flow

1. In the left sidebar click **Authentication → Advanced settings**.

2. Under **Allow public client flows**, toggle **Enable the following mobile and desktop flows** to **Yes**.

3. Click **Save**.

This is required for the MSAL device-code flow. Without it Azure returns
`AADSTS7000218: The request body must contain the following parameter: 'client_assertion'`.

---

## Step 4 — Configure FrostGate environment variables

In the FrostGate operator environment (`.env` or your secrets manager):

```bash
# The client ID from Step 1
FG_MSAL_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Required for scan receipt signing — generate once per deployment
FG_ACKNOWLEDGMENT_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

The **tenant ID** from Step 1 is entered at scan time in the console UI — not
stored in the environment. This allows one FrostGate deployment to scan multiple
client tenants.

---

## Step 5 — Run the first scan

1. Open the FrostGate console → **Field Assessments** → select the engagement.

2. Click the **Scans** tab.

3. In the **Run MS Graph Scan** panel:
   - Paste the **Directory (tenant) ID** from Step 1.
   - Optionally fill in Operator Name and Operator Org for the receipt audit trail.
   - Click **Run MS Graph Scan**.

4. A large authentication code appears (e.g. `ABC123XY`). You have approximately
   15 minutes to use it.

5. Open the link shown (e.g. `https://microsoft.com/devicelogin`) in a browser
   that is already signed in to the client tenant — or hand the URL + code to a
   client administrator.

6. Enter the code, sign in, and review the permission consent prompt. Click **Accept**.

7. The console status updates through:
   `Waiting for authentication` → `Running MS Graph scan` → `Importing scan results` → `Scan complete`

8. The scan result is automatically imported into the engagement. Navigate to the
   **Findings** tab to see normalised findings.

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `MSAL_NOT_CONFIGURED` | `FG_MSAL_CLIENT_ID` env var is not set | Add it to your `.env` |
| `ACKNOWLEDGMENT_KEY_MISSING` | `FG_ACKNOWLEDGMENT_KEY` not set | Generate and add it |
| `DEVICE_FLOW_FAILED` | Tenant ID is wrong or app not registered in that tenant | Verify tenant ID and app registration |
| `AADSTS7000218` on auth page | Public client flow not enabled | See Step 3 |
| `AADSTS65001` on auth page | Admin consent not granted | Repeat Step 2, grant consent |
| `Token acquisition failed` | Code expired (> 15 min) | Click **Run another scan** and re-authenticate faster |
| Scan stuck at `Scanning` | Scan timeout (> 15 min) after auth | Result imports as partial — findings may be incomplete |

---

## Security notes

- The access token lives only in server process memory during the scan. It is
  zeroed on exit and revoked via Graph API before the background task completes.
- No token is written to disk, logged, or stored in the database.
- The acknowledgment receipt (HMAC-SHA256) is stored with the scan record as
  chain-of-custody evidence.
- The app registration grants read-only delegated permissions. No write operations
  are performed against the client tenant.
- Revoking the operator's Azure AD session or removing admin consent immediately
  stops any in-progress scan.
