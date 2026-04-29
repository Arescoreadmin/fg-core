# FrostGate Agent — Windows Enterprise Deployment Guide

**Version:** 1.0.0
**Status:** APPROVED — authoritative guide for enterprise install, enrollment, upgrade, and uninstall.
**Depends on:** Task 18.2 (MSI installer), 18.3 (silent enrollment), 18.4 (credential storage), 18.5 (upgrade/uninstall), 18.6 (release signing)

---

## 1. Overview

### What is deployed

The FrostGate Agent ships as a digitally signed Windows Installer package (MSI):

```
FrostGateAgent-<version>-x64.msi
```

The package includes:
- `FrostGateAgent.exe` — PyInstaller-bundled agent binary (independently signed)
- Windows service registration (NT SERVICE\FrostGateAgent — least-privilege virtual account)
- Installer custom actions for enrollment and credential storage
- `manifest.sha256` — SHA256 hash of every file in the package

### What is signed

Both the MSI container and the embedded `FrostGateAgent.exe` binary are signed with an organization code signing certificate using SHA-256 Authenticode (RFC 3161 timestamp required).

### What is verified before deployment

Before any enterprise deployment:

1. Verify Authenticode signature:
   ```powershell
   signtool.exe verify /pa /v FrostGateAgent-<version>-x64.msi
   ```
2. Verify SHA256 hash against the published manifest:
   ```powershell
   Get-FileHash FrostGateAgent-<version>-x64.msi -Algorithm SHA256
   # Compare against sha256 value in release_metadata.json
   ```
3. Confirm `release_metadata.json` shows `"signing_status": "signed"` and `"production_ready": true`.

**Unsigned artifacts MUST NOT be deployed to production endpoints.**

---

## 2. Prerequisites

### Supported Windows versions

| Windows Version | Support |
|---|---|
| Windows 10 (build 1607 / LTSB 2016) | Minimum |
| Windows 11 | Supported |
| Windows Server 2016 | Minimum server |
| Windows Server 2019/2022/2025 | Supported |

### Administrative rights

- **Install / upgrade / uninstall:** Local administrator required (MSI registration, service creation).
- **Runtime operation:** No admin rights. Service runs as `NT SERVICE\FrostGateAgent` (non-privileged virtual account with no interactive logon and no admin access).

### Network access

| Destination | Protocol | Purpose |
|---|---|---|
| `<FROSTGATE_ENDPOINT>` | HTTPS/443 | Control plane (enrollment, telemetry, commands) |
| Timestamp authority | HTTP/80 or HTTPS/443 | Authenticode timestamp validation (install-time only) |

TLS 1.2 minimum, TLS 1.3 preferred. Certificate validation is enforced. Self-signed certificates are rejected in production unless explicitly pinned via `FG_CORE_CERT_SHA256`.

### Certificate / signature verification

Deploying systems (Intune, GPO, RMM) must be able to verify the Authenticode signature of the MSI before execution. Ensure the organization's code signing CA is trusted in the machine certificate store.

---

## 3. Silent Install

### Basic silent install command

```cmd
msiexec /i FrostGateAgent-<version>-x64.msi /qn /l*v <INSTALL_LOG> ^
  TENANT_ID=<TENANT_ID> ^
  FROSTGATE_ENDPOINT=<FROSTGATE_ENDPOINT> ^
  ENROLLMENT_TOKEN=<ENROLLMENT_TOKEN> ^
  ENVIRONMENT=prod
```

### Parameters

| Parameter | Required | Description |
|---|---|---|
| `TENANT_ID` | Yes | Your organization's FrostGate tenant identifier |
| `FROSTGATE_ENDPOINT` | Yes | HTTPS control plane URL (e.g. `https://control-plane.frostgate.io`) |
| `ENROLLMENT_TOKEN` | One of | Pre-issued enrollment token for this deployment batch |
| `BOOTSTRAP_TOKEN` | One of | Bootstrap token (mutually exclusive with `ENROLLMENT_TOKEN`) |
| `ENVIRONMENT` | Yes | `prod` or `staging`. `dev` / `local` are rejected. |
| `INSTALLDIR` | Optional | Override install directory (default: `C:\Program Files\FrostGate\Agent`) |
| `LOG_LEVEL` | Optional | Override log verbosity (default: `info`) |

### Important: token handling

- `<ENROLLMENT_TOKEN>` is consumed at install time for the enrollment exchange only.
- After enrollment, the agent stores the resulting **device credential** in Windows Credential Manager (DPAPI-encrypted). The raw enrollment token is discarded.
- The token MUST NOT be written to any persistent configuration file, registry key, or log.
- The install log (`/l*v`) is written to the path you specify. Ensure it is not world-readable if it may contain transient token material.

### Log file

```cmd
/l*v C:\Windows\Temp\FrostGateAgent_install.log
```

Review this file for enrollment status and any error codes. The file does not persist the raw token after enrollment completes.

---

## 4. Enterprise Distribution

### Microsoft Intune (Win32 App)

**Prepare the package:**
```powershell
# Wrap MSI as .intunewin using IntuneWinAppUtil.exe
IntuneWinAppUtil.exe -c .\installer -s FrostGateAgent-<version>-x64.msi -o .\output
```

**Intune silent install command:**
```cmd
msiexec /i FrostGateAgent-<version>-x64.msi /qn /l*v %TEMP%\FrostGateAgent_install.log TENANT_ID=<TENANT_ID> FROSTGATE_ENDPOINT=<FROSTGATE_ENDPOINT> ENROLLMENT_TOKEN=<ENROLLMENT_TOKEN> ENVIRONMENT=prod
```

**Intune silent uninstall command (non-purge):**
```cmd
msiexec /x FrostGateAgent-<version>-x64.msi /qn /l*v %TEMP%\FrostGateAgent_uninstall.log
```

**Intune purge uninstall command (destructive — deletes credential and data):**
```cmd
msiexec /x FrostGateAgent-<version>-x64.msi /qn /l*v %TEMP%\FrostGateAgent_purge.log PURGE_DATA=1
```

**Detection rule:**
- File exists: `C:\Program Files\FrostGate\Agent\FrostGateAgent.exe`
- Registry key exists: `HKLM\SYSTEM\CurrentControlSet\Services\FrostGateAgent`

**Return codes:**
- `0` — Success
- `1641` — Success, reboot initiated
- `3010` — Success, reboot required
- Any other — Failure; check install log

### Group Policy (GPO Software Installation)

Assign to **Computer Configuration** (not User Configuration). Run in system context.

To pre-populate required properties for org-wide silent deployment, use an MSI transform (`.mst`):

```cmd
# Create transform with TENANT_ID and FROSTGATE_ENDPOINT pre-populated
# (use Orca or equivalent MSI editor — do not embed ENROLLMENT_TOKEN in transform)
```

```cmd
# GPO install command with transform
msiexec /i \\server\share\FrostGateAgent-<version>-x64.msi TRANSFORMS=FrostGate_OrgDefaults.mst /qn
```

**Important:** Do not embed `ENROLLMENT_TOKEN` in the transform file. Supply tokens via a separate secure mechanism (e.g. bootstrap-time provisioning script that retrieves the token from a secrets vault).

### RMM Tools (NinjaRMM, ConnectWise, Datto, etc.)

Any RMM that supports `msiexec` invocation:

1. Upload the signed MSI to the RMM.
2. Configure a deployment script using the silent install command above.
3. Configure a detection condition (file/registry check per Intune example).
4. Retrieve the enrollment token from your secrets vault at script execution time — do not hardcode in the script.

### Staged rollout / pilot guidance

1. Deploy to a pilot group of 5–10 devices.
2. Verify enrollment succeeds: check Windows Event Log (`FrostGateAgent`) for `ENROLLED` event.
3. Verify service is running: `sc query FrostGateAgent`.
4. Verify device appears in FrostGate console under tenant `<TENANT_ID>`.
5. After pilot validation, expand rollout incrementally (10% → 25% → 100%).

### Offline verification (air-gapped environments)

Before deploying in environments without internet access:

```powershell
# Verify Authenticode signature offline using trusted CA in local store
signtool.exe verify /pa /v FrostGateAgent-<version>-x64.msi

# Verify SHA256 against published release_metadata.json
$hash = (Get-FileHash FrostGateAgent-<version>-x64.msi -Algorithm SHA256).Hash
$expected = (Get-Content release_metadata.json | ConvertFrom-Json).sha256_msi
if ($hash -eq $expected) { Write-Host "Hash OK" } else { Write-Host "HASH MISMATCH — DO NOT DEPLOY" }
```

---

## 5. Enrollment Flow

### What happens during install

1. MSI runs installer custom actions.
2. Enrollment token (`<ENROLLMENT_TOKEN>` or `<BOOTSTRAP_TOKEN>`) is passed to the enrollment exchange.
3. Agent contacts `<FROSTGATE_ENDPOINT>` and presents the token.
4. Control plane issues a **device credential** (HMAC key + key ID + tenant binding).
5. Device credential is stored in **Windows Credential Manager** (DPAPI-encrypted, machine scope).
6. Raw enrollment token is discarded — never persisted to disk, registry, or config.
7. Installer verifies device credential exists in Credential Manager.
8. Windows service (`FrostGateAgent`) is started. **Service start is gated on device credential existence** — if enrollment failed, the service does not start.

### Enrollment failure behavior

- If the enrollment exchange fails (network error, invalid token, duplicate device): installer exits with a non-zero return code. The device is not enrolled. No partial credential is left behind.
- Retry: re-run the silent install command with a valid token.
- The enrollment token is single-use (exchange happens once). Obtain a new token for retry if the token was consumed.

### Credential storage

Device credentials are stored in Windows Credential Manager under:
```
FrostGate/agent/<tenant_id>/<device_id>
```

DPAPI encrypts the credential blob using the local machine account key. The credential is accessible only to processes running as the machine account or as a process with equivalent privilege — not to regular user sessions.

---

## 6. Upgrade

### Behavior

```cmd
msiexec /i FrostGateAgent-<version>-x64.msi /qn /l*v %TEMP%\FrostGateAgent_upgrade.log
```

Upgrade:
- **Preserves** the enrolled device credential in Windows Credential Manager.
- **Preserves** collected state in the data directory (`C:\ProgramData\FrostGate\data`).
- **Does NOT** re-enroll silently.
- **Does NOT** delete or overwrite the device credential.
- **Does NOT** require a new enrollment token.
- Updates: binaries, service wrapper, non-secret configuration schema, version metadata.

The upgrade uses a stable MSI `UpgradeCode` GUID — the same GUID is used across all versions. Windows Installer detects the existing installation and upgrades in place.

### Rollback after failed upgrade

```cmd
# Re-deploy the previous version MSI — device identity is preserved (non-purge)
msiexec /i FrostGateAgent-<previous-version>-x64.msi /qn /l*v %TEMP%\FrostGateAgent_rollback.log
```

---

## 7. Uninstall and Purge

### Normal uninstall (non-destructive)

```cmd
msiexec /x FrostGateAgent-<version>-x64.msi /qn /l*v %TEMP%\FrostGateAgent_uninstall.log
```

Normal uninstall:
- Stops the service (`sc stop FrostGateAgent`).
- De-registers the service.
- Removes installed binaries.
- **PRESERVES** the device credential in Windows Credential Manager.
- **PRESERVES** collected state in the data directory.

Use normal uninstall for agent replacement, re-imaging with device identity preservation, or temporary removal.

### Purge uninstall (destructive — explicit only)

```cmd
msiexec /x FrostGateAgent-<version>-x64.msi /qn /l*v %TEMP%\FrostGateAgent_purge.log PURGE_DATA=1
```

Purge uninstall (`PURGE_DATA=1`):
- Stops and de-registers the service.
- Removes installed binaries.
- **Deletes** the device credential from Windows Credential Manager via the OS-protected credential store API (no filesystem path guessing).
- **Deletes** collected data and log directories.
- If credential deletion fails (access-denied, API error): the installer reports the failure and exits with a non-zero code — it does NOT claim success.
- If the credential was already absent (already removed): treated as already done (idempotent for true not-found cases only).

Use purge uninstall for device decommission, compliance wipe, or complete tenant offboarding.

### Credential cleanup guarantee

Credential removal always goes through the Windows Credential Manager API (`CredDelete`). The agent never guesses filesystem paths for credential cleanup. Access-denied and API failures are surfaced — never silently swallowed.

---

## 8. Troubleshooting

### Signature verification failure

```
Error: SignTool Error: No signature found.
```

**Cause:** MSI is unsigned or signature is corrupt.
**Resolution:** Download a fresh copy of the signed MSI from the official release channel. Verify the SHA256 hash against `release_metadata.json`. **Do not deploy an unsigned artifact.**

### Missing enrollment parameter

```
Error: TENANT_ID is required
```

**Cause:** `TENANT_ID` or `FROSTGATE_ENDPOINT` was not passed to msiexec.
**Resolution:** Supply all required parameters. See [Section 3](#3-silent-install).

### Endpoint validation failure

```
Error: Production endpoint must use HTTPS
```

**Cause:** `FROSTGATE_ENDPOINT` uses HTTP, localhost, or an RFC 1918 address.
**Resolution:** Use the HTTPS production endpoint. Dev/local endpoints are rejected in production-signed MSI.

### Credential storage unavailable

```
Error: WindowsCredentialManagerStore requires Windows with pywin32 installed
```

**Cause:** pywin32 is not installed in the agent's Python environment.
**Resolution:** Ensure pywin32 is bundled in the agent binary. Contact support if this occurs with an official release artifact.

### Service start failure

```
sc start FrostGateAgent: FAILED — no device credential found
```

**Cause:** Enrollment did not complete successfully. No device credential was stored.
**Resolution:** Re-run the install command with a valid enrollment token. Check the install log for the enrollment failure reason.

### Log locations

| Log | Path |
|---|---|
| Install log | `%TEMP%\FrostGateAgent_install.log` (or path you specify with `/l*v`) |
| Upgrade log | `%TEMP%\FrostGateAgent_upgrade.log` |
| Uninstall log | `%TEMP%\FrostGateAgent_uninstall.log` |
| Agent runtime log | `C:\ProgramData\FrostGate\logs\` |
| Windows Event Log | Event Viewer → Windows Logs → Application (Source: FrostGateAgent) |

**Important:** Log file commands must not print secrets. The agent redacts `device_key`, enrollment tokens, and API keys from all log output.

---

## 9. Security Guarantees

| Guarantee | Details |
|---|---|
| No embedded secrets | MSI artifact contains no tenant secrets, API keys, signing secrets, or credentials |
| No plaintext credentials | Device credential stored in Windows Credential Manager (DPAPI-encrypted), never in plaintext files or environment variables |
| No production localhost fallback | `localhost`, HTTP, and RFC 1918 endpoints are rejected in production-signed MSI |
| Signed artifacts only | Production release requires Authenticode-signed MSI and executable. SHA-256 digest algorithm. RFC 3161 timestamp required. |
| SHA256 verification required | `manifest.sha256` lists SHA256 of every file. Verified by installer at extract time. |
| Least-privilege runtime | Service runs as `NT SERVICE\FrostGateAgent` — no interactive logon, no admin access |
| Enrollment token single-use | Raw token is consumed at enrollment, discarded, never persisted |
| Credential deletion explicit | Purge requires `PURGE_DATA=1`. Deletion failures are surfaced. Not-found is idempotent. |
| Upgrade preserves identity | Device credential and collected state are never deleted by upgrade |
| Logs never contain secrets | `device_key`, tokens, signing secrets, and API keys are never written to log output |

---

## Appendix A: Placeholder Reference

All deployment examples in this guide use the following placeholders. Replace with actual values from your FrostGate tenant configuration before deployment.

| Placeholder | Description |
|---|---|
| `<TENANT_ID>` | Your FrostGate tenant identifier |
| `<FROSTGATE_ENDPOINT>` | HTTPS URL of the FrostGate control plane |
| `<ENROLLMENT_TOKEN>` | Single-use enrollment token (retrieve from FrostGate console or secrets vault) |
| `<version>` | Agent version string (e.g. `1.2.3`) |
| `<INSTALL_LOG>` | Absolute path for the MSI install log (e.g. `C:\Windows\Temp\fg_install.log`) |

**Do not hardcode real tokens or tenant IDs in deployment scripts.** Retrieve them from a secrets management system (HashiCorp Vault, Azure Key Vault, AWS Secrets Manager, or equivalent) at deployment time.
