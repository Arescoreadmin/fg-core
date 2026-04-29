# FrostGate Agent — Windows Service and MSI Installer Contract

**Version:** 1.0.0
**Status:** APPROVED — drives 18.1 (service wrapper) and 18.2 (MSI installer) implementation.
**Depends on:** Task 17.4 (lifecycle controls), Task 17.5 (agent observability)

---

## 1. Windows Service Wrapper Contract

### 1.1 Service Identity

| Field | Value |
|---|---|
| Service name | `FrostGateAgent` |
| Display name | `FrostGate Agent` |
| Description | `FrostGate endpoint telemetry agent — collects and forwards device telemetry to the FrostGate control plane` |
| Executable entrypoint | `FrostGateAgent.exe` (PyInstaller-bundled or native binary) |
| Install directory | `C:\Program Files\FrostGate\Agent` |
| Working directory | `C:\ProgramData\FrostGate\Agent` |
| Log directory | `C:\ProgramData\FrostGate\Agent\logs` |
| Config directory | `C:\ProgramData\FrostGate\Agent\config` |
| Data / state directory | `C:\ProgramData\FrostGate\Agent\data` |
| Queue directory | `C:\ProgramData\FrostGate\Agent\data\queue` |

### 1.2 Service Lifecycle

| Operation | Behavior |
|---|---|
| **install** | Register service with SCM using `sc create`. Validate required config before registration completes. Fail closed if config missing or invalid. |
| **start** | SCM starts `FrostGateAgent.exe`. Service validates enrolled device credential before accepting any commands or starting collectors. |
| **stop** | SCM sends `SERVICE_CONTROL_STOP`. Service enters graceful shutdown: flush inflight telemetry, stop collectors, dequeue pending events, exit within `GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS` (default 30s). |
| **restart** | SCM stops then starts. Device credential and identity must survive restart unchanged. |
| **upgrade** | MSI upgrade runs, existing service stopped, binary replaced, service re-registered if needed, started. Device identity (device_id, device key) preserved unless purge requested. |
| **uninstall** | Service stopped and de-registered from SCM. Config and data directories preserved (non-purge uninstall). |
| **purge uninstall** | Service stopped and de-registered. All FrostGate directories removed: `C:\ProgramData\FrostGate\Agent\`. Device credential removed from Windows Credential Manager. Device revocation via control plane is a SEPARATE operator action. |

### 1.3 Startup Behavior

**REQUIRED — fail closed:**

- Service MUST validate that a device credential (device_id + device_key) exists in protected storage before starting any collector.
- Service MUST NOT start collectors or submit telemetry if no valid enrolled device credential is found.
- Service MUST NOT silently default to localhost, `http://127.0.0.1`, or any dev/test endpoint in production.
- Service MUST NOT use a dev-bypass mode (`FG_DEV_AUTH_BYPASS=1` or equivalent) in production builds.
- Service MUST fetch effective configuration (version floor, collector config, policy) only after device identity is authenticated via `/agent/heartbeat` or `/agent/config`.
- If the control plane returns `disabled` or `revoked` for this device (per 17.4 lifecycle controls), service MUST halt collector execution and cease telemetry submission until operator intervenes.
- If agent version is below the effective version floor (per 17.4), service MUST log the outdated condition and cease normal operation until upgraded.

**Config load order:**

1. `C:\ProgramData\FrostGate\Agent\config\agent.toml` (primary config)
2. MSI-written defaults (install-time parameters, non-secret)
3. Environment variables (optional, for admin overrides)

Required config keys (startup fails without these):
- `control_plane_url` — HTTPS endpoint, no localhost in production
- `tenant_id` — non-empty, no placeholder
- `device_credential_target` — Windows Credential Manager target name

### 1.4 Shutdown Behavior

- **Graceful shutdown timeout:** `GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS` default `30`. Configurable via `agent.toml`.
- **Collector stop:** All collectors receive stop signal; each collector must honor stop within 10s or be force-terminated.
- **Inflight telemetry:** Queued events are flushed to durable local queue (SQLite WAL) before exit. Unflushed in-memory events are written to queue, not dropped.
- **Failure mode if timeout exceeded:** Service logs `SHUTDOWN_TIMEOUT` event to Windows Event Log and Windows Application log, then exits forcefully. Data integrity protected by WAL journal.

### 1.5 Recovery Behavior

| Parameter | Value |
|---|---|
| **Restart policy** | Automatic restart on failure (SCM first/second/subsequent failure actions) |
| **Backoff policy** | 0s → 60s → 300s (first, second, subsequent failure reset interval: 86400s) |
| **Max restart threshold** | Subsequent failures after threshold use maximum backoff; operator must investigate after 5 consecutive failures within reset window |
| **Failure logging** | Every restart cycle MUST write to Windows Application Event Log (source: `FrostGateAgent`) with failure reason and timestamp |
| **Unhealthy state** | If service cannot reach control plane for `OFFLINE_THRESHOLD_SECONDS` (default 3600), log `CONTROL_PLANE_UNREACHABLE` to Event Log; continue local queue accumulation; do not discard queued telemetry |

### 1.6 Local Account / Privilege Model

- **Service identity target:** `NT SERVICE\FrostGateAgent` (Windows virtual service account). No interactive logon rights. No local admin.
- **Filesystem ACLs:**
  - `C:\Program Files\FrostGate\Agent\` — read + execute for `NT SERVICE\FrostGateAgent`; write for `SYSTEM` and local `Administrators` only
  - `C:\ProgramData\FrostGate\Agent\` — read + write for `NT SERVICE\FrostGateAgent`; no broader access
- **No admin-required runtime:** The service MUST run under a non-privileged virtual account at runtime. Admin privilege is required only during install/uninstall operations (MSI elevation).
- **No interactive session dependency:** Service runs in Session 0 (non-interactive). No UI, no desktop access, no user-profile dependency.
- **Network access:** Service requires outbound HTTPS (port 443) to control plane. No inbound ports required.

### 1.7 Logs and Observability

- **Windows Event Log source:** `FrostGateAgent` registered in `SYSTEM\CurrentControlSet\Services\EventLog\Application\FrostGateAgent`
- **Local log path:** `C:\ProgramData\FrostGate\Agent\logs\agent.log` (rotating, max 10MB × 5 files)
- **Log format:** Structured JSON (same as Linux agent), one event per line
- **Minimum structured log fields:** `timestamp` (ISO 8601 UTC), `level`, `agent_id`, `device_id`, `tenant_id`, `event`, `message`
- **Secrets MUST NOT appear in logs:** device_key, enrollment_token, bootstrap_token, FG_SIGNING_SECRET, FG_INTERNAL_AUTH_SECRET, any bearer token or API key
- **Heartbeat observability (17.5):** Service MUST include collector_statuses in every heartbeat per the 17.5 schema. Health status reported via `/admin/agent/devices/{device_id}/status` MUST reflect Windows service state.
- **Service events logged to Event Log:** start, stop, restart, enrollment success, enrollment failure, config update, collector start, collector failure, graceful shutdown, forced shutdown, lifecycle state changes (disabled/revoked/outdated)

---

## 2. MSI Installer Build / Install Contract

### 2.1 Supported Install Modes

| Mode | Description |
|---|---|
| **interactive** | GUI-driven install wizard; prompts for required parameters if not pre-supplied |
| **silent** | `msiexec /i FrostGateAgent.msi /qn PROPERTY=VALUE ...` — no UI; fails closed if required properties absent |
| **repair** | `msiexec /f FrostGateAgent.msi` — reinstalls files, re-registers service; preserves device credential and data |
| **upgrade** | Major/minor upgrade via MSI ProductCode replacement; device identity preserved; service restarted |
| **uninstall** | `msiexec /x FrostGateAgent.msi /qn` — removes service and binaries; preserves `C:\ProgramData\FrostGate\Agent\` |
| **purge uninstall** | `msiexec /x FrostGateAgent.msi /qn PURGE_DATA=1` — removes service, binaries, and all data/credential directories |

### 2.2 Silent Install Parameters

| Property | Required | Description |
|---|---|---|
| `TENANT_ID` | **Required** | Tenant identifier. Non-empty, no placeholder. Validated against `^[a-zA-Z0-9_-]{3,128}$`. |
| `ENROLLMENT_TOKEN` | **Required** (first install) | Bootstrap enrollment token. Used once to exchange for device credential. Never written to disk as plaintext. |
| `FROSTGATE_ENDPOINT` | **Required** | HTTPS control plane URL. Must begin with `https://`. Localhost and non-TLS endpoints rejected in production profile. |
| `ENVIRONMENT` | **Required** | One of `prod`, `staging`. `dev` and `local` are rejected in production-signed MSI. |
| `INSTALLDIR` | Optional | Override install directory. Defaults to `C:\Program Files\FrostGate\Agent`. |
| `LOG_LEVEL` | Optional | One of `debug`, `info`, `warn`, `error`. Default: `info`. |
| `PURGE_DATA` | Optional (uninstall only) | If `1`, purge all data and credentials on uninstall. Default: `0`. |

### 2.3 Parameter Validation

- **Missing required parameters:** MSI fails closed; installation does not proceed; exit code 1603 (fatal error).
- **TENANT_ID format:** Validated as `^[a-zA-Z0-9_-]{3,128}$`. Invalid format → fail closed.
- **FROSTGATE_ENDPOINT validation:** Must be `https://` scheme. Must not be `localhost`, `127.0.0.1`, `::1`, or any RFC 1918/link-local address in `ENVIRONMENT=prod` or `ENVIRONMENT=staging`. Invalid → fail closed.
- **ENROLLMENT_TOKEN:** Validated as non-empty, minimum 32 characters. Never written to disk in plaintext. Used only during the enrollment exchange. After successful enrollment, removed from memory and not stored anywhere.
- **ENVIRONMENT:** `dev` and `local` are rejected by production-signed MSI. Non-production builds may permit these for lab use; this MUST be clearly indicated in the artifact signing status.

### 2.4 Enrollment Flow

**ENROLLMENT_TOKEN / BOOTSTRAP_TOKEN MUST NOT be written to disk at any point.** No `.enroll` file, no temporary token file, no plaintext bootstrap token file, no config-stored enrollment token. No installer log and no Windows Event Log entry may contain raw enrollment/bootstrap token material. No crash dump or diagnostic bundle may intentionally include raw enrollment/bootstrap token material.

**Approved handoff patterns:**
- MSI custom action passes token directly to the enrollment process via secure in-memory process invocation (e.g., `CreateProcess` with an inherited handle or a named pipe — never a command-line argument that can be logged).
- If deferred handoff is required, the token MUST be stored using Windows Credential Manager or DPAPI-protected secret storage directly — never as a plaintext file.
- Raw token lifetime is bounded: token is cleared from process environment and memory as soon as the exchange completes.

**Explicitly forbidden:**
- `.enroll` raw token file or any raw bootstrap token file on disk
- Plaintext enrollment/bootstrap token in any config file (including `agent.toml`)
- Command-line echo or logging of the token value
- Fallback enrollment using a localhost or dev endpoint in production profile

**Required enrollment flow:**

1. MSI receives `TENANT_ID`, `CONTROL_PLANE_URL`, `ENVIRONMENT`, and `ENROLLMENT_TOKEN` / `BOOTSTRAP_TOKEN` as install-time inputs.
2. Installer validates all required inputs before service registration. Missing or invalid inputs → install fails closed; no service is registered.
3. Installer MUST NOT write the raw enrollment/bootstrap token to disk in any form.
4. Installer performs bootstrap enrollment immediately (preferred) via an in-process custom action, OR if enrollment must be deferred, stores the token only via Windows Credential Manager / DPAPI — never as a plaintext file.
5. Enrollment call (`POST /agent/enroll`) exchanges the raw install-time token for a `device_id` + `device_key` device credential.
6. Device credential is stored using DPAPI, Windows Credential Manager (target: `FrostGate/Agent/{tenant_id}/{device_id}`), or an approved equivalent. Raw device credential is never written to disk as plaintext.
7. Raw enrollment/bootstrap token is cleared immediately after the exchange and is never reused.
8. `device_id` (non-secret identifier) is written to `agent.toml`.
9. Service starts only after device credential exists in protected storage and is validated by a successful control plane call.
10. If enrollment fails, installation fails closed with an actionable, non-token-leaking error message. Service is not started.
11. On all subsequent starts, service reads `device_id` from `agent.toml` and `device_key` from Windows Credential Manager. No enrollment token is referenced after initial exchange.
12. **Identity stability:** device_id and device_key survive restart, upgrade (non-purge), and repair. Purge uninstall removes the Credential Manager entry.
13. **Revoked/disabled device behavior (17.4):** If control plane returns `DEVICE_REVOKED` or `DEVICE_DISABLED`, service halts collector execution immediately and logs the lifecycle state. Reenrollment requires operator action (purge + fresh enrollment token).

### 2.5 Artifact Contents

| Artifact | Description |
|---|---|
| `FrostGateAgent.msi` | Signed MSI package |
| `FrostGateAgent.exe` | Signed PyInstaller-bundled agent executable |
| `agent.toml.template` | Config template (no secrets, substituted by MSI installer actions) |
| `service_register.ps1` | Service registration script (called by MSI custom action) |
| `service_unregister.ps1` | Service deregistration script (called by MSI uninstall) |
| `migrate_config.ps1` | Config migration hook for upgrades (runs before service start on upgrade) |
| `LICENSE.txt` | Apache 2.0 / commercial license |
| `RELEASE_NOTES.txt` | Human-readable release notes |
| `manifest.sha256` | SHA256 hash of every artifact in the MSI |

### 2.6 Config File Contents (`agent.toml`)

`agent.toml` is the non-secret runtime config file written by the MSI installer and read by the service at startup.

**`agent.toml` MAY contain:**
- `tenant_id` — non-secret tenant identifier
- `control_plane_url` — HTTPS endpoint
- `environment` / `profile` — `prod`, `staging`
- `log_level` — `debug`, `info`, `warn`, `error`
- `device_id` — non-secret device identifier (written after successful enrollment)
- Other non-secret service settings (flush interval, queue path, etc.)

**`agent.toml` MUST NOT contain:**
- Enrollment token or bootstrap token of any kind
- Device private key or device_key
- API key, signing secret, or bearer token
- HMAC secret or any credential material
- `FG_SIGNING_SECRET`, `FG_INTERNAL_AUTH_SECRET`, `FG_AGENT_KEY`, `FG_API_KEY`

Violation is a release blocker and a security incident trigger.

### 2.7 Artifact Exclusions

The MSI MUST NOT contain:

- Baked tenant secrets (`FG_SIGNING_SECRET`, `FG_INTERNAL_AUTH_SECRET`, API keys)
- Baked enrollment token or bootstrap token
- Plaintext device credentials
- Environment-specific production secrets of any kind
- Dev-bypass defaults (`FG_DEV_AUTH_BYPASS=1`, `FG_ALLOW_INSECURE_HTTP=1`, `FG_ALLOW_PRIVATE_CORE=1`)
- Pre-populated `FG_AGENT_KEY` or `FG_API_KEY`

Violation of any exclusion is a release blocker.

### 2.8 Versioning and Upgrade

- **Version field:** Semantic version `MAJOR.MINOR.PATCH` embedded in MSI ProductVersion and `FrostGateAgent.exe` file metadata.
- **Upgrade preserves identity:** Non-purge upgrade keeps device_id in `agent.toml` and device_key in Credential Manager. Collectors restart; queue is preserved.
- **Downgrade behavior:** Downgrade to a version below the effective `version_floor` (per 17.4) is permitted by MSI but agent will immediately enter `outdated` health state on next heartbeat and halt collector execution. This is intentional: the version floor is enforced at runtime by the control plane, not blocked at install time.
- **Version floor compatibility:** Agent binary MUST report its version in every heartbeat per 17.5 schema. Control plane health evaluation (17.4) determines if the running version is below floor.
- **Rollback behavior:** MSI rollback (failed upgrade) restores previous binary; Credential Manager entry and `agent.toml` are preserved; service restarted on rollback. If rollback leaves agent below version floor, behavior is same as downgrade above.

### 2.9 Signing and Release Metadata

- **MSI signing:** Required for production release. Signed with organization code signing certificate. SHA-256 digest algorithm. Timestamp authority required. Unsigned MSI MUST be labeled `NOT FOR PRODUCTION`.
- **Executable signing:** `FrostGateAgent.exe` signed independently. Both MSI container and embedded executable must be signed.
- **Unsigned artifacts:** Build pipeline MUST mark unsigned artifacts with `BUILD_SIGNED=false` in release metadata. Unsigned artifacts MUST NOT be deployed to production endpoints.
- **Hash manifest:** `manifest.sha256` lists SHA256 of every file in the package. Verified by installer at extract time and again by agent at startup (self-integrity check on binary).
- **Release metadata fields (release_metadata.json):**
  ```json
  {
    "product": "FrostGateAgent",
    "version": "MAJOR.MINOR.PATCH",
    "commit": "<git sha>",
    "build_time": "<ISO 8601 UTC>",
    "signing_status": "signed|unsigned",
    "signed_by": "<certificate CN or 'N/A'>",
    "sha256_msi": "<hex>",
    "sha256_exe": "<hex>",
    "min_os": "Windows 10 1903 / Server 2019",
    "arch": "x86_64"
  }
  ```

### 2.10 Enterprise Deployment (Intune / GPO / RMM)

**Compatibility:** The MSI is a standard Windows Installer package compatible with:
- Microsoft Intune (Win32 app deployment)
- Group Policy (GPO software installation)
- Any RMM tool supporting `msiexec` invocation (e.g., NinjaRMM, ConnectWise, Datto)

**Intune silent install command:**
```
msiexec /i FrostGateAgent.msi /qn /l*v C:\Windows\Temp\FrostGateAgent_install.log TENANT_ID="<your-tenant-id>" ENROLLMENT_TOKEN="<bootstrap-token>" FROSTGATE_ENDPOINT="https://your-control-plane.example.com" ENVIRONMENT="prod"
```

**Intune silent uninstall command:**
```
msiexec /x {PRODUCT-CODE-GUID} /qn /l*v C:\Windows\Temp\FrostGateAgent_uninstall.log
```

**Intune purge uninstall command:**
```
msiexec /x {PRODUCT-CODE-GUID} /qn PURGE_DATA=1 /l*v C:\Windows\Temp\FrostGateAgent_uninstall.log
```

**GPO deployment:** Assign to computer configuration (not user). Run in system context. Use transform (`.mst`) to pre-populate required properties for org-wide silent deployment.

**Log collection path:** `C:\Windows\Temp\FrostGateAgent_install.log` (MSI log) and `C:\ProgramData\FrostGate\Agent\logs\agent.log` (runtime log).

**Detection rule (Intune):** File exists: `C:\Program Files\FrostGate\Agent\FrostGateAgent.exe` AND registry key `HKLM\SYSTEM\CurrentControlSet\Services\FrostGateAgent` exists.

**Rollback (Intune / RMM):**
```
msiexec /x {PRODUCT-CODE-GUID} /qn
```
Then re-deploy previous version MSI via Intune. Device identity preserved (non-purge).

---

## 3. Security and Failure Contract

The following guarantees MUST be maintained by any implementation:

| Guarantee | Requirement |
|---|---|
| No embedded secrets | MSI artifact contains no tenant secrets, API keys, signing secrets, or credentials of any kind |
| No raw token persistence | ENROLLMENT_TOKEN / BOOTSTRAP_TOKEN is never written to disk in plaintext; deleted from all intermediate files after exchange |
| Protected credential at rest | device_key stored exclusively via Windows DPAPI / Credential Manager; never in plaintext file, registry plaintext, or environment variable |
| Fail closed on missing config | Service and installer fail with non-zero exit if TENANT_ID, FROSTGATE_ENDPOINT, or device credential is absent or invalid |
| Production rejects dev defaults | ENVIRONMENT=prod and ENVIRONMENT=staging reject localhost, HTTP, and dev-bypass flags |
| Revoked agents cannot submit telemetry | If control plane returns DEVICE_REVOKED or lifecycle_status=revoked (17.4), service halts collector execution immediately |
| Disabled agents cannot submit telemetry | If lifecycle_status=disabled (17.4), same halt behavior as revoked |
| Version floor enforced | If agent version is below effective_min_version (17.4/17.5), agent halts collectors and reports outdated health status |
| Logs never contain secrets | device_key, tokens, signing secrets, and API keys are never written to any log output |
| Config tampering | Agent verifies SHA256 of own executable at startup against `manifest.sha256`. Mismatch → halt with INTEGRITY_FAILURE event log entry |
| TLS required | All control plane communication requires HTTPS (TLS 1.2 minimum, TLS 1.3 preferred). Certificate validation enabled. Self-signed certificates rejected in production profile unless explicitly pinned via `FG_CORE_CERT_SHA256`. |

---

## 4. Implementation Status

This document drives tasks 18.1 (Windows service wrapper) and 18.2 (MSI installer).

### Implemented in task 18.1 (this task)

- `agent/app/service/wrapper.py` — Typed service wrapper contract module:
  - `WindowsServiceConfig` dataclass with all required fields
  - `validate_service_config()` — enforces non-empty fields, forbidden accounts, no secret material in config path
  - `build_install_command_plan()` — deterministic `sc create` command plan; no token material; uses non-privileged service account
  - `build_start_command_plan()` — fails closed without config path and device credential
  - `build_stop_command_plan()` — deterministic `sc stop` command plan
  - `build_uninstall_command_plan()` — purge-off by default; explicit `purge=True` required to signal data removal
  - `execute_live()` — platform-gated; raises `UnsupportedPlatformError` on non-Windows
  - `validate_production_endpoint()` — rejects localhost, HTTP, and loopback addresses
  - `default_frostgate_service_config()` — canonical defaults with `NT SERVICE\FrostGateAgent` account
- `tests/agent/test_windows_service_wrapper.py` — 44 tests covering config, security, platform behavior, lifecycle compatibility, and regression invariants

**Live Windows service execution was NOT tested** — implementation runs on Linux CI.
Command plans are cross-platform and deterministic; actual SCM execution is platform-gated.
**MSI packaging is NOT implemented** — that is task 18.2.

### Existed before task 18.1

- `agent/windows_service.py` — pywin32 service skeleton (implements service name, display name, SvcStop/SvcDoRun lifecycle)
- `agent/windows-requirements.txt` — pywin32 + pyinstaller declared
- `agent/app/config.py` — `AgentConfig` load_config() (enforces required env vars via `os.environ[...]`)

### Implemented in task 18.2

- `agent/app/installer/msi_contract.py` — Typed MSI build contract module:
  - `MsiBuildContract` dataclass — product name, version, GUIDs, output dir, signing and manifest requirements
  - `MsiArtifactManifest` dataclass — release metadata schema (SHA256 hashes, signing status, arch, OS floor)
  - `validate_contract()` — GUID regex, no secrets in artifact name, sha256_manifest_required must be True
  - `build_build_command_plan()` — deterministic WiX candle + light command plan (cross-platform generation)
  - `build_smoke_test_plan()` — PowerShell SHA256 verification command
  - `build_install_command_example()` — msiexec install command with `<placeholder>` values only (never real tokens)
  - `build_uninstall_command_example()` — standard and `PURGE_DATA=1` variants; purge off by default
  - `build_manifest_template()` — unsigned `MsiArtifactManifest` pre-build template
  - `execute_live_build()` — platform-gated; raises `MsiToolchainError` on non-Windows or missing WiX toolchain
  - `validate_msi_endpoint()` — rejects localhost, RFC 1918, link-local, HTTP; mirrors wrapper.py logic
  - `validate_environment()` — rejects `dev` and `local` environment strings in production context
  - `default_frostgate_msi_contract()` — factory with canonical upgrade GUID and signing defaults
- `agent/app/installer/__init__.py` — package init re-exporting all public symbols
- `tests/agent/test_msi_installer_contract.py` — 63 tests covering contract validation, command plan determinism, security invariants, manifest schema, endpoint/environment guards, platform behavior, and plan YAML cross-reference

**Live MSI build was NOT tested** — WiX toolchain unavailable on Linux CI.
Command plans are cross-platform and deterministic; actual toolchain execution is platform-gated.

### Implemented in task 18.3

- `agent/app/installer/silent_enrollment.py` — Typed silent enrollment parameter model and command builders:
  - `SilentEnrollmentParams` frozen dataclass — tenant_id, control_plane_url (→ `FROSTGATE_ENDPOINT`), environment, enrollment_token, bootstrap_token (mutually exclusive), install_dir, log_level
  - `validate()` — rejects missing/empty tenant_id; rejects HTTP, localhost, RFC 1918, link-local endpoints; rejects dev/local environment; enforces token mutual exclusivity
  - `build_msiexec_args(artifact_path, *, redact_token=False)` — deterministic `msiexec /i … /qn` argument list; raw token only when `redact_token=False`
  - `build_log_safe_args(artifact_path)` — identical to `build_msiexec_args(redact_token=True)`; safe for log output
  - `execute_live_enrollment(artifact_path)` — platform-gated; raises `EnrollmentToolchainError` on non-Windows or missing msiexec; uses `shell=False` arg list (no metacharacter injection)
  - `SERVICE_CREDENTIAL_GATE_REQUIRED = True` — explicit invariant: service start is gated on device credential, never on raw token presence
  - `placeholder_enrollment_params()` — factory returning non-production placeholder values for docs and tests
- `agent/app/installer/__init__.py` — updated to re-export all silent_enrollment public symbols
- `tests/agent/test_silent_enrollment_install_flow.py` — 65 tests covering parameter validation, command plan content and determinism, token redaction in log-safe output, service credential gate, platform behavior, plan YAML cross-reference, and regression invariants

**Token persistence rules (unchanged from 17.6 contract):**
- Raw enrollment/bootstrap token is install-time only; exchanged for a device credential and discarded
- Token is never written to `agent.toml`, disk, or any non-secret config
- Token never appears in `build_log_safe_args()` output — always replaced with `<redacted>`
- Token is not part of any log, release manifest, or MSI artifact

**Live MSI enrollment was NOT tested** — msiexec unavailable on Linux CI.
Command plan generation is cross-platform and deterministic; live enrollment execution is platform-gated.
Silent install examples use placeholder values only; log-safe examples always redact tokens.

### Still required in 18.4 and later tasks

- Credential Manager integration (DPAPI storage of device_key)
- Enrollment flow with token deletion after exchange (live Windows path)
- ACL setup in installer custom actions
- Windows Event Log source registration
- Config tampering / binary integrity check
- Release signing pipeline
