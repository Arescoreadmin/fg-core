# Agent Phase 2 — Enterprise Ready Architecture

## Current Capability Inventory (Before Phase 2)

- **Enrollment flow:** `/agent/enroll` with one-time enrollment token from `/admin/agent/enrollment-tokens`; returns `device_id` and device HMAC key pair prefix.  
- **Key model:** Per-device symmetric secret is generated server-side and stored encrypted (`hmac_secret_enc`) in `agent_device_keys`; agent signs requests with HMAC headers (`X-FG-*`).  
- **Heartbeat:** `/agent/heartbeat` updates `agent_device_registry.last_seen_at`, supports tamper signals and state transitions (active→suspicious→quarantined).  
- **Update flow:** No authenticated software update manifest or rollback-protected updater existed in control-plane APIs.  
- **Logging model:** Server audit events via `audit_admin_action`; no tamper-evident local hash-chain log in agent package.  
- **Service wrapper:** Linux systemd unit exists (`deploy/systemd/frostgate-agent.service`) and Windows service wrapper exists (`agent/windows_service.py`).  
- **Revocation handling:** Admin revocation endpoint disables keys + marks device revoked; revoked device denied by heartbeat/key rotation auth checks.  
- **Control-plane endpoints involved:** `/admin/agent/enrollment-tokens`, `/agent/enroll`, `/agent/heartbeat`, `/agent/key/rotate`, `/admin/agent/devices`, `/admin/agent/devices/{device_id}/revoke`.

## Trust Model and Gaps (Pre-Phase-2)

- **Trust anchors:** API key + HMAC device secret; HTTPS transport policy on agent core client.
- **Gaps:**
  - No device certificate identity lifecycle (CSR, renewal, revocation/expiry checks).
  - No signed remote command plane for enterprise orchestration.
  - No quarantine command/control with strict allowed-command gating.
  - No signed update manifest validation and rollback constraints.
  - No append-only local integrity log + anchor evidence loop.
  - No policy bundle model with signed + hash pinned retrieval.

## Phase 2 Extension Plan (Mapped to Planes)

### Control Plane
- Add endpoints for cert lifecycle (`/agent/cert/enroll`, `/agent/cert/renew`, `/agent/cert/status`).
- Add enterprise command channel (`/agent/commands/poll`, `/agent/commands/ack`, admin issue endpoint).
- Add secure update control (`/agent/update/manifest`, `/agent/update/report`).
- Add quarantine actions (`/admin/agent/quarantine/{device_id}`, `/admin/agent/unquarantine/{device_id}`).
- Add policy publication/fetch (`/admin/agent/policy/publish`, `/agent/policy/fetch`).

### Data Plane
- Add DB tables for identities, commands, policy bundles, quarantine events, log anchors.
- Preserve tenant binding in all queries (`tenant_id + device_id` filters).
- RLS policies for new Postgres tables in migration.

### Compliance Plane
- Continue server `audit_admin_action` for issue/ack/fail/update/quarantine flows.
- Add evidence anchoring endpoint (`/agent/log/anchor`) to tie local chain hash into control-plane evidence.
- Add tests for replay, revocation/expiry denial, tamper detection primitives.

## Threat Model / Attack Surface / Mitigations

- **Compromised update artifact:** mitigated by signature + sha256 + size checks and rollback constraints.
- **Replay of command execution:** mitigated by single-ack state transition (`issued -> acked/failed`) and nonce-bearing signed command documents.
- **Cross-tenant command abuse:** mitigated by strict tenant-scoped lookups and admin tenant binding.
- **Revoked/expired identity bypass:** mitigated by identity checks before command/policy/update endpoints.
- **Local log tampering:** mitigated by chained hashes and anchor submission.

## CI + Platform Deltas

- Added regression tests for Phase 2 security conditions.
- Added new contracts schemas for update manifest and policy bundle.
- Added Postgres migration for enterprise agent entities + RLS.
- Windows service defaults now enable update/policy/quarantine feature flags.

## Phase 2.1 / 2.2 Follow-on Hardening Plan

### P2.1 (Operational Hardening + Fleet Scale)
- Add command lease semantics + idempotency keys.
- Add per-tenant and per-device command/update/policy rate limits with fail-closed 429 audit.
- Formalize explicit device state transition table with invariant tests.
- Add update ring controls (pilot/staged/broad) and auto-pause on error budget burn.
- Add safe-mode behavior to suppress repeated verify-fail update retries until a new manifest version.

### P2.2 (Trust + Compliance)
- Add attestation hooks (TPM-backed where available) and signed inventory proofs.
- Add evidence export bundles and verification CLI workflows.
- Add credential compartmentalization by environment/tenant-group + KEK rotation playbooks.
- Add tag-scoped policy/command targeting to reduce blast radius.
- Add break-glass scoped override with ticket/reason/TTL + high-severity audit events.

### Phase2 Gate
- Added CI gate target `make agent-phase2-gate` to prevent Phase2 drift by enforcing route inventory, openapi security diff, phase2 lint/compile/tests, explicit public-path checks, and RLS expectation checks.

## Phase 2.1 Implemented Delta (this change)
- Command lease + idempotency fields and semantics: `lease_owner`, `lease_expires_at`, `attempt_count`, `idempotency_key`, `terminal_state`.
- Contract-bound command allowlist with schema-validated params for: `collect_diagnostics`, `rotate_identity`, `flush_cache`, `run_integrity_check`, `fetch_inventory`.
- Tenant rollout controls for staged updates with ring-aware gating and kill switch.
- Budget counters for policy publish, command issuance, and update checks with stable 429 code envelopes.
- Anchor cadence primitives and evidence-bundle verification script hook.
