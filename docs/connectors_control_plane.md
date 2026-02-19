# Connector Control Plane v1

Connector Control Plane v1 provides tenant-isolated connector governance and execution.

## Capabilities

- Per-tenant connector enable/disable via `POST /admin/connectors/{connector_id}/state`.
- Tenant policy version management via `GET/POST /admin/connectors/policy`.
- Credential lifecycle:
  - connect/rotate via `POST /admin/connectors/{connector_id}/connect`
  - revoke via `POST /admin/connectors/{connector_id}/revoke`
- Policy-gated ingest via `POST /internal/connectors/{connector_id}/ingest`.
- Deterministic contract validation (`tools/ci/validate_connector_contracts.py`).
- Idempotency support for policy/state/connect/revoke via `Idempotency-Key`.

## Security invariants

- Tenant isolation uses existing tenant binding (`bind_tenant_id`, `require_bound_tenant`, `tenant_db_required`) and Postgres RLS for connector tables.
- Credential secrets are encrypted using AES-GCM with KEK versioning and AAD bound to tenant/connector/credential identity and environment:
  - `FG_CONNECTOR_KEK_CURRENT_VERSION`
  - `FG_CONNECTOR_KEK_<VERSION>` (base64 key material)
- Missing/invalid policy fails closed (`CONNECTOR_POLICY_DENY`).
- Missing KEK material fails closed in credential decryption.
- No raw secrets are logged; only stable IDs and hashes are emitted.
- Connector status endpoint is non-leaky and emits only coarse fields.

## Status response contract (safe)

For each connector, `/admin/connectors/status` returns only:

- `connector_id`
- `connected` (boolean)
- `enabled` (boolean)
- `last_success_at` (timestamp/null)
- `last_error_code` (deterministic code/null)
- `health` (`ok | degraded | blocked`)

## Dispatch controls

- Policy allowlist gating (`enabled_connectors`, `allowed_collections`, `allowed_resources`).
- Deterministic payload hashing in connector audit ledger.
- Per-tenant and per-connector dispatch budgets.
- Cooldown window after repeated failures.
- Deny decisions audited with deterministic error codes.

## Contract layout

- `contracts/connectors/schema/connector.schema.json`
- `contracts/connectors/schema/policy.schema.json`
- `contracts/connectors/connectors/*.json`
- `contracts/connectors/policies/default.json`

## Extension path

Connector runtime implementations should be added behind `services/connectors/runner.py` dispatch interfaces.
Polling/subscription hooks are currently explicit stubs to preserve safe default behavior in v1.
