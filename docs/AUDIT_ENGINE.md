# Runtime Audit Engine (Bank-Grade Hardening)

FrostGate Core audit spine is deterministic, tenant-scoped, and fail-closed.

## Capabilities

- Append-only tamper-evident `audit_ledger` with SHA-256 hash-chain + HMAC internal signatures
- Deterministic export bundle + deterministic manifest (`sort_keys=True` canonical JSON)
- Optional asymmetric export signing (Ed25519, KID rotation)
- Evidence store abstraction (`api/evidence_store.py`) and metadata registry (`audit_exports`)
- Export indexing + retention controls (`/audit/exports`, `/audit/retention/apply`)
- Queue/job pattern for heavy exports (`audit_export_jobs` + `/audit/export-jobs/*`) with idempotent states `queued|running|succeeded|failed|cancelled`
- Bypass leash requires reason/ticket/TTL headers and is quota-limited per principal unless super-admin scope
- Chain checkpointing (`audit_chain_checkpoints`) for scalable verification
- Optional daily anchors (`audit_anchors`) with trust-domain labeling
- Compliance UI summary endpoints (no raw debug log exposure)
- Offline verifier CLI: `scripts/fg_audit_verify.py`

## Required env knobs

- `FG_AUDIT_VERIFY_REQUIRED=1` (required in prod/staging)
- `FG_AUDIT_EXPORT_SIGNING_MODE=hmac|ed25519`
- `FG_AUDIT_ED25519_ACTIVE_KID`
- `FG_AUDIT_ED25519_PRIVATE_KEYS_JSON` / `FG_AUDIT_ED25519_PRIVATE_KEYS_FILE`
- `FG_AUDIT_ED25519_PUBLIC_KEYS_JSON` / `FG_AUDIT_ED25519_PUBLIC_KEYS_FILE`
- `FG_AUDIT_CHECKPOINT_INTERVAL` (default `10000`)
- `FG_AUDIT_ANCHOR_ENABLED=1` (optional)
- `FG_AUDIT_SYNC_EXPORT_MAX_ROWS` (default `5000`)
- `FG_AUDIT_AUDITOR_BYPASS_SCOPES` (default `audit:auditor,audit:admin`)

## Offline verification

```bash
.venv/bin/python scripts/fg_audit_verify.py --bundle /path/to/export.zip --pubkeys /path/to/keys.json
```

The verifier runs without DB/service and checks:

- manifest signature validity
- root/bundle/section hash integrity
- signed timestamp format
- explicit range metadata (`range_start_utc`, `range_end_utc`, `range_end_inclusive`)
- chain head presence (if sessions included)

## Local verification

```bash
make audit-chain-verify
make audit-engine
make audit-export-test
make audit-repro-test
make audit-export-verify-determinism
make audit-checkpoint-verify
make audit-evidence-verify
.venv/bin/python -m pytest -q tests/test_audit_engine.py tests/test_audit_signing.py tests/test_audit_api.py tests/test_audit_jobs.py tests/test_audit_offline_verify.py tests/security/test_prod_invariants.py
```

## API

- `GET /audit/sessions` (`audit:read`)
- `GET /audit/exports` (`audit:read`)
- `POST /audit/retention/apply` (`audit:export`)
- `GET /audit/export?start=...&end=...` (`audit:export`)
- `POST /audit/export-jobs` (`audit:export`)
- `GET /audit/export-jobs/{job_id}` (`audit:read`)
- `POST /audit/export-jobs/{job_id}/run` (`audit:export`)
- `POST /audit/export-jobs/{job_id}/cancel` (`audit:export`)
  - Request body: `{ "reason": "...", "ticket_id": "...", "notes": "..." }` where `reason` must be one of `SECURITY_INCIDENT|CUSTOMER_REQUEST|LEGAL_HOLD|OPERATOR_ERROR|DATA_CORRECTION|OTHER`; if `OTHER`, notes are required. `ticket_id` is mandatory in prod/staging.
  - Authorization policy: `audit:export` may cancel only jobs they created; `audit:admin` may cancel any tenant job; `audit:auditor_bypass` may cancel any tenant job with explicit bypass audit events and dedicated bypass rate limiting.
  - Success: `{ "job_id": "...", "status": "cancelled", "error_code": null }`
  - Terminal conflict (`succeeded|failed`): `409` with `error_code=AUDIT_EXPORT_JOB_TERMINAL_STATE`
  - Run-after-cancel: `POST /audit/export-jobs/{job_id}/run` returns `409` and `{ "job_id": "...", "status": "cancelled", "error_code": "AUDIT_EXPORT_JOB_CANCELLED" }`
- `POST /audit/reproduce` (`audit:reproduce`)
- `GET /ui/audit/overview` (`audit:read`)
- `GET /ui/audit/status` (`audit:read`)
- `GET /ui/audit/chain-integrity` (`audit:read`)
- `GET /ui/audit/export-link` (`audit:read`)


Operator note: cancellation is terminal and cannot resurrect a cancelled job. Re-enqueue with the same idempotency key reuses the existing cancelled job deterministically; create a new logical request (different key inputs) to produce a new job. Cancellation meta-audit records include requested_by (stable auth principal id / API key id prefix), reason, ticket_id, notes_hash, bypass flag, event_seq, and UTC RFC3339 `timestamp_utc` hashed into the append-only ledger entry (notes are canonicalized via NFKC + whitespace folding + control-char rejection before hashing).

Cancel rate limiting is enforced per `(tenant_id, actor_id, action)` for both normal and bypass cancellation flows.

Each export-job intent increments `job_event_seq` transactionally and includes `{event_seq, timestamp_utc}` in hashed audit event material for forensic reconstruction.
