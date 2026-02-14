# FrostGate Agent

Production-grade additive agent implementation that communicates with FrostGate Core only via documented control-plane endpoints.

## Setup

1. Copy `.env.example` to `.env` and fill credentials.
2. Install dependencies:
   ```bash
   pip install -r agent/requirements.txt
   ```
3. Run agent:
   ```bash
   python -m agent.app.agent_main
   ```

## Environment variables

- `FG_CORE_BASE_URL`: Base URL of control plane (https required by default).
- `FG_ALLOW_INSECURE_HTTP`: Set to `1` only for local/dev to permit `http://` Core URLs.
- `FG_ALLOW_PRIVATE_CORE`: Set to `1` to allow private/loopback/link-local Core hosts.
- `FG_CORE_HOST_ALLOWLIST`: Optional comma list of allowed Core hosts/CIDRs (supports exact host, `*.suffix`, `.suffix`, CIDR).
- `FG_CORE_CERT_SHA256`: Optional comma list of TLS certificate SHA256 fingerprints for pinning.
- `FG_AGENT_KEY`: Agent API key.
- `FG_TENANT_ID`: Tenant identifier (authoritative from control plane context).
- `FG_AGENT_ID`: Agent identifier.
- `FG_CONTRACT_VERSION`: Contract version sent via `X-Contract-Version`.
- `FG_QUEUE_PATH`: SQLite queue file path (must be writable local disk; WAL creates `-wal`/`-shm` sidecar files).
- `FG_QUEUE_MAX_SIZE`: Queue cap.
- `FG_BATCH_SIZE`: Max events per flush.
- `FG_FLUSH_INTERVAL_SECONDS`: Sender flush interval.
- `FG_REDIS_URL`: Optional Redis limiter endpoint.
- `FG_COMMAND_POLL_INTERVAL_SECONDS`: Command poll interval.
- `FG_EVENT_ID_MODE`: `hmac_v2` (default) or `legacy` during migration.
- `FG_EVENT_ID_KEY_CURRENT`: Current HMAC key for event IDs (`hmac_v2` mode).
- `FG_EVENT_ID_KEY_PREV`: Optional previous key for verifier compatibility during rotation.
- `FG_EVENT_ID_KEYS`: Alternate comma-separated key list (first key is used for signing).
- `FG_DEAD_LETTER_MAX`: Dead-letter retention cap (default `10000`, oldest purged first).

## Local development

```bash
python -m pytest -c agent/ci/pytest.ini agent/tests
python agent/ci/verify_agent_contracts.py
python agent/ci/verify_rate_limit_keys.py
```

## Docker

```bash
docker compose -f agent/docker-compose.yml up --build
```

## Command flow

- Poller fetches commands with cursor pagination and dedupes command IDs.
- Executor enforces allow-listed command types.
- Receipt sender submits idempotent receipts and handles replay / terminal codes.

## Compliance & posture

- Inventory and posture collectors report platform details, attestation stubs, root/jailbreak signals, and compliance status.
- Event IDs are deterministic over canonical payload slices and default to HMAC-based `ev2_` IDs.

## Rate limiting

- Redis-first limiter with in-memory fallback.
- Key format: `tenant:<tenant>|agent:<agent>|route:<route>|api_key_hash:<hash>`.
- Internal `rate_limited` observability events are logged locally (never sent to Core).

## Failure modes

- Retries only on transient errors.
- `AUTH_REQUIRED` and `SCOPE_DENIED` fail fast.
- `ABUSE_CAP_EXCEEDED` / `PLAN_LIMIT_EXCEEDED` trigger bounded cooldown.
- Queue persists across restart with retry scheduling.

## Contract versioning

All outbound requests include:
- `X-Contract-Version`
- `X-Request-ID`

Error handling expects stable envelope:
`{code, message, details, request_id}`.


## Operational notes

- Memory rate-limit fallback is **non-distributed** (per-process) and is only a degraded safety net when Redis is unavailable. In multi-instance deployments, keep Redis healthy for global enforcement.
- Deterministic event IDs use a **5-second UTC bucket** (`EVENT_BUCKET_SECONDS=5`). The agent normalizes timestamps to UTC before hashing. If hosts have large clock skew, dedupe quality may degrade; keep NTP synchronized.
- `X-Request-ID` handling: new ID per distinct logical request, but retries for the same event batch reuse the same request ID for traceability.

- `agent_boot` is intended for rollout observability. Billing/active-device accounting should key off distinct device identity over long windows (for example, 30d), not raw boot-event count.
- Future hardening: capture Core `Date`/time headers on auth/rate-limit responses to estimate local clock skew for dedupe diagnostics.


## Integration smoke

A minimal integration smoke is available at `agent/ci/integration_smoke.py`. It starts:
- a mock Core HTTP service,
- a lightweight Redis TCP placeholder for wiring checks,
- the agent runtime for ~10-20 seconds.

It asserts Core-observed outcomes:
- `agent_boot` received,
- `heartbeat` received,
- one command is polled and a receipt is submitted,
- command transitions to terminal.

Run:
```bash
python agent/ci/integration_smoke.py
```
