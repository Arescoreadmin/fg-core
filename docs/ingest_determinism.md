# Ingest determinism contract

`/ingest` determinism is client-supplied: clients **must** provide a stable `event_id`.

The system enforces tenant-scoped uniqueness on `(tenant_id, event_id)` and replays return the existing stored response.
This behavior is a correctness contract (idempotency), not a best-effort optimization.

Any future batching or async ingest pipeline must preserve this exact collision behavior for identical `(tenant_id, event_id)` values.
