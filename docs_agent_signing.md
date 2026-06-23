# Agent signing (request canonicalization + Windows artifact signing)

## Request signing spec (agent -> core)

Agent signed endpoints (`/agent/heartbeat`, `/agent/key/rotate`) require:

- `X-FG-DEVICE-KEY`: public key id (`device_key_prefix`)
- `X-FG-TS`: unix timestamp (seconds)
- `X-FG-NONCE`: unique request nonce
- `X-FG-SIG`: lowercase hex HMAC-SHA256 over canonical request

Canonical request string is exactly:

```text
{METHOD}\n{PATH_WITH_SORTED_QUERY}\n{BODY_SHA256}\n{TS}\n{NONCE}
```

Where:

- `METHOD` is uppercased (for current endpoints: `POST`)
- `PATH_WITH_SORTED_QUERY` is request path plus query params sorted by `(key, value)`
- `BODY_SHA256` is SHA-256 of canonical JSON body (`sort_keys=true`, compact separators)
- `TS` and `NONCE` are from headers

Validation rules:

- Missing `TS` / `NONCE` / `SIG` => `401`
- TS too far in future or too old (skew window) => `401`
- Signature mismatch => `403`
- Nonce replay => `403`

Nonce retention policy:

- Nonces are stored with `created_at`
- Cleanup deletes nonces older than retention window (default 10m)
- Per-device nonce table cap enforced (default 10k); oldest rows are evicted

## Shared test vector

Inputs:

- method: `POST`
- path: `/agent/heartbeat?b=2&a=1`
- body: `{"hostname":"host-1","os":"linux"}`
- ts: `1700000000`
- nonce: `abc123nonce`
- secret: `test-secret`

Canonical:

```text
POST
/agent/heartbeat?a=1&b=2
ab091d3221061fa87966d84c02da635664a6a0b39730f99629966bd0adc60740
1700000000
abc123nonce
```

Expected signature:

```text
4f70d52e74880e519cdcae05ba6a8748a47579f5437354d409a5a7db2dfef6a2
```

## Windows artifact signing (Authenticode)

Use `tools/build/sign_agent_windows.ps1` after `tools/build/build_agent_windows.ps1`.

Environment variables:

- `FG_SIGN_CERT_PATH`: path to Authenticode `.pfx`
- `FG_SIGN_CERT_PASSWORD`: certificate password

If not provided, CI keeps artifact unsigned and still emits hash manifest.
