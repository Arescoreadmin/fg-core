# Agent Core Security Notes

## Config authenticity modes

- Integrity hash is always required (`config_hash`, SHA-256 over canonical JSON).
- If no HMAC keys are configured, validation runs in integrity-only mode.
- If any HMAC key is configured, `config_sig` is mandatory and must validate with HMAC-SHA256.

## HMAC key rotation

- Verification accepts:
  - `FG_CONFIG_HMAC_KEY_CURRENT`
  - `FG_CONFIG_HMAC_KEY_PREV`
  - `FG_CONFIG_HMAC_KEYS` (comma-separated)
  - legacy `FG_CONFIG_HMAC_KEY`
- Signing uses deterministic key id `k0` mapped to CURRENT (or the first resolved key if CURRENT is unset).
- Verifiers accept signatures validated by CURRENT/PREV/KEYS/legacy keyring entries.
- Safety rail: PREV-only configuration (without CURRENT/legacy/list) is rejected for signing (`config_hmac_current_required_for_signing`).
- Signature encoding is lowercase hex SHA-256 digest (64 chars).

## Queue quarantine semantics

- On integrity check failure, queue fails closed, writes quarantine sentinel, emits quarantine audit, and moves DB aside.
- Startup with unreadable sentinel is treated as quarantined (fail-closed).
- Clearing quarantine requires explicit operator action: `force=True` and non-empty reason.

## Log redaction guarantees

Transport logs redact sensitive headers including auth/cookie/api-key/proxy headers.
Logged URLs strip query strings and userinfo to prevent credential leakage.
