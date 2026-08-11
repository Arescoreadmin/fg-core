-- 0178_drop_legacy_api_keys
-- R4.11: retire legacy api_keys table. All auth now uses tenant_credentials
-- and tenant_credential_roles. Rows were legacy/demo/seed, auth-unreachable,
-- with 6 historically used (confirmed by R4.11 Phase 1 audit, SHA256 archived).
DROP INDEX IF EXISTS idx_api_keys_prefix;
DROP INDEX IF EXISTS idx_api_keys_key_lookup;
DROP INDEX IF EXISTS idx_api_keys_tenant_id;
DROP TABLE IF EXISTS api_keys;
