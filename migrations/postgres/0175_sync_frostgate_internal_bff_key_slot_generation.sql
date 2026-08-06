-- Migration 0175: re-sync credential_slots.current_generation for frostgate-internal
-- console-bff-key with the actual active generation in tenant_credentials.
--
-- Migration 0174 reset current_generation = 0 to break a stuck slot.  The API
-- bootstrap (internal_platform_authority.py) uses an idempotency key, so if a
-- tenant_credentials row already existed with that key the slot advance was
-- skipped — leaving credential_slots.current_generation = 0 while the live
-- credential lives at generation N in tenant_credentials.
--
-- This UPDATE sets current_generation to the highest active generation, allowing
-- bootstrap on the next API restart to detect the credential as reused rather than
-- attempting a fresh issuance.  If no active credential exists (gen = 0), the WHERE
-- guard keeps the row unchanged so bootstrap issues a new credential on startup.

WITH actual_gen AS (
    SELECT COALESCE(MAX(tc.generation), 0) AS gen
    FROM tenant_credentials tc
    WHERE tc.tenant_id       = 'frostgate-internal'
      AND tc.credential_type = 'tenant_api_key'
      AND tc.credential_slot = 'console-bff-key'
      AND tc.status          = 'active'
)
UPDATE credential_slots cs
SET current_generation = a.gen
FROM actual_gen a
WHERE cs.tenant_id       = 'frostgate-internal'
  AND cs.credential_type = 'tenant_api_key'
  AND cs.credential_slot = 'console-bff-key'
  AND a.gen > 0;
