-- Migration 0174: reset stuck console-bff-key credential slot for frostgate-internal.
--
-- credential_slots shows current_generation > 0 for frostgate-internal /
-- console-bff-key, but no matching tenant_credentials row exists.  The
-- provision-tenant route cannot create or rotate the credential until the
-- slot counter is reset to zero.  This UPDATE is a no-op if the row is
-- absent or already zero.

UPDATE credential_slots
SET current_generation = 0
WHERE tenant_id       = 'frostgate-internal'
  AND credential_slot = 'console-bff-key';
