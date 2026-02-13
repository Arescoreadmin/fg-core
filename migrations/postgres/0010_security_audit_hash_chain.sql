ALTER TABLE security_audit_log
    ADD COLUMN IF NOT EXISTS chain_id TEXT NOT NULL DEFAULT 'global',
    ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT 'GENESIS',
    ADD COLUMN IF NOT EXISTS entry_hash TEXT;

UPDATE security_audit_log
SET entry_hash = COALESCE(entry_hash, md5(id::text || ':' || created_at::text));

ALTER TABLE security_audit_log
    ALTER COLUMN entry_hash SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ix_security_audit_entry_hash ON security_audit_log(entry_hash);
CREATE UNIQUE INDEX IF NOT EXISTS uq_security_audit_chain_entry ON security_audit_log(chain_id, entry_hash);
