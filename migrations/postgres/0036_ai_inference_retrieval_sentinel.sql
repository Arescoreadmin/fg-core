-- Replace the legacy placeholder retrieval sentinel for current/future rows.
-- Historical migrations remain immutable; this forward migration normalizes
-- existing records and sets the runtime default used by Postgres deployments.

ALTER TABLE IF EXISTS ai_inference_records
    ALTER COLUMN retrieval_id SET DEFAULT 'rag:none';

UPDATE ai_inference_records
SET retrieval_id = 'rag:none'
WHERE retrieval_id = 'stub';
