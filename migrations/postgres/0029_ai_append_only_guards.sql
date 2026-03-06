DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'ai_device_registry',
    'ai_token_usage',
    'ai_quota_daily'
  ]
  LOOP
    IF EXISTS (
      SELECT 1
      FROM information_schema.tables
      WHERE table_schema = 'public'
        AND table_name = t
    ) THEN
      EXECUTE format('DROP TRIGGER IF EXISTS %%I_append_only_update ON %%I', t, t);
      EXECUTE format('DROP TRIGGER IF EXISTS %%I_append_only_delete ON %%I', t, t);

      EXECUTE format(
        'CREATE TRIGGER %%I_append_only_update BEFORE UPDATE ON %%I FOR EACH ROW EXECUTE FUNCTION audit_ledger_append_only_guard()',
        t, t
      );
      EXECUTE format(
        'CREATE TRIGGER %%I_append_only_delete BEFORE DELETE ON %%I FOR EACH ROW EXECUTE FUNCTION audit_ledger_append_only_guard()',
        t, t
      );
    END IF;
  END LOOP;
END;
$$;