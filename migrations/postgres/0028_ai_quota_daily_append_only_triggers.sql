-- 0028_ai_append_only_triggers_backfill.sql
-- Backfill append-only triggers for AI append-only tables that were added after 0002.

DO $$
BEGIN
  -- sanity: enforce function exists (created by 0002)
  IF NOT EXISTS (
    SELECT 1
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND p.proname = 'fg_append_only_enforcer'
  ) THEN
    RAISE EXCEPTION 'Expected function public.fg_append_only_enforcer() to exist';
  END IF;

  -- helper: ensure table exists
  IF NOT EXISTS (
    SELECT 1
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'r'
      AND n.nspname = 'public'
      AND c.relname = 'ai_device_registry'
  ) THEN
    RAISE EXCEPTION 'Expected table public.ai_device_registry to exist';
  END IF;

  -- ai_device_registry UPDATE trigger
  IF EXISTS (
    SELECT 1
    FROM pg_trigger t
    JOIN pg_class c ON c.oid = t.tgrelid
    WHERE NOT t.tgisinternal
      AND c.relname = 'ai_device_registry'
      AND t.tgname = 'ai_device_registry_append_only_update'
  ) THEN
    EXECUTE 'DROP TRIGGER ai_device_registry_append_only_update ON public.ai_device_registry';
  END IF;

  EXECUTE $SQL$
    CREATE TRIGGER ai_device_registry_append_only_update
    BEFORE UPDATE ON public.ai_device_registry
    FOR EACH ROW
    EXECUTE FUNCTION public.fg_append_only_enforcer()
  $SQL$;

  -- ai_device_registry DELETE trigger
  IF EXISTS (
    SELECT 1
    FROM pg_trigger t
    JOIN pg_class c ON c.oid = t.tgrelid
    WHERE NOT t.tgisinternal
      AND c.relname = 'ai_device_registry'
      AND t.tgname = 'ai_device_registry_append_only_delete'
  ) THEN
    EXECUTE 'DROP TRIGGER ai_device_registry_append_only_delete ON public.ai_device_registry';
  END IF;

  EXECUTE $SQL$
    CREATE TRIGGER ai_device_registry_append_only_delete
    BEFORE DELETE ON public.ai_device_registry
    FOR EACH ROW
    EXECUTE FUNCTION public.fg_append_only_enforcer()
  $SQL$;

  -- Optional: also fix ai_quota_daily if it still lacks triggers (harmless if present)
  IF EXISTS (
    SELECT 1
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'r'
      AND n.nspname = 'public'
      AND c.relname = 'ai_quota_daily'
  ) THEN
    IF EXISTS (
      SELECT 1
      FROM pg_trigger t
      JOIN pg_class c ON c.oid = t.tgrelid
      WHERE NOT t.tgisinternal
        AND c.relname = 'ai_quota_daily'
        AND t.tgname = 'ai_quota_daily_append_only_update'
    ) THEN
      EXECUTE 'DROP TRIGGER ai_quota_daily_append_only_update ON public.ai_quota_daily';
    END IF;

    EXECUTE $SQL$
      CREATE TRIGGER ai_quota_daily_append_only_update
      BEFORE UPDATE ON public.ai_quota_daily
      FOR EACH ROW
      EXECUTE FUNCTION public.fg_append_only_enforcer()
    $SQL$;

    IF EXISTS (
      SELECT 1
      FROM pg_trigger t
      JOIN pg_class c ON c.oid = t.tgrelid
      WHERE NOT t.tgisinternal
        AND c.relname = 'ai_quota_daily'
        AND t.tgname = 'ai_quota_daily_append_only_delete'
    ) THEN
      EXECUTE 'DROP TRIGGER ai_quota_daily_append_only_delete ON public.ai_quota_daily';
    END IF;

    EXECUTE $SQL$
      CREATE TRIGGER ai_quota_daily_append_only_delete
      BEFORE DELETE ON public.ai_quota_daily
      FOR EACH ROW
      EXECUTE FUNCTION public.fg_append_only_enforcer()
    $SQL$;
  END IF;

END $$;