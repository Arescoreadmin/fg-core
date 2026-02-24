-- 0030_ai_token_usage_append_only_triggers.sql
-- Ensure append-only enforcement triggers exist for ai_token_usage.

DO $$
BEGIN
  -- require append-only function exists (created in 0002)
  IF NOT EXISTS (
    SELECT 1
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND p.proname = 'fg_append_only_enforcer'
  ) THEN
    RAISE EXCEPTION 'Expected function public.fg_append_only_enforcer() to exist';
  END IF;

  -- require table exists
  IF NOT EXISTS (
    SELECT 1
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'r'
      AND n.nspname = 'public'
      AND c.relname = 'ai_token_usage'
  ) THEN
    RAISE EXCEPTION 'Expected table public.ai_token_usage to exist';
  END IF;

  -- UPDATE trigger
  IF EXISTS (
    SELECT 1
    FROM pg_trigger t
    JOIN pg_class c ON c.oid = t.tgrelid
    WHERE NOT t.tgisinternal
      AND c.relname = 'ai_token_usage'
      AND t.tgname = 'ai_token_usage_append_only_update'
  ) THEN
    EXECUTE 'DROP TRIGGER ai_token_usage_append_only_update ON public.ai_token_usage';
  END IF;

  EXECUTE $SQL$
    CREATE TRIGGER ai_token_usage_append_only_update
    BEFORE UPDATE ON public.ai_token_usage
    FOR EACH ROW
    EXECUTE FUNCTION public.fg_append_only_enforcer()
  $SQL$;

  -- DELETE trigger
  IF EXISTS (
    SELECT 1
    FROM pg_trigger t
    JOIN pg_class c ON c.oid = t.tgrelid
    WHERE NOT t.tgisinternal
      AND c.relname = 'ai_token_usage'
      AND t.tgname = 'ai_token_usage_append_only_delete'
  ) THEN
    EXECUTE 'DROP TRIGGER ai_token_usage_append_only_delete ON public.ai_token_usage';
  END IF;

  EXECUTE $SQL$
    CREATE TRIGGER ai_token_usage_append_only_delete
    BEFORE DELETE ON public.ai_token_usage
    FOR EACH ROW
    EXECUTE FUNCTION public.fg_append_only_enforcer()
  $SQL$;

END $$;