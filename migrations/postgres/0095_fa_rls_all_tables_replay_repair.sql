-- Migration 0095: Replay repair for all FA table RLS.
--
-- 0094 handled FA tables tables with tenant_id. Some FA tables are tenant-scoped
-- indirectly and do not have tenant_id, but assert_tenant_rls still requires
-- RLS enabled. This migration enables/FORCES RLS on every real public FA tables table
-- and adds tenant policies only where tenant_id exists.

DO $$
DECLARE
    r RECORD;
    has_tenant_id BOOLEAN;
    policy_name TEXT;
BEGIN
    FOR r IN
        SELECT c.relname AS table_name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind = 'r'
          AND left(c.relname, 3) = 'fa_'
        ORDER BY c.relname
    LOOP
        EXECUTE
            'ALTER TABLE public.' ||
            quote_ident(r.table_name) ||
            ' ENABLE ROW LEVEL SECURITY';

        EXECUTE
            'ALTER TABLE public.' ||
            quote_ident(r.table_name) ||
            ' FORCE ROW LEVEL SECURITY';

        SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = r.table_name
              AND column_name = 'tenant_id'
        )
        INTO has_tenant_id;

        IF has_tenant_id THEN
            policy_name := r.table_name || '_tenant_isolation';

            EXECUTE
                'DROP POLICY IF EXISTS ' ||
                quote_ident(policy_name) ||
                ' ON public.' ||
                quote_ident(r.table_name);

            EXECUTE
                'CREATE POLICY ' ||
                quote_ident(policy_name) ||
                ' ON public.' ||
                quote_ident(r.table_name) ||
                ' USING (
                    tenant_id = current_setting(''app.current_tenant_id'', true)
                    OR current_setting(''app.current_tenant_id'', true) = ''''
                )';
        END IF;
    END LOOP;
END $$;
