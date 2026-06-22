-- Migration 0094: Replay repair for FA RLS

DO $$
DECLARE
    r RECORD;
    policy_name TEXT;
BEGIN
    FOR r IN
        SELECT DISTINCT c.table_name
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema
         AND t.table_name = c.table_name
        WHERE c.table_schema = 'public'
          AND left(c.table_name, 3) = 'fa_'
          AND c.column_name = 'tenant_id'
          AND t.table_type = 'BASE TABLE'
        ORDER BY c.table_name
    LOOP
        policy_name := r.table_name || '_tenant_isolation';

        EXECUTE
            'ALTER TABLE public.' ||
            quote_ident(r.table_name) ||
            ' ENABLE ROW LEVEL SECURITY';

        EXECUTE
            'ALTER TABLE public.' ||
            quote_ident(r.table_name) ||
            ' FORCE ROW LEVEL SECURITY';

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
    END LOOP;
END $$;
