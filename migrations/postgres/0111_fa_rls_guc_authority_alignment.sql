-- Migration 0111: FA Tenant Context Authority Alignment (P0-4A)
--
-- SECURITY FIX: Migrations 0093–0097, 0105, 0107, 0108, 0109 created RLS policies
-- referencing current_setting('app.current_tenant_id', true). The application never
-- sets this GUC — the sole authoritative setter is set_tenant_context() in api/db.py
-- and _set_pg_tenant() in api/auth_scopes/store.py, both of which use 'app.tenant_id'.
-- Those policies were effectively silent deny-all (NULL != any tenant_id).
--
-- This migration:
--   1. Drops abbreviated non-standard policy names introduced by 0108/0109.
--   2. Iterates every fa_* table that carries a tenant_id column and recreates
--      the {table}_tenant_isolation policy referencing the correct GUC: app.tenant_id.
--
-- Replacement policy follows the 0110 pattern (fail-closed):
--   USING (tenant_id IS NOT NULL
--          AND current_setting('app.tenant_id', true) IS NOT NULL
--          AND tenant_id = current_setting('app.tenant_id', true))
--   WITH CHECK (same)
-- If app.tenant_id is unset the NOT NULL guard rejects every row; no bypass.

-- ---------------------------------------------------------------------------
-- 1. Drop abbreviated non-standard policy names (0108 / 0109)
--    These tables carry tenant_id so section 2 will recreate standard-named
--    {table}_tenant_isolation policies for them.
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_trust_intelligence_snapshots') IS NOT NULL THEN
        DROP POLICY IF EXISTS fa_tis_tenant_isolation ON fa_trust_intelligence_snapshots;
    END IF;
    IF to_regclass('public.fa_trust_intelligence_ledger') IS NOT NULL THEN
        DROP POLICY IF EXISTS fa_til_tenant_isolation ON fa_trust_intelligence_ledger;
    END IF;
    IF to_regclass('public.fa_trust_decision_memory') IS NOT NULL THEN
        DROP POLICY IF EXISTS fa_tdm_tenant_isolation ON fa_trust_decision_memory;
    END IF;
    IF to_regclass('public.fa_auditor_proof_packages') IS NOT NULL THEN
        DROP POLICY IF EXISTS fa_app_tenant_isolation ON fa_auditor_proof_packages;
    END IF;
    IF to_regclass('public.fa_trust_certifications') IS NOT NULL THEN
        DROP POLICY IF EXISTS fa_tc_tenant_isolation ON fa_trust_certifications;
    END IF;
    IF to_regclass('public.fa_decision_reconstruction_records') IS NOT NULL THEN
        DROP POLICY IF EXISTS fa_drr_tenant_isolation ON fa_decision_reconstruction_records;
    END IF;
    IF to_regclass('public.fa_chain_of_custody_records') IS NOT NULL THEN
        DROP POLICY IF EXISTS fa_cocr_tenant_isolation ON fa_chain_of_custody_records;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Recreate all fa_* tenant_isolation policies using the correct GUC
--    Covers every fa_* table with tenant_id: 0093-0109 scope and future tables.
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    r          RECORD;
    pol_name   TEXT;
    using_expr TEXT;
BEGIN
    using_expr :=
        'tenant_id IS NOT NULL'
        ' AND current_setting(''app.tenant_id'', true) IS NOT NULL'
        ' AND tenant_id = current_setting(''app.tenant_id'', true)';

    FOR r IN
        SELECT DISTINCT c.table_name
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema
         AND t.table_name   = c.table_name
        WHERE c.table_schema = 'public'
          AND left(c.table_name, 3) = 'fa_'
          AND c.column_name = 'tenant_id'
          AND t.table_type  = 'BASE TABLE'
        ORDER BY c.table_name
    LOOP
        pol_name := r.table_name || '_tenant_isolation';

        EXECUTE
            'DROP POLICY IF EXISTS ' || quote_ident(pol_name) ||
            ' ON public.' || quote_ident(r.table_name);

        EXECUTE
            'CREATE POLICY ' || quote_ident(pol_name) ||
            ' ON public.' || quote_ident(r.table_name) ||
            ' USING ('      || using_expr || ')' ||
            ' WITH CHECK (' || using_expr || ')';
    END LOOP;
END $$;
