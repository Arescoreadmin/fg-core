-- Migration 0075: Row Level Security for FA substrate and governance tables.
--
-- Covers all ORM-managed FA tables (fa_engagements, fa_scan_results,
-- fa_document_analyses, fa_field_observations, fa_normalized_findings,
-- fa_evidence_links, fa_engagement_audit_events, fa_quarantined_scans)
-- plus migration-managed tables (fa_questionnaires, fa_questionnaire_responses,
-- governance_promotions) that were absent from the RLS assertion set.
--
-- Policy: tenant_id = current_setting('app.tenant_id', true)
-- FORCE ROW LEVEL SECURITY is required so that the app role (which owns the
-- tables) is also subject to the policy.
--
-- All blocks are idempotent: to_regclass() guards prevent errors on fresh
-- databases where ORM-managed tables may not yet exist, and NOT EXISTS checks
-- prevent duplicate policy creation on re-run.

DO $$
DECLARE
    t TEXT;
    tables TEXT[] := ARRAY[
        'fa_engagements',
        'fa_scan_results',
        'fa_document_analyses',
        'fa_field_observations',
        'fa_normalized_findings',
        'fa_evidence_links',
        'fa_engagement_audit_events',
        'fa_quarantined_scans',
        'fa_questionnaires',
        'fa_questionnaire_responses',
        'governance_promotions'
    ];
BEGIN
    FOREACH t IN ARRAY tables LOOP
        IF to_regclass('public.' || t) IS NOT NULL THEN
            EXECUTE format('ALTER TABLE %%I ENABLE ROW LEVEL SECURITY', t);
            EXECUTE format('ALTER TABLE %%I FORCE ROW LEVEL SECURITY', t);
        END IF;
    END LOOP;
END $$;

DO $$
DECLARE
    t TEXT;
    pol TEXT;
    tables TEXT[] := ARRAY[
        'fa_engagements',
        'fa_scan_results',
        'fa_document_analyses',
        'fa_field_observations',
        'fa_normalized_findings',
        'fa_evidence_links',
        'fa_engagement_audit_events',
        'fa_quarantined_scans',
        'fa_questionnaires',
        'fa_questionnaire_responses',
        'governance_promotions'
    ];
BEGIN
    FOREACH t IN ARRAY tables LOOP
        pol := t || '_tenant_isolation';
        IF to_regclass('public.' || t) IS NOT NULL AND NOT EXISTS (
            SELECT 1
            FROM pg_policies
            WHERE schemaname = 'public'
              AND tablename  = t
              AND policyname = pol
        ) THEN
            EXECUTE format(
                $policy$
                CREATE POLICY %%I ON %%I
                    USING (
                        tenant_id IS NOT NULL
                        AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true)
                    )
                    WITH CHECK (
                        tenant_id IS NOT NULL
                        AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true)
                    )
                $policy$,
                pol, t
            );
        END IF;
    END LOOP;
END $$;
