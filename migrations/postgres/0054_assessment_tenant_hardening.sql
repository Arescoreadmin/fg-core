-- Migration: 0054_assessment_tenant_hardening
-- Hardens assessment/report tenant isolation by eliminating the "public" pseudo-tenant.
--
-- Prior to this migration every pre-tenant (anonymous onboarding) assessment was
-- stored with tenant_id = 'public', meaning ALL such records shared a single
-- namespace.  This migration moves each record into an isolated lead namespace
-- keyed by the assessment UUID so that no two pre-tenant leads share a
-- queryable namespace.
--
-- All three tables use the SAME namespace key: lead:<assessment_id>.
-- org_profiles are linked to assessments via org_profile_id (FK); the earliest
-- linked assessment's id is used so the namespace is consistent with the code.
-- Orphaned org_profiles (no linked assessment) are rare and fall back to
-- lead:<org_id> — they cannot be reached through any tenant-predicated query
-- in the application today.
--
-- Rollback:
--   UPDATE assessments   SET tenant_id = 'public' WHERE tenant_id LIKE 'lead:%%';
--   UPDATE org_profiles  SET tenant_id = 'public' WHERE tenant_id LIKE 'lead:%%';
--   UPDATE reports       SET tenant_id = 'public' WHERE tenant_id LIKE 'lead:%%';
--   (Rollback restores the insecure state — perform only in dev/test environments.)
--   Note: %% is the psycopg3 escape for a literal % character.

BEGIN;

-- 1. Backfill assessments: public → lead:<assessment_id>
UPDATE assessments
SET    tenant_id = 'lead:' || id
WHERE  tenant_id = 'public';

-- 2. Backfill org_profiles: public → lead:<assessment_id>
--    Joins to the earliest linked assessment to keep the namespace consistent
--    with what the application code now writes on new org creation.
--    Orphaned org_profiles (no assessment) fall back to lead:<org_id>.
UPDATE org_profiles op
SET    tenant_id = COALESCE(
           'lead:' || (
               SELECT a.id FROM assessments a
               WHERE  a.org_profile_id = op.id
               ORDER  BY a.created_at
               LIMIT  1
           ),
           'lead:' || op.org_id
       )
WHERE  op.tenant_id = 'public';

-- 3. Backfill reports: public → lead:<assessment_id>
--    Reports without a linked assessment fall back to lead:<report_id>.
UPDATE reports
SET    tenant_id = 'lead:' || COALESCE(assessment_id, id)
WHERE  tenant_id = 'public';

-- 4. Drop DEFAULT 'public' so future inserts that omit tenant_id fail loudly
--    rather than silently creating a public-namespace row that the new
--    fail-closed predicates will never surface.
ALTER TABLE org_profiles  ALTER COLUMN tenant_id DROP DEFAULT;
ALTER TABLE assessments   ALTER COLUMN tenant_id DROP DEFAULT;
ALTER TABLE reports       ALTER COLUMN tenant_id DROP DEFAULT;

-- 5. Composite indexes on (id, tenant_id) for O(1) tenant-predicated lookups.
CREATE INDEX IF NOT EXISTS ix_assessments_id_tenant
    ON assessments (id, tenant_id);

CREATE INDEX IF NOT EXISTS ix_reports_id_tenant
    ON reports (id, tenant_id);

CREATE INDEX IF NOT EXISTS ix_reports_tenant_assessment
    ON reports (tenant_id, assessment_id);

COMMIT;
