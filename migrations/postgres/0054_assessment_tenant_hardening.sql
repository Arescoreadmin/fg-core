-- Migration: 0054_assessment_tenant_hardening
-- Hardens assessment/report tenant isolation by eliminating the "public" pseudo-tenant.
--
-- Prior to this migration every pre-tenant (anonymous onboarding) assessment was
-- stored with tenant_id = 'public', meaning ALL such records shared a single
-- namespace.  This migration moves each record into an isolated lead namespace
-- keyed by the record's own UUID so that no two pre-tenant leads share a
-- queryable namespace.
--
-- Assessment lead namespace : lead:<assessment_id>
-- Org profile lead namespace : lead:<org_id>   (using the org_id UUID field)
-- Report lead namespace      : inherited from the linked assessment
--
-- Rollback:
--   UPDATE assessments   SET tenant_id = 'public' WHERE tenant_id LIKE 'lead:%';
--   UPDATE org_profiles  SET tenant_id = 'public' WHERE tenant_id LIKE 'lead:%';
--   UPDATE reports       SET tenant_id = 'public' WHERE tenant_id LIKE 'lead:%';
--   (Rollback restores the insecure state — perform only in dev/test environments.)

BEGIN;

-- 1. Backfill assessments: public → lead:<assessment_id>
UPDATE assessments
SET    tenant_id = 'lead:' || id
WHERE  tenant_id = 'public';

-- 2. Backfill org_profiles: public → lead:<org_id>
--    org_id is the application-level UUID (not the integer PK).
UPDATE org_profiles
SET    tenant_id = 'lead:' || org_id
WHERE  tenant_id = 'public';

-- 3. Backfill reports: public → lead:<assessment_id> (inherit from linked assessment)
--    Reports without a linked assessment fall back to lead:<report_id>.
UPDATE reports r
SET    tenant_id = COALESCE(
           'lead:' || (SELECT a.id FROM assessments a WHERE a.id = r.assessment_id LIMIT 1),
           'lead:' || r.id
       )
WHERE  r.tenant_id = 'public';

-- 4. Composite indexes on (id, tenant_id) for O(1) tenant-predicated lookups.
CREATE INDEX IF NOT EXISTS ix_assessments_id_tenant
    ON assessments (id, tenant_id);

CREATE INDEX IF NOT EXISTS ix_reports_id_tenant
    ON reports (id, tenant_id);

CREATE INDEX IF NOT EXISTS ix_reports_tenant_assessment
    ON reports (tenant_id, assessment_id);

COMMIT;
