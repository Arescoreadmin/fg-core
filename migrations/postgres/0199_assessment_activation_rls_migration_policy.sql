-- Migration 0199: Additive RLS policy for assessment activation tenant migration.
--
-- The activation flow (L14-PORTAL-HANDOFF-001) must change assessments.tenant_id
-- from "lead:{assessment_id}" to a real tenant UUID. The standard
-- assessments_tenant_isolation policy uses USING = WITH CHECK, so PostgreSQL's
-- RLS WITH CHECK rejects the UPDATE because the new tenant_id no longer matches
-- the GUC that was used for the read (lead:{id} ≠ new_uuid).
--
-- This additive PERMISSIVE policy relaxes the WITH CHECK for lead: rows only:
--   USING:      row must currently have a lead: tenant (pre-activation)
--   WITH CHECK: new tenant_id must NOT be a lead: prefix (enforces one-way migration)
--
-- PostgreSQL combines PERMISSIVE policies with OR; a WITH CHECK that passes on
-- any one policy is sufficient. Normal tenant-scoped UPDATEs continue to satisfy
-- the existing assessments_tenant_isolation WITH CHECK and are unaffected.

CREATE POLICY assessments_activation_migration ON assessments
    AS PERMISSIVE
    FOR UPDATE
    USING  (tenant_id LIKE 'lead:%')
    WITH CHECK (tenant_id NOT LIKE 'lead:%');
