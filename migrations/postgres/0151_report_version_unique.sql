-- Migration 0151: enforce unique version numbers per report
--
-- Adds a UNIQUE constraint on (tenant_id, report_id, version) in
-- fa_report_versions so that concurrent POSTs allocating version numbers via
-- SELECT max(version)+1 cannot commit duplicate version identifiers.
-- The application layer catches IntegrityError and returns HTTP 409.

ALTER TABLE fa_report_versions
    ADD CONSTRAINT fa_report_versions_tenant_report_version_uq
    UNIQUE (tenant_id, report_id, version);
