-- Migration 0110: Core tenant RLS hardening (P0-4)
--
-- Enables Row Level Security and adds tenant_isolation policies for all non-FA
-- tables that carry a tenant_id column but were missing RLS coverage.
-- FA tables are handled dynamically by migrations 0094/0095.
-- Agent-phase2 tables are covered by 0024/0025 (check_agent_phase2_rls.py).
-- Connector tables are covered by 0026 (check_connectors_rls.py).
--
-- Pattern follows 0003_tenant_rls.sql: each table gets:
--   ALTER TABLE ... ENABLE ROW LEVEL SECURITY;
--   ALTER TABLE ... FORCE ROW LEVEL SECURITY;
--   CREATE POLICY ..._tenant_isolation ON ... USING (...) WITH CHECK (...);
--
-- All statements are idempotent (IF to_regclass ... IS NOT NULL).

-- ---------------------------------------------------------------------------
-- Block 1: Enable + force RLS
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.agent_collector_statuses') IS NOT NULL THEN
        ALTER TABLE agent_collector_statuses ENABLE ROW LEVEL SECURITY;
        ALTER TABLE agent_collector_statuses FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.agent_device_keys') IS NOT NULL THEN
        ALTER TABLE agent_device_keys ENABLE ROW LEVEL SECURITY;
        ALTER TABLE agent_device_keys FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.agent_device_registry') IS NOT NULL THEN
        ALTER TABLE agent_device_registry ENABLE ROW LEVEL SECURITY;
        ALTER TABLE agent_device_registry FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.agent_enrollment_tokens') IS NOT NULL THEN
        ALTER TABLE agent_enrollment_tokens ENABLE ROW LEVEL SECURITY;
        ALTER TABLE agent_enrollment_tokens FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.agent_tenant_configs') IS NOT NULL THEN
        ALTER TABLE agent_tenant_configs ENABLE ROW LEVEL SECURITY;
        ALTER TABLE agent_tenant_configs FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.ai_governance_reviews') IS NOT NULL THEN
        ALTER TABLE ai_governance_reviews ENABLE ROW LEVEL SECURITY;
        ALTER TABLE ai_governance_reviews FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.approval_logs') IS NOT NULL THEN
        ALTER TABLE approval_logs ENABLE ROW LEVEL SECURITY;
        ALTER TABLE approval_logs FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.assessments') IS NOT NULL THEN
        ALTER TABLE assessments ENABLE ROW LEVEL SECURITY;
        ALTER TABLE assessments FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.audit_exam_sessions') IS NOT NULL THEN
        ALTER TABLE audit_exam_sessions ENABLE ROW LEVEL SECURITY;
        ALTER TABLE audit_exam_sessions FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.billing_count_sync_checkpoint_events') IS NOT NULL THEN
        ALTER TABLE billing_count_sync_checkpoint_events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE billing_count_sync_checkpoint_events FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.billing_count_sync_checkpoints') IS NOT NULL THEN
        ALTER TABLE billing_count_sync_checkpoints ENABLE ROW LEVEL SECURITY;
        ALTER TABLE billing_count_sync_checkpoints FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.billing_coverage_daily_state') IS NOT NULL THEN
        ALTER TABLE billing_coverage_daily_state ENABLE ROW LEVEL SECURITY;
        ALTER TABLE billing_coverage_daily_state FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.billing_credit_notes') IS NOT NULL THEN
        ALTER TABLE billing_credit_notes ENABLE ROW LEVEL SECURITY;
        ALTER TABLE billing_credit_notes FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.billing_daily_counts') IS NOT NULL THEN
        ALTER TABLE billing_daily_counts ENABLE ROW LEVEL SECURITY;
        ALTER TABLE billing_daily_counts FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.billing_device_activity_proofs') IS NOT NULL THEN
        ALTER TABLE billing_device_activity_proofs ENABLE ROW LEVEL SECURITY;
        ALTER TABLE billing_device_activity_proofs FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.billing_device_enrollments') IS NOT NULL THEN
        ALTER TABLE billing_device_enrollments ENABLE ROW LEVEL SECURITY;
        ALTER TABLE billing_device_enrollments FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.billing_devices') IS NOT NULL THEN
        ALTER TABLE billing_devices ENABLE ROW LEVEL SECURITY;
        ALTER TABLE billing_devices FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.billing_identity_claim_events') IS NOT NULL THEN
        ALTER TABLE billing_identity_claim_events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE billing_identity_claim_events FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.billing_identity_claims') IS NOT NULL THEN
        ALTER TABLE billing_identity_claims ENABLE ROW LEVEL SECURITY;
        ALTER TABLE billing_identity_claims FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.billing_invoice_state_events') IS NOT NULL THEN
        ALTER TABLE billing_invoice_state_events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE billing_invoice_state_events FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.billing_invoices') IS NOT NULL THEN
        ALTER TABLE billing_invoices ENABLE ROW LEVEL SECURITY;
        ALTER TABLE billing_invoices FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.billing_runs') IS NOT NULL THEN
        ALTER TABLE billing_runs ENABLE ROW LEVEL SECURITY;
        ALTER TABLE billing_runs FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.compliance_findings') IS NOT NULL THEN
        ALTER TABLE compliance_findings ENABLE ROW LEVEL SECURITY;
        ALTER TABLE compliance_findings FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.compliance_requirement_updates') IS NOT NULL THEN
        ALTER TABLE compliance_requirement_updates ENABLE ROW LEVEL SECURITY;
        ALTER TABLE compliance_requirement_updates FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.compliance_requirements') IS NOT NULL THEN
        ALTER TABLE compliance_requirements ENABLE ROW LEVEL SECURITY;
        ALTER TABLE compliance_requirements FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.compliance_snapshots') IS NOT NULL THEN
        ALTER TABLE compliance_snapshots ENABLE ROW LEVEL SECURITY;
        ALTER TABLE compliance_snapshots FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.config_versions') IS NOT NULL THEN
        ALTER TABLE config_versions ENABLE ROW LEVEL SECURITY;
        ALTER TABLE config_versions FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.deployment_environments') IS NOT NULL THEN
        ALTER TABLE deployment_environments ENABLE ROW LEVEL SECURITY;
        ALTER TABLE deployment_environments FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.deployment_events') IS NOT NULL THEN
        ALTER TABLE deployment_events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE deployment_events FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.deployment_health_records') IS NOT NULL THEN
        ALTER TABLE deployment_health_records ENABLE ROW LEVEL SECURITY;
        ALTER TABLE deployment_health_records FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.deployment_records') IS NOT NULL THEN
        ALTER TABLE deployment_records ENABLE ROW LEVEL SECURITY;
        ALTER TABLE deployment_records FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.device_coverage_ledger') IS NOT NULL THEN
        ALTER TABLE device_coverage_ledger ENABLE ROW LEVEL SECURITY;
        ALTER TABLE device_coverage_ledger FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.embedding_vectors') IS NOT NULL THEN
        ALTER TABLE embedding_vectors ENABLE ROW LEVEL SECURITY;
        ALTER TABLE embedding_vectors FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.evidence_anchor_records') IS NOT NULL THEN
        ALTER TABLE evidence_anchor_records ENABLE ROW LEVEL SECURITY;
        ALTER TABLE evidence_anchor_records FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.evidence_bundles') IS NOT NULL THEN
        ALTER TABLE evidence_bundles ENABLE ROW LEVEL SECURITY;
        ALTER TABLE evidence_bundles FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.governance_assets') IS NOT NULL THEN
        ALTER TABLE governance_assets ENABLE ROW LEVEL SECURITY;
        ALTER TABLE governance_assets FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.governance_promotions') IS NOT NULL THEN
        ALTER TABLE governance_promotions ENABLE ROW LEVEL SECURITY;
        ALTER TABLE governance_promotions FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.governance_workflows') IS NOT NULL THEN
        ALTER TABLE governance_workflows ENABLE ROW LEVEL SECURITY;
        ALTER TABLE governance_workflows FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.ops_backup_records') IS NOT NULL THEN
        ALTER TABLE ops_backup_records ENABLE ROW LEVEL SECURITY;
        ALTER TABLE ops_backup_records FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.ops_environments') IS NOT NULL THEN
        ALTER TABLE ops_environments ENABLE ROW LEVEL SECURITY;
        ALTER TABLE ops_environments FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.ops_export_requests') IS NOT NULL THEN
        ALTER TABLE ops_export_requests ENABLE ROW LEVEL SECURITY;
        ALTER TABLE ops_export_requests FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.ops_governance_audit_events') IS NOT NULL THEN
        ALTER TABLE ops_governance_audit_events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE ops_governance_audit_events FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.ops_key_rotation_schedules') IS NOT NULL THEN
        ALTER TABLE ops_key_rotation_schedules ENABLE ROW LEVEL SECURITY;
        ALTER TABLE ops_key_rotation_schedules FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.ops_recovery_records') IS NOT NULL THEN
        ALTER TABLE ops_recovery_records ENABLE ROW LEVEL SECURITY;
        ALTER TABLE ops_recovery_records FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.ops_restore_records') IS NOT NULL THEN
        ALTER TABLE ops_restore_records ENABLE ROW LEVEL SECURITY;
        ALTER TABLE ops_restore_records FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.ops_retention_policies') IS NOT NULL THEN
        ALTER TABLE ops_retention_policies ENABLE ROW LEVEL SECURITY;
        ALTER TABLE ops_retention_policies FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.ops_secret_governance') IS NOT NULL THEN
        ALTER TABLE ops_secret_governance ENABLE ROW LEVEL SECURITY;
        ALTER TABLE ops_secret_governance FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.org_profiles') IS NOT NULL THEN
        ALTER TABLE org_profiles ENABLE ROW LEVEL SECURITY;
        ALTER TABLE org_profiles FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.provisioning_audit_events') IS NOT NULL THEN
        ALTER TABLE provisioning_audit_events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE provisioning_audit_events FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.provisioning_organizations') IS NOT NULL THEN
        ALTER TABLE provisioning_organizations ENABLE ROW LEVEL SECURITY;
        ALTER TABLE provisioning_organizations FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.provisioning_workflows') IS NOT NULL THEN
        ALTER TABLE provisioning_workflows ENABLE ROW LEVEL SECURITY;
        ALTER TABLE provisioning_workflows FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.rag_chunks') IS NOT NULL THEN
        ALTER TABLE rag_chunks ENABLE ROW LEVEL SECURITY;
        ALTER TABLE rag_chunks FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.rag_corpora') IS NOT NULL THEN
        ALTER TABLE rag_corpora ENABLE ROW LEVEL SECURITY;
        ALTER TABLE rag_corpora FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.rag_documents') IS NOT NULL THEN
        ALTER TABLE rag_documents ENABLE ROW LEVEL SECURITY;
        ALTER TABLE rag_documents FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.reports') IS NOT NULL THEN
        ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
        ALTER TABLE reports FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.risk_alert_rules') IS NOT NULL THEN
        ALTER TABLE risk_alert_rules ENABLE ROW LEVEL SECURITY;
        ALTER TABLE risk_alert_rules FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.risk_alerts_fired') IS NOT NULL THEN
        ALTER TABLE risk_alerts_fired ENABLE ROW LEVEL SECURITY;
        ALTER TABLE risk_alerts_fired FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.risk_score_snapshots') IS NOT NULL THEN
        ALTER TABLE risk_score_snapshots ENABLE ROW LEVEL SECURITY;
        ALTER TABLE risk_score_snapshots FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.tenant_ai_policy') IS NOT NULL THEN
        ALTER TABLE tenant_ai_policy ENABLE ROW LEVEL SECURITY;
        ALTER TABLE tenant_ai_policy FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.tenant_config_active') IS NOT NULL THEN
        ALTER TABLE tenant_config_active ENABLE ROW LEVEL SECURITY;
        ALTER TABLE tenant_config_active FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.tenant_contracts') IS NOT NULL THEN
        ALTER TABLE tenant_contracts ENABLE ROW LEVEL SECURITY;
        ALTER TABLE tenant_contracts FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.tenant_control_state') IS NOT NULL THEN
        ALTER TABLE tenant_control_state ENABLE ROW LEVEL SECURITY;
        ALTER TABLE tenant_control_state FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.tenant_identity_governance_snapshots') IS NOT NULL THEN
        ALTER TABLE tenant_identity_governance_snapshots ENABLE ROW LEVEL SECURITY;
        ALTER TABLE tenant_identity_governance_snapshots FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.tenant_keywords') IS NOT NULL THEN
        ALTER TABLE tenant_keywords ENABLE ROW LEVEL SECURITY;
        ALTER TABLE tenant_keywords FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.tenant_retrieval_policies') IS NOT NULL THEN
        ALTER TABLE tenant_retrieval_policies ENABLE ROW LEVEL SECURITY;
        ALTER TABLE tenant_retrieval_policies FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.tenant_role_audit') IS NOT NULL THEN
        ALTER TABLE tenant_role_audit ENABLE ROW LEVEL SECURITY;
        ALTER TABLE tenant_role_audit FORCE ROW LEVEL SECURITY;
    END IF;

    -- Tables with RLS already enabled but no tenant_isolation policy
    IF to_regclass('public.evaluation_query_items') IS NOT NULL THEN
        ALTER TABLE evaluation_query_items ENABLE ROW LEVEL SECURITY;
        ALTER TABLE evaluation_query_items FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.evaluation_query_sets') IS NOT NULL THEN
        ALTER TABLE evaluation_query_sets ENABLE ROW LEVEL SECURITY;
        ALTER TABLE evaluation_query_sets FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.governance_timeline_events') IS NOT NULL THEN
        ALTER TABLE governance_timeline_events ENABLE ROW LEVEL SECURITY;
        ALTER TABLE governance_timeline_events FORCE ROW LEVEL SECURITY;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Block 2: Create tenant_isolation policies
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.agent_collector_statuses') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'agent_collector_statuses'
          AND policyname = 'agent_collector_statuses_tenant_isolation'
    ) THEN
        CREATE POLICY agent_collector_statuses_tenant_isolation ON agent_collector_statuses
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.agent_device_keys') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'agent_device_keys'
          AND policyname = 'agent_device_keys_tenant_isolation'
    ) THEN
        CREATE POLICY agent_device_keys_tenant_isolation ON agent_device_keys
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.agent_device_registry') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'agent_device_registry'
          AND policyname = 'agent_device_registry_tenant_isolation'
    ) THEN
        CREATE POLICY agent_device_registry_tenant_isolation ON agent_device_registry
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.agent_enrollment_tokens') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'agent_enrollment_tokens'
          AND policyname = 'agent_enrollment_tokens_tenant_isolation'
    ) THEN
        CREATE POLICY agent_enrollment_tokens_tenant_isolation ON agent_enrollment_tokens
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.agent_tenant_configs') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'agent_tenant_configs'
          AND policyname = 'agent_tenant_configs_tenant_isolation'
    ) THEN
        CREATE POLICY agent_tenant_configs_tenant_isolation ON agent_tenant_configs
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.ai_governance_reviews') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'ai_governance_reviews'
          AND policyname = 'ai_governance_reviews_tenant_isolation'
    ) THEN
        CREATE POLICY ai_governance_reviews_tenant_isolation ON ai_governance_reviews
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.approval_logs') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'approval_logs'
          AND policyname = 'approval_logs_tenant_isolation'
    ) THEN
        CREATE POLICY approval_logs_tenant_isolation ON approval_logs
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.assessments') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'assessments'
          AND policyname = 'assessments_tenant_isolation'
    ) THEN
        CREATE POLICY assessments_tenant_isolation ON assessments
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.audit_exam_sessions') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'audit_exam_sessions'
          AND policyname = 'audit_exam_sessions_tenant_isolation'
    ) THEN
        CREATE POLICY audit_exam_sessions_tenant_isolation ON audit_exam_sessions
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.billing_count_sync_checkpoint_events') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'billing_count_sync_checkpoint_events'
          AND policyname = 'billing_count_sync_checkpoint_events_tenant_isolation'
    ) THEN
        CREATE POLICY billing_count_sync_checkpoint_events_tenant_isolation ON billing_count_sync_checkpoint_events
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.billing_count_sync_checkpoints') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'billing_count_sync_checkpoints'
          AND policyname = 'billing_count_sync_checkpoints_tenant_isolation'
    ) THEN
        CREATE POLICY billing_count_sync_checkpoints_tenant_isolation ON billing_count_sync_checkpoints
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.billing_coverage_daily_state') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'billing_coverage_daily_state'
          AND policyname = 'billing_coverage_daily_state_tenant_isolation'
    ) THEN
        CREATE POLICY billing_coverage_daily_state_tenant_isolation ON billing_coverage_daily_state
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.billing_credit_notes') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'billing_credit_notes'
          AND policyname = 'billing_credit_notes_tenant_isolation'
    ) THEN
        CREATE POLICY billing_credit_notes_tenant_isolation ON billing_credit_notes
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.billing_daily_counts') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'billing_daily_counts'
          AND policyname = 'billing_daily_counts_tenant_isolation'
    ) THEN
        CREATE POLICY billing_daily_counts_tenant_isolation ON billing_daily_counts
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.billing_device_activity_proofs') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'billing_device_activity_proofs'
          AND policyname = 'billing_device_activity_proofs_tenant_isolation'
    ) THEN
        CREATE POLICY billing_device_activity_proofs_tenant_isolation ON billing_device_activity_proofs
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.billing_device_enrollments') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'billing_device_enrollments'
          AND policyname = 'billing_device_enrollments_tenant_isolation'
    ) THEN
        CREATE POLICY billing_device_enrollments_tenant_isolation ON billing_device_enrollments
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.billing_devices') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'billing_devices'
          AND policyname = 'billing_devices_tenant_isolation'
    ) THEN
        CREATE POLICY billing_devices_tenant_isolation ON billing_devices
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.billing_identity_claim_events') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'billing_identity_claim_events'
          AND policyname = 'billing_identity_claim_events_tenant_isolation'
    ) THEN
        CREATE POLICY billing_identity_claim_events_tenant_isolation ON billing_identity_claim_events
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.billing_identity_claims') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'billing_identity_claims'
          AND policyname = 'billing_identity_claims_tenant_isolation'
    ) THEN
        CREATE POLICY billing_identity_claims_tenant_isolation ON billing_identity_claims
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.billing_invoice_state_events') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'billing_invoice_state_events'
          AND policyname = 'billing_invoice_state_events_tenant_isolation'
    ) THEN
        CREATE POLICY billing_invoice_state_events_tenant_isolation ON billing_invoice_state_events
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.billing_invoices') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'billing_invoices'
          AND policyname = 'billing_invoices_tenant_isolation'
    ) THEN
        CREATE POLICY billing_invoices_tenant_isolation ON billing_invoices
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.billing_runs') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'billing_runs'
          AND policyname = 'billing_runs_tenant_isolation'
    ) THEN
        CREATE POLICY billing_runs_tenant_isolation ON billing_runs
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.compliance_findings') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'compliance_findings'
          AND policyname = 'compliance_findings_tenant_isolation'
    ) THEN
        CREATE POLICY compliance_findings_tenant_isolation ON compliance_findings
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.compliance_requirement_updates') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'compliance_requirement_updates'
          AND policyname = 'compliance_requirement_updates_tenant_isolation'
    ) THEN
        CREATE POLICY compliance_requirement_updates_tenant_isolation ON compliance_requirement_updates
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.compliance_requirements') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'compliance_requirements'
          AND policyname = 'compliance_requirements_tenant_isolation'
    ) THEN
        CREATE POLICY compliance_requirements_tenant_isolation ON compliance_requirements
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.compliance_snapshots') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'compliance_snapshots'
          AND policyname = 'compliance_snapshots_tenant_isolation'
    ) THEN
        CREATE POLICY compliance_snapshots_tenant_isolation ON compliance_snapshots
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.config_versions') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'config_versions'
          AND policyname = 'config_versions_tenant_isolation'
    ) THEN
        CREATE POLICY config_versions_tenant_isolation ON config_versions
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.deployment_environments') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'deployment_environments'
          AND policyname = 'deployment_environments_tenant_isolation'
    ) THEN
        -- tenant_id IS NULL denotes a platform-level (shared) environment visible
        -- to any operator. USING allows those rows while WITH CHECK keeps writes
        -- tenant-scoped (prevents tenants from creating platform-level rows).
        CREATE POLICY deployment_environments_tenant_isolation ON deployment_environments
            USING (
                tenant_id IS NULL
                OR (tenant_id IS NOT NULL
                    AND current_setting('app.tenant_id', true) IS NOT NULL
                    AND tenant_id = current_setting('app.tenant_id', true))
            )
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.deployment_events') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'deployment_events'
          AND policyname = 'deployment_events_tenant_isolation'
    ) THEN
        CREATE POLICY deployment_events_tenant_isolation ON deployment_events
            USING (
                tenant_id IS NULL
                OR (tenant_id IS NOT NULL
                    AND current_setting('app.tenant_id', true) IS NOT NULL
                    AND tenant_id = current_setting('app.tenant_id', true))
            )
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.deployment_health_records') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'deployment_health_records'
          AND policyname = 'deployment_health_records_tenant_isolation'
    ) THEN
        CREATE POLICY deployment_health_records_tenant_isolation ON deployment_health_records
            USING (
                tenant_id IS NULL
                OR (tenant_id IS NOT NULL
                    AND current_setting('app.tenant_id', true) IS NOT NULL
                    AND tenant_id = current_setting('app.tenant_id', true))
            )
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.deployment_records') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'deployment_records'
          AND policyname = 'deployment_records_tenant_isolation'
    ) THEN
        CREATE POLICY deployment_records_tenant_isolation ON deployment_records
            USING (
                tenant_id IS NULL
                OR (tenant_id IS NOT NULL
                    AND current_setting('app.tenant_id', true) IS NOT NULL
                    AND tenant_id = current_setting('app.tenant_id', true))
            )
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.device_coverage_ledger') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'device_coverage_ledger'
          AND policyname = 'device_coverage_ledger_tenant_isolation'
    ) THEN
        CREATE POLICY device_coverage_ledger_tenant_isolation ON device_coverage_ledger
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.embedding_vectors') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'embedding_vectors'
          AND policyname = 'embedding_vectors_tenant_isolation'
    ) THEN
        CREATE POLICY embedding_vectors_tenant_isolation ON embedding_vectors
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.evidence_anchor_records') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'evidence_anchor_records'
          AND policyname = 'evidence_anchor_records_tenant_isolation'
    ) THEN
        CREATE POLICY evidence_anchor_records_tenant_isolation ON evidence_anchor_records
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.evidence_bundles') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'evidence_bundles'
          AND policyname = 'evidence_bundles_tenant_isolation'
    ) THEN
        CREATE POLICY evidence_bundles_tenant_isolation ON evidence_bundles
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.governance_assets') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'governance_assets'
          AND policyname = 'governance_assets_tenant_isolation'
    ) THEN
        CREATE POLICY governance_assets_tenant_isolation ON governance_assets
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.governance_promotions') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'governance_promotions'
          AND policyname = 'governance_promotions_tenant_isolation'
    ) THEN
        CREATE POLICY governance_promotions_tenant_isolation ON governance_promotions
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.governance_workflows') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'governance_workflows'
          AND policyname = 'governance_workflows_tenant_isolation'
    ) THEN
        CREATE POLICY governance_workflows_tenant_isolation ON governance_workflows
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.ops_backup_records') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'ops_backup_records'
          AND policyname = 'ops_backup_records_tenant_isolation'
    ) THEN
        CREATE POLICY ops_backup_records_tenant_isolation ON ops_backup_records
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.ops_environments') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'ops_environments'
          AND policyname = 'ops_environments_tenant_isolation'
    ) THEN
        CREATE POLICY ops_environments_tenant_isolation ON ops_environments
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.ops_export_requests') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'ops_export_requests'
          AND policyname = 'ops_export_requests_tenant_isolation'
    ) THEN
        CREATE POLICY ops_export_requests_tenant_isolation ON ops_export_requests
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.ops_governance_audit_events') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'ops_governance_audit_events'
          AND policyname = 'ops_governance_audit_events_tenant_isolation'
    ) THEN
        CREATE POLICY ops_governance_audit_events_tenant_isolation ON ops_governance_audit_events
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.ops_key_rotation_schedules') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'ops_key_rotation_schedules'
          AND policyname = 'ops_key_rotation_schedules_tenant_isolation'
    ) THEN
        CREATE POLICY ops_key_rotation_schedules_tenant_isolation ON ops_key_rotation_schedules
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.ops_recovery_records') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'ops_recovery_records'
          AND policyname = 'ops_recovery_records_tenant_isolation'
    ) THEN
        CREATE POLICY ops_recovery_records_tenant_isolation ON ops_recovery_records
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.ops_restore_records') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'ops_restore_records'
          AND policyname = 'ops_restore_records_tenant_isolation'
    ) THEN
        CREATE POLICY ops_restore_records_tenant_isolation ON ops_restore_records
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.ops_retention_policies') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'ops_retention_policies'
          AND policyname = 'ops_retention_policies_tenant_isolation'
    ) THEN
        CREATE POLICY ops_retention_policies_tenant_isolation ON ops_retention_policies
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.ops_secret_governance') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'ops_secret_governance'
          AND policyname = 'ops_secret_governance_tenant_isolation'
    ) THEN
        CREATE POLICY ops_secret_governance_tenant_isolation ON ops_secret_governance
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.org_profiles') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'org_profiles'
          AND policyname = 'org_profiles_tenant_isolation'
    ) THEN
        CREATE POLICY org_profiles_tenant_isolation ON org_profiles
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.provisioning_audit_events') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'provisioning_audit_events'
          AND policyname = 'provisioning_audit_events_tenant_isolation'
    ) THEN
        CREATE POLICY provisioning_audit_events_tenant_isolation ON provisioning_audit_events
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.provisioning_organizations') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'provisioning_organizations'
          AND policyname = 'provisioning_organizations_tenant_isolation'
    ) THEN
        CREATE POLICY provisioning_organizations_tenant_isolation ON provisioning_organizations
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.provisioning_workflows') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'provisioning_workflows'
          AND policyname = 'provisioning_workflows_tenant_isolation'
    ) THEN
        CREATE POLICY provisioning_workflows_tenant_isolation ON provisioning_workflows
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.rag_chunks') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'rag_chunks'
          AND policyname = 'rag_chunks_tenant_isolation'
    ) THEN
        CREATE POLICY rag_chunks_tenant_isolation ON rag_chunks
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.rag_corpora') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'rag_corpora'
          AND policyname = 'rag_corpora_tenant_isolation'
    ) THEN
        CREATE POLICY rag_corpora_tenant_isolation ON rag_corpora
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.rag_documents') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'rag_documents'
          AND policyname = 'rag_documents_tenant_isolation'
    ) THEN
        CREATE POLICY rag_documents_tenant_isolation ON rag_documents
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.reports') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'reports'
          AND policyname = 'reports_tenant_isolation'
    ) THEN
        CREATE POLICY reports_tenant_isolation ON reports
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.risk_alert_rules') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'risk_alert_rules'
          AND policyname = 'risk_alert_rules_tenant_isolation'
    ) THEN
        CREATE POLICY risk_alert_rules_tenant_isolation ON risk_alert_rules
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.risk_alerts_fired') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'risk_alerts_fired'
          AND policyname = 'risk_alerts_fired_tenant_isolation'
    ) THEN
        CREATE POLICY risk_alerts_fired_tenant_isolation ON risk_alerts_fired
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.risk_score_snapshots') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'risk_score_snapshots'
          AND policyname = 'risk_score_snapshots_tenant_isolation'
    ) THEN
        CREATE POLICY risk_score_snapshots_tenant_isolation ON risk_score_snapshots
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.tenant_ai_policy') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'tenant_ai_policy'
          AND policyname = 'tenant_ai_policy_tenant_isolation'
    ) THEN
        CREATE POLICY tenant_ai_policy_tenant_isolation ON tenant_ai_policy
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.tenant_config_active') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'tenant_config_active'
          AND policyname = 'tenant_config_active_tenant_isolation'
    ) THEN
        CREATE POLICY tenant_config_active_tenant_isolation ON tenant_config_active
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.tenant_contracts') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'tenant_contracts'
          AND policyname = 'tenant_contracts_tenant_isolation'
    ) THEN
        CREATE POLICY tenant_contracts_tenant_isolation ON tenant_contracts
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.tenant_control_state') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'tenant_control_state'
          AND policyname = 'tenant_control_state_tenant_isolation'
    ) THEN
        CREATE POLICY tenant_control_state_tenant_isolation ON tenant_control_state
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.tenant_identity_governance_snapshots') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'tenant_identity_governance_snapshots'
          AND policyname = 'tenant_identity_governance_snapshots_tenant_isolation'
    ) THEN
        CREATE POLICY tenant_identity_governance_snapshots_tenant_isolation ON tenant_identity_governance_snapshots
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.tenant_keywords') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'tenant_keywords'
          AND policyname = 'tenant_keywords_tenant_isolation'
    ) THEN
        CREATE POLICY tenant_keywords_tenant_isolation ON tenant_keywords
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.tenant_retrieval_policies') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'tenant_retrieval_policies'
          AND policyname = 'tenant_retrieval_policies_tenant_isolation'
    ) THEN
        CREATE POLICY tenant_retrieval_policies_tenant_isolation ON tenant_retrieval_policies
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.tenant_role_audit') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'tenant_role_audit'
          AND policyname = 'tenant_role_audit_tenant_isolation'
    ) THEN
        CREATE POLICY tenant_role_audit_tenant_isolation ON tenant_role_audit
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    -- Policies for tables that had RLS enabled but no tenant_isolation policy
    IF to_regclass('public.evaluation_query_items') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'evaluation_query_items'
          AND policyname = 'evaluation_query_items_tenant_isolation'
    ) THEN
        CREATE POLICY evaluation_query_items_tenant_isolation ON evaluation_query_items
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.evaluation_query_sets') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'evaluation_query_sets'
          AND policyname = 'evaluation_query_sets_tenant_isolation'
    ) THEN
        CREATE POLICY evaluation_query_sets_tenant_isolation ON evaluation_query_sets
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;

    IF to_regclass('public.governance_timeline_events') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public'
          AND tablename = 'governance_timeline_events'
          AND policyname = 'governance_timeline_events_tenant_isolation'
    ) THEN
        CREATE POLICY governance_timeline_events_tenant_isolation ON governance_timeline_events
            USING (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                   AND tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL
                        AND tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;
