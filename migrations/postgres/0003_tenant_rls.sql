DO $$
BEGIN
    IF to_regclass('public.decisions') IS NOT NULL THEN
        ALTER TABLE decisions ENABLE ROW LEVEL SECURITY;
        ALTER TABLE decisions FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.decision_evidence_artifacts') IS NOT NULL THEN
        ALTER TABLE decision_evidence_artifacts ENABLE ROW LEVEL SECURITY;
        ALTER TABLE decision_evidence_artifacts FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.api_keys') IS NOT NULL THEN
        ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
        ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.security_audit_log') IS NOT NULL THEN
        ALTER TABLE security_audit_log ENABLE ROW LEVEL SECURITY;
        ALTER TABLE security_audit_log FORCE ROW LEVEL SECURITY;
    END IF;

    IF to_regclass('public.policy_change_requests') IS NOT NULL THEN
        ALTER TABLE policy_change_requests ENABLE ROW LEVEL SECURITY;
        ALTER TABLE policy_change_requests FORCE ROW LEVEL SECURITY;
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('public.decisions') IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'decisions'
          AND policyname = 'decisions_tenant_isolation'
    ) THEN
        CREATE POLICY decisions_tenant_isolation ON decisions
            USING (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;

    IF to_regclass('public.decision_evidence_artifacts') IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'decision_evidence_artifacts'
          AND policyname = 'decision_evidence_artifacts_tenant_isolation'
    ) THEN
        CREATE POLICY decision_evidence_artifacts_tenant_isolation
            ON decision_evidence_artifacts
            USING (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;

    IF to_regclass('public.api_keys') IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'api_keys'
          AND policyname = 'api_keys_tenant_isolation'
    ) THEN
        CREATE POLICY api_keys_tenant_isolation ON api_keys
            USING (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;

    IF to_regclass('public.security_audit_log') IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'security_audit_log'
          AND policyname = 'security_audit_log_tenant_isolation'
    ) THEN
        CREATE POLICY security_audit_log_tenant_isolation ON security_audit_log
            USING (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;

    IF to_regclass('public.policy_change_requests') IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'policy_change_requests'
          AND policyname = 'policy_change_requests_tenant_isolation'
    ) THEN
        CREATE POLICY policy_change_requests_tenant_isolation ON policy_change_requests
            USING (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;
END $$;
