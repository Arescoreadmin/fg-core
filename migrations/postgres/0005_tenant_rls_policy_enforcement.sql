ALTER POLICY decisions_tenant_isolation ON decisions
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

ALTER POLICY decision_evidence_artifacts_tenant_isolation ON decision_evidence_artifacts
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

ALTER POLICY api_keys_tenant_isolation ON api_keys
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

ALTER POLICY security_audit_log_tenant_isolation ON security_audit_log
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

ALTER POLICY policy_change_requests_tenant_isolation ON policy_change_requests
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
