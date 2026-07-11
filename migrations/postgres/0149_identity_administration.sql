-- 0149: Identity Administration — IdentityRecord, Invitation, Group, GroupMember, AuditRecord

CREATE TABLE IF NOT EXISTS identity_records (
    record_id       VARCHAR(64)   PRIMARY KEY,
    tenant_id       VARCHAR(255)  NOT NULL,
    subject         VARCHAR(255)  NOT NULL,
    email           VARCHAR(255)  NOT NULL,
    display_name    VARCHAR(255)  NOT NULL DEFAULT '',
    lifecycle_state VARCHAR(64)   NOT NULL,
    invited_by      VARCHAR(255),
    invitation_id   VARCHAR(64),
    created_at      VARCHAR(64)   NOT NULL,
    updated_at      VARCHAR(64)   NOT NULL,
    UNIQUE (tenant_id, subject)
);
CREATE INDEX ix_identity_records_tenant_email ON identity_records (tenant_id, email);
CREATE INDEX ix_identity_records_tenant_state ON identity_records (tenant_id, lifecycle_state);
ALTER TABLE identity_records ENABLE ROW LEVEL SECURITY;
CREATE POLICY identity_records_tenant_isolation
    ON identity_records USING (tenant_id = current_setting('app.tenant_id', true));

CREATE TABLE IF NOT EXISTS identity_invitations (
    invitation_id   VARCHAR(64)   PRIMARY KEY,
    tenant_id       VARCHAR(255)  NOT NULL,
    email           VARCHAR(255)  NOT NULL,
    token_hash      VARCHAR(64)   NOT NULL UNIQUE,
    invited_by      VARCHAR(255)  NOT NULL,
    invited_at      VARCHAR(64)   NOT NULL,
    expires_at      VARCHAR(64)   NOT NULL,
    status          VARCHAR(32)   NOT NULL DEFAULT 'PENDING',
    custom_message  TEXT          NOT NULL DEFAULT '',
    assigned_roles  TEXT          NOT NULL DEFAULT '[]',
    assigned_caps   TEXT          NOT NULL DEFAULT '[]',
    accepted_at     VARCHAR(64),
    accepted_by     VARCHAR(255),
    revoked_at      VARCHAR(64),
    revoked_by      VARCHAR(255)
);
CREATE INDEX ix_identity_invitations_tenant_email ON identity_invitations (tenant_id, email);
CREATE INDEX ix_identity_invitations_tenant_status ON identity_invitations (tenant_id, status);
ALTER TABLE identity_invitations ENABLE ROW LEVEL SECURITY;
CREATE POLICY identity_invitations_tenant_isolation
    ON identity_invitations USING (tenant_id = current_setting('app.tenant_id', true));

CREATE TABLE IF NOT EXISTS identity_groups (
    group_id        VARCHAR(64)   PRIMARY KEY,
    tenant_id       VARCHAR(255)  NOT NULL,
    name            VARCHAR(255)  NOT NULL,
    description     TEXT          NOT NULL DEFAULT '',
    created_by      VARCHAR(255)  NOT NULL,
    created_at      VARCHAR(64)   NOT NULL,
    updated_at      VARCHAR(64)   NOT NULL,
    roles_json      TEXT          NOT NULL DEFAULT '[]',
    capabilities_json TEXT        NOT NULL DEFAULT '[]',
    UNIQUE (tenant_id, name)
);
CREATE INDEX ix_identity_groups_tenant ON identity_groups (tenant_id);
ALTER TABLE identity_groups ENABLE ROW LEVEL SECURITY;
CREATE POLICY identity_groups_tenant_isolation
    ON identity_groups USING (tenant_id = current_setting('app.tenant_id', true));

CREATE TABLE IF NOT EXISTS identity_group_members (
    group_id        VARCHAR(64)   NOT NULL,
    tenant_id       VARCHAR(255)  NOT NULL,
    subject         VARCHAR(255)  NOT NULL,
    added_by        VARCHAR(255)  NOT NULL,
    added_at        VARCHAR(64)   NOT NULL,
    PRIMARY KEY (group_id, tenant_id, subject)
);
CREATE INDEX ix_identity_group_members_tenant_subject ON identity_group_members (tenant_id, subject);
ALTER TABLE identity_group_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY identity_group_members_tenant_isolation
    ON identity_group_members USING (tenant_id = current_setting('app.tenant_id', true));

CREATE TABLE IF NOT EXISTS identity_admin_audit (
    audit_id        VARCHAR(64)   PRIMARY KEY,
    tenant_id       VARCHAR(255)  NOT NULL,
    action          VARCHAR(64)   NOT NULL,
    actor           VARCHAR(255)  NOT NULL,
    subject         VARCHAR(255)  NOT NULL,
    occurred_at     VARCHAR(64)   NOT NULL,
    reason          TEXT          NOT NULL DEFAULT '',
    previous_state  VARCHAR(64)   NOT NULL DEFAULT '',
    new_state       VARCHAR(64)   NOT NULL DEFAULT '',
    correlation_id  VARCHAR(255),
    object_id       VARCHAR(255),
    object_type     VARCHAR(64)
);
CREATE INDEX ix_identity_admin_audit_tenant_subject ON identity_admin_audit (tenant_id, subject);
CREATE INDEX ix_identity_admin_audit_tenant_occurred ON identity_admin_audit (tenant_id, occurred_at);
ALTER TABLE identity_admin_audit ENABLE ROW LEVEL SECURITY;
CREATE POLICY identity_admin_audit_tenant_isolation
    ON identity_admin_audit USING (tenant_id = current_setting('app.tenant_id', true));
