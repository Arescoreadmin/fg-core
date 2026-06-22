-- 0085_fa_governance_decisions.sql
-- H14: Governance Decision Ledger — append-only attribution & provenance
--
-- Creates three append-only tables:
--   fa_governance_decisions    — immutable decision ledger (every governance act)
--   fa_risk_acceptances        — structured risk acceptance records
--   fa_governance_exceptions   — structured exception records
--
-- All three tables carry DB-level UPDATE/DELETE triggers that raise immediately.
-- Governance decisions survive personnel changes, audits, and litigation.

-- ─── Table: fa_governance_decisions ─────────────────────────────────────────
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'fa_governance_decisions') THEN
    CREATE TABLE fa_governance_decisions (
        id                     VARCHAR(64)   PRIMARY KEY,
        tenant_id              VARCHAR(255)  NOT NULL,
        engagement_id          VARCHAR(64)   NOT NULL,
        decision_type          VARCHAR(64)   NOT NULL,
        entity_type            VARCHAR(64)   NOT NULL,
        entity_id              VARCHAR(64)   NOT NULL,
        -- Actor attribution — full human-readable, non-repudiation anchor
        actor_id               VARCHAR(255)  NOT NULL,
        actor_name             VARCHAR(512),
        actor_email            VARCHAR(512),
        actor_role             VARCHAR(255),
        actor_auth_source      VARCHAR(64)   NOT NULL DEFAULT 'api_key',
        -- Approval chain (supports future dual-control workflows)
        creator_id             VARCHAR(255),
        reviewer_id            VARCHAR(255),
        approver_id            VARCHAR(255)  NOT NULL,
        -- Decision content
        decision_reason        TEXT          NOT NULL,
        decision_notes         TEXT,
        status                 VARCHAR(32)   NOT NULL DEFAULT 'active',
        -- Evidence provenance
        evidence_snapshot_hash VARCHAR(64),
        evidence_refs          TEXT,
        related_finding_ids    TEXT,
        related_control_ids    TEXT,
        -- Timestamps
        decision_at            VARCHAR(64)   NOT NULL,
        effective_until        VARCHAR(64),
        review_date            VARCHAR(64),
        -- H13 correlation
        transaction_id         VARCHAR(64),
        correlation_id         VARCHAR(64),
        -- Type-specific metadata (JSON blob for extensibility)
        decision_metadata      TEXT
    );
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_fa_gov_decisions_tenant
    ON fa_governance_decisions (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_decisions_tenant_eng
    ON fa_governance_decisions (tenant_id, engagement_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_decisions_entity
    ON fa_governance_decisions (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_decisions_type
    ON fa_governance_decisions (tenant_id, decision_type);
CREATE INDEX IF NOT EXISTS ix_fa_gov_decisions_actor
    ON fa_governance_decisions (tenant_id, actor_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_decisions_tx
    ON fa_governance_decisions (transaction_id);

CREATE OR REPLACE FUNCTION fn_fa_gov_decisions_append_only()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION USING MESSAGE =
            'fa_governance_decisions is append-only: UPDATE forbidden (id='
            || OLD.id
            || ')';
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING MESSAGE =
            'fa_governance_decisions is append-only: DELETE forbidden (id='
            || OLD.id
            || ')';
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS tg_fa_gov_decisions_append_only ON fa_governance_decisions;
CREATE TRIGGER tg_fa_gov_decisions_append_only
    BEFORE UPDATE OR DELETE ON fa_governance_decisions
    FOR EACH ROW EXECUTE FUNCTION fn_fa_gov_decisions_append_only();

-- ─── Table: fa_risk_acceptances ──────────────────────────────────────────────
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'fa_risk_acceptances') THEN
    CREATE TABLE fa_risk_acceptances (
        id                     VARCHAR(64)   PRIMARY KEY,
        decision_id            VARCHAR(64)   NOT NULL,
        tenant_id              VARCHAR(255)  NOT NULL,
        engagement_id          VARCHAR(64)   NOT NULL,
        finding_id             VARCHAR(64)   NOT NULL,
        risk_owner             VARCHAR(255)  NOT NULL,
        risk_owner_email       VARCHAR(512),
        business_justification TEXT          NOT NULL,
        accepted_risk_level    VARCHAR(32)   NOT NULL,
        expires_at             VARCHAR(64)   NOT NULL,
        review_date            VARCHAR(64)   NOT NULL,
        evidence_refs          TEXT,
        approver_id            VARCHAR(255)  NOT NULL,
        approver_name          VARCHAR(512),
        approver_email         VARCHAR(512),
        status                 VARCHAR(32)   NOT NULL DEFAULT 'active',
        created_at             VARCHAR(64)   NOT NULL
    );
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_fa_risk_accept_tenant_eng
    ON fa_risk_acceptances (tenant_id, engagement_id);
CREATE INDEX IF NOT EXISTS ix_fa_risk_accept_finding
    ON fa_risk_acceptances (finding_id);
CREATE INDEX IF NOT EXISTS ix_fa_risk_accept_decision
    ON fa_risk_acceptances (decision_id);
CREATE INDEX IF NOT EXISTS ix_fa_risk_accept_status
    ON fa_risk_acceptances (tenant_id, status);

CREATE OR REPLACE FUNCTION fn_fa_risk_acceptances_append_only()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION USING MESSAGE =
            'fa_risk_acceptances is append-only: UPDATE forbidden (id='
            || OLD.id
            || ')';
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING MESSAGE =
            'fa_risk_acceptances is append-only: DELETE forbidden (id='
            || OLD.id
            || ')';
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS tg_fa_risk_acceptances_append_only ON fa_risk_acceptances;
CREATE TRIGGER tg_fa_risk_acceptances_append_only
    BEFORE UPDATE OR DELETE ON fa_risk_acceptances
    FOR EACH ROW EXECUTE FUNCTION fn_fa_risk_acceptances_append_only();

-- ─── Table: fa_governance_exceptions ─────────────────────────────────────────
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'fa_governance_exceptions') THEN
    CREATE TABLE fa_governance_exceptions (
        id                     VARCHAR(64)   PRIMARY KEY,
        decision_id            VARCHAR(64)   NOT NULL,
        tenant_id              VARCHAR(255)  NOT NULL,
        engagement_id          VARCHAR(64)   NOT NULL,
        exception_type         VARCHAR(64)   NOT NULL,
        owner                  VARCHAR(255)  NOT NULL,
        owner_email            VARCHAR(512),
        business_justification TEXT          NOT NULL,
        expires_at             VARCHAR(64)   NOT NULL,
        review_schedule        VARCHAR(64),
        related_control_ids    TEXT,
        related_finding_ids    TEXT,
        compensating_controls  TEXT,
        approver_id            VARCHAR(255)  NOT NULL,
        approver_name          VARCHAR(512),
        status                 VARCHAR(32)   NOT NULL DEFAULT 'active',
        created_at             VARCHAR(64)   NOT NULL
    );
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_fa_gov_exceptions_tenant_eng
    ON fa_governance_exceptions (tenant_id, engagement_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_exceptions_decision
    ON fa_governance_exceptions (decision_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_exceptions_status
    ON fa_governance_exceptions (tenant_id, status);

CREATE OR REPLACE FUNCTION fn_fa_gov_exceptions_append_only()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION USING MESSAGE =
            'fa_governance_exceptions is append-only: UPDATE forbidden (id='
            || OLD.id
            || ')';
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING MESSAGE =
            'fa_governance_exceptions is append-only: DELETE forbidden (id='
            || OLD.id
            || ')';
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS tg_fa_gov_exceptions_append_only ON fa_governance_exceptions;
CREATE TRIGGER tg_fa_gov_exceptions_append_only
    BEFORE UPDATE OR DELETE ON fa_governance_exceptions
    FOR EACH ROW EXECUTE FUNCTION fn_fa_gov_exceptions_append_only();
