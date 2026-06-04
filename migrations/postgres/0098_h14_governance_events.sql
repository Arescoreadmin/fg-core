-- Migration 0098: H14 Governance Event Ledger
--
-- Creates fa_governance_events for benchmark intelligence and immutable
-- governance audit trail. Adds actor_subject (Auth0 sub) to the existing
-- fa_governance_decisions table for non-repudiation hardening.
--
-- Security: UPDATE and DELETE are prohibited at the DB layer via triggers.
-- Schema evolution: bump event_version / schema_version in application code;
--   add columns via additive ALTER TABLE migrations (never drop columns).

BEGIN;

-- ============================================================
-- 1. Add actor_subject to existing governance decisions
--    actor_subject = Auth0 sub / key prefix — the non-repudiation anchor.
--    Nullable so existing rows are preserved without back-fill.
-- ============================================================

ALTER TABLE fa_governance_decisions
    ADD COLUMN IF NOT EXISTS actor_subject VARCHAR(255);

CREATE INDEX IF NOT EXISTS ix_fa_gov_decisions_actor_subject
    ON fa_governance_decisions (tenant_id, actor_subject)
    WHERE actor_subject IS NOT NULL;

-- ============================================================
-- 2. Governance event ledger — append-only
-- ============================================================

CREATE TABLE IF NOT EXISTS fa_governance_events (
    id                      VARCHAR(64)   PRIMARY KEY,
    tenant_id               VARCHAR(255)  NOT NULL,
    engagement_id           VARCHAR(64)   NOT NULL,

    -- Event identity
    event_type              VARCHAR(128)  NOT NULL,
    event_version           VARCHAR(16)   NOT NULL DEFAULT 'v1',
    schema_version          VARCHAR(16)   NOT NULL DEFAULT 'v1',

    -- Entity
    entity_type             VARCHAR(64)   NOT NULL,
    entity_id               VARCHAR(64)   NOT NULL,

    -- Actor attribution — ALL from ActorContext, never from request body
    actor_subject           VARCHAR(255)  NOT NULL,
    actor_email             VARCHAR(512),
    actor_name              VARCHAR(512),
    actor_role              VARCHAR(255),
    actor_auth_source       VARCHAR(64)   NOT NULL DEFAULT 'api_key',

    -- Decision — first-class fields
    decision_reason         TEXT          NOT NULL DEFAULT '',
    event_payload           TEXT,               -- JSON: full decision data

    -- Compliance context
    framework_refs          TEXT,               -- JSON array: control IDs

    -- Timing and benchmark intelligence
    occurred_at             VARCHAR(64)   NOT NULL,
    review_duration_seconds INTEGER,            -- entity_created_at → occurred_at (seconds)

    -- Analytics seed fields
    industry_sector         VARCHAR(64),        -- banking | healthcare | govcon | ...
    risk_level              VARCHAR(32),        -- critical | high | medium | low
    outcome                 VARCHAR(64),        -- approved | rejected | exception_granted

    -- Delegation — schema only; UI not yet built
    delegated_by            VARCHAR(255),
    delegation_reason       TEXT,
    delegation_expires_at   VARCHAR(64),

    -- H13 correlation
    transaction_id          VARCHAR(64)
);

-- ============================================================
-- 3. Indexes for common query patterns
-- ============================================================

CREATE INDEX IF NOT EXISTS ix_fa_gov_events_tenant_type
    ON fa_governance_events (tenant_id, event_type);

CREATE INDEX IF NOT EXISTS ix_fa_gov_events_tenant_eng
    ON fa_governance_events (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_gov_events_entity
    ON fa_governance_events (entity_type, entity_id);

CREATE INDEX IF NOT EXISTS ix_fa_gov_events_actor
    ON fa_governance_events (tenant_id, actor_subject);

CREATE INDEX IF NOT EXISTS ix_fa_gov_events_occurred
    ON fa_governance_events (tenant_id, occurred_at);

-- ============================================================
-- 4. Append-only enforcement: UPDATE and DELETE are forbidden
-- ============================================================

CREATE OR REPLACE FUNCTION fa_governance_events_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION
            'fa_governance_events rows are immutable (H14 governance event ledger). '
            'Event id=%% cannot be updated.', OLD.id;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'fa_governance_events rows cannot be deleted (H14 governance event ledger). '
            'Event id=%% is permanent.', OLD.id;
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS fa_governance_events_no_update ON fa_governance_events;
CREATE TRIGGER fa_governance_events_no_update
    BEFORE UPDATE ON fa_governance_events
    FOR EACH ROW EXECUTE FUNCTION fa_governance_events_immutable();

DROP TRIGGER IF EXISTS fa_governance_events_no_delete ON fa_governance_events;
CREATE TRIGGER fa_governance_events_no_delete
    BEFORE DELETE ON fa_governance_events
    FOR EACH ROW EXECUTE FUNCTION fa_governance_events_immutable();

-- ============================================================
-- 5. Row-Level Security — tenants see only their own events
-- ============================================================

ALTER TABLE fa_governance_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fa_governance_events_tenant_isolation ON fa_governance_events;
CREATE POLICY fa_governance_events_tenant_isolation
    ON fa_governance_events
    USING (tenant_id = current_setting('app.tenant_id', TRUE));

COMMIT;
