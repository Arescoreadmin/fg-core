-- Migration 0123: Canonical Evidence Authority (PR 14.6.1)
--
-- Creates FrostGate's authoritative evidence entity: fa_evidence.
-- All future evidence references converge here. No subsystem may create
-- a competing evidence ownership model after this migration.
--
-- Tables created:
--   fa_evidence                 — canonical evidence entity (the authority)
--   fa_evidence_ownership       — append-only ownership history per evidence record
--   fa_evidence_relationships   — M2M links: evidence ↔ governed resources
--   fa_evidence_trust_events    — append-only trust state transitions (hash-chained)
--   fa_evidence_audit_events    — append-only lifecycle audit trail
--
-- Security contract:
--   All tables carry tenant_id NOT NULL with a per-table index.
--   RLS must be enforced at the application layer (tenant_id in every query).
--   Append-only tables are guarded by UPDATE/DELETE triggers below.
--
-- Forward-compatibility:
--   content_hash / integrity_hash / provenance_chain_head support FA-17.5
--   (Raw Artifact Storage, Hash Chain, Artifact Replay) without schema migration.
--   trust_score supports autonomous trust scoring without schema migration.
--   actor_type supports human/service/agent/autonomous_system without migration.
--   classification_labels JSONB supports future PII/PHI/CJIS/ITAR labels.

BEGIN;

-- ---------------------------------------------------------------------------
-- fa_evidence — canonical evidence entity
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_evidence (
    -- Identity
    id                          TEXT        NOT NULL PRIMARY KEY,
    tenant_id                   TEXT        NOT NULL,
    evidence_ref                TEXT        NOT NULL,   -- human-friendly stable ref (slugified)

    -- Lifecycle
    lifecycle_state             TEXT        NOT NULL DEFAULT 'DRAFT',
    -- Valid: DRAFT|COLLECTED|SUBMITTED|UNDER_REVIEW|VERIFIED|REJECTED|SUPERSEDED|EXPIRED|REVOKED|ARCHIVED

    -- Classification
    classification              TEXT        NOT NULL DEFAULT 'INTERNAL',
    -- Valid: PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED|REGULATED
    classification_labels       TEXT        NOT NULL DEFAULT '[]',   -- JSON array

    -- Source
    source_type                 TEXT        NOT NULL,
    -- Valid: INTERVIEW|DOCUMENT|SCREENSHOT|SYSTEM_EXPORT|CONNECTOR|SCAN|POLICY|
    --        ATTESTATION|CONTROL_VERIFICATION|REMEDIATION_VERIFICATION|MANUAL_UPLOAD
    source_system               TEXT,
    source_ref                  TEXT,
    collection_method           TEXT        NOT NULL,
    -- Valid: MANUAL_UPLOAD|AUTOMATED_EXPORT|API_PULL|AGENT_COLLECT|
    --        ATTESTATION_SUBMISSION|EXTERNAL_CONNECTOR

    -- Description
    title                       TEXT        NOT NULL,
    description                 TEXT,

    -- Integrity / provenance (forward-compatible with FA-17.5)
    content_hash                TEXT,                   -- SHA-256 of raw artifact content
    content_hash_algorithm      TEXT        DEFAULT 'sha256',
    integrity_hash              TEXT,                   -- SHA-256 of canonical identity fields
    integrity_hash_algorithm    TEXT        DEFAULT 'sha256',
    provenance_chain_head       TEXT,                   -- latest fa_evidence_provenance event ID

    -- Trust
    trust_state                 TEXT        NOT NULL DEFAULT 'UNVERIFIED',
    -- Valid: UNVERIFIED|PARTIALLY_VERIFIED|VERIFIED|HIGH_CONFIDENCE|DISPUTED|INVALIDATED
    verification_count          INTEGER     NOT NULL DEFAULT 0,
    trust_score                 INTEGER,                -- 0-100, computed by trust engine
    last_verification_source    TEXT,                   -- HUMAN|AI|CONNECTOR|THIRD_PARTY|AUTOMATED
    last_verifier_id            TEXT,

    -- Ownership
    owner_id                    TEXT,
    owner_type                  TEXT        DEFAULT 'human',
    -- Valid: human|service|agent|autonomous_system
    creator_id                  TEXT        NOT NULL,
    creator_type                TEXT        NOT NULL DEFAULT 'human',

    -- Context pointers (soft references — cross-domain, no FK)
    engagement_id               TEXT,

    -- Temporal
    collected_at                TEXT        NOT NULL,   -- when evidence was gathered at source
    submitted_at                TEXT,
    reviewed_at                 TEXT,
    verified_at                 TEXT,
    expires_at                  TEXT,
    revoked_at                  TEXT,
    archived_at                 TEXT,

    -- Versioning
    evidence_version            TEXT        NOT NULL DEFAULT '1',
    superseded_by               TEXT,                   -- ID of successor evidence record
    schema_version              TEXT        NOT NULL DEFAULT '1.0',

    created_at                  TEXT        NOT NULL,
    updated_at                  TEXT        NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_evidence_tenant
    ON fa_evidence (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_tenant_state
    ON fa_evidence (tenant_id, lifecycle_state);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_tenant_trust
    ON fa_evidence (tenant_id, trust_state);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_tenant_classification
    ON fa_evidence (tenant_id, classification);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_tenant_source_type
    ON fa_evidence (tenant_id, source_type);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_engagement
    ON fa_evidence (tenant_id, engagement_id);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_tenant_created
    ON fa_evidence (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_expires
    ON fa_evidence (tenant_id, expires_at);

-- Unique per-tenant stable ref
CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_evidence_tenant_ref
    ON fa_evidence (tenant_id, evidence_ref);


-- ---------------------------------------------------------------------------
-- fa_evidence_ownership — append-only ownership history
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_evidence_ownership (
    id              TEXT        NOT NULL PRIMARY KEY,
    tenant_id       TEXT        NOT NULL,
    evidence_id     TEXT        NOT NULL,  -- soft ref to fa_evidence.id

    role            TEXT        NOT NULL,
    -- Valid: OWNER|REVIEWER|VERIFIER|APPROVER|CUSTODIAN

    actor_id        TEXT        NOT NULL,
    actor_type      TEXT        NOT NULL DEFAULT 'human',
    -- Valid: human|service|agent|autonomous_system

    assigned_at     TEXT        NOT NULL,
    assigned_by     TEXT        NOT NULL,
    assigned_by_type TEXT       NOT NULL DEFAULT 'human',

    revoked_at      TEXT,
    revoked_by      TEXT,
    is_active       INTEGER     NOT NULL DEFAULT 1,   -- 1=active, 0=revoked

    schema_version  TEXT        NOT NULL DEFAULT '1.0',
    created_at      TEXT        NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_evidence_ownership_tenant
    ON fa_evidence_ownership (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_ownership_evidence
    ON fa_evidence_ownership (tenant_id, evidence_id);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_ownership_active
    ON fa_evidence_ownership (tenant_id, evidence_id, is_active);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_ownership_actor
    ON fa_evidence_ownership (tenant_id, actor_id);


-- ---------------------------------------------------------------------------
-- fa_evidence_relationships — M2M: evidence ↔ governed resources
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_evidence_relationships (
    id                      TEXT    NOT NULL PRIMARY KEY,
    tenant_id               TEXT    NOT NULL,
    evidence_id             TEXT    NOT NULL,   -- soft ref to fa_evidence.id

    related_entity_type     TEXT    NOT NULL,
    -- Valid: assessment|finding|control|risk_acceptance|review|
    --        governance_decision|remediation|report|timeline_event

    related_entity_id       TEXT    NOT NULL,
    relationship_type       TEXT    NOT NULL,
    -- Valid: SUPPORTS|PROVES|REFUTES|SUPERSEDES|LINKED_TO

    link_metadata           TEXT    NOT NULL DEFAULT '{}',   -- JSON

    linked_at               TEXT    NOT NULL,
    linked_by               TEXT    NOT NULL,
    linked_by_type          TEXT    NOT NULL DEFAULT 'human',

    schema_version          TEXT    NOT NULL DEFAULT '1.0',
    created_at              TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_evidence_rel_tenant
    ON fa_evidence_relationships (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_rel_evidence
    ON fa_evidence_relationships (tenant_id, evidence_id);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_rel_entity
    ON fa_evidence_relationships (tenant_id, related_entity_type, related_entity_id);

-- Prevent duplicate relationships
CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_evidence_relationship
    ON fa_evidence_relationships (
        tenant_id, evidence_id, related_entity_type, related_entity_id, relationship_type
    );


-- ---------------------------------------------------------------------------
-- fa_evidence_trust_events — append-only, hash-chained trust transitions
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_evidence_trust_events (
    id                      TEXT    NOT NULL PRIMARY KEY,
    tenant_id               TEXT    NOT NULL,
    evidence_id             TEXT    NOT NULL,   -- soft ref to fa_evidence.id

    from_trust_state        TEXT    NOT NULL,
    to_trust_state          TEXT    NOT NULL,

    verification_source     TEXT    NOT NULL,
    -- Valid: HUMAN|AI|CONNECTOR|THIRD_PARTY|AUTOMATED|SYSTEM

    verifier_id             TEXT    NOT NULL,
    verifier_type           TEXT    NOT NULL DEFAULT 'human',
    -- Valid: human|service|agent|autonomous_system

    verification_method     TEXT,
    -- e.g. manual_review|document_check|automated_scan|ai_analysis|third_party_cert

    confidence_score        INTEGER,    -- 0-100
    notes                   TEXT,

    -- Hash chain for tamper evidence
    event_hash              TEXT,       -- SHA-256 of this event's canonical fields
    prev_event_hash         TEXT,       -- links to prior trust event for this evidence

    schema_version          TEXT    NOT NULL DEFAULT '1.0',
    created_at              TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_evidence_trust_events_tenant
    ON fa_evidence_trust_events (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_trust_events_evidence
    ON fa_evidence_trust_events (tenant_id, evidence_id);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_trust_events_created
    ON fa_evidence_trust_events (tenant_id, created_at);

-- Prevent duplicate consecutive events with same hash
CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_evidence_trust_event_hash
    ON fa_evidence_trust_events (event_hash)
    WHERE event_hash IS NOT NULL;


-- ---------------------------------------------------------------------------
-- fa_evidence_audit_events — append-only lifecycle audit trail
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_evidence_audit_events (
    id              TEXT    NOT NULL PRIMARY KEY,
    tenant_id       TEXT    NOT NULL,
    evidence_id     TEXT    NOT NULL,   -- soft ref to fa_evidence.id

    event_type      TEXT    NOT NULL,
    -- Values: evidence_created|lifecycle_transitioned|ownership_assigned|
    --         ownership_revoked|relationship_linked|metadata_updated|
    --         trust_state_changed|classification_changed|expired|revoked|archived

    from_state      TEXT,
    to_state        TEXT,

    actor_id        TEXT    NOT NULL,
    actor_type      TEXT    NOT NULL DEFAULT 'human',

    reason          TEXT,
    event_metadata  TEXT    NOT NULL DEFAULT '{}',  -- JSON

    -- H13-style correlation
    transaction_id  TEXT,
    correlation_id  TEXT,

    schema_version  TEXT    NOT NULL DEFAULT '1.0',
    created_at      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_evidence_audit_tenant
    ON fa_evidence_audit_events (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_audit_evidence
    ON fa_evidence_audit_events (tenant_id, evidence_id);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_audit_created
    ON fa_evidence_audit_events (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS ix_fa_evidence_audit_event_type
    ON fa_evidence_audit_events (tenant_id, event_type);


-- ---------------------------------------------------------------------------
-- Append-only guards — PostgreSQL triggers
-- (SQLite fallback: ORM-level guards in db_models_evidence_authority.py)
-- ---------------------------------------------------------------------------

-- Guard fa_evidence_ownership (no deletes; revocation via is_active=0)
CREATE OR REPLACE FUNCTION _fa_evidence_ownership_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'fa_evidence_ownership rows are immutable — use revoked_at/is_active=0 instead of DELETE';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_fa_evidence_ownership_immutable ON fa_evidence_ownership;
CREATE TRIGGER trg_fa_evidence_ownership_immutable
    BEFORE DELETE ON fa_evidence_ownership
    FOR EACH ROW EXECUTE FUNCTION _fa_evidence_ownership_immutable();


-- Guard fa_evidence_trust_events (fully immutable)
CREATE OR REPLACE FUNCTION _fa_evidence_trust_events_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fa_evidence_trust_events rows are immutable';
END;
$$;

DROP TRIGGER IF EXISTS trg_fa_evidence_trust_events_no_update ON fa_evidence_trust_events;
CREATE TRIGGER trg_fa_evidence_trust_events_no_update
    BEFORE UPDATE ON fa_evidence_trust_events
    FOR EACH ROW EXECUTE FUNCTION _fa_evidence_trust_events_immutable();

DROP TRIGGER IF EXISTS trg_fa_evidence_trust_events_no_delete ON fa_evidence_trust_events;
CREATE TRIGGER trg_fa_evidence_trust_events_no_delete
    BEFORE DELETE ON fa_evidence_trust_events
    FOR EACH ROW EXECUTE FUNCTION _fa_evidence_trust_events_immutable();


-- Guard fa_evidence_audit_events (fully immutable)
CREATE OR REPLACE FUNCTION _fa_evidence_audit_events_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fa_evidence_audit_events rows are immutable';
END;
$$;

DROP TRIGGER IF EXISTS trg_fa_evidence_audit_no_update ON fa_evidence_audit_events;
CREATE TRIGGER trg_fa_evidence_audit_no_update
    BEFORE UPDATE ON fa_evidence_audit_events
    FOR EACH ROW EXECUTE FUNCTION _fa_evidence_audit_events_immutable();

DROP TRIGGER IF EXISTS trg_fa_evidence_audit_no_delete ON fa_evidence_audit_events;
CREATE TRIGGER trg_fa_evidence_audit_no_delete
    BEFORE DELETE ON fa_evidence_audit_events
    FOR EACH ROW EXECUTE FUNCTION _fa_evidence_audit_events_immutable();


-- Guard fa_evidence_relationships (append-only; no delete or update)
CREATE OR REPLACE FUNCTION _fa_evidence_relationships_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fa_evidence_relationships rows are immutable';
END;
$$;

DROP TRIGGER IF EXISTS trg_fa_evidence_rel_no_update ON fa_evidence_relationships;
CREATE TRIGGER trg_fa_evidence_rel_no_update
    BEFORE UPDATE ON fa_evidence_relationships
    FOR EACH ROW EXECUTE FUNCTION _fa_evidence_relationships_immutable();

DROP TRIGGER IF EXISTS trg_fa_evidence_rel_no_delete ON fa_evidence_relationships;
CREATE TRIGGER trg_fa_evidence_rel_no_delete
    BEFORE DELETE ON fa_evidence_relationships
    FOR EACH ROW EXECUTE FUNCTION _fa_evidence_relationships_immutable();

COMMIT;
