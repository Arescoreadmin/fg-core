-- 0043_verified_knowledge_base.sql
-- PR 31 verified knowledge base layer.
--
-- Verified facts, entities, and relationships are tenant-owned and source-bound.
-- No graph database dependency is introduced.

CREATE TABLE IF NOT EXISTS knowledge_facts (
    id                       UUID        PRIMARY KEY,
    tenant_id                TEXT        NOT NULL,
    subject                  TEXT        NOT NULL,
    predicate                TEXT        NOT NULL,
    object                   TEXT        NOT NULL,
    normalized_subject       TEXT        NOT NULL,
    normalized_predicate     TEXT        NOT NULL,
    normalized_object        TEXT        NOT NULL,
    confidence               NUMERIC     NOT NULL,
    source_doc_id            TEXT        NOT NULL,
    source_chunk_id          TEXT        NOT NULL,
    source_hash              TEXT        NOT NULL,
    valid_from               TIMESTAMPTZ,
    valid_to                 TIMESTAMPTZ,
    review_status            TEXT        NOT NULL DEFAULT 'active',
    contradiction_of_fact_id UUID,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_knowledge_facts_subject CHECK (btrim(subject) <> ''),
    CONSTRAINT ck_knowledge_facts_predicate CHECK (btrim(predicate) <> ''),
    CONSTRAINT ck_knowledge_facts_object CHECK (btrim(object) <> ''),
    CONSTRAINT ck_knowledge_facts_source_hash CHECK (btrim(source_hash) <> ''),
    CONSTRAINT ck_knowledge_facts_confidence CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT ck_knowledge_facts_valid_window CHECK (
        valid_to IS NULL OR valid_from IS NULL OR valid_to > valid_from
    ),
    CONSTRAINT ck_knowledge_facts_review_status CHECK (
        review_status IN ('active', 'contradicted', 'needs_review', 'superseded', 'expired')
    ),
    CONSTRAINT fk_knowledge_facts_source_doc
        FOREIGN KEY (source_doc_id) REFERENCES rag_documents (document_id),
    CONSTRAINT fk_knowledge_facts_source_chunk
        FOREIGN KEY (source_chunk_id) REFERENCES rag_chunks (chunk_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_knowledge_facts_source_fact
    ON knowledge_facts (
        tenant_id,
        source_doc_id,
        source_chunk_id,
        source_hash,
        normalized_subject,
        normalized_predicate,
        normalized_object
    );

CREATE INDEX IF NOT EXISTS ix_knowledge_facts_tenant_current
    ON knowledge_facts (tenant_id, review_status, valid_to);

CREATE INDEX IF NOT EXISTS ix_knowledge_facts_tenant_sp
    ON knowledge_facts (tenant_id, normalized_subject, normalized_predicate);

CREATE INDEX IF NOT EXISTS ix_knowledge_facts_tenant_source
    ON knowledge_facts (tenant_id, source_doc_id, source_chunk_id);

CREATE TABLE IF NOT EXISTS knowledge_entities (
    id                 UUID        PRIMARY KEY,
    tenant_id          TEXT        NOT NULL,
    label              TEXT        NOT NULL,
    normalized_label   TEXT        NOT NULL,
    entity_type        TEXT        NOT NULL DEFAULT '',
    confidence         NUMERIC,
    source_doc_id      TEXT,
    source_chunk_id    TEXT,
    source_hash        TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_knowledge_entities_label CHECK (btrim(label) <> ''),
    CONSTRAINT ck_knowledge_entities_normalized_label CHECK (btrim(normalized_label) <> ''),
    CONSTRAINT ck_knowledge_entities_confidence CHECK (
        confidence IS NULL OR (confidence >= 0 AND confidence <= 1)
    ),
    CONSTRAINT fk_knowledge_entities_source_doc
        FOREIGN KEY (source_doc_id) REFERENCES rag_documents (document_id),
    CONSTRAINT fk_knowledge_entities_source_chunk
        FOREIGN KEY (source_chunk_id) REFERENCES rag_chunks (chunk_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_knowledge_entities_identity
    ON knowledge_entities (tenant_id, normalized_label, entity_type);

CREATE INDEX IF NOT EXISTS ix_knowledge_entities_tenant_label
    ON knowledge_entities (tenant_id, normalized_label);

CREATE TABLE IF NOT EXISTS knowledge_relationships (
    id                 UUID        PRIMARY KEY,
    tenant_id          TEXT        NOT NULL,
    subject_entity_id  UUID        NOT NULL REFERENCES knowledge_entities (id),
    predicate          TEXT        NOT NULL,
    object_entity_id   UUID        REFERENCES knowledge_entities (id),
    object_literal     TEXT,
    confidence         NUMERIC     NOT NULL,
    source_doc_id      TEXT        NOT NULL,
    source_chunk_id    TEXT        NOT NULL,
    source_hash        TEXT        NOT NULL,
    valid_from         TIMESTAMPTZ,
    valid_to           TIMESTAMPTZ,
    review_status      TEXT        NOT NULL DEFAULT 'active',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_knowledge_relationships_predicate CHECK (btrim(predicate) <> ''),
    CONSTRAINT ck_knowledge_relationships_object CHECK (
        object_entity_id IS NOT NULL OR btrim(COALESCE(object_literal, '')) <> ''
    ),
    CONSTRAINT ck_knowledge_relationships_source_hash CHECK (btrim(source_hash) <> ''),
    CONSTRAINT ck_knowledge_relationships_confidence CHECK (
        confidence >= 0 AND confidence <= 1
    ),
    CONSTRAINT ck_knowledge_relationships_valid_window CHECK (
        valid_to IS NULL OR valid_from IS NULL OR valid_to > valid_from
    ),
    CONSTRAINT ck_knowledge_relationships_review_status CHECK (
        review_status IN ('active', 'contradicted', 'needs_review', 'superseded', 'expired')
    ),
    CONSTRAINT fk_knowledge_relationships_source_doc
        FOREIGN KEY (source_doc_id) REFERENCES rag_documents (document_id),
    CONSTRAINT fk_knowledge_relationships_source_chunk
        FOREIGN KEY (source_chunk_id) REFERENCES rag_chunks (chunk_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_knowledge_relationships_source_relation
    ON knowledge_relationships (
        tenant_id,
        subject_entity_id,
        predicate,
        COALESCE(object_entity_id::TEXT, ''),
        COALESCE(object_literal, ''),
        source_hash
    );

CREATE INDEX IF NOT EXISTS ix_knowledge_relationships_tenant_subject
    ON knowledge_relationships (tenant_id, subject_entity_id);

CREATE INDEX IF NOT EXISTS ix_knowledge_relationships_tenant_source
    ON knowledge_relationships (tenant_id, source_doc_id, source_chunk_id);

ALTER TABLE knowledge_facts ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge_facts FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge_entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge_entities FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge_relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge_relationships FORCE ROW LEVEL SECURITY;

CREATE POLICY knowledge_facts_tenant_isolation ON knowledge_facts
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

CREATE POLICY knowledge_entities_tenant_isolation ON knowledge_entities
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

CREATE POLICY knowledge_relationships_tenant_isolation ON knowledge_relationships
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
