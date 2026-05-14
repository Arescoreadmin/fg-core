# Verified Knowledge Base

PR 31 adds a source-bound verified knowledge substrate for FrostGate RAG evidence.

## Model

- `knowledge_facts` stores tenant-scoped subject/predicate/object facts.
- `knowledge_entities` stores tenant-scoped normalized entity identities.
- `knowledge_relationships` stores tenant-scoped source-bound relationships.
- The layer uses Postgres/SQLite tables only. It does not introduce a graph database.

## Source Proof

Facts are not trusted unless source-bound. A fact must include:

- `tenant_id`
- `source_doc_id`
- `source_chunk_id`
- `source_hash`

Model-generated claims alone are never persisted as facts. The service verifies that the source document and chunk exist, match the tenant, are current/active for current facts, are not quarantined, and that the supplied hash matches stored chunk/source evidence.

## Confidence

Confidence is numeric and constrained to `0 <= confidence <= 1`. Retrieval-safe lookup defaults to `0.70` minimum confidence.

## Lifecycle

Facts support `valid_from` and `valid_to`. Expired facts remain stored for audit/history, but current lookup excludes rows where `valid_to <= now`. Historical lookup remains tenant-scoped.

## Contradictions

A possible contradiction is detected when a new high-confidence fact has the same tenant, normalized subject, normalized predicate, a different normalized object, and an overlapping validity window. The default threshold is `0.70`.

Contradictions are not overwritten or deleted. The new row is persisted as `needs_review` with a pointer to the conflicting fact. Contradicted facts are excluded from retrieval-safe current lookup until review/escalation resolves them.

## Retrieval Integration

Verified facts are available only as source-bound fast-path evidence through `list_retrieval_safe_current_facts()`. Retrieval-safe lookup:

- requires tenant context
- excludes expired facts
- excludes non-active review statuses
- enforces confidence threshold
- revalidates source document/chunk/hash
- excludes quarantined, superseded, inactive, or policy-denied sources

If proof revalidation fails, the fact is excluded and a safe audit log event is emitted. The layer does not replace RAG retrieval.

## Deferred

- Public API routes are deferred until auth scope and contract authority are explicitly assigned.
- Ontology management and graph traversal are deferred.
- Human review workflow UI is deferred; `needs_review` is the durable hook.
