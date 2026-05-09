# Embedding Pipeline MVP (PR 21)

## Purpose

Implements the first real embedding generation pipeline over persisted RAG
chunks.  Uses the PR 19 embedding contracts and the PR 20 persistence layer.

This document describes `services/embeddings/pipeline.py` and
`api/embeddings/stub_provider.py`.

This PR creates a deterministic, tenant-safe embedding pipeline foundation
suitable for future pgvector semantic retrieval.  It does NOT implement
semantic retrieval.

---

## Pipeline Architecture

```
rag_chunks (persisted) → pipeline → EmbeddingProvider → upsert_embedding → embedding_vectors
```

Three public entry points:

| Function | Scope |
|---|---|
| `generate_embedding_for_chunk(db, *, tenant_id, corpus_id, document_id, chunk_id, chunk_text, provider)` | Single chunk |
| `generate_embeddings_for_document(db, *, tenant_id, corpus_id, document_id, provider)` | All chunks in a document |
| `generate_embeddings_for_corpus(db, *, tenant_id, corpus_id, provider)` | All documents + chunks in a corpus |

All entry points:
- require explicit `tenant_id` (fail closed on blank)
- operate ONLY on persisted `rag_chunks` rows
- use `upsert_embedding` for idempotent writes
- preserve `content_hash` lineage from `api/rag_corpus_store.py`
- emit structured audit logs (no raw chunk text, no raw vectors)

---

## Deterministic Generation Model

The `DeterministicStubProvider` (`api/embeddings/stub_provider.py`) produces
stable, reproducible vectors from chunk text:

1. SHA-256 hash the UTF-8 chunk text.
2. Extend the hash bytes to cover all required dimensions (repeated SHA-256 chain).
3. Interpret 4-byte LE uint32 chunks as floats normalized to `[0, 1]`.

Properties:
- **Deterministic**: same text always produces the same vector.
- **No network**: no external calls, no OpenAI keys.
- **Stable across restarts**: pure SHA-256, no PRNG.
- **Not semantically meaningful**: for dev/test only.

---

## Persistence Flow

```
chunk_text
    → canonical_content_hash(chunk_text) → content_hash
    → EmbeddingRequest.from_chunk(...)
    → provider.embed(request) → EmbeddingResponse
    → ChunkEmbeddingRecord.from_response(...)
    → upsert_embedding(db, record) → EmbeddingRow
```

`upsert_embedding` (from PR 20) handles idempotency:
- If `(tenant_id, corpus_id, chunk_id, model, content_hash)` already exists: update vector + `updated_at`.
- If not: insert new row.

---

## Content Hash Behavior

- `content_hash` is computed by `canonical_content_hash` (SHA-256 of UTF-8 text).
- The pipeline computes the hash from `chunk_text` at generation time.
- The hash is stored in `embedding_vectors.content_hash`.
- If chunk text changes between pipeline runs: `content_hash` changes, triggering
  an upsert with the new vector.
- The uniqueness constraint on `(tenant_id, corpus_id, chunk_id, model, content_hash)`
  prevents stale hashes from silently overwriting fresh embeddings.

---

## Idempotency Behavior

Pipeline reruns are safe:
- Same chunk text → same hash → `upsert_embedding` updates in place (no new row).
- Different text → different hash → new content produces a new embedding upsert.
- Zero duplicate rows: uniqueness is enforced by the persistence layer constraint.

---

## Tenant Isolation

Every pipeline entry point:
- Rejects blank `tenant_id` with `PipelineTenantRequiredError`.
- Passes `tenant_id` into every `rag_corpus_store` read (all queries scoped).
- Passes `tenant_id` into every `upsert_embedding` / `get_embedding_for_chunk` call.
- Cross-tenant reads return empty/None — no enumeration leakage.
- No admin bypass; no global fallback.

---

## Audit Boundaries

Audit log events emitted by the pipeline:

| Event | Fields |
|---|---|
| `embedding.pipeline.chunk_persisted` | `tenant_id`, `corpus_id`, `document_id`, `chunk_id`, `embedding_model`, `dimensions`, `content_hash` |
| `embedding.pipeline.chunk_failed` | `tenant_id`, `corpus_id`, `document_id`, `chunk_id`, `embedding_model`, `content_hash`, `error` |
| `embedding.pipeline.document_started` | `tenant_id`, `corpus_id`, `document_id`, `embedding_model`, `chunk_count` |
| `embedding.pipeline.document_completed` | `tenant_id`, `corpus_id`, `document_id`, `embedding_model`, `total_chunks`, `persisted`, `skipped`, `failed`, `duration_ms` |
| `embedding.pipeline.corpus_started` | `tenant_id`, `corpus_id`, `embedding_model`, `document_count` |
| `embedding.pipeline.corpus_completed` | `tenant_id`, `corpus_id`, `embedding_model`, `total_documents`, `total_chunks`, `persisted`, `skipped`, `failed`, `duration_ms` |

**Forbidden in audit logs:**
- Raw chunk text
- PHI / PII
- Provider secrets / API keys
- Auth headers / cookies
- Raw vectors

---

## Result Types

| Type | Fields |
|---|---|
| `ChunkEmbeddingResult` | `tenant_id`, `corpus_id`, `document_id`, `chunk_id`, `content_hash`, `embedding_model`, `dimensions`, `status`, `error` |
| `DocumentEmbeddingResult` | `tenant_id`, `corpus_id`, `document_id`, `embedding_model`, `chunk_results`, `total_chunks`, `persisted`, `skipped`, `failed`, `duration_ms` |
| `CorpusEmbeddingResult` | `tenant_id`, `corpus_id`, `embedding_model`, `document_results`, `total_documents`, `total_chunks`, `persisted`, `skipped`, `failed`, `duration_ms` |

All result types are `frozen=True` dataclasses.  No raw chunk text, no raw
vectors in any result type.

---

## Error Codes

| Code | Class | Meaning |
|---|---|---|
| `EMBED_PIPE_001` | `PipelineTenantRequiredError` | Blank tenant_id at pipeline entry |
| `EMBED_PIPE_002` | `PipelineProviderUnavailableError` | Provider not available |
| `EMBED_PIPE_003` | — | Chunk not found (informational) |

---

## Current Limitations (Not Included)

This PR explicitly does NOT include:

- **Semantic retrieval** — no similarity search, no ANN queries.
- **Similarity search** — no cosine, L2, or inner-product queries.
- **pgvector ANN indexing** — no IVFFlat/HNSW index creation.
- **Reranking** — no cross-encoder or relevance reranking.
- **Hybrid retrieval** — no BM25 + vector fusion.
- **Vector search API** — no public endpoint for nearest-neighbor lookup.
- **Live provider embeddings** — no OpenAI, Voyage, or remote model calls.
- **Background queue workers** — no Celery/NATS/Redis workers.
- **Async tasks** — no asyncio embedding workers.
- **Provider routing changes** — no changes to `ring_router.py` or AI plane.
- **UI changes** — no ingestion or embedding UI.
- **Streaming** — no streaming embedding responses.

---

## Future pgvector Handoff

This pipeline produces `embedding_vectors` rows suitable for pgvector
retrieval.  When semantic retrieval is enabled (post PR 21):

1. Operator creates IVFFlat/HNSW indexes per the runbook in migration
   `0039_vector_index_runbook.sql`.
2. Operator sets `FG_EMBEDDINGS_ANN_INDEX_STATUS=ready` and registers the
   primary model in `vector_index_registry`.
3. `assert_ann_index_ready()` passes.
4. Semantic retrieval routes can query `embedding_vectors` using pgvector
   operators (`<->`, `<#>`, `<=>`) against the same rows this pipeline writes.

---

## Future Semantic Retrieval Handoff

When the semantic retrieval PR lands:

- A new retrieval service reads `embedding_vectors` rows scoped by `tenant_id`.
- Queries are issued as `SELECT ... ORDER BY embedding <-> query_vector LIMIT k`.
- This pipeline is not modified — it remains the write path only.
- The `EmbeddingState` enum in `api/embeddings/state.py` tracks chunk lifecycle.
