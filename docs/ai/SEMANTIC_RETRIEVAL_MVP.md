# Semantic Retrieval MVP (PR 22)

## Purpose

Implements the first production-safe hybrid lexical + semantic retrieval layer
over persisted embeddings and pgvector-ready storage.  Upgrades retrieval from
purely lexical scoring to embedding-assisted semantic retrieval while preserving
all existing governance invariants.

This is retrieval infrastructure, not a chatbot or UI enhancement.

---

## Architecture

```
RagContextRequest
    │
    ├── Lexical SQL pre-filter (same as PR 15)
    │       rag_chunks JOIN rag_documents JOIN rag_corpora
    │       WHERE tenant_id = :tenant_id
    │         AND (corpus_id filter if present)
    │         AND (LIKE clause per query term)
    │
    ├── Query embedding (via EmbeddingProvider.embed())
    │       → query_vector : tuple[float, ...]
    │       → On failure: degrade to lexical-only
    │
    ├── Chunk embedding load (via get_embedding_for_chunk per chunk_id)
    │       → chunk_vectors : dict[chunk_id → vector]
    │       → Missing chunks: semantic_score = 0.0 (not excluded)
    │
    ├── Hybrid scoring per candidate
    │       lexical_score   = _score_text(query_terms, chunk_text)
    │       semantic_score  = normalise(cosine(query_vector, chunk_vector))
    │       combined_score  = 0.4 × lexical_score + 0.6 × semantic_score
    │
    ├── Re-rank: combined_score DESC → corpus_id ASC → document_id ASC
    │            → ordinal ASC → chunk_id ASC
    │
    └── RagContextResponse (top_k chunks with provenance + scoring fields)
```

Public entry point: `api/rag_semantic_retrieval.py:retrieve_rag_context_hybrid`.

---

## Hybrid Scoring Model

### Formula

```
combined_score = lexical_weight × lexical_score
               + semantic_weight × semantic_score
```

Default weights: `lexical_weight = 0.4`, `semantic_weight = 0.6`.

### Lexical score

Same computation as PR 15 `_score_text`:

```
unique_matched_query_terms + matching_term_occurrences / (chunk_term_count + 1)
```

Non-zero only if at least one query term appears in the chunk.

### Semantic score

1. Cosine similarity between query vector and chunk vector: `cosine ∈ [-1, 1]`.
2. Linear normalisation to `[0, 1]`: `(cosine + 1) / 2`.

Properties:
- **Bounded**: always in `[0, 1]` after normalisation.
- **Deterministic**: pure arithmetic, no PRNG.
- **Finite**: zero-vector guard prevents NaN/inf.

### Score provenance fields

Every returned chunk includes:
- `lexical_score` — raw lexical relevance score.
- `semantic_score` — normalised cosine similarity.
- `combined_score` — hybrid weighted sum (= `score`).
- `retrieval_strategy` — `"hybrid"` or `"lexical"`.

Existing `score` field always equals `combined_score` for backward compatibility.

---

## Similarity Strategy

Algorithm: **weighted lexical + normalised cosine similarity**.

Cosine similarity is computed in Python (O(N) scan over candidates).  This is
intentional for the MVP — no ANN indexing is required at this scale.

The similarity computation is:
1. Deterministic.
2. Bounded to `[-1, 1]` with explicit clamp for float drift.
3. Zero-safe (zero-vector guard → returns `0.0`).
4. Length-mismatch safe (returns `0.0`).

---

## Fallback Behavior

| Condition | Behavior |
|---|---|
| `provider=None` | Degrade to lexical-only. `retrieval_strategy="lexical"`. |
| Provider unavailable (`is_available()=False`) | Degrade to lexical-only. Structured warning logged. |
| Query embed failure (exception) | Degrade to lexical-only. Structured warning logged. |
| Chunk has no persisted embedding | `semantic_score=0.0`. Chunk retained if lexical match. |
| Empty query / no tokenizable terms | Return empty `RagContextResponse`. |
| Invalid corpus filter (all-blank IDs) | Return empty `RagContextResponse`. |

Degradation is **always explicit**:
- `retrieval_strategy` is set to `"lexical"` in returned chunks.
- Audit log includes `semantic_available=false`.
- No silent fabrication of semantic success.

---

## Deterministic Guarantees

All retrieval results are deterministic:

1. Lexical pre-filter: SQL `ORDER BY corpus_id ASC, document_id ASC, ordinal ASC, chunk_id ASC`.
2. Scoring: pure arithmetic over stable persisted data.
3. Tie-breaking: `combined_score DESC → corpus_id ASC → document_id ASC → ordinal ASC → chunk_id ASC`.
4. Embedding provider: `DeterministicStubProvider` (SHA-256 hash → normalised floats).
5. No PRNG, no randomised ordering, no nondeterministic SQL.

CI runs produce identical results on every run.

---

## Tenant Isolation

Every code path enforces tenant isolation:

1. `tenant_id` is required at the entry point — `ValueError` on blank.
2. Lexical SQL query:
   - `WHERE c.tenant_id = :tenant_id`
   - `JOIN rag_documents d ON … d.tenant_id = c.tenant_id`
   - `JOIN rag_corpora corp ON … corp.tenant_id = c.tenant_id`
3. Embedding lookup: `get_embedding_for_chunk(tenant_id=tenant_id, chunk_id=...)`.
   - Returns `None` if chunk belongs to a different tenant.
4. No cross-tenant lookup is possible — wrong-tenant queries return empty results.
5. No global fallback or admin bypass.

---

## Provenance

Returned chunks include all existing PR 15 provenance fields:
- `corpus_id`, `document_id`, `chunk_id`
- `source`, `title`, `uri`, `page`

New fields added (additive, backward-compatible):
- `lexical_score` — component score.
- `semantic_score` — component score.
- `combined_score` — hybrid weighted sum.
- `retrieval_strategy` — `"hybrid"` or `"lexical"`.

Existing callers that only use `score` and `provenance` are unaffected.

---

## Audit Boundaries

Permitted in audit logs:
- `retrieval_strategy`, `corpus_count`, `candidate_count`, `returned_count`
- `semantic_available`, `duration_ms`, `tenant_id`

Forbidden in audit logs:
- Raw embedding vectors
- Raw chunk text
- PHI / PII
- Provider secrets / API keys
- Auth headers, cookies

---

## pgvector Compatibility

The MVP uses Python-side cosine similarity (O(N) scan) for CI and dev.

pgvector compatibility:
- Embeddings are stored in `embedding_vectors` via the PR 20 persistence layer.
- SQLite stores vectors as JSON text; PostgreSQL stores them as `vector` columns.
- No pgvector SQL operators (`<->`, `<#>`, `<=>`) are used in this PR.
- The persistence layer (`services/embeddings/persistence.py`) handles the
  SQLite/pgvector backend difference transparently.

When pgvector ANN indexing is ready (post-PR 22), the retrieval layer can be
upgraded to use `ORDER BY embedding <-> query_vector LIMIT k` without changing
the public interface.

### SQLite fallback behavior

- All tests run against SQLite (dev/test backend).
- Embedding vectors are loaded as Python tuples and scored in-process.
- No ANN index is required — linear scan is used.
- Functionally equivalent to pgvector cosine similarity at this scale.

---

## Performance

- Lexical SQL pre-filter runs first — reduces the candidate set before Python scoring.
- Embeddings are loaded per-chunk (one lookup per candidate).
- Memory: O(N × D) where N = candidate count, D = embedding dimensions.
- Ordering: stable sort with explicit tie-breaker.
- top_k is enforced during sort (heap-bounded).

No O(N²) operations.  No full-corpus load.  No distributed systems.

---

## Known Limitations

1. **O(N) similarity scan** — all candidate embeddings are loaded and scored in Python.
   For large corpora this will be slow.  ANN indexing (IVFFlat/HNSW) is the post-PR-22 upgrade.
2. **Per-chunk embedding load** — individual `get_embedding_for_chunk` calls per candidate.
   A batch fetch would be more efficient; deferred to a follow-up.
3. **No query embedding cache** — the same query is re-embedded on every call.
   A short-lived cache would reduce provider calls in high-traffic scenarios.
4. **DeterministicStubProvider** — dev/test vectors are not semantically meaningful.
   Production requires a real embedding model with semantic coherence.

---

## What Is NOT Included

This PR explicitly does NOT include:

- **Reranking models** — no cross-encoder or relevance reranking.
- **ANN indexing** — no IVFFlat/HNSW index creation or usage.
- **Distributed vector infra** — no Pinecone, Weaviate, Milvus, OpenSearch, or LangChain.
- **Remote embedding APIs** — no OpenAI, Voyage, or remote model calls at retrieval time.
- **Streaming / async workers** — no Celery/NATS/Redis background workers.
- **Autonomous agents** — no multi-hop retrieval, graph retrieval, or self-directed queries.
- **Memory systems** — no long-term user memory or session state.
- **Live internet retrieval** — all retrieval is over persisted corpus data only.
- **Provider routing changes** — no changes to `ring_router.py` or AI-plane dispatch.
- **UI changes** — no chat redesign, no ingestion UI, no embedding UI.
- **Hidden retries** — no silent fallback that fabricates retrieval context.
- **pgvector SQL operators** — no `<->`, `<#>`, `<=>` in retrieval queries.
