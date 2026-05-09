# Hybrid Retrieval Engine (PR 23)

## Purpose

`api/rag_hybrid_retrieval.py` adds tenant-scoped hybrid retrieval that fuses
lexical and semantic candidates with Reciprocal Rank Fusion (RRF).

This is retrieval infrastructure only. It does not add reranking, UI, provider
routing changes, answer-generation changes, citation enforcement, policy
engine changes, dashboards, or external vector databases.

## Public Entry Point

`retrieve_rag_context_hybrid_rrf(db, request, provider=None, embedding_model=None, config=None)`

The legacy lexical entry point and PR 22 semantic weighted retrieval entry point
remain intact.

## Candidate Sources

Lexical candidates:

- Tenant-scoped SQL over `rag_chunks`, `rag_documents`, and `rag_corpora`.
- Uses the PR 15 token scoring function.
- Defaults to `lexical_candidate_limit=100`.

Semantic candidates:

- Query embedding comes from the supplied `EmbeddingProvider`.
- Chunk vectors are read only from persisted `embedding_vectors`.
- SQL joins embeddings back to tenant-scoped corpus chunks and documents.
- Defaults to `semantic_candidate_limit=100`.

Semantic candidates do not require a lexical match. This is the PR 23 change
from PR 22's lexical-prefiltered semantic retrieval.

## Reciprocal Rank Fusion

RRF formula:

```text
rrf_score = sum(1 / (k + rank))
```

Default `k` is explicit: `DEFAULT_RRF_K = 60`.

Weighted contribution:

```text
rrf_score =
    lexical_weight / (k + lexical_rank)
  + semantic_weight / (k + semantic_rank)
```

Default weights:

- `lexical_weight = 1.0`
- `semantic_weight = 1.0`

`combined_score` equals `rrf_score` in this PR. Returned chunks include:

- `lexical_score`
- `semantic_score`
- `rrf_score`
- `combined_score`
- `retrieval_strategy="hybrid_rrf"`

## Deterministic Ordering

Final ordering is stable:

1. `combined_score DESC`
2. `rrf_score DESC`
3. `semantic_score DESC`
4. `lexical_score DESC`
5. `corpus_id ASC`
6. `document_id ASC`
7. `ordinal ASC`
8. `chunk_id ASC`

Duplicate candidates from lexical and semantic lists merge by `chunk_id`.

## Tenant Isolation

- `tenant_id` is mandatory.
- All lexical SQL filters by `tenant_id`.
- All semantic SQL filters by `embedding_vectors.tenant_id` and joins back to
  tenant-matched corpus chunks/documents/corpora.
- Corpus filters are applied only inside tenant-scoped SQL.
- There is no cross-tenant fallback, global fallback, or enumeration path.

## Audit Safety

Audit logs include:

- tenant id
- retrieval strategy
- corpus count
- lexical/semantic candidate counts
- returned count
- semantic availability
- RRF `k`
- duration

Audit logs do not include raw chunk text, vectors, provider secrets, PHI, auth
headers, or cookies.

## Configuration

`HybridRetrievalConfig` controls:

- `lexical_weight`
- `semantic_weight`
- `rrf_k`
- `lexical_candidate_limit`
- `semantic_candidate_limit`

Weights must be finite non-negative numbers, at least one weight must be
positive, and limits plus `rrf_k` must be positive integers.

## Not Included

- No reranking
- No UI
- No provider routing changes
- No new embedding providers
- No answer-generation changes
- No citation enforcement
- No policy engine
- No dashboards
- No external vector databases
