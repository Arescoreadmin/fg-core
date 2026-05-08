# RAG Flow (PR 18)

## Scope

This document describes the complete RAG path from corpus persistence through
retrieval, prompt inclusion, answer metadata, no-context fallback, audit
boundaries, and validation.

This is lexical retrieval, not semantic search. There are no embeddings, no
vector database, and no external search engine.

---

## Component Overview

| Component | File | Role |
|---|---|---|
| Corpus persistence | `api/rag_corpus_store.py` | Store tenant-scoped corpora, documents, chunks |
| Context contract | `api/rag_context.py` | Typed request/response/provenance models |
| Lexical retrieval | `api/rag_retrieval.py` | Ranked chunk retrieval over persisted tables |
| Service adapter | `services/ai/rag_context.py` | Bridge retrieval to AI plane; builds augmented prompt |
| AI plane | `services/ai_plane_extension/service.py` | Orchestrates retrieval → BAA → provider → validation |
| Response validation | `services/ai/response_validation.py` | Lexical grounding check; replaces ungrounded output |
| Audit | `services/ai/audit.py` | Safe metadata builder; hashes only for text fields |

---

## Flow: Corpus Context Exists

```
1. AIPlaneService.infer receives query + trusted tenant_id.
2. retrieve_persisted_rag_context(db, tenant_id, query_text) is called.
   - SQL filters rag_chunks by tenant_id (row-level isolation).
   - Lexical scoring: lowercase tokenize, count unique matched terms + occurrence weight.
   - Returns RagContextResult with chunks, source_chunk_ids, retrieval_reason_code.
3. build_rag_augmented_prompt() wraps context before the query:
     Retrieved context:
     [chunk_id=<id>]
     <chunk text>

     User query:
     <user query>
4. BAA gate checks PHI sensitivity of the augmented prompt before provider dispatch.
5. Provider is called with the augmented prompt.
6. validate_provider_response_grounding() checks that provider output tokens are
   a subset of retrieved context tokens. Ungrounded output → NO_ANSWER.
7. Response returned with metadata:
   - used_rag: true
   - context_count: N (number of included chunks)
   - source_chunk_ids: [<real persisted chunk IDs>]
8. Audit event emitted with safe RAG fields only (no chunk text, no full prompt).
```

## Flow: No Relevant Context

```
1. retrieve_persisted_rag_context returns RagContextResult with chunks=[].
2. rag_used=False → build_rag_augmented_prompt returns the bare query (no context block).
3. Provider is NOT called.
4. validate_provider_response_grounding returns RESPONSE_NO_RAG_CONTEXT → NO_ANSWER.
5. Response returned with metadata:
   - used_rag: false
   - context_count: 0
   - source_chunk_ids: []
6. Audit event emitted with rag_used=false, retrieval_reason_code=RAG_RETRIEVAL_EMPTY.
```

---

## Retrieval Details

- Lexical only: lowercase alphanumeric tokenization, LIKE prefilter, in-Python scoring.
- Score = `unique_matched_query_terms + matching_occurrence_count / (chunk_term_count + 1)`.
- Zero-score chunks are excluded.
- Result order: score DESC → corpus_id ASC → document_id ASC → ordinal ASC → chunk_id ASC.
- `top_k` bounded by `MAX_RAG_CONTEXT_LIMIT = 8`; default 4 in AI plane.
- `corpus_ids` filter is applied inside the tenant-scoped query only.

---

## Prompt Inclusion Boundaries

Included in the provider prompt:
- Retrieved chunk text (bounded to `MAX_RAG_CHUNK_CHARS = 1200` chars per chunk).
- Safe chunk marker: `[chunk_id=<id>]`.
- User query text.

Not included in the provider prompt:
- Tenant ID, corpus ID, document ID as raw labels.
- Corpus/document metadata dumps.
- Auth headers, cookies, or secrets.
- Internal configuration values.

Total context bounded to `MAX_RAG_CONTEXT_CHARS = 4000` chars.

---

## Answer Metadata

Every `/ai/infer` response includes:

```json
{
  "used_rag": true,
  "context_count": 2,
  "source_chunk_ids": ["ck-<hex>", "ck-<hex>"]
}
```

- `used_rag` is derived from `context_count > 0`.
- `source_chunk_ids` contains only chunk IDs that were included in the prompt.
- IDs are real persisted values from `rag_chunks.chunk_id` (prefix `ck-`).
- No fabricated or placeholder IDs are ever emitted.

---

## No-Context Fallback Proof

When no relevant context is retrieved:
- `rag_used=false`, `context_count=0`, `source_chunk_ids=[]` in response metadata.
- Provider is not called.
- Response text is `NO_ANSWER`.
- `sources=[]`, `confidence=0.0`.
- Audit records `rag_retrieval_reason_code=RAG_RETRIEVAL_EMPTY`.

---

## Audit Boundaries

Audit metadata (`services/ai/audit.py`) emits:

**Safe (always logged):**
- `rag_used` — bool
- `rag_chunk_count` — int
- `rag_source_ids` — list of chunk IDs
- `rag_source_chunk_ids` — list of chunk IDs
- `rag_retrieval_reason_code` — enum string
- `rag_query_phi_sensitivity` — sensitivity level string
- `rag_max_sensitivity_level` — sensitivity level string
- `response_grounded` — bool
- `response_validation_result` — enum string
- `response_citation_source_ids` — list of source IDs
- `response_evidence_count` — int
- `request_hash` / `response_hash` — SHA-256 hashes only

**Forbidden (never logged):**
- Retrieved chunk text
- Full provider prompt text
- Raw document body or corpus metadata
- Auth headers, cookies, API keys, secrets

---

## Tenant Isolation

- `retrieve_persisted_rag_context` enforces `tenant_id` in SQL.
- Every chunk query joins `rag_chunks → rag_documents → rag_corpora` on `tenant_id`.
- Wrong-tenant reads return an empty `RagContextResult` (no error, no leak).
- Retrieval error fails closed: `RagContextError` is raised, provider is not called.

---

## Current Limitation

**This is lexical retrieval, not semantic search.**

Matching is based on exact token overlap between query and chunk text. Short
queries, synonyms, or paraphrases may not retrieve relevant chunks even when
semantically relevant content exists. This is a known limitation of the current
implementation.

Grounding validation (`response_validation.py`) also operates lexically: provider
output tokens must be a subset of retrieved context tokens. This is a strict,
extractive check that may reject valid paraphrased answers.

---

## What Is NOT Included

- No embeddings.
- No semantic search.
- No vector database (pgvector or otherwise).
- No external search engine.
- No ingestion pipeline changes.
- No UI changes.
- No new providers.
- No provider routing changes.
- No legacy placeholder retrieval (removed in PR 17).

---

## PR Handoff

| PR | Purpose |
|---|---|
| PR 13 | Typed RAG context contract (`api/rag_context.py`) |
| PR 14 | Corpus persistence (`api/rag_corpus_store.py`) |
| PR 15 | Lexical retrieval (`api/rag_retrieval.py`) |
| PR 16 | AI plane wiring (`services/ai_plane_extension/service.py`) |
| PR 17 | Legacy placeholder retrieval removal |
| PR 18 | Grounded answer validation (this document) |
