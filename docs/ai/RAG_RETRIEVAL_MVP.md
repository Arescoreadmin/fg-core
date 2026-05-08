# RAG Retrieval MVP (PR 15)

## Scope

`api/rag_retrieval.py` adds an internal tenant-scoped retrieval service over the
persisted PR 14 corpus tables. It returns PR 13 `RagContextResponse` objects.

This is lexical retrieval only. It is not semantic search.

## Scoring

The service lowercases query and chunk text, tokenizes stable alphanumeric terms,
and excludes chunks with zero matching query terms.

Score:

```
unique_matched_query_terms + matching_term_occurrences / (chunk_term_count + 1)
```

Scores are finite floats.

## Ranking

Results are ordered deterministically:

1. score descending
2. corpus_id ascending
3. document_id ascending
4. ordinal ascending
5. chunk_id ascending

`RagContextRequest.top_k` bounds the returned chunk count.

## Tenant Isolation

- `tenant_id` is mandatory.
- Every SQL query filters `rag_chunks` by tenant_id.
- Document and corpus joins include tenant_id.
- `corpus_ids` filtering is applied only inside the tenant-scoped query.
- Wrong-tenant reads return an empty context and do not reveal foreign rows.
- There is no global fallback or admin bypass.

## Provenance

Returned chunks include:

- corpus_id
- document_id
- chunk_id
- score
- document title
- document source
- uri/page from chunk metadata when present, with document metadata as fallback

Chunk text comes from persisted `rag_chunks.text`.

## Not Included

- No embeddings
- No vector DB
- No pgvector
- No external search engine
- No provider routing changes
- No AI-plane wiring changes
- No public endpoint
- No runtime fallback to the legacy RAG stub

## PR 16 Handoff

PR 16 can wire the AI plane to this internal service by constructing
`RagContextRequest` from trusted tenant context and passing an existing SQLAlchemy
session. Provider prompting and answer behavior remain out of scope for PR 15.
