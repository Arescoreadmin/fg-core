# Reranking Layer

PR 28 adds an additive, production-safe reranking layer over already-retrieved
RAG candidates. It improves final context ordering without changing retrieval
policy enforcement, tenant scope, corpus filters, provider routing, auth,
billing, UI, or answer generation.

## Boundary

Reranking runs only after the policy-approved retriever returns a
`RagContextResponse`.

It does not:

- fetch additional chunks
- broaden corpus scope
- cross tenant boundaries
- call external reranking APIs
- create or route AI providers
- log raw chunk text, prompts, vectors, secrets, or provider responses

## Reranker Abstraction

`api.rag_reranking.Reranker` is a small protocol:

- input: query text, one retrieved chunk, and that chunk's original rank
- output: bounded `rerank_score` plus a safe `rerank_reason`

The default implementation is `DeterministicLocalReranker`. It is CI-safe and
uses deterministic lexical query-term coverage and density over the retrieved
chunk text. It performs no network I/O and uses no model/provider calls.

## Controls

`RerankConfig` provides bounded controls:

- `enabled`: disables reranking while preserving retrieval behavior
- `max_rerank_candidates`: reranks only the first N returned candidates
- `timeout_ms`: fail-open latency guard for the reranking step

If reranking is disabled, unavailable, or over the latency bound, the original
retrieval order is preserved and chunks receive fallback-safe rerank metadata.

## Metadata

Reranking is additive on `RagContextChunk`:

- `rerank_score`
- `final_score`
- `rerank_reason`

Original retrieval scores remain unchanged:

- `score`
- `lexical_score`
- `semantic_score`
- `rrf_score`
- `combined_score`

`why_this_chunk.score_components` is extended with rerank score and final score
for already-safe explainability metadata.

## Ordering

Reranked candidates use the required deterministic ordering:

1. `final_score DESC`
2. `rerank_score DESC`
3. `combined_score DESC`
4. `corpus_id ASC`
5. `document_id ASC`
6. `ordinal ASC`
7. `chunk_id ASC`

Candidates outside `max_rerank_candidates` remain after the reranked window in
their original order.

## Tenant and Policy Safety

The reranker consumes only chunks returned by the existing retrieval path.
Therefore tenant isolation, corpus allow/deny controls, max-top-k clamping, and
strategy policy decisions remain enforced before reranking starts.

The persisted AI-plane adapter applies reranking after
`evaluate_retrieval_policy()` and after the effective retriever executes.

## Audit Safety

Reranking logs only:

- trace ID when available
- rerank candidate count
- returned count
- timeout bound

It does not log raw chunk text, query text, prompts, vectors, secrets, provider
data, or matched terms.
