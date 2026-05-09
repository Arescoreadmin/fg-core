# Retrieval Observability + Explainability (PR 24)

## Purpose

PR 24 adds audit-safe retrieval diagnostics to the internal RAG retrieval
contracts. The goal is to explain why a chunk was selected without exposing raw
chunk text, raw vectors, full prompts, secrets, or provider internals.

## Trace Model

Every persisted retrieval response includes `retrieval_trace`:

- `retrieval_trace_id`
- `retrieval_strategy`
- `candidate_count`
- `returned_count`
- `duration_ms`
- `confidence`
- `confidence_reason`

Each returned chunk also includes:

- `retrieval_trace_id`
- `candidate_count`
- `returned_count`
- `lexical_rank`
- `semantic_rank`
- `rrf_rank` when available
- `why_this_chunk`
- `confidence`
- `confidence_reason`

## Why This Chunk

`why_this_chunk` is deliberately safe. It may include:

- matched query terms
- score components
- rank reason
- corpus ID
- document ID
- chunk ID

It must not include:

- raw chunk text
- raw vectors
- full prompts
- secrets
- auth tokens
- provider responses

## Confidence

Confidence is bounded to `[0.0, 1.0]`, finite, and deterministic.

It is based on:

- top result score strength
- score gap between the top two results when at least two results exist

No model call, reranking, random value, or prompt content contributes to
confidence.

## Audit Safety

Retrieval audit logs include only safe diagnostics:

- trace ID
- strategy
- candidate and returned counts
- timing
- confidence and confidence reason
- semantic availability flag

Audit logs do not include raw chunk text, raw vectors, full prompts, secrets, or
PHI beyond the existing policy-approved metadata.

AI-plane audit metadata also carries safe persisted-RAG trace fields:

- `rag_retrieval_trace_id`
- `rag_retrieval_strategy`
- `rag_candidate_count`
- `rag_returned_count`
- `rag_confidence`
- `rag_confidence_reason`

## Ranking Boundary

PR 24 does not change ranking. Existing score calculations and sort keys remain
unchanged. Explainability metadata is attached after ranking.
