# Provenance UI API (PR 26)

## Purpose

PR 26 exposes safe provenance and retrieval explainability data for UI
consumption through the AI inference API response.

This is an additive backend/API surface only. It does not change retrieval
ranking, reranking, provider routing, embeddings, answer generation, policy
enforcement, or frontend UI.

## API Surface

`POST /ai/infer` now includes a top-level `provenance` object.

Fields:

- `retrieval_trace_id`
- `used_rag`
- `context_count`
- `source_chunk_ids`
- `source_summaries`
- `confidence`
- `why_this_chunk`
- `retrieval_strategy`
- `provenance_status`

The existing `metadata` payload remains unchanged for backward compatibility.

## Source Summaries

`source_summaries` contains safe chunk/source metadata only:

- `source_id`
- `chunk_id`
- `chunk_index`
- `included_in_prompt`
- `phi_sensitivity_level`
- `phi_types`

It does not include raw chunk text, full document text, raw vectors, provider
prompts, auth material, cookies, secrets, or cross-tenant data.

## Why This Chunk

`why_this_chunk` is keyed by included `chunk_id` and carries the existing
audit-safe retrieval explanation metadata:

- matched term count
- coarse matched term categories
- score components
- rank reason
- corpus/document/chunk IDs

It never exposes raw matched terms, raw chunk text, raw vectors, prompts, or
secrets.

## Tenant Scope

The payload is derived only from the tenant-bound RAG context selected for the
current request. Wrong-tenant requests return no context and empty source
summary/explanation lists rather than exposing foreign tenant candidates.

## Provenance Status

`provenance_status` uses the stable provenance reason codes:

- `PROVENANCE_VALID`
- `PROVENANCE_SOURCE_NOT_RETRIEVED`
- `PROVENANCE_SOURCE_NOT_IN_PROMPT`
- `PROVENANCE_NO_CONTEXT_AVAILABLE`

Invalid provider source claims continue to be rejected or stripped by the
provenance enforcement layer before this payload is returned.

## Contract Notes

`/ai/infer` is currently documented in OpenAPI as a generic object response, so
the additive `provenance` object does not require generated contract artifact
changes. Regression coverage asserts that this contract remains generic and that
the runtime payload includes the safe provenance fields.
