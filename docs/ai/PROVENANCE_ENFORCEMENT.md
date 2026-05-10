# Provenance Enforcement Layer (PR 25)

## Purpose

PR 25 prevents fake citations and invalid source claims by enforcing that every
source or chunk ID associated with an AI answer maps to context retrieved and
included in the prompt for that request.

This is an AI-plane validation layer only. It does not change retrieval ranking,
provider routing, auth, embeddings, UI, or answer generation.

## Stable Reasons

- `PROVENANCE_VALID`
- `PROVENANCE_SOURCE_NOT_RETRIEVED`
- `PROVENANCE_SOURCE_NOT_IN_PROMPT`
- `PROVENANCE_NO_CONTEXT_AVAILABLE`

## Enforcement Rules

The provenance validator checks:

- `response_validation.citation_source_ids`
- explicit provider response citation markers such as `chunk_id=<id>`,
  `source_id=<id>`, and `[ck-...]`

Rules:

- A cited source/chunk must exist in the retrieved context for the request.
- A cited source/chunk must also be present in the prompt-included context.
- Empty-context answers cannot claim sources.
- Invalid provenance is stripped by replacing the answer with `NO_ANSWER`,
  emptying citation metadata, and setting an explicit provenance reason.

## Prompt Inclusion

`RagContextResult.source_chunk_ids` now reflects chunk IDs actually included in
the prompt context block. `retrieved_source_chunk_ids` preserves the full set of
retrieved chunk IDs for validation/debugging.

This distinction prevents a retrieved-but-truncated chunk from being cited.

## Audit Safety

Audit metadata includes:

- `provenance_validation_result`
- `provenance_valid`

Audit metadata does not include raw chunk text, provider prompts, invalid source
claim text, full provider responses, secrets, or PHI beyond existing policy-safe
metadata.

## Not Included

- No UI changes
- No reranking
- No retrieval ranking changes
- No provider routing changes
- No new providers
- No embeddings
- No auth changes
