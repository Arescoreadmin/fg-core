# RAG AI Plane Wiring (PR 16)

## Scope

The AI plane now calls persisted lexical RAG retrieval before provider dispatch.
This wires PR 13 context models, PR 14 corpus persistence, and PR 15 retrieval
into `AIPlaneService.infer`.

This is still lexical retrieval. It is not semantic search.

## Retrieval Call Point

`api/ai_plane_extension.py` resolves the trusted tenant and DB session before
calling `AIPlaneService.infer`.

`AIPlaneService.infer` calls `services.ai.rag_context.retrieve_persisted_rag_context`
with:

- the trusted tenant_id
- the request query text
- the existing SQLAlchemy session
- the bounded RAG limit

The adapter calls `api.rag_retrieval.retrieve_rag_context`. There is no legacy
placeholder retrieval fallback.

## Prompt Inclusion

When chunks are returned, the provider prompt is built with a delimited context
block before the user query:

```
Retrieved context:
[chunk_id=<chunk id>]
<chunk text>

User query:
<user query>
```

Only chunk text and safe chunk markers are included. Tenant IDs, corpus metadata,
document metadata dumps, secrets, and internal config are not added to the prompt.

## Answer Metadata

`/ai/infer` responses include a metadata block:

- `used_rag`
- `context_count`
- `source_chunk_ids`

`used_rag` is derived from `context_count > 0`. `source_chunk_ids` contains only
chunk IDs actually included in the prompt.

## Audit Boundaries

Audit metadata remains hash-only for request/response text. RAG audit fields are
safe identifiers and counts only:

- `rag_used`
- `rag_chunk_count`
- `rag_source_ids`
- `rag_source_chunk_ids`
- `rag_retrieval_reason_code`
- query/context sensitivity summaries

Audit metadata does not include retrieved chunk text, full provider prompts, raw
document content, auth headers, cookies, or secrets.

## Not Included

- No new providers
- No provider routing changes
- No embeddings
- No vector DB
- No public endpoint changes
- No UI changes
- No legacy placeholder retrieval removal

## PR 17 Handoff

PR 17 removes the legacy placeholder retrieval module and seed file. Persisted
retrieval is the only AI-plane RAG path. PR 18 will validate grounded-answer
behavior on top of this path.
