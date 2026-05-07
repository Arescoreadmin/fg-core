# RAG Context Contract

## Purpose

Defines the typed contract that future retrieval and AI-plane wiring will use
to pass context between the retrieval layer and the AI plane.

This document covers `api/rag_context.py` — the canonical source for these
models.  No retrieval is implemented.  No persistence.  No AI answer behavior
is changed.

---

## Models

### RagContextRequest

Fields passed from the AI plane to the retrieval layer.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `query` | `str` | yes | — | min_length=1 |
| `tenant_id` | `str` | yes | — | min_length=1; must originate from auth context |
| `corpus_ids` | `list[str]` | no | `[]` | Filter retrieval to these corpora; empty = all tenant corpora |
| `top_k` | `int` | no | `5` | 1–100; number of chunks to return |

---

### RagContextResponse

Fields returned from the retrieval layer to the AI plane.

| Field | Type | Notes |
|---|---|---|
| `query` | `str` | Echo of the original query |
| `chunks` | `list[RagContextChunk]` | Retrieved chunks in rank order |
| `context_count` | `int` | **Derived** — always equals `len(chunks)`; caller-supplied values are normalised |
| `used_retrieval` | `bool` | **Derived** — always equals `bool(chunks)`; caller-supplied values are normalised |

> **Note:** `context_count` and `used_retrieval` are computed by a `model_validator` after construction.
> Callers should not manually supply these fields; if they do, the model normalises them to match `chunks`.
> This ensures a non-empty chunk list can never produce `context_count == 0` or `used_retrieval == False`.

---

### RagContextChunk

A single retrieved chunk with its relevance score and provenance.

| Field | Type | Notes |
|---|---|---|
| `text` | `str` | Chunk text; min_length=1 |
| `score` | `float` | Relevance score; must be a finite number |
| `provenance` | `RagChunkProvenance` | Source provenance for this chunk |

---

### RagChunkProvenance

Provenance metadata identifying where a chunk originated.

| Field | Type | Required | Notes |
|---|---|---|---|
| `corpus_id` | `str` | yes | min_length=1 |
| `document_id` | `str` | yes | min_length=1 |
| `chunk_id` | `str` | yes | min_length=1 |
| `source` | `str \| None` | no | Human-readable source name |
| `title` | `str \| None` | no | Document title |
| `uri` | `str \| None` | no | Canonical URI for the source document |
| `page` | `int \| None` | no | Page number within source document |

---

## What This PR Does NOT Implement

- No retrieval logic
- No corpus persistence or database access
- No AI answer behavior changes
- No FastAPI router or endpoint
- No stub removal

---

## Future PR Handoff

| PR | Purpose |
|---|---|
| PR 14 | Corpus persistence — store and index corpus documents |
| PR 15 | Retrieval service — implement `search_chunks` returning `RagContextResponse` |
| PR 16 | AI plane wiring — connect retrieval service to `AIPlaneService.infer` via `RagContextRequest` |
| PR 17 | Stub removal — delete `rag_stub.py`, `seeds/rag_stub_sources_v1.json`, update DB default |
