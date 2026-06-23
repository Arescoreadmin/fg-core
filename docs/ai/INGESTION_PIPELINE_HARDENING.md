# Ingestion Pipeline Hardening

PR 29 hardens persisted RAG ingestion with explicit lifecycle metadata,
tenant-scoped deduplication, deterministic source hashing, quarantine handling,
source/chunk proof preservation, and safe re-index behavior.

## Lifecycle

Persisted document versions use these states:

- `received`
- `validating`
- `duplicate`
- `quarantined`
- `chunking`
- `embedding`
- `indexed`
- `failed`
- `superseded`
- `reindexing`

Legacy rows default to `indexed` and `is_current=true` so existing retrieval
continues to work. New hardened ingestion only exposes chunks from current
indexed versions.

## Versioning

`rag_documents` now carries version metadata:

- `version_id`
- `source_hash`
- `normalized_source_hash`
- `version_number`
- `is_current`
- `ingestion_status`
- `quarantine_reason`
- `failure_reason`
- `indexed_at`
- `superseded_at`
- `superseded_by_version_id`

Prior versions remain auditable. Superseded versions are not deleted, but their
chunks are marked inactive and excluded from default retrieval.

## Deduplication

Deduplication is tenant and corpus scoped. A current indexed document with the
same `source_hash` returns `duplicate` and does not create new chunks or
embeddings. Identical content in another tenant is ingested independently and
does not reveal the other tenant's document existence.

## Source Proof

`source_hash` is SHA-256 over canonical source text with line endings normalized
to LF. Chunks carry:

- `document_version_id`
- `source_hash`
- chunk `content_hash`
- deterministic chunk ID for hardened ingestion
- future-ready metadata for evidence graph, fact binding, and RAG evaluation

## Quarantine

Malformed documents are persisted as non-current `quarantined` document rows
with safe operator metadata. Quarantined rows create no active chunks and are
not retrievable.

Supported quarantine reasons:

- `empty_document`
- `unsupported_type`
- `parse_failed`
- `too_large`
- `unsafe_content`
- `encoding_error`
- `chunking_failed`
- `metadata_invalid`
- `unknown`

## Re-Index Safety

Re-index targets a known tenant, corpus, document, and version. Only current
indexed versions are accepted. Source hash mismatch fails closed. Replacement
chunks are deterministically rebuilt and old chunks for the same version are
marked inactive.

Known limitation: the current SQLAlchemy store uses per-helper commits inherited
from the existing persistence layer, so the PR implements a bounded safe
approximation rather than a full transactional shadow-index swap. Failed
chunking marks the document failed and does not expose partial replacement
chunks.

## Retrieval Boundary

Lexical, semantic, hybrid, and hybrid RRF retrieval now apply lifecycle filters
when the columns exist:

- current document version
- `indexed` status
- active chunk

Legacy schemas without the new columns remain readable for compatibility.

## Audit Safety

Ingestion logs include tenant ID, corpus ID, document ID, version ID, lifecycle
status, and reason code. Logs do not include raw document text, vectors, prompts,
provider payloads, secrets, or stack traces.
