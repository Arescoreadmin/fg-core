# RAG Corpus Persistence (PR 14)

## Purpose

This document describes the tenant-scoped corpus persistence layer introduced in
PR 14.  Persistence only — no retrieval, no embeddings, no vector DB, no AI
answer changes.

---

## Tables

### rag_corpora

| Column | Type | Notes |
|---|---|---|
| `corpus_id` | TEXT PRIMARY KEY | `corp-<uuid4.hex>` prefix |
| `tenant_id` | TEXT NOT NULL | Mandatory on every row |
| `name` | TEXT NOT NULL | Non-blank enforced in service layer |
| `description` | TEXT | Optional |
| `metadata` | JSONB (Postgres) / TEXT JSON (SQLite) | Optional; serialised dict |
| `created_at` | TIMESTAMPTZ / TEXT | ISO-8601 UTC |
| `updated_at` | TIMESTAMPTZ / TEXT | ISO-8601 UTC |

Index: `(tenant_id, corpus_id)`

---

### rag_documents

| Column | Type | Notes |
|---|---|---|
| `document_id` | TEXT PRIMARY KEY | `doc-<uuid4.hex>` prefix |
| `corpus_id` | TEXT NOT NULL | FK → `rag_corpora(corpus_id)` |
| `tenant_id` | TEXT NOT NULL | Mandatory on every row |
| `title` | TEXT NOT NULL | Non-blank enforced in service layer |
| `source` | TEXT | Optional URI or human-readable source |
| `metadata` | JSONB / TEXT JSON | Optional; serialised dict |
| `created_at` | TIMESTAMPTZ / TEXT | ISO-8601 UTC |
| `updated_at` | TIMESTAMPTZ / TEXT | ISO-8601 UTC |

Indexes: `(tenant_id, corpus_id)`, `(tenant_id, document_id)`

---

### rag_chunks

| Column | Type | Notes |
|---|---|---|
| `chunk_id` | TEXT PRIMARY KEY | `ck-<uuid4.hex>` prefix |
| `document_id` | TEXT NOT NULL | FK → `rag_documents(document_id)` |
| `corpus_id` | TEXT NOT NULL | Denormalized for fast tenant-corpus scans |
| `tenant_id` | TEXT NOT NULL | Mandatory on every row |
| `text` | TEXT NOT NULL | Non-blank enforced in service layer |
| `ordinal` | INTEGER NOT NULL | Ordering within document; sort ascending |
| `metadata` | JSONB / TEXT JSON | Optional; serialised dict |
| `created_at` | TIMESTAMPTZ / TEXT | ISO-8601 UTC |

Indexes: `(tenant_id, corpus_id)`, `(tenant_id, document_id)`

---

## Service Layer

File: `api/rag_corpus_store.py`

Public functions (all accept `conn: Session` as first argument):

```
create_corpus(conn, tenant_id, name, description=None, metadata=None) -> dict
get_corpus(conn, tenant_id, corpus_id) -> dict | None
list_corpora(conn, tenant_id) -> list[dict]
create_document(conn, tenant_id, corpus_id, title, source=None, metadata=None) -> dict
get_document(conn, tenant_id, document_id) -> dict | None
list_documents(conn, tenant_id, corpus_id) -> list[dict]
store_chunks(conn, tenant_id, document_id, corpus_id, chunks: list[dict]) -> list[dict]
list_chunks(conn, tenant_id, document_id) -> list[dict]
```

---

## Tenant Isolation Rules

1. Every function raises `ValueError` immediately if `tenant_id` is blank or None.
2. Every SQL query includes `WHERE tenant_id = :tenant_id`.
3. `create_document` verifies corpus ownership by `tenant_id` before inserting.
4. `store_chunks` verifies document ownership by `tenant_id` before inserting.
5. `get_corpus` and `get_document` return `None` (not an error) for cross-tenant
   reads — this prevents ID enumeration leakage.
6. No admin bypass; no cross-tenant read path exists.

---

## JSONB Policy

- **PostgreSQL (prod/staging):** `metadata` columns are `JSONB` — use
  migration `0035_rag_corpus_persistence.sql`.
- **SQLite (test/dev):** `metadata` columns are `TEXT`.  The service layer
  (`_encode_metadata` / `_decode_metadata`) serialises/deserialises JSON
  explicitly so callers always receive plain dicts or `None`.

The service layer handles both transparently; callers pass/receive Python dicts.

---

## Migration

File: `migrations/postgres/0035_rag_corpus_persistence.sql`

- Idempotent (`IF NOT EXISTS` throughout).
- Creates all three tables with FK constraints and all required indexes.
- Safe to run on a clean database or one that was already partially migrated.

SQLite test databases are handled by `api/db.py::_auto_migrate_sqlite` which
creates equivalent TEXT-metadata tables at `init_db()` time.

---

## What This PR Does NOT Implement

- No retrieval / search / ranking logic
- No embeddings or vector storage
- No changes to AI inference or answer generation
- No removal of `rag_stub.py`
- No FastAPI public endpoints (service layer only)
- No file upload or async ingestion workers

---

## Handoff to Future PRs

| PR | Purpose |
|---|---|
| PR 15 | Retrieval service — implement `search_chunks` returning `RagContextResponse` |
| PR 16 | AI plane wiring — connect retrieval service to `AIPlaneService.infer` via `RagContextRequest` |
| PR 17 | Stub removal — delete `rag_stub.py`, `seeds/rag_stub_sources_v1.json`, update DB default |

For PR 15: `list_chunks` in this store is the read primitive; retrieval adds
scoring, ranking, and `top_k` filtering on top of it.

For PR 16: `AIPlaneService.__init__` injection point must be wired to pass
real chunks from `list_chunks` per tenant.

For PR 17: existing `retrieval_id = 'stub'` data-migration concern is unchanged
by this PR; see `docs/ai/RAG_STUB_INVENTORY.md`.
