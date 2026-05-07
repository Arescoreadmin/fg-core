# RAG Stub Removal Inventory

## Purpose

This document catalogs every reference to `rag_stub.py` and every fake/stubbed
RAG execution path discovered in the repository as of 2026-05-07 (branch
`pr/12-rag-stub-inventory`). It provides the coupling map and risk areas required
before any stub removal PR is opened. No runtime behavior is changed by this PR.

---

## Current Architecture

`services/ai_plane_extension/rag_stub.py` is a legacy stub module that was the
original retrieval implementation before real tenant-scoped RAG was wired into
the AI plane (PR `codex/wire-real-rag-retrieval`, 2026-05-01).

**What `rag_stub.py` does today:**

1. Defines a single function `retrieve(tenant_id: str, query: str) -> dict`.
2. Validates that `tenant_id` is non-empty; raises `ValueError("AI_TENANT_REQUIRED")`
   if blank.
3. Reads `seeds/rag_stub_sources_v1.json` from disk (relative CWD path — not
   absolute). If the file is absent, `sources` defaults to `[]`.
4. Calls `services.phi_classifier.classifier.classify_phi(query)` to obtain a
   sensitivity level.
5. Returns a hard-coded dict:
   ```python
   {
       "ok": True,
       "sources": <seed file contents or []>,
       "retrieval_id": "stub",       # literal constant "stub"
       "query_phi_sensitivity": <sensitivity level>,
   }
   ```

**Key stub behavior:**
- `retrieval_id` is always the string `"stub"` — never a real content-derived hash.
- `sources` are read from a static seed file with an empty list; no real retrieval.
- No tenant scoping of sources (the seed file is not tenant-namespaced).
- No scoring, ranking, or relevance filtering.
- PHI classification is real (calls the actual classifier), but it has no effect on
  the returned `sources`.

**Current runtime status:** `rag_stub.py` is **NOT called** by the AI plane
execution path. `services/ai_plane_extension/service.py` calls
`retrieve_rag_context()` from `services/ai/rag_context.py` which calls
`search_chunks()` from `api/rag/retrieval.py`. The stub module exists on disk
but is unreachable from any production code path.

---

## File Inventory

### The stub module itself

| File | Role |
|---|---|
| `services/ai_plane_extension/rag_stub.py` | Stub implementation — defines `retrieve()` returning hardcoded `retrieval_id: "stub"` |
| `seeds/rag_stub_sources_v1.json` | Static seed file read by `rag_stub.py`; contains `{"sources": []}` (empty list) |

### Files containing `rag_stub` references

| File | Line | Reference type |
|---|---|---|
| `services/ai_plane_extension/rag_stub.py` | 6 | `SEED_PATH = Path("seeds/rag_stub_sources_v1.json")` — only self-reference |
| `tests/security/test_ai_rag_context.py` | 188–192 | Regression test asserting `rag_stub` is NOT in `AIPlaneService.infer` source |
| `docs/ai/PR_FIX_LOG.md` | 383, 416 | Historical references describing the stub's prior role |

### SQL migration references (historical — do not rewrite)

| File | Line | Reference type |
|---|---|---|
| `migrations/postgres/0017_ai_plane_policy_hardening.sql` | 10 | `retrieval_id = COALESCE(retrieval_id, 'stub')` — historical migration; preserves stub sentinel for legacy rows inserted before real RAG was wired |

**Note:** This is intentional migration history. The migration must not be rewritten. Any future
RAG removal PR must address the data-migration concern (existing rows with `retrieval_id = 'stub'`)
separately from runtime code removal. See Recommended Removal Order below.

### Files containing `retrieval_id = "stub"` (database schema residue)

| File | Line | Reference type |
|---|---|---|
| `api/db.py` | 554 | `ai_inference_records` schema: `retrieval_id TEXT NOT NULL DEFAULT 'stub'` |
| `api/db.py` | 672 | `_sqlite_add_column_if_missing` migration: `TEXT DEFAULT 'stub'` |
| `tests/test_ai_plane_extension.py` | 445 | Test assertion: `assert row["retrieval_id"] != "stub"` — verifies stub value is no longer written |

---

## Import Graph

```
rag_stub.py
└── seeds/rag_stub_sources_v1.json          (file read, relative CWD)
└── services.phi_classifier.classifier      (real PHI classifier, lazy import)

Nothing imports rag_stub.py.
```

No module in `services/`, `api/`, `tests/`, or `tools/` imports `rag_stub` at
module load or call time. The only reference is a string negation check in a
test (`assert "rag_stub" not in source`).

---

## Runtime Execution Paths

### Current real RAG execution path (active)

```
POST /ai/infer  →  api/ai_plane_extension.py
    →  services/ai_plane_extension/service.py :: AIPlaneService.infer()
        →  services/ai/rag_context.py :: retrieve_rag_context()
            →  api/rag/retrieval.py :: search_chunks()   [tenant-filtered, scored]
        →  services/ai/rag_context.py :: build_rag_augmented_prompt()
        →  services/ai_plane_extension/service.py :: _rag_retrieval_id()
            →  returns "rag:none" when corpus empty
            →  returns "rag:<sha256[:24]>" when chunks retrieved
```

`retrieval_id` written to `ai_inference_records` is now always a deterministic
`"rag:..."` prefix — not `"stub"`.

### Legacy stub execution path (dead — not reachable from any caller)

```
[NO CALLERS]  →  services/ai_plane_extension/rag_stub.py :: retrieve()
    →  seeds/rag_stub_sources_v1.json  (read_text, relative path)
    →  services/phi_classifier/classifier :: classify_phi()
    →  returns {"ok": True, "sources": [], "retrieval_id": "stub", ...}
```

---

## Stub Metadata Surfaces

The following fake/stub metadata values appear in the system as residue from the
stub era. None are produced by the current active code path.

| Surface | Fake value | Location |
|---|---|---|
| `ai_inference_records.retrieval_id` schema default | `"stub"` | `api/db.py:554` |
| `ai_inference_records.retrieval_id` migration default | `"stub"` | `api/db.py:672` |
| `rag_stub.retrieve()` return dict | `"retrieval_id": "stub"` | `services/ai_plane_extension/rag_stub.py:24` |
| `rag_stub.retrieve()` return dict | `"sources": []` | static empty list from seed file |
| SQL migration fill value | `COALESCE(retrieval_id, 'stub')` | `migrations/postgres/0017_ai_plane_policy_hardening.sql:10` — historical; immutable migration |

**Real metadata produced by current code path:**

| Surface | Real value | Location |
|---|---|---|
| `ai_inference_records.retrieval_id` | `"rag:none"` or `"rag:<sha256[:24]>"` | `services/ai_plane_extension/service.py:617` |
| Audit field `rag_used` | bool | `services/ai/audit.py` |
| Audit field `rag_chunk_count` | int | `services/ai/audit.py` |
| Audit field `rag_source_ids` | list[str] | `services/ai/audit.py` |
| Audit field `rag_retrieval_reason_code` | `RAG_RETRIEVAL_SELECTED` / `RAG_RETRIEVAL_EMPTY` | `services/ai/rag_context.py` |

---

## Known Fake Grounding Behavior

1. **Static empty sources list.** `seeds/rag_stub_sources_v1.json` contains
   `{"sources": []}`. Any caller that had used `rag_stub.retrieve()` would have
   received zero source documents regardless of the query or tenant.

2. **Hardcoded `retrieval_id: "stub"`.** The stub always returned the literal
   string `"stub"` — not a content-derived hash. This value cannot be used to
   reconstruct or audit which documents grounded a response.

3. **No tenant filtering.** The seed file is not partitioned by tenant. Had the
   stub been active with a non-empty seed file, all tenants would have seen the
   same sources.

4. **No relevance scoring.** Sources from the seed file would have been returned
   in file order without ranking, coverage, or term frequency scoring.

5. **DB column default `"stub"`.** The `retrieval_id` column in
   `ai_inference_records` still defaults to `"stub"` in the schema DDL and
   migration. Any row inserted without an explicit `retrieval_id` would record
   the stub sentinel value, making it impossible to distinguish legacy rows from
   genuinely unstubbed rows without inspecting the prefix.

---

## Risk Areas for Replacement

### 1. `services/ai_plane_extension/rag_stub.py` — module deletion

- **Coupling:** Zero production callers. The only reference is a string-negation
  assertion in `tests/security/test_ai_rag_context.py:190`.
- **Risk on deletion:** The test at line 190 would need to be updated or removed
  when the module is deleted, because `inspect.getsource` would no longer be
  able to fail on the module's content.
- **Safe to delete when:** No callers exist and the test guard is rephrased.

### 2. `seeds/rag_stub_sources_v1.json` — seed file deletion

- **Coupling:** Only `rag_stub.py` reads this file via `SEED_PATH`. No other
  module references it.
- **Risk on deletion:** If `rag_stub.py` is retained and called, it gracefully
  falls back to `sources: []` when the file is absent (line 13–15). Deleting
  the seed file before the module is deleted is safe.

### 3. `api/db.py` — `retrieval_id` column default `"stub"`

- **Coupling:** Schema DDL at line 554 and migration at line 672.
- **Risk:** The default `"stub"` is a sentinel that cannot be distinguished from
  an intentional value. Changing the default to `""` or `"rag:none"` is a schema
  migration and must be handled carefully to avoid breaking existing rows.
- **Note:** This is a schema file change. Call it out explicitly in any removal PR.

### 4. `tests/security/test_ai_rag_context.py` — regression guard

- **Coupling:** `test_ai_plane_execution_path_does_not_call_rag_stub` at line 188
  uses `inspect.getsource(AIPlaneService.infer)` and asserts `"rag_stub"` is not
  present. This test is a guard against re-introduction of the stub.
- **Risk on stub deletion:** The test continues to pass after deletion (the source
  string will never contain `"rag_stub"` once the module is gone). The test
  assertion is forward-safe and should be retained.

### 5. In-memory corpus — corpus injection at startup

- **Coupling:** `AIPlaneService.__init__` accepts `rag_chunks: Sequence[CorpusChunk] | None`.
  The live `service` singleton in `api/ai_plane_extension.py` is instantiated as
  `AIPlaneService()` with no chunks — defaulting to an empty tuple.
- **Risk:** When a persistent corpus source is introduced, the injection point at
  `AIPlaneService.__init__` must be wired to pass real chunks. Until that is done,
  retrieval always returns `RAG_RETRIEVAL_EMPTY`.

---

## Security Concerns

1. **Fake provenance leakage.** If `rag_stub.retrieve()` were ever re-introduced
   into the execution path, responses would carry the hardcoded `retrieval_id: "stub"`
   value and zero source citations. Any downstream audit or compliance check
   relying on `retrieval_id` to verify grounding would silently pass on fabricated
   evidence.

2. **No tenant boundary in stub.** The stub imposes only a non-blank `tenant_id`
   check — it does not filter the seed file by tenant. A real corpus with content
   from multiple tenants would expose cross-tenant data.

3. **PHI classifier call without effect.** The stub calls `classify_phi(query)` but
   the result has no bearing on what is returned in `sources`. A PHI-sensitive query
   would not receive stricter handling in the stub path.

4. **`retrieval_id: "stub"` in historical DB rows.** Any `ai_inference_records`
   rows inserted before the real RAG path was wired (pre-2026-05-01) will have
   `retrieval_id = "stub"`. These rows cannot be used to reconstruct grounding
   evidence. Audit tooling that checks `retrieval_id != "stub"` (as in
   `tests/test_ai_plane_extension.py:445`) correctly flags this.

---

## Tenant Isolation Concerns

The following must be verified when replacing the in-memory corpus with a
persistent retrieval backend:

1. `trusted_tenant_id` must originate from the authenticated execution context,
   not from any client-controlled field. `search_chunks` currently enforces this
   by requiring `trusted_tenant_id` as a parameter distinct from query payload.
2. The `_rag_retrieval_id` hash in `service.py` includes only `chunk_id` and
   `source_id` — not `tenant_id`. When a persistent corpus is introduced, the hash
   derivation should be reviewed to ensure cross-tenant chunk collisions are
   impossible.
3. The corpus injection point (`AIPlaneService.__init__`) currently accepts a flat
   `Sequence[CorpusChunk]`. A persistent corpus API must enforce that only the
   calling tenant's chunks are ever passed to `retrieve_rag_context`.

---

## Recommended Removal Order

The following ordering minimizes coupling breakage. This is documentation only —
no implementation is implied.

1. **Delete `seeds/rag_stub_sources_v1.json`** — zero callers after step 2.
2. **Delete `services/ai_plane_extension/rag_stub.py`** — no production callers;
   update or remove the string-negation test guard in `test_ai_rag_context.py`.
3. **Update `api/db.py` schema default** — change `DEFAULT 'stub'` to
   `DEFAULT 'rag:none'` in DDL and migration. Treat as a schema change; call it
   out in the PR. Existing rows with `retrieval_id = "stub"` are historical and
   should be documented, not back-filled.
4. **Address SQL migration history separately** —
   `migrations/postgres/0017_ai_plane_policy_hardening.sql` contains
   `COALESCE(retrieval_id, 'stub')`. This migration must **not** be rewritten (it
   is immutable history). The data-migration concern — rows that still hold the
   `"stub"` sentinel — must be resolved via a new forward migration that updates
   existing `retrieval_id = 'stub'` rows to `'rag:none'` (or equivalent). This is
   a data migration concern, not a code removal concern, and must be handled in a
   dedicated migration PR.
4. **Remove the `retrieval_id != "stub"` test assertion** in
   `tests/test_ai_plane_extension.py:445` (or update it to assert the `"rag:"`
   prefix is present) once the schema default is updated.
