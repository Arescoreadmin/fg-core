# FrostGate Field Assessment — Forensic Test Suite

## Mission

You are tasked with writing a forensic-grade test suite for the FrostGate Field Assessment (FA) platform. The goal is **adversarial completeness**: not happy-path confidence, but the ability to detect silent data corruption, tenant bleed, invariant violations, concurrency hazards, and business logic bypasses that would survive a superficial review.

Every test you write must be written from the perspective of an auditor who does not trust the application. Every assertion must be a specific, falsifiable claim about system state — not a vague check that "the response was 200."

---

## Codebase orientation

### Entry points
- **FastAPI backend**: `api/field_assessment.py` (~7000 lines). All routes, request models, and response models live here.
- **Domain services**: `services/field_assessment/` — `store.py` (DB layer), `readiness.py` (engine), `promotion.py` (governance bootstrap), `promotion_store.py`, `promotion_drift.py`, `normalizer.py`, `questionnaire_store.py`, `questionnaire_framework.py`, `audit.py`, `timeline.py`, `remediation.py`, `redaction.py`, `playbooks.py`.
- **DB models**: `api/db_models_field_assessment.py`, `api/db_models_governance_*.py`.
- **MS Graph bridge**: `services/field_assessment/connectors/msgraph_bridge.py`.

### Test infrastructure (existing patterns — copy these exactly)
```python
# SQLite in-memory engine fixture
@pytest.fixture()
def engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()

# FastAPI TestClient with operator auth
@pytest.fixture()
def client(engine):
    def override_db():
        with Session(engine) as session:
            yield session
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[require_operator_auth] = lambda: None
    yield TestClient(app)
    app.dependency_overrides.clear()
```

Imports used throughout existing tests:
```python
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from api.main import app
from api.db import get_db
from api.auth import require_operator_auth
from api.db_models import Base
import api.db_models_field_assessment  # noqa: F401 — registers ORM models
import api.db_models_governance_*      # noqa: F401 — registers governance ORM models
```

`_TENANT = "test-tenant-fa"` is the standard tenant fixture value. Cross-tenant tests use a second tenant `"tenant-other"`.

### What already has coverage (do not duplicate)
- Basic CRUD for engagements, scan results, documents, observations, findings, evidence links
- Happy-path status transitions (in_progress → cancelled)
- Invalid transition rejection
- Tenant isolation on GET (wrong tenant → 404)
- Auth required (missing operator key → 403)
- Scan deduplication by evidence_hash
- QA approve gate enforcement and 409 on re-approve
- Observation audio evidence validation (invalid URL, non-numeric duration, foreign finding IDs)
- Audit diff contents for structured_evidence and linked_finding_ids
- Promotion service: workflow creation, asset promotion, idempotency, retry, race conditions
- Corpus feed: findings + document_analyses + observations, soft-delete exclusion, pagination, tenant isolation
- Readiness engine: playbook selection, gate evaluation, pagination beyond 100 items
- MS Graph bridge: lock enforcement when engagement is delivered, graph rebuild skip, error logging
- Normalizer: finding extraction, idempotency, severity normalization
- Questionnaire: NIST AI RMF control linking, evidence link creation, tenant isolation
- Reports: manifest hash, version increment, signing/verification, cross-tenant isolation, export formats
- Closed-loop finding resolution: status patch, terminal status enforcement, coverage promotion gate

---

## What is NOT covered — the forensic gap list

Write new tests for every category below. Each category includes the specific invariants to enforce. Name test files `tests/test_fa_forensic_*.py`.

---

### GAP-01 — Tenant Bleed (WRITE MUTATIONS)

The existing tenant isolation tests only cover read operations (GET returns 404 for wrong tenant). Write mutation tests:

1. **`PATCH /field-assessment/engagements/{id}`** — A tenant-B operator POSTing a valid body to a tenant-A engagement ID must receive 404, not silently mutate the record.
2. **`PATCH /field-assessment/findings/{id}/status`** — Tenant-B must not be able to change the status of a tenant-A finding.
3. **`PATCH /field-assessment/findings/{id}/remediation`** — Same: cross-tenant remediation patch must fail.
4. **`DELETE /field-assessment/observations/{id}`** — Tenant-B delete of a tenant-A observation must fail with 404.
5. **`PATCH /field-assessment/observations/{id}`** — Tenant-B update of tenant-A observation must fail.
6. **`POST /field-assessment/engagements/{id}/evidence-links`** — Creating an evidence link that references a finding from tenant-B must be rejected (foreign finding guard).
7. **`POST /field-assessment/engagements/{id}/promote`** — Admin retry promote on wrong tenant must fail.
8. After each failed cross-tenant mutation, assert the target record in the DB is **unchanged** (read it back with the correct tenant and compare every mutable field).

---

### GAP-02 — Engagement Lifecycle Invariants

1. **Delivered engagement is immutable for scan ingest**: `POST .../scan-results` on a delivered engagement must be rejected. Assert status code and that no scan was inserted.
2. **Delivered engagement is immutable for observation capture**: `POST .../observations` must be rejected.
3. **Delivered engagement is immutable for document registration**: `POST .../document-analyses` must be rejected.
4. **Delivered engagement is immutable for evidence link creation**: `POST .../evidence-links` must be rejected.
5. **Cancelled engagement accepts no further mutations**: same set of rejections for status=cancelled.
6. **Transition from delivered back to in_progress is invalid**: must reject with 4xx.
7. **Transition from cancelled is invalid to any status**: cancelled is a terminal state.
8. **Engagement patch (client_name, client_domain, metadata) on delivered engagement**: assert whether allowed or rejected, and that the response matches the DB state.
9. **Concurrent transition race**: two goroutine-equivalent sequential requests both attempt `in_progress → cancelled` on the same engagement. Assert only one succeeds; the second sees 409 or 404 (not a double transition).

---

### GAP-03 — Evidence Integrity Chain

The evidence hash chain is a core integrity guarantee. Test it forensically:

1. **Hash determinism**: ingest the same raw_payload twice under two different scan IDs — both scans must produce the same evidence_hash if the payload content is byte-identical.
2. **Hash sensitivity**: changing a single byte in raw_payload must produce a different evidence_hash (test with at least 3 single-byte mutations).
3. **Deduplication blocks second insert**: two sequential ingests of the same engagement + evidence_hash → second must return 409.
4. **Deduplication is tenant-scoped**: the same evidence_hash ingested under two different tenants must produce two distinct scan records (not deduplicated across tenants).
5. **Deduplication is engagement-scoped**: the same evidence_hash ingested under two different engagements (same tenant) must produce two distinct scan records.
6. **normalized_payload findings hash**: after `normalize_scan_findings`, fetch the scan record and assert `findings_hash` matches the deterministic hash of the normalized findings list (verify the hash is not null and is stable across two identical payloads).
7. **Evidence link cannot reference a scan from a different engagement** (even within the same tenant): assert that `create_evidence_link_route` rejects the request.
8. **Evidence link cannot reference a finding from a different engagement** (same tenant): assert rejection.

---

### GAP-04 — Observation Lifecycle and Soft-Delete

1. **Soft delete marks deleted_at, not hard-deletes**: after `DELETE /field-assessment/observations/{id}`, the row must still exist in the DB with `deleted_at IS NOT NULL`.
2. **Soft-deleted observation excluded from list**: `GET .../observations` must not return the deleted observation.
3. **Soft-deleted observation excluded from engagement_summary count**: `GET .../summary` before and after soft-delete must show decremented `observation_count`.
4. **Soft-deleted observation excluded from readiness engine**: execution state after soft-delete must not cite the deleted observation in any gate's `evidence_present` list.
5. **Soft-deleted observation excluded from corpus feed**: run promotion after soft-deleting an observation; assert no `fa:{eng_id}:observation:{deleted_id}` source_id in the corpus.
6. **Linked finding IDs survive PATCH round-trip**: PATCH an observation with `linked_finding_ids=["id1","id2"]`, then GET the observation and assert both IDs are present in the response.
7. **Linked finding IDs on PATCH require same-engagement findings**: attempt to PATCH with a finding ID from a different engagement (same tenant) — must be rejected.
8. **Structured evidence round-trip**: PATCH with `structured_evidence={"_audio_url":"https://example.com/audio.webm","_audio_hash":"abc","_audio_duration_sec":"45","_audio_size_kb":"1200"}`, then GET and assert all four fields survive.
9. **PATCH audit event diff is correct**: after a PATCH that changes `title`, `description`, and `structured_evidence`, the audit event for this mutation must contain `old_value` and `new_value` entries for all three changed fields.

---

### GAP-05 — Finding Lifecycle

1. **Finding status progression — full positive path**: open → acknowledged → remediated → closed. Assert each DB state transition is persisted and returned in GET.
2. **Finding status — accepted_risk terminal**: once `accepted_risk`, any further status patch must be rejected (terminal state).
3. **Finding status — closed terminal**: once `closed`, any further status patch must be rejected.
4. **Finding severity filter**: create findings with severities critical, high, medium, low, info. `GET .../findings?severity=high` must return only high findings for this engagement.
5. **Finding status filter**: `GET .../findings?status=open` must return only open findings.
6. **Combined severity + status filter**: `GET .../findings?severity=critical&status=open` must return the intersection.
7. **Finding remediation patch persists notes**: PATCH remediation with `remediation_notes="patched note"` then GET finding and assert the note is in the response.
8. **Finding remediation patch — foreign evidence_doc_id rejected**: supply a `evidence_doc_id` that belongs to a different engagement (same tenant) and assert 422 or 404.
9. **Finding explanation route returns structured response**: `GET .../findings/{id}/explanation` must return a response with at least `title`, `severity`, and `explanation` keys (mock the LLM call if needed).
10. **Closed-loop gate**: after all findings for an engagement are `remediated` or `closed`, the closed-loop readiness gate must report `passed`. If any finding is still `open`, it must report `blocked`.

---

### GAP-06 — Questionnaire Integrity

1. **Idempotent init**: `POST .../questionnaires` called twice on the same engagement + framework returns the same questionnaire_id both times (not a duplicate).
2. **Response patch persists**: PATCH a questionnaire response with `answer="yes"` and `notes="confirmed"`, then GET the questionnaire and assert both values are present on the correct control.
3. **Evidence link created on patch**: PATCH a response that links a finding (provide valid `linked_finding_ids`) and assert a `FaEvidenceLink` row was created in the DB.
4. **Foreign evidence_doc_id rejected**: PATCH a questionnaire response with a `evidence_doc_id` from a different engagement (same tenant) and assert rejection.
5. **Submit marks questionnaire submitted_at**: `POST .../questionnaires/{id}/submit` must set `submitted_at` on the DB record and return it in the response.
6. **Submit is idempotent**: calling submit twice must not create a second audit event; the second call must succeed (or fail gracefully) without changing `submitted_at`.
7. **Coverage endpoint returns per-category percentages**: `GET .../questionnaires/{id}/coverage` must return a JSON object with at least `total_controls`, `answered_controls`, and `completion_pct` keys. Assert the math is correct for a known subset of answered controls.
8. **Questionnaire list excludes other-tenant questionnaires**: create questionnaires for two tenants; `GET .../questionnaires` for tenant-A must not contain tenant-B's questionnaire_id.

---

### GAP-07 — Readiness Engine Determinism and Correctness

1. **Determinism across identical inputs**: call `_evaluate_execution_state` twice with the same DB state and assert the two outputs are byte-identical (JSON-serialized, key-sorted).
2. **Readiness score bounds**: for any input combination (fuzz with random combinations of 0–10 scans, 0–5 documents, 0–20 observations), the returned `readiness_score` must be in [0, 100] inclusive.
3. **Score increases monotonically as evidence is added**: start with a bare engagement (score=S0); add a required scan (score=S1); assert S1 >= S0. Add a document (score=S2); assert S2 >= S1.
4. **Blocked gate presence**: if a required scan source is missing, the corresponding gate must be present in `gates` with `status="blocked"` and a non-empty `missing_items` list.
5. **Passed gate evidence_present populated**: after adding the required scan, the gate must switch to `status="passed"` and `evidence_present` must be non-empty.
6. **Gate schema completeness**: every gate in the response must have non-null `gate_id`, `status`, `title`, `explanation`, `evidence_required`, `evidence_present`, `missing_items`, `blocks_status_transition`.
7. **Next actions are specific**: each next action must have a non-empty `instruction` and a `closes_gate_ids` list that is non-empty and references a real gate_id in the response.
8. **Escalation items reference real entities**: every escalation item's `related_entities` list must contain IDs that exist in the DB for the engagement.
9. **Stale document gate**: register a document with `freshness_date` 13 months ago; assert the corresponding document gate reports `status="warning"` or `"blocked"`.
10. **Multiple scan sources**: add scans from `microsoft_graph`, `network_scan`, `dns_email`, and `web_headers`. Assert each has its own gate with `status="passed"` and distinct `evidence_present` entries.

---

### GAP-08 — Drift and Promotion Integrity

1. **Drift detection: degraded path**: create two sequential engagements with baseline_readiness_score=80 then 65. Promote both. Assert the second promotion's drift record has `direction="degraded"` and `delta=-15`.
2. **Drift detection: improved path**: scores 65 then 80. Assert `direction="improved"`, `delta=+15`.
3. **Drift detection: stable path**: scores 80 then 80. Assert no `readiness_drift_detected` timeline event is emitted.
4. **Drift detection: first engagement (no prior)**: promote a single engagement. Assert `detect_readiness_drift` returns None (no prior to compare to).
5. **Promotion is idempotent**: call `promote_engagement_to_governance` three times on the same completed engagement. Assert all three calls return the same promotion record and that `GovernanceWorkflow` count does not increase after the first call.
6. **Failed promotion retry resets status**: manually force a promotion to `status="failed"`, then call `promote_engagement_to_governance` again. Assert the promotion transitions to `status="completed"` and workflows are created.
7. **Admin retry route (POST /promote) is 409 for non-delivered engagement**: inline test using TestClient; do not call service directly.
8. **Promotion gate_snapshot stored verbatim**: create a promotion with a specific `gate_snapshot` dict; GET the promotion and assert the stored snapshot matches.
9. **Cross-engagement workflow ID uniqueness**: promote two separate engagements; assert no GovernanceWorkflow `id` appears in both.
10. **Corpus entries_added is bounded by actual document count**: create an engagement with 3 findings, 2 documents, 1 observation. Promote. Assert `corpus_entries_added <= 6`.

---

### GAP-09 — Audit Log Immutability

Audit events have a Postgres BEFORE UPDATE/DELETE trigger (migration 0076) that enforces append-only semantics. In the SQLite test environment (where triggers are not available), enforce the invariant at the application layer:

1. **Audit events accumulate — never overwrite**: perform 5 distinct mutations on an engagement (create, patch, add observation, transition, delete observation). Assert `GET .../audit-events` returns exactly 5 events in reverse chronological order.
2. **Audit event actor is correct**: each event's `actor` field must match the actor from the request (use `X-Actor` header or operator identity).
3. **Audit event reason_code is specific**: each event must have a `reason_code` that is non-empty and distinct per operation type (not a generic code re-used for all mutations).
4. **Audit event payload contains changed fields**: a `PATCH /observations/{id}` that changes `title` must produce an audit event whose `payload` contains `old_title` (or equivalent diff key).
5. **Audit events are tenant-scoped**: events from engagement-A (tenant-A) must not appear under engagement-B (tenant-B).
6. **Audit event count is monotonically non-decreasing**: after any write operation, `GET .../audit-events` must return at least as many events as before.
7. **No audit event is ever returned with null event_type, null actor, or null created_at**.

---

### GAP-10 — QA Gate and Report Delivery Lock

1. **QA approve fails if no report exists**: `POST .../qa-approve` on an engagement with no registered report must return a 4xx with a message that explains the blocker.
2. **QA approve fails if report exists but not finalized**: create a report in draft state; assert qa-approve is blocked.
3. **QA approve advances status to delivered**: on a fully gated engagement (valid report, finalized, all required scans present), `qa-approve` must set engagement status to `delivered`.
4. **Delivered status triggers auto-promotion**: after QA approval advances to `delivered`, `GET /field-assessment/engagements/{id}/promote` must return a promotion record with `status="completed"` (may require mocking `ingest_corpus`).
5. **Re-approve returns 409**: calling qa-approve a second time on an already-approved engagement must return 409 with a human-readable error.
6. **Reviewer display name in response**: the qa-approve response must contain `qa_approved_by` equal to the reviewer's display name (not the JWT sub or email).
7. **Gate evaluation is exhaustive**: call `qa-approve` on an engagement missing only one required piece (e.g., missing one required scan). The response must list exactly that one missing item in the `blockers` array. Add the scan; call `qa-approve` again; assert it now succeeds.

---

### GAP-11 — Remediation Roadmap

1. **Roadmap phases are non-empty for an engagement with findings**: create an engagement with findings of severities critical, high, and medium. `GET .../remediation-roadmap` must return at least one phase.
2. **Phase ordering is deterministic**: same inputs → same phase order across multiple calls.
3. **Each phase contains at least one finding**: no phase in the response may have an empty `findings` list.
4. **Finding in roadmap matches DB**: every `finding_id` in the roadmap must exist in `fa_normalized_findings` for the correct engagement + tenant.
5. **Roadmap excludes remediated/closed findings**: mark a finding as `remediated`; re-fetch the roadmap and assert the finding is no longer in any phase.
6. **Roadmap is tenant-isolated**: findings from tenant-B must not appear in tenant-A's roadmap.

---

### GAP-12 — Connector Run Asset Promotion Lock (MS Graph Bridge)

This tests the lock logic in `services/field_assessment/connectors/msgraph_bridge.py` at the integration level (via `POST /field-assessment/engagements/{id}/connectors/microsoft-graph`):

1. **Asset candidates are NOT auto-promoted when engagement is delivered**: POST a connector import run to a delivered engagement; assert that no new `GaAsset` rows were created in the DB.
2. **Asset candidates ARE auto-promoted when engagement is in_progress**: same import run to an in_progress engagement; assert `GaAsset` rows were created.
3. **Graph rebuild is NOT triggered when engagement is delivered**: mock `build_graph_for_engagement`; POST to delivered engagement; assert mock was NOT called.
4. **Graph rebuild IS triggered when engagement is in_progress**: assert mock WAS called once.
5. **Connector error is logged but response still succeeds**: if the connector scan itself fails internally, the route must return 200 (or appropriate non-5xx status) with an error description in the response body — not a 500.

---

### GAP-13 — Pagination Correctness and Stability

All paginated list endpoints must be tested for:

1. **`GET .../findings` pagination**: create 110 findings; retrieve with `limit=50&offset=0`, `limit=50&offset=50`, `limit=50&offset=100`. Assert the union is exactly 110 distinct findings with no duplicates.
2. **`GET .../observations` pagination**: create 105 observations; paginate with limit=50; assert all 105 unique IDs are collected.
3. **`GET .../scan-results` pagination**: same pattern with 55 scan results.
4. **`GET .../audit-events` pagination**: create 60 mutations; paginate; assert all 60 events collected.
5. **Page stability**: create 20 findings, retrieve page 1 (limit=10), add 5 more findings, retrieve page 2 (limit=10, offset=10). Assert page 2 returns the same items as if no insertion happened (ordering is by a stable column like `created_at` + `id`).
6. **Empty page at boundary**: `GET .../findings?offset=1000` on an engagement with 10 findings must return an empty list, not an error.
7. **`limit=0` or negative limit**: must return a validation error (422), not 200 with an empty list.

---

### GAP-14 — Report Signing and Verification Chain

1. **Tampered `manifest_hash` is detected**: generate a valid report, then directly mutate `manifest_hash` in the DB and call `POST .../verify`. Assert the response has `verified=false`.
2. **Tampered `signature` is detected**: same approach — mutate `signature` field; assert `verified=false`.
3. **Tampered section content is detected**: mutate a nested field inside the report's `sections` JSON in the DB; assert `verified=false`.
4. **Version increment is atomic**: two concurrent `POST .../reports` calls on the same engagement must produce version numbers 1 and 2, not both 1 (use sequential calls to simulate).
5. **Report is tenant-isolated at verify**: attempt to verify a report using the wrong tenant's client; assert 404.
6. **Export JSON contains all expected top-level keys**: `GET .../reports/{id}/export?format=json` must contain `engagement_id`, `report_type`, `findings_register`, `sections`, `generated_at`, `manifest_hash`, `signature`.
7. **Prior report version survives regeneration**: create a report, regenerate it (version 2), then `GET .../reports/{id}/version/1` and assert it is still retrievable and verifiable.

---

### GAP-15 — Playbook and Execution State Completeness

1. **Playbook exists for all registered assessment types**: for each value in `AssessmentType` enum (ai_governance, cmmc, hipaa, soc2, iso27001, pci_dss, dora, fedramp, nist_800_171, comprehensive), call `_evaluate_execution_state` with an empty engagement and assert no `KeyError` or `None` playbook is returned.
2. **All playbook gates have distinct gate_ids**: within a single playbook, no two gates may share the same `gate_id`.
3. **Execution state output schema stability**: call the execution state route for a known engagement and assert the response JSON contains all required top-level keys: `gates`, `next_actions`, `escalations`, `transition_blockers`, `asset_candidates`, `continuity_opportunities`, `readiness_score`, `schema_version`.
4. **Schema version is pinned**: `readiness_state["schema_version"]` must equal `"1.0"` (or whatever the current pinned value is in `readiness.py`).
5. **Continuity opportunities are scoped to the engagement**: any `prior_engagement_id` cited in a continuity opportunity must belong to the same tenant.

---

## Execution and file structure

Write each GAP group as a separate file:
- `tests/test_fa_forensic_tenant_bleed.py` — GAP-01
- `tests/test_fa_forensic_lifecycle.py` — GAP-02
- `tests/test_fa_forensic_evidence_chain.py` — GAP-03
- `tests/test_fa_forensic_observation.py` — GAP-04
- `tests/test_fa_forensic_finding.py` — GAP-05
- `tests/test_fa_forensic_questionnaire.py` — GAP-06
- `tests/test_fa_forensic_readiness.py` — GAP-07
- `tests/test_fa_forensic_drift_promotion.py` — GAP-08
- `tests/test_fa_forensic_audit_log.py` — GAP-09
- `tests/test_fa_forensic_qa_gate.py` — GAP-10
- `tests/test_fa_forensic_remediation.py` — GAP-11
- `tests/test_fa_forensic_connector_lock.py` — GAP-12
- `tests/test_fa_forensic_pagination.py` — GAP-13
- `tests/test_fa_forensic_report_chain.py` — GAP-14
- `tests/test_fa_forensic_playbook.py` — GAP-15

---

## Mandatory quality rules

**Every test must:**
1. Use SQLite in-memory database (never touch production or a real PostgreSQL instance).
2. Be fully isolated — no shared state across tests. Each test creates its own fixtures.
3. Assert DB state directly in addition to HTTP response status. A 200 that silently drops data is a bug.
4. Use `pytest.raises` or explicit status-code assertions — never a bare `assert response.json()` without specifying what you expect.
5. Include a one-line docstring explaining the invariant being tested.
6. Not mock the DB layer or the store functions — only mock external I/O (LLM calls, `ingest_corpus`, `build_graph_for_engagement`).

**Tests must NOT:**
- Duplicate what is already tested (see "What already has coverage" section above).
- Test only the happy path. Every test must either test a failure mode OR assert a negative (something that must NOT be in the response/DB).
- Use `time.sleep()`.
- Use `unittest.mock.patch` to bypass tenant checks.

---

## Deliverables

For each GAP group, deliver a complete, runnable Python test file. Every test must pass against the current `main` branch. Run:

```bash
python -m pytest tests/test_fa_forensic_*.py -x -q
```

and confirm all tests pass before considering the work complete.

After all tests pass, append a row to `ROADMAP.md` under the appropriate phase and update `AUDIT_TRACKER.md` noting that forensic test coverage was added.
