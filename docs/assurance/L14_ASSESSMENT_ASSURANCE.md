# L14-ASSESSMENT-ASSURANCE-001 — Assessment Assurance

**Status:** PARTIAL. The four mandatory defects (CZ-23, CZ-12B, CZ-17, QA rejection) are enforced server-side. The remaining launch blockers are listed in §20.
**Predecessor:** PR #815 (L14-CUSTOMER-ZERO-E2E-001).
**Scope:** canonical provenance, independent QA, rejection and rework, draft access, and the release decision.

This module is NOT standalone. It extends the Field Assessment Engagement Substrate's existing authorities and adds no parallel governance system.

## 1. Executive summary

| Finding | Before (PR #815) | After |
|---|---|---|
| CZ-23 provenance split | The trust gate read only legacy `evidence_provenance`. Under strict mode, scanner-only reports were blocked with 403, and under warn mode the run logged 16 critical warnings. | Every trust consumer reads one canonical evaluator over the runtime envelopes. Strict mode accepts clean scanner evidence and blocks only on real failures. |
| CZ-12B self-approval | One dual-scope API key could generate and then approve its own report (200). | QA decisions need a named human. That human's canonical principal must have made no material contribution to the engagement. |
| CZ-17 draft download | A customer could download an unapproved draft. The watermark was the only control. | Backend policy applies on every report-content route. Customers see FINAL content only, unless the engagement explicitly opts in to draft review. |
| QA rejection | No route existed. | `qa-reject` (report record) and `versions/{id}/reject`. Rejection is terminal, audited and race-safe. Rework produces a corrected report linked to the rejected version. |

## 2. Threat model

| Threat | Control |
|---|---|
| Assessor approves own work | Reviewer identity set (all subjects bound to the principal) is checked against the report authors and the engagement's material-contribution audit trail. |
| Same person, second credential | API keys cannot make QA decisions: a key has no holder binding (`tenant_credentials` records the issuer, not the holder). Every human subject bound to the same `fg_principals` row counts as one person. |
| Authorship laundering via `compiled_by` | `compiled_by` is caller-supplied display text. It can only widen the exclusion. The canonical author is the `engagement_report_created` audit actor. |
| Warn mode used as a bypass | Integrity, scope and legacy-chain failures refuse approval and FINAL/delivery in every `FG_PROVENANCE_MODE`. |
| Tampered or out-of-scope evidence | Batched digest re-verification. A finding that references evidence outside the tenant+engagement is a scope violation. Cross-tenant and absent references look identical, so no existence oracle is exposed. |
| Customer reads an unreleased draft | `draft_access_decision`. Portal-origin requests are always treated as customer access. |
| Reviewer shopping after rejection | A rejected record can get no new version and no approval. Only a corrected report can be reviewed. |
| Concurrent approve and reject | Compare-and-swap on `qa_approved_by`, plus one terminal QA decision per record/version and stage, enforced by DB unique indexes. |

## 3. Canonical authority map

| Authority | Single owner | Consumers | Defect closed | Security tests |
|---|---|---|---|---|
| Engagement provenance | `assessment_assurance.evaluate_engagement_provenance` | `derive_engagement_trust_inputs` → QA approve, export, finalization (`reports_engine`), verification bundle; `_require_production_qualified`; `_authoritative_report_state` | CZ-23 | `test_provenance.py` |
| Reviewer independence | `assessment_assurance.enforce_independent_reviewer` | `/qa-approve`, `/qa-reject`, `versions/{id}/approve`, `versions/{id}/reject` | CZ-12B | `test_independent_qa.py` |
| QA decision log | `fa_report_qa_decisions` (append-only, 0188 + 0205) | approve/reject routes, `governance_qa_status`, FINAL state, release gate | QA reject | `test_qa_rejection.py` |
| Draft access | `assessment_assurance.draft_access_decision` | `GET /reports/{v}`, `GET /reports/{v}/export` (JSON + PDF) | CZ-17 | `test_draft_access.py` |
| DRAFT/REJECTED/FINAL state | `report_proof.evaluate_report_state` via `_authoritative_report_state` | export, document route, PDF marking | — | `test_release_and_performance.py` |
| Client release | `_require_production_qualified` (existing) | version deliver, governed delivery, QA auto-advance | — | `test_release_and_performance.py` |

No competing source remains for these decisions on the field-assessment report path. `report_authority` (`/reports/*`, `audit:read` scope) is a separate audit-report system with no QA lifecycle; see §20.

## 4. Provenance unification

`evaluate_engagement_provenance` makes one bounded, read-only pass. It writes nothing and makes no network calls:

1. It loads the engagement's `fa_scan_evidence_envelopes`, then their `fa_scan_results` in chunked `IN` reads.
2. Each envelope is classified:
   - a sticky persisted INVALID stays INVALID;
   - no scan result → INDETERMINATE;
   - scan result deleted → MISSING;
   - scan result in another engagement → scope violation;
   - otherwise the canonical digest is re-verified (`evidence_integrity_svc.verify_envelope`).
3. Findings are checked against the envelopes and NORMALIZED custody events. A reference outside scope is a violation; a finding with no evidence is disclosed.
4. The legacy `evidence_provenance` chain is replayed and AND-combined only where rows exist. The replay is unchanged and renamed to `legacy_provenance_trust_inputs`.
5. The result is a `ProvenanceDecision`:
   - counts per classification;
   - integrity, unverifiable and scope counts;
   - findings without evidence;
   - legacy state;
   - `source_authenticated`;
   - a deterministic `snapshot_fingerprint`;
   - release blockers;
   - disclosures.

Scanner workers are not asked to fabricate legacy rows. The consumers moved to the canonical authority instead.

**Separate assertions stay separate.**
- `VERIFIED_INTEGRITY_ONLY` is never reported as `VERIFIED_AUTHENTIC`. `source_authenticated` is true only when every item is authentic, and the disclosure is `SOURCE_AUTHENTICITY_NOT_ESTABLISHED`.
- In `to_trust_inputs`, `signature_valid` means that the evidence authority's verification passed. It is documented as such and does not claim source authenticity.

## 5. Strict-mode enforcement

| Condition | Strict result |
|---|---|
| Clean runtime evidence, no legacy rows | **allowed**. This is the CZ-23 fix. |
| Tampered digest (INVALID) | `chain_failure`, 403 on export, 422 on QA. |
| Out-of-scope reference (cross-engagement or cross-tenant) | `chain_failure` + `engagement_mismatch`, blocked. |
| Missing or indeterminate source | `replay_failure`, blocked. |
| No evidence at all | All dimensions False, blocked. Unknown is never trusted. |

## 6. Warn-mode semantics

Warn and off modes are observation modes. They are not release bypasses.

- An internal draft export still works, and the marking stays truthful.
- These conditions refuse QA approval in **every** mode (`ASSURANCE_PROVENANCE_BLOCKED`, 422):
  - `PROVENANCE_INTEGRITY_FAILED`;
  - `PROVENANCE_SCOPE_VIOLATION`;
  - `PROVENANCE_LEGACY_CHAIN_INVALID`;
  - `PROVENANCE_EVALUATION_BOUND_EXCEEDED`.
- All provenance release blockers keep the report out of FINAL and refuse client delivery in every mode (`ASSURANCE_RELEASE_BLOCKED`).
- `PROVENANCE_EVIDENCE_ABSENT` is a disclosure, not a blocker, outside strict mode. Questionnaire-only assessments carry no scanner evidence, and per-finding rules such as `CONFIRMED_WITHOUT_VERIFIED_EVIDENCE` still apply.

**Behaviour change:** warn mode previously allowed QA approval over a broken chain. It no longer does for integrity, scope and legacy-chain failures.

## 7. Identity and reviewer attribution

- `require_human_reviewer` refuses with `HUMAN_REVIEWER_REQUIRED`:
  - service principals;
  - API keys, including role-bound persona keys and the global key.
- It accepts OIDC actors (`oidc_*`, including verified delegation `oidc_delegated`), and `dev_bypass` in non-production only.
- `reviewer_identity_set` expands the reviewer subject to every `identity_subject` bound to the same `fg_principals` row in the tenant. If the lookup fails, it fails closed with 503 `QA_IDENTITY_RESOLUTION_UNAVAILABLE`; independence is never assumed.
- The persisted approval authority is the canonical subject. Reviewer name and role in the request body remain display metadata.

## 8. Separation of duties

For a reviewer to decide, none of their identities may be:
- a report author: the version `generated_by`, the `engagement_report_created` actor, or `compiled_by`;
- a material contributor to the engagement: an actor on any `MATERIAL_CONTRIBUTION_EVENTS` audit event, which covers report or version creation, finding status or remediation edits, observations, scans, evidence links, artifacts and questionnaires.

A violation returns `REPORT_QA_SELF_REVIEW` (409). The check runs inside the transaction that records the decision, on every approve and reject route. The engagement is the policy boundary, so someone who contributed to any part of an assessment cannot review any report for it.

## 9. QA lifecycle

| Pipeline | States |
|---|---|
| Report record (governance stage) | generated (finalized) → **approved** (`/qa-approve`) or **rejected** (`/qa-reject`). Both are terminal. |
| Version (report stage) | `draft` → `internal_review` → **approved** or **rejected**, then `delivered` / `superseded` (existing). |

`rejected` joins `_REPORT_VERSION_STATUSES` and the immutable set, and the `rejected` delivery event type is added. No new state field was introduced.

## 10. Rejection and rework

- **Rejection requirements:**
  - a named, independent human holding `report.qa_approve`;
  - `reason_code` from a fixed vocabulary: `EVIDENCE_INSUFFICIENT`, `EVIDENCE_INTEGRITY`, `FINDING_INACCURATE`, `SEVERITY_INCORRECT`, `COVERAGE_MISSTATED`, `REMEDIATION_INADEQUATE`, `SCOPE_OR_AUTHORIZATION`, `PRESENTATION_ERROR`, `OTHER`;
  - a written explanation of at least 10 characters.
- **Persisted records:**
  - an append-only `fa_report_qa_decisions` row: decision `rejected`, `actor_type` human, reviewer subject, `report_hash` / `manifest_hash`, and the reason;
  - an engagement audit event (`report.qa_rejected` / `report_version_rejected`) carrying the proof fingerprint, independence evidence and correlation ID;
  - a governance decision `report_rejected`.
- **A rejected record cannot be:**
  - approved, by a stale or second reviewer (`REPORT_QA_REJECTED`);
  - rejected again (`REPORT_QA_DECISION_REPLAY`);
  - given a new version, which would re-submit identical content to a different reviewer;
  - FINAL (state `REJECTED`, marking `DRAFT — QA REJECTED — NOT VERIFIED`);
  - delivered (`REPORT_QA_REJECTED` from the release gate).
- **Rework:** the assessor generates a corrected report, which is a new record. Its first version gets `parent_version_id` pointing to the most recent rejected version. The rejected version and its reasons remain history, no approval state carries over, and the corrected report needs a fresh independent review.

## 11. Draft-access policy

| Actor | DRAFT / DRAFT_SYNTHETIC | REJECTED | FINAL |
|---|---|---|---|
| Assessor, QA reviewer or compliance reviewer (`report.generate` / `report.qa_approve` / `report.qualify`), not via portal | yes (`INTERNAL_DRAFT_REVIEW`) | yes | yes |
| Customer via portal (grant or named-user session) | only if `engagement_metadata.report_access_policy.customer_draft_review` is `true` | **never** | yes |
| Customer or viewer roles on a direct key (no internal permission) | no | no | yes |
| Unrelated tenant or engagement | 404 / 403 (existing isolation) | — | — |

- Enabling the engagement policy needs `assessment.create` plus `governance:write`, which the assessor side holds. Customers cannot enable it for themselves. The change is audited (`engagement.metadata_updated`).
- No request parameter (`allow_draft`, `state`, and so on) affects the decision.
- Every content response, granted or denied, is written to the engagement audit trail and committed before content leaves:
  - granted: `report.content_accessed`;
  - denied: `report.access_denied`, recording channel, state, portal origin, access basis, provenance snapshot and correlation ID.
- Content responses carry `Cache-Control: no-store, private`.
- Non-FINAL PDF filenames carry the state (`…-v1-draft-synthetic.pdf`). `X-Report-State` stays authoritative, the PDF watermark is unchanged, and the portal proxy preserves bytes and headers (CZ-29, PR #815).

## 12. Release-state model

`_authoritative_report_state` is the single computation used by the export and document routes. FINAL needs all of the following:
- a QA approval;
- that approval made by an **independent human**, per the append-only log (a legacy API-key approval yields blocker `QA_INDEPENDENT_APPROVAL_MISSING`);
- no rejection;
- a QUALIFIED decision;
- a clean signed proof with unchanged evidence;
- a clean canonical provenance decision.

Synthetic data is always `DRAFT_SYNTHETIC`. The API exposes `state`, `marking`, `is_draft`, `qa_approved`, `qa_rejected`, `independent_qa`, `provenance` (summary) and `access_basis`. `GET /reports/{v}` now returns `report_state` as well, so the portal can render the truthful state (L14-PORTAL-TRUTH-001).

## 13. Evidence and report-proof binding

- Rejections record the signed `proof_fingerprint` and `manifest_hash`.
- Approvals record the provenance `snapshot_fingerprint`.
- Delivery re-runs `release_blockers_now`, which compares evidence against the proof snapshot, and then the canonical provenance decision.

## 14. Tenant isolation

- All reads are tenant- and engagement-filtered.
- Cross-tenant reviewers and cross-tenant draft reads get 404. A grant for another engagement gets 403.
- An evidence reference into another tenant or engagement is a scope violation, and it leaks no existence information.
- Migration 0205 keeps the RLS policy from 0188.

## 15. Concurrency behaviour

| Race | Outcome |
|---|---|
| Two approvals | `UPDATE … WHERE qa_approved_by IS NULL`; rowcount ≠ 1 → 409. |
| Approve vs reject, double reject, replay | One terminal decision per (tenant, version, stage) via the 0188 index. For governance-stage records (`report_version_id IS NULL`), the new 0205 partial unique index applies. The loser's flush raises IntegrityError, which rolls back the whole transaction, including the approval CAS, and returns 409. |
| Stale version | Approval or rejection is accepted only from `internal_review`. Rejected versions are immutable. |

## 16. Audit events

| Event | When |
|---|---|
| `report.qa_approved` / `report_version_approved` | Approval. Payload adds `independence`, `provenance` and `correlation_id`. |
| `report.qa_rejected` / `report_version_rejected` | Rejection. Includes the reason, explanation and proof fingerprint. |
| `report.content_accessed` / `report.access_denied` | Every report-content request. |

Existing trust events (`trust_validation_*`) are emitted once per operation by the engine, not per evidence item. No event carries API keys, session tokens, raw payloads or evidence content.

## 17. Failure behaviour

| Failure | Response |
|---|---|
| Missing reviewer identity | 401 `CANONICAL_ACTOR_REQUIRED` |
| Key or service actor | 403 `HUMAN_REVIEWER_REQUIRED` |
| Conflict of interest | 409 `REPORT_QA_SELF_REVIEW` |
| Identity lookup failure | 503 `QA_IDENTITY_RESOLUTION_UNAVAILABLE` |
| Provenance prevents approval | 422 `ASSURANCE_PROVENANCE_BLOCKED` |
| Provenance prevents release | 422 `ASSURANCE_RELEASE_BLOCKED` |
| Rejected report | 409 / 422 `REPORT_QA_REJECTED` |
| Draft access refused | 403 `REPORT_DRAFT_ACCESS_DENIED`, with no-store |

Evaluator exceptions inside `derive_engagement_trust_inputs` return all-False trust inputs, so the default is fail-closed.

## 18. Performance

Measured by `test_provenance_evaluation_is_batched_and_bounded` on SQLite on the development workstation:

| Findings / evidence | Evaluation time | SELECT queries |
|---|---|---|
| 14 | 2.9 ms | 5 |
| 100 | 4.2 ms | 5 |
| 500 | 11.1 ms | 5 |

- The query count is constant, so there is no N+1. It is asserted at ≤ 6.
- Reads are bounded at 20,000 evidence records and findings. Above the bound the result is `PROVENANCE_EVALUATION_BOUND_EXCEEDED`, which is fail-closed and never a truncated sample.
- No network calls are made during approval or export decisions.

## 19. Tests

`tests/test_assessment_assurance/`:

| File | Tests | Covers |
|---|---|---|
| `test_provenance.py` | 10 | CZ-23 |
| `test_independent_qa.py` | 12 | CZ-12B |
| `test_qa_rejection.py` | 10 | Rejection and rework |
| `test_draft_access.py` | 9 | CZ-17 |
| `test_release_and_performance.py` | 7 | FINAL path, legacy approval, rejected delivery, synthetic, 14/100/500 performance |

The customer-zero journey (`tests/test_customer_zero_e2e/test_customer_zero_journey.py`) now observes enforcement for CZ-12, CZ-12B, CZ-12C (new), CZ-17 and CZ-23. Real-Postgres coverage of migration 0205 is in `tests/test_migrations_postgres_replay.py`. Gate results are in the PR description.

**Named reviewers in tests.** HTTP tests simulate the result of OIDC resolution through `tests/_assurance_actors.py`, using the same `get_actor_context` dependency-override pattern existing suites use. The override is installed only in the test app by `build_app`, and only activates on the `X-Test-Human-Actor` header. Every authority check still runs.

## 20. Remaining limitations (customer-pilot blockers in bold)

1. **Interactive OIDC reviewer login has not been exercised end-to-end.** Reviewers are simulated at the resolution seam in tests.
2. **Reviewer qualification is not enforced.** Competence and credentials remain policy-only. Non-conflict is now enforced, so FVA-05 is PARTIALLY_IMPLEMENTED.
3. **API-key-authored reports are an independence edge case.** A human reviewer is independent of an API-key author only at the credential-subject level, because keys have no holder binding. Follow-up: credential holder binding (`tenant_credentials` holder principal).
4. **Scanner evidence is integrity-only.** Source authenticity needs Vault Transit receipt signing (L14-SCAN-VAULT-001).
5. Draft-review policy is a per-engagement flag in `engagement_metadata` rather than a typed contract field. It is audited and assessor-controlled.
6. Generated artifacts are not stored or served by URL on this path; every download re-evaluates. No previously issued link can bypass the policy. Tenant suspension enforcement on SQLite is a no-op (Postgres R3), so that revocation case is proven in CI only via the existing lifecycle tests.
7. `report_authority` (`/reports/*`, `audit:read`) and `connectors_msgraph_report` are separate report systems without this QA lifecycle. They are not the customer-zero path and are not reachable with the portal BFF key's `governance:read` scope.
8. The portal UI does not yet render `REJECTED` / `independent_qa` (CZ-24, CZ-25 → L14-PORTAL-TRUTH-001). CZ-18 and CZ-19 are unchanged.
9. A corrections log and the client dispute process (FVA-06) remain open.

## 21. Customer-pilot readiness impact

CZ-23, CZ-12B, CZ-17 and QA rejection are closed in code. A controlled pilot additionally needs:
- items 1 and 3 above, or an operator procedure that requires named-human report generation;
- an operator rehearsal of OIDC reviewer login;
- the portal truth fixes (L14-PORTAL-TRUTH-001).

The verdict moves from "Not yet" to **"Not yet — assurance blockers closed; identity rehearsal and portal truth remain."**

## 22. Follow-up PR boundaries

| PR | Scope |
|---|---|
| L14-PORTAL-TRUTH-001 | CZ-24, CZ-25 and portal rendering of the REJECTED state and access basis |
| L14-SCAN-VAULT-001 | Source authenticity for scanner receipts |
| Credential holder binding | Linking API-key holders to principals |
| FVA-05 qualification registry; FVA-06 corrections log and dispute process | Not started |
| CI log redaction | Separate remediation (see the PR description) |
