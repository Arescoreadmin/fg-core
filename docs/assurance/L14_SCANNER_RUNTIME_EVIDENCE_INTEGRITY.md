# L14-SCAN-RUNNER-INTEGRITY-001: Runtime Scanner Evidence Integrity

**Status:** Implemented for the 10 production scanner worker paths (3 target scanners plus 7 Graph-family connectors). Three paths are out of scope and listed in §19.

**Predecessors:**
- #810: evidence integrity authorities;
- #811: collection completeness;
- #812: authorization hardening (merged `fa74a2c9`).

**Assurance effect:** FVA-02, FVA-03 and FVA-04 are strengthened at runner level but all remain `PARTIALLY_IMPLEMENTED` (§18). Report-level enforcement is L14-SCAN-REPORT-PROOF-001.

> Not standalone: this PR adds no evidence store, no confidence policy and no custody ledger. It calls the PR #810 authorities from real worker code. `EvidenceIntegrityService.build_envelope()` builds envelopes, `EvidenceCustodyService.record()` writes custody, and `classify_confidence()` sets confidence. Rows persist to `fa_scan_evidence_envelopes`, `fa_evidence_custody_events` and `fa_normalized_findings`.

## 1. Runtime authority map

| Concern | Authority | Where it runs now |
|---|---|---|
| Canonicalization and digest | `evidence_integrity.canonicalize_payload` / `compute_payload_digest` (#810) | `runtime_evidence._persist_envelope` → `build_envelope()` |
| Envelope persistence | `FaScanEvidenceEnvelope` (0201, widened by 0204) | same, inside the import transaction |
| Custody | `EvidenceCustodyService.record(commit=False)` | COLLECTED and INGESTED per envelope; NORMALIZED per finding link; VERIFIED on verification |
| Confidence | `finding_confidence.classify_confidence` | `runtime_evidence._link_findings` |
| Collection status | `CollectionStatus` (#811) | stored per envelope and per finding |
| Authorization provenance | worker-start `authorization_context` (#812) | copied onto every envelope |
| Integration boundary | `_c6_capture_runtime_evidence` (`api/field_assessment.py`) | after the bridge persists results, before the job is marked complete |

## 2. Scanner execution matrix

Legend: **E** = ENFORCED, **P** = PARTIAL, **A** = ABSENT.

| Scanner | Runner → bridge | Evidence integrity | Custody | Finding link | Collection status | Authorization |
|---|---|---|---|---|---|---|
| network_scan | guarded worker → `import_network_scan` | E (scan + per host) | E | E (per `affected_hosts`) | E (per host) | E (receipt + scope from worker start) |
| dns_email | guarded worker → `import_dns_email_scan` | E (scan + per domain) | E | E (per domain) | E (per domain) | E |
| web_headers | guarded worker → `import_web_headers_scan` | E (scan + per target) | E | E (per target) | E (per target) | E |
| microsoft_graph | `_msgraph_scan_background` → msgraph bridge | P (scan-level envelope only) | E | P (scan-level) | P (payload status, often UNKNOWN) | P (`GRAPH_CUSTOMER_DEVICE_CODE_LOGIN_ONLY`, no FrostGate receipt) |
| oauth_inventory | worker → bridge | P | E | P | P | P |
| endpoint_inventory | worker → bridge | P | E | P | P | P |
| entra_governance | worker → bridge | P | E | P | P | P |
| sharepoint_onedrive | worker → bridge | P | E | P | P (TRUNCATED preserved) | P |
| oauth_risk | worker → bridge | P | E | P | P | P |
| ai_tool_discovery | worker → bridge | P | E | P | P | P |
| scan-results ingest route, ai-data-access-mapping, ai-vendor-governance | — | A | A | A | — | — (§19) |
| scheduled scans | none exist (the scheduler stores schedules only) | — | — | — | — | — |

`tests/test_scan_runner_integrity/test_end_to_end.py::test_every_wired_worker_captures_before_completion` proves the wiring. It parses `api/field_assessment.py` and asserts that all 8 worker functions (the guarded function serves the 3 target scanners) call `_c6_capture_runtime_evidence` **before** any completion transition.

## 3. Capture adapter contract

The adapter is `capture_scan_result_evidence(db, *, tenant_id, engagement_id, scan_result_id, scanner_id, scan_job_id, …)`. `capture_with_retry` runs it inside a SAVEPOINT.

1. The scanner must be supported (`SCANNER_NOT_SUPPORTED` otherwise).
2. The engagement must belong to the tenant, and the job must belong to the tenant and engagement (`ENGAGEMENT_NOT_FOUND`, `SCAN_JOB_NOT_FOUND`).
3. The scan result is loaded **server-side** by `(id, tenant, engagement)`. The caller never supplies the payload. A missing or cross-tenant result returns `SCAN_RESULT_NOT_FOUND`, and nothing is enumerable.
4. The payload must be a non-empty dict (`UNSUPPORTED_PAYLOAD`).
5. Authorization provenance is validated (§8).
6. One scan-level envelope (`source_type=scan_result`, `observation_path="$"`) plus one envelope per observation.
7. Custody, then finding links and confidence.
8. The adapter does not commit. The worker's import transaction makes the scan result, envelopes, custody and finding links durable together.

Return value: `CaptureResult` with envelope ids, created/reused counts, findings linked and collection status.

## 4. Canonicalization

The adapter reuses `canonicalize_payload` from #810:
- recursively sorted keys;
- NFC Unicode;
- explicit nulls;
- compact separators;
- a version-scoped `__meta__` block.

The schema version is `1.0`. Key order and NFC-equivalent strings don't change the digest; a material change does (`test_key_order_does_not_change_digest`).

## 5. Digest creation, and what it proves

- The digest is computed over the evidence **as stored in `fa_scan_results.raw_payload`**: the payload the bridge persisted, after any redaction the bridge applies. It is not computed over network bytes.
- No payload is duplicated. Envelopes store a digest plus an `observation_path` (`hosts[2]`, `targets[0]`, …).
- Digest verification proves **integrity**: stored evidence is unchanged since capture. It does **not** prove the source or scanner is authentic.
- `provenance_status` is `VERIFIED_INTEGRITY_ONLY`. It is never `VERIFIED_AUTHENTIC`, because Vault Transit signing of scanner receipts is still L14-SCAN-VAULT-001. `_try_vault_sign` returns nothing, and this PR does not change that.
- **Bounded resources:** canonical bytes are capped at 16 MiB per scan envelope and 4 MiB per observation. Above the cap, capture fails with `EVIDENCE_PAYLOAD_TOO_LARGE` and the savepoint rolls back, so no partial envelope set remains.

## 6. Evidence persistence

Migration 0204 makes envelopes idempotent and immutable:
- **Idempotency:** the unique index `uq_fa_scan_evidence_env_observation (tenant_id, scan_result_id, source_type, source_id)`. A retry or duplicate delivery reuses envelopes; it never duplicates them.
- **Immutability:** a Postgres trigger, mirrored by an ORM listener for SQLite, forbids changes to identity, digest, collection status or authorization fields after capture.
- **Allowed changes:** `provenance_status` may move only once, to `INVALID`. `scan_result_id` may only become NULL (via the FK `ON DELETE SET NULL`).
- **Legacy rows:** unaffected. No historical envelope is manufactured.

## 7. Custody lifecycle (real actions only)

| Event | When | `reason` / state |
|---|---|---|
| COLLECTED | envelope created from the runner's observation | `scanner:source_type:path`, `to_state=collected`, `digest_ref` |
| INGESTED | same transaction, envelope persisted | `to_state=persisted`, `digest_ref` |
| NORMALIZED | an envelope supports a finding | `reason=finding:<finding_id>`, `to_state=supports_finding` |
| VERIFIED | `verify_stored_evidence(record_custody=True)` | `to_state=VERIFIED_INTEGRITY_ONLY` or `INVALID` (`reason=integrity_failure`) |

- Custody is written with `commit=False`, so it is **atomic** with the envelope. There is no state where an envelope exists without custody, and no recovery path is needed.
- Retries add **no** custody events. Envelopes are reused, and NORMALIZED is de-duplicated per (envelope, finding).
- Observations no finding used get only COLLECTED and INGESTED.
- Custody rows are append-only: the 0201 DB trigger and an ORM listener both enforce it (`test_custody_history_cannot_be_rewritten`).

## 8. Authorization receipt linkage

- **Target scanners:** provenance comes from the `authorization_context` the guarded worker writes **at worker start** (#812). That is the authorization that actually permitted collection, never the current state.
- If authorization is revoked later, the evidence keeps its original receipt (`test_revocation_between_hosts_keeps_attributed_partial_evidence`). The execution guard still stops further outbound work.
- The context's tenant, engagement, job and scanner must match. Ids must be UUIDs, and a scope authorization id is mandatory.
- Each envelope stores `authorization_ref`, `authorization_version`, `customer_receipt_id` and `authorization_proof_level`.
- A target scan **without** that context did not run through the guarded path. Capture is refused (`AUTHORIZATION_CONTEXT_MISSING`) rather than invented.
- **Graph-family:** there is no FrostGate customer receipt. Envelopes are labelled `GRAPH_CUSTOMER_DEVICE_CODE_LOGIN_ONLY`. A Graph payload that *claims* an authorization context is rejected (`AUTHORIZATION_CONTEXT_UNEXPECTED`).

## 9. Collection status propagation

- All nine canonical values persist on envelopes. Any other value becomes `UNKNOWN` (fail closed).
- Each observation carries its own status:
  - network: from `collection_status` or `error`;
  - DNS and web: from the runner's per-target status.
- A finding's `collection_status` combines its supporting observations, worst first (FAILED > DENIED > TIMEOUT > CANCELLED > TRUNCATED > PARTIAL > UNKNOWN > NOT_ASSESSED > COMPLETE).
- An interrupted scan's scan-level envelope is `CANCELLED`, and only observations actually collected get envelopes.
- Normalization can't erase a limitation: the stored status is immutable.

## 10. Finding confidence enforcement

`classify_confidence` is applied unchanged (policy `fg.finding_confidence.v1`) with these inputs:
- `evidence_present=True`;
- `collection_complete` = the **finding's own supporting observations** are all COMPLETE;
- verification method: `DIRECT_TECHNICAL_OBSERVATION` for target scanners, `AUTHORITATIVE_CONFIGURATION_EXPORT` for Graph exports;
- provenance: `VERIFIED_INTEGRITY_ONLY`.

Consequences:
- A directly observed finding on a fully collected host stays **CONFIRMED** inside a PARTIAL or CANCELLED scan. This is what the policy allows for integrity-verified evidence; it is not an authenticity claim.
- A finding on an incomplete observation is capped at **PROBABLE** (rule C-5).
- A finding that can't be attributed to an observation uses the scan-level envelope and the scan's status.
- If capture fails, `mark_findings_evidence_missing` sets **UNKNOWN** with `NOT_VERIFIED`. Such findings never look evidence-backed.
- Severity is never read or written.
- Already-classified findings are never re-linked or upgraded on retry. Legacy findings with NULL confidence are untouched, and the manifest reports them as `legacy_unclassified`, effective confidence UNKNOWN.
- At report time, evidence that fails verification caps effective confidence at SUSPECTED (rule C-2). The stored value stays visible beside it.

## 11. Tenant isolation

Every query carries tenant and engagement predicates. The scan result, engagement and job are server-side lookups. Cross-tenant verification returns `MISSING`, custody history raises `PermissionError`, and the manifest returns nothing. Tests: `TestOwnershipAndIsolation` (5).

## 12. Retention and redaction

- No new payload storage is added; only digests and paths.
- Redaction and retention of `raw_payload` stay governed by the existing bridge and retention authorities. The digest is bound to the post-redaction stored form.
- Envelopes are marked `data_sensitivity=confidential`.
- Logs contain only reason codes and ids, never payload content.

## 13. Retry and idempotency

| Case | Behaviour |
|---|---|
| Worker retry or duplicate delivery of the same payload | `create_scan_result` returns the same row; capture reuses envelopes; no custody added |
| Concurrent capture of one scan result | The loser hits the unique index; `capture_with_retry` rolls back its savepoint and re-runs, reusing the winner's rows (`test_concurrent_capture_race_resolves_to_single_envelope_set`) |
| Stored payload changed before a retry | `STORED_EVIDENCE_INTEGRITY_FAILURE`; never re-baselined; the digest is unchanged |
| Capture failure (oversize, bad authorization context, DB error) | Savepoint rolled back; the scan result is kept; findings set to UNKNOWN; audit `scan.evidence.capture_failed`; the job still completes (the data is real, but evidence is absent and visible as such) |

## 14. Worker cancellation behaviour

- Capture runs after evidence persistence and before the terminal compare-and-swap (#812).
- On cancellation, emergency stop or revocation, evidence already collected is captured with `CANCELLED` coverage and the job ends `cancelled`.
- A late success after cancellation keeps its evidence and the job stays cancelled.
- Tests: `TestNetworkEndToEnd` (3).

## 15. Report-facing evidence contract

`build_evidence_manifest(db, tenant_id, engagement_id)` → `fg.evidence_manifest.v1`. It is built **only from persisted rows** and re-verifies integrity against stored payloads on every build. That verification can mark tampered evidence INVALID, but it writes no custody.

Per finding:
- `finding_id`, `evidence_ids` (from NORMALIZED custody plus the primary envelope), `source_scanner`;
- `collection_status`, `evidence_integrity_status` (`INTEGRITY_VERIFIED` / `INTEGRITY_FAILED` / `NOT_VERIFIABLE`), `provenance_status`;
- `confidence_stored`, `confidence_effective`, `severity`, `legacy_unclassified`;
- `authorization` (authorization id, version, customer receipt id, proof level);
- `evidence_verified_at`.

Top level: `scans`, `coverage_limitations`, and `report_constraints`:

| Constraint | Rule |
|---|---|
| `may_claim_authenticated_evidence` | false unless every envelope is VERIFIED_AUTHENTIC (never today) |
| `may_claim_full_coverage` | false if any envelope is not COMPLETE |
| `may_claim_zero_risk` | always false |
| `confirmed_finding_ids` | list of finding ids |
| `integrity_failed_evidence_ids` | list of evidence ids |

The manifest is a service function and is not exposed by a route. L14-SCAN-REPORT-PROOF-001 consumes it at report assembly and release. Reproducibility is tested by building it from two fresh sessions and comparing the results.

## 16. Performance measurements (test environment only)

`test_capture_overhead_measured` captured 50 hosts (40 ports each) plus one scan envelope: 51 envelopes, 102 custody events and 1 finding link in **32 ms**. That was SQLite on the development workstation. It is not a production figure. Each envelope costs two canonicalizations: one size check and one digest.

## 17. Threat model

| Threat | Control | Test |
|---|---|---|
| Stored evidence edited after capture | Digest re-verification; INVALID is sticky; digest immutable | `TestTamperDetection` (4) |
| Re-baselining a digest to hide tampering | Immutability listener and trigger; retry refuses on mismatch | `test_digest_never_recomputed_after_tamper`, `test_envelope_digest_is_immutable` |
| Claiming authenticity from a hash | Provenance capped at INTEGRITY_ONLY; cannot be upgraded | `test_provenance_cannot_be_upgraded`, manifest `may_claim_authenticated_evidence=false` |
| Forged or mismatched authorization attribution | Context validated against tenant, engagement, job and scanner | `test_mismatched_authorization_rejected` (6) |
| Graph scan claiming a receipt | Rejected | `test_graph_payload_claiming_receipt_rejected` |
| Cross-tenant evidence, custody or manifest access | Predicates; MISSING / PermissionError | `TestOwnershipAndIsolation` |
| Evidence attached to the wrong scan or job | Job and scan ownership checks | `test_job_from_other_engagement_rejected` |
| Duplicate evidence or custody inflation on retry | Unique index; reuse; NORMALIZED de-duplication | `TestIdempotencyAndCustody` |
| Confirmed finding without evidence | Capture failure → UNKNOWN; manifest MISSING → no confirmed | `test_capture_failure_is_explicit_and_blocks_claims` |
| Incomplete collection hidden | Per-observation status; manifest limitations; full-coverage flag | `TestNetworkEndToEnd`, `test_every_canonical_status_preserved` |
| Memory exhaustion via huge payloads | Bounded canonical size | `test_oversized_observation_refused` |
| Custody rewrite | Append-only trigger and listener | `test_custody_history_cannot_be_rewritten` |

## 18. Test coverage

`tests/test_scan_runner_integrity/` has 55 tests:
- capture: 44;
- end to end: 11 (web, network revocation, emergency stop, late completion, DNS timeout, tamper downgrade, capture failure, concurrency race, wiring proof, performance).

The end-to-end tests drive the **production** `_c6_run_guarded_target_scan`, the real runners (network I/O mocked), the real bridges and real SQLite persistence. Authorization decisions use the real `check_scan_authorized()` over the #812 harness store, because that store's SQL is Postgres-only.

## 19. Unsupported scanner paths

- **`POST /engagements/{id}/scan-results` (manual ingest):** externally produced payloads with no runner provenance and no findings created. Not captured.
- **`ai-data-access-mapping/run`, `ai-vendor-governance/run`:** offline analyzers over stored engagement data. No collection occurs.
- **Graph-family connectors:** only a scan-level envelope; there are no per-object observation extractors yet. Payload collection status is often absent, so it reads UNKNOWN and findings cannot be CONFIRMED.

## 20. Residual risks and future PRs

1. **Report path:** the canonical report and PDF do not yet consume the manifest, confidence labels or collection status. See `L14_CUSTOMER_REPORT_PREVIEW_READINESS.md`. This is **L14-SCAN-REPORT-PROOF-001**.
2. **No authenticated provenance:** **L14-SCAN-VAULT-001**.
3. **Graph-family gaps:** per-object observation envelopes and receipt binding (L14-SCAN-SAFETY-002 / follow-up).
4. **Bridge id derivation:** `finding_observation_map` mirrors three bridges' deterministic finding-id formulas. The end-to-end tests pin them, but a bridge change without a matching update would fall back to scan-level evidence. That fallback is safe but less precise.
5. **Terminal transition failure** (pre-existing, #812): an exception during the terminal transition logs and leaves the job `running`. Evidence is already committed; job finalization is not.
6. Migration 0204 replay runs in CI only. No local destructive database commands were run.
