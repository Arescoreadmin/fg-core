# L14-SCAN-AUTH-HARDENING-001 — Customer Authorization Proof & Execution-Time Safety

**Status:** Implemented for target-based scanners (network, DNS/email, web headers). Partial for Graph-family connectors.
**FVA-01:** `PARTIALLY_IMPLEMENTED` (see §18). This document does not claim it is `IMPLEMENTED`.
**Closes:** AUTH-GAP-002 for target-based scanners. AUTH-GAP-001 is closed at the *server-attested authenticated approval* proof level; a customer-controlled digital signature is not implemented.
**Predecessors:** #809 (scan safety), #810 (evidence integrity), #811 (collection completeness, merged and validated at `94ff137e`).

> Not standalone: every control here reuses the canonical authorities: `fa_scan_authorizations` (0200), `check_scan_authorized()`, `fa_scan_jobs`, `fa_scan_audit_events`, `CollectionStatus`, and ActorContext identity. No second authorization service, ledger or job state machine exists.

---

## 1. Authority map

| Concern | Canonical authority | New in this PR |
|---|---|---|
| Operator scope (targets, operations, window) | `fa_scan_authorizations` + `check_scan_authorized()` | `customer_receipt_id` binding column; receipt check is step 7 of `check_scan_authorized()` |
| Customer consent | — (gap) | `fa_customer_authorization_receipts` + `services/field_assessment/customer_authorization.py` |
| Execution-time decisions | — (gap) | `services/field_assessment/scan_execution_guard.py` (fresh-read guard) |
| Runner boundary contract | — | `services/connectors/execution_checkpoint.py` (dependency-free) |
| Job state machine | `fa_scan_jobs` + `DurableJobService` + `cancel_scan` / `confirm_scan_cancelled` | Transitions are now compare-and-swap |
| Emergency stop | `fa_scan_emergency_stops` | Release route + cross-tenant release fix; Graph-family gates |
| Decision records | `fa_scan_audit_events` (scan plane), `audit_atomicity_svc` (e-stop) | New event types; structured decision payload |
| Coverage truth | `CollectionStatus` (#811) | `CANCELLED` on interruption; `fa_scan_jobs.collection_status` set at terminal transition |

## 2. Customer approval model

An operator with `scan.scope.manage` **requests** approval (`POST /engagements/{id}/customer-authorizations`) for explicit targets, operations, a time window, purpose, rules-of-engagement reference and customer organization. The receipt starts in `pending_approval`.

A customer representative **approves** (`POST …/{receipt_id}/approve`). The approval body contains only `acknowledge_consent_statement_version`, which must equal `fg.scan_consent_statement.v1`. It carries **no identity fields** (`extra="forbid"`). The approver, tenant and authority basis are taken from the authenticated `ActorContext` alone.

The operator then creates a scope bound to the receipt (`customer_receipt_id` on `POST …/scan-authorizations`). Create and activate both verify that the scope is a subset of the receipt (§6).

## 3. Customer identity verification (`validate_approver`)

All of these must hold, or approval fails closed with a specific `APPROVER_*` code:

1. The actor has `scan.consent.approve`. It is granted only to `tenant_admin` and `client_security_owner`; `platform_admin` holds it only via `ALL_PERMISSIONS`.
2. The actor holds a customer authority role (`tenant_admin` or `client_security_owner`) and **does not** hold `platform_admin`. FrostGate staff can never stand in for the customer.
3. Interactive IdP authentication: `auth_source ∈ {oidc_auth0, oidc_entra, oidc_okta}`. API keys, `system`, `dev_bypass` and service principals are rejected.
4. `email_verified` is true.
5. The actor's tenant equals the receipt tenant. The route also enforces `_resolve_caller_tenant` plus engagement ownership.
6. The actor is not the requester (`APPROVER_SELF_APPROVAL_DENIED`). An approver who also holds `assessor` is allowed but recorded as `approver_also_assessor=true` inside the digest.

Assessors get `scan.consent.revoke` but never `scan.consent.approve`. Revocation only reduces authority.

## 4. Receipt cryptographic trust semantics: what is actually proven

| Proof level | Meaning | When |
|---|---|---|
| `SERVER_ATTESTED_AUTHENTICATED_APPROVAL` | Authenticated approver (§3). A versioned canonical SHA-256 digest binds every material field. FrostGate attests the canonical bytes with HMAC-SHA256 under a trusted, non-revoked key id. | Attestation key ring configured |
| `AUTHENTICATED_APPROVAL_DIGEST_ONLY` | Same authenticated approval and digest, but no attestation. Detects accidental or naive edits only. | Non-production only. **Production refuses to approve without a key** (`ATTESTATION_KEY_UNAVAILABLE`). |
| `LEGACY_OPERATOR_ASSERTED` | Scope without a receipt. Never reported as customer consent. | Non-production legacy fixtures. Denied whenever consent is required. |

**This is a server attestation, not a customer signature.** The customer does not hold the key, and anyone holding the attestation key could forge an attestation. Offline verification by the customer with a public key is **not implemented**; it needs an asymmetric signing authority (L14-SCAN-VAULT-001, Vault Transit). The digest is labelled a digest and never called a signature.

Canonical payload: `canonicalize_payload()` from PR #810, with schema version `fg.customer_scan_authorization.v1`. It binds receipt id, group, version, schema, tenant, engagement, customer org, purpose, RoE ref, consent statement version, target normalization version, normalized and sorted targets, sorted operations, window start/end, requester, approver identity (subject, email, auth source, authority basis, membership id, also-assessor) and approval time.

Verification (`verify_receipt_integrity`) recomputes the digest from stored columns on **every** execution-time check. It rejects:

- digest mismatch (altered scope, dates, principal, engagement, tenant, organization or RoE);
- missing digest;
- an unsupported schema version;
- an unknown or revoked key id;
- a wrong key;
- algorithm substitution (anything other than `HMAC-SHA256`);
- partial attestation;
- a stripped attestation when attestation is required.

## 5. Effective authorization calculation

New outbound work is permitted only if **all** of the following hold. `check_scan_authorized()` evaluates them on every call, reading current database state:

1. No active emergency stop at platform, `tenant:{id}` or `engagement:{id}`.
2. An `active` scope exists for this tenant and engagement, is not revoked, and `effective_from ≤ now < expires_at`.
3. The target normalizes and matches a scope entry (exact FQDN, opt-in subdomains, IP in CIDR, exact CIDR). No string-prefix matching.
4. The operation is permitted for that scope entry.
5. If the scope is bound to a receipt: the receipt belongs to the same tenant and engagement, is `approved`, not revoked, and `window_start ≤ now < window_end`; its integrity verifies (§4); and the **receipt itself** approves this exact target and operation.
6. If the scope is not bound and consent is required, the result is `CUSTOMER_AUTHORIZATION_REQUIRED`.

Consent is required always in production and staging (no downgrade switch). Elsewhere it is opt-in with `FG_SCAN_REQUIRE_CUSTOMER_CONSENT=1`. If the environment can't be determined, the code treats it as production.

The decision returns `authorization_id`, `authorization_version`, `customer_receipt_id`, `consent_status` and `proof_level`, which feed decision records and evidence provenance.

## 6. Target and operation binding

- Receipt targets are validated, normalized and de-duplicated at request time. Wildcards, `url` types, unknown fields, subdomains on non-FQDN entries, operations outside `authorized_operations`, and anything outside {`network_scan`, `web_headers`, `dns_email`} are all rejected.
- A scope entry is covered only if a receipt entry contains it (same target, or IP inside receipt CIDR, or CIDR that is a subnet of a receipt CIDR), its operations are a subset, it uses `allow_subdomains` only where the receipt allows it, and its expiry falls inside the receipt window.
- A DNS-only receipt can never authorize `network_scan`. Approval for one host never authorizes a different or look-alike host (`app.example.com.attacker.net`). A receipt can't be replayed against another engagement or tenant, because every lookup is predicated on tenant and engagement.

## 7. Execution-time validation (AUTH-GAP-002)

`ScanExecutionGuard` opens a **new short-lived session** for every check, binds the tenant context, reads current rows and closes the session. No ORM identity map or module cache carries a decision between checks. Any read failure produces `AUTHORIZATION_STORE_UNAVAILABLE` or `EMERGENCY_STOP_CHECK_FAILED` (fail closed).

`worker_start()` runs before any outbound I/O. It checks:

- the job exists;
- the job's tenant and engagement match the worker (`WORKER_*_MISMATCH`);
- the status is `queued` or `running` (`JOB_CANCELLED`, `JOB_NOT_EXECUTABLE` for duplicate delivery or finished jobs);
- **every** target passes §5.

The worker then performs the compare-and-swap `queued → running`. If that CAS is lost (a cancel arrived meanwhile), the job is confirmed cancelled and no outbound work happens.

## 8. Multi-target revocation behaviour

Runners accept `checkpoint(phase, target)` and call it before each boundary:

| Runner | Boundaries checked |
|---|---|
| network | before each host (after CIDR expansion) |
| web headers | before each target **and before each redirect hop** (the destination host must be in scope) |
| DNS/email | before each domain |

The checkpoint can signal two outcomes:

- `ScanTargetDenied`: this target or redirect destination is out of scope. It is skipped and recorded as `DENIED`, and the run continues with the remaining targets.
- `ScanCheckpointHalt`: revocation, expiry, emergency stop, cancellation or an unavailable store. All **new** outbound work stops. Hosts already collected are kept, the payload reports `collection_status=CANCELLED`, `scan_status=interrupted` and `interrupted={reason_code, phase, remaining_targets_not_started}`.

**Revocation observation boundary:** a change committed at time T is observed at the first checkpoint after T. Requests already in flight are **not** aborted. The worst-case unobserved window is one target's collection time plus one guard round trip:

- network: one host's port-probe fan-out;
- web headers: one HTTP hop at the client timeout;
- DNS: one domain's record lookups (SPF, DMARC, DKIM selectors, MX, DNSSEC are not individually checkpointed).

## 9. Emergency-stop enforcement

- Platform, tenant and engagement stops are durable rows in Postgres, so they persist across restarts. They are checked at dispatch, worker start and every checkpoint, and take precedence over any scope or receipt.
- Activation (existing) and **release** (new: `POST /emergency-stop/{stop_id}/clear`) are both audited via `audit_atomicity_svc` (`scan.emergency_stop.activated` / `.released`).
- **Fixed:** `clear_emergency_stop` previously looked the stop up by id alone, so a tenant actor holding `scan.emergency_stop` could release another tenant's **engagement-scoped** stop. Release now verifies the engagement belongs to the actor's tenant unless the actor holds `scan.emergency_stop.platform`.
- A stop raised mid-scan interrupts at the next checkpoint. Evidence collected so far is preserved and attributed, coverage is `CANCELLED`, and the job goes `running → cancel_requested → cancelled` with `cancelled_by=system:scan_execution_guard` and the reason code.
- SQLite test databases now create `fa_scan_emergency_stops` in `init_db()` (the same pattern as other Postgres-only tables). Without it, every stop gate failed closed in tests. The stop query uses a portable `IN (…)` instead of `= ANY(…)`.

## 10. Cancellation race behaviour

`DurableJobService` transitions are now compare-and-swap. Each returns `True` only if it performed the transition:

| Transition | Predicate |
|---|---|
| `mark_running` | `status = 'queued'` |
| `mark_complete` | `status = 'running'` |
| `mark_failed` | `status IN ('queued','running')` |

Previously all three were unconditional `UPDATE … WHERE id = :id`, so a late success could overwrite `cancel_requested` or `cancelled`, and a cancelled job could be set back to `running`.

| Race | Behaviour |
|---|---|
| Cancel before worker start | Guard sees `cancel_requested` → confirmed `cancelled`; zero outbound I/O |
| Cancel between start check and running CAS | CAS lost → confirmed `cancelled`; zero outbound I/O |
| Cancel during scan | Next checkpoint halts; partial evidence persisted; `cancelled` |
| Cancel after last checkpoint, before persist | Evidence persisted; `mark_complete` CAS fails → `scan.late_completion_rejected` → `cancelled`, coverage `CANCELLED` |
| Duplicate cancellation | Idempotent (existing `cancel_scan`) |
| Failure after cancel | `mark_failed` CAS refuses; stays `cancelled` |
| Duplicate delivery or retry of a finished job | `JOB_NOT_EXECUTABLE`; job untouched |
| Worker crash after cancel | Job remains `cancel_requested` and can never be revived (`mark_running` CAS); the next delivery confirms `cancelled` |

A cancelled scan is never reported as an empty successful result: coverage is `CANCELLED` and `scan.completed` is not emitted.

## 11. Audit events (decision records)

All events go to `fa_scan_audit_events` (the existing append-only scan ledger). Decision payloads hold:

- decision, reason code and boundary;
- authorization id and version, customer receipt id;
- consent status and proof level;
- correlation id (scan job id) and decision time.

No credentials, tokens, key material or scan payloads are logged.

| Event | Boundary |
|---|---|
| `scan.consent.requested` / `.approved` / `.approval_denied` / `.rejected` / `.revoked` | customer consent |
| `scan.authorization.created` / `.activated` / `.revoked` (existing) and `.activation_denied` | scope |
| `scan.authorization.dispatch_authorized` / `.denied` | dispatch |
| `scan.authorization.worker_start_authorized` / `.worker_start_denied` | worker start |
| `scan.authorization.target_denied` | execution checkpoint (per target or redirect) |
| `scan.authorization.lost` | authority lost during execution |
| `scan.cancel.requested` / `.denied` (existing), `scan.cancelled`, `scan.late_completion_rejected` | cancellation |
| `scan.emergency_stop.activated` / `.released` | e-stop (via `audit_atomicity_svc`) |

**Fixed (latent):** migration 0079's `CHECK (event_type IN (…six values…))` would have rejected every `scan.authorization.*` and `scan.cancel.*` event written since PR #809 on real Postgres. Unit tests mock the session, so this was never observed. Migration 0203 widens the constraint to the full set, and a test asserts every event type emitted in code is allowed.

## 12. Threat model: threat → control → test

| Threat | Control | Test(s) (`tests/test_scan_authorization_hardening/`) |
|---|---|---|
| Forged consent (operator asserts consent) | Receipt approval requires customer identity from ActorContext; legacy scope labelled `LEGACY_OPERATOR_ASSERTED`; denied when consent required | `TestApproverValidation`, `test_legacy_scope_is_never_reported_as_customer_verified`, `test_missing_receipt_when_consent_required_denies_scan` |
| Forged approval via request body | Approval body has no identity fields, `extra=forbid` | `test_approve_route_takes_no_identity_fields` |
| Stolen operator credentials | Operator roles lack `scan.consent.approve`; self-approval denied | `test_assessor_cannot_approve_but_can_revoke`, self-approval case |
| Platform staff impersonating customer | `platform_admin` rejected as approver despite holding all permissions | `test_platform_admin_permission_is_not_customer_authority` |
| Customer principal escalation or untrusted auth | auth_source allow-list, verified email, no service principals, tenant match | `TestApproverValidation` (12 cases) |
| Cross-tenant authorization replay | Tenant and engagement predicates on every receipt read; tenant/engagement checks in evaluation | `test_receipt_replay_against_other_tenant_denied`, `…other_engagement_denied`, `test_approval_from_other_tenant_cannot_find_receipt` |
| Target substitution | Receipt target check at execution plus digest | `test_unrelated_host_not_authorized_by_receipt`, `test_prefix_lookalike_host_not_matched`, `test_altered_targets_in_store_denies_execution` |
| Operation substitution | Receipt operation check | `test_dns_approval_does_not_authorize_port_scan` |
| Expired receipt reuse | Window check at every boundary; expiry derived, never renewed | `test_expired_receipt_denies_scan_and_is_derived_expired`, `test_receipt_expired_after_dispatch` |
| Revoked receipt reuse | Revocation checked at every boundary | `test_revoked_receipt_denies_and_history_retained`, `test_receipt_revoked_between_dispatch_and_start` |
| Stale worker authorization / TOCTOU | Fresh-session reads per check; running CAS | `test_no_cached_decision_reused`, `test_cancel_lands_between_start_check_and_running_cas` |
| Emergency-stop bypass | Checked at dispatch, worker start, each checkpoint, Graph worker gate | `test_emergency_stop_before_start`, `test_emergency_stop_between_batches`, `TestGraphFamilyGates` |
| Cross-tenant e-stop release | Engagement ownership check on clear | `TestEmergencyStopRelease` |
| Cancellation race / late completion | CAS transitions | `test_job_state_cas.py`, `test_late_success_after_cancellation_rejected` |
| Redirect target escape | Scope checkpoint before each hop | `test_redirect_outside_scope_blocked_before_request` |
| DNS rebinding | Partially mitigated (see §17): SSRF validator re-validates each hop; IP-literal private redirects blocked | `test_ssrf_redirect_still_blocked_by_validator`, `test_dns_rebinding_style_redirect_to_private_ip_literal_blocked` |
| Duplicate worker execution | `JOB_NOT_EXECUTABLE` for non-queued/running jobs; running CAS | `test_duplicate_delivery_of_finished_job`, `test_duplicate_delivery_of_completed_job_does_nothing` |
| Receipt tampering | Canonical digest recomputed at every check; DB immutability trigger | `TestReceiptIntegrity` (9 field-tamper cases), `test_receipt_immutability_trigger_present` |
| Signature downgrade / stripping | Algorithm pinned; attestation required in production | `test_algorithm_downgrade_rejected`, `test_stripping_attestation_rejected_when_required` |
| Signing key compromise | Key-id revocation list; rotation keeps old receipts verifiable | `test_revoked_key_id_rejected_for_verification`, `test_key_rotation_keeps_old_receipts_verifiable`, `test_revoked_active_key_blocks_new_approvals` |
| Unauthorized historical evidence access | Existing tenant-scoped routes (unchanged); new list/get routes require `scan.read` with tenant and engagement predicates | Route registration test. Cross-tenant read is enforced by `_resolve_caller_tenant` (existing suites). |

## 13. Scanner enforcement matrix

Legend: **E** = ENFORCED, **P** = PARTIAL, **A** = ABSENT, — = not applicable.

| Path | Operator perm | Tenant from auth | Engagement owner | Scope @dispatch | Receipt | Worker start | Boundary rechecks | E-stop dispatch / worker | Cancel CAS | Late-complete reject | Audit |
|---|---|---|---|---|---|---|---|---|---|---|---|
| network_scan | E | E | E | E | E | E | E (per host) | E / E | E | E | E |
| dns_email | E | E | E | E | E | E | P (per domain, not per record phase) | E / E | E | E | E |
| web_headers | E | E | E | E | E | E | E (per target + per redirect hop) | E / E | E | E | E |
| microsoft_graph | E | E | E | A (no host-target model) | A | P (e-stop + cancel after device-code token, before Graph I/O) | A (no per-page checks) | E / E | E | P (CAS refuses overwrite; worker still emits `scan.completed`) | P |
| oauth_inventory | E | E | E | A | A | P | A | E / E | E | P | P |
| endpoint_inventory | E | E | E | A | A | P | A | E / E | E | P | P |
| entra_governance | E | E | E | A | A | P | A | E / E | E | P | P |
| sharepoint_onedrive | E | E | E | A | A | P | A | E / E | E | P | P |
| oauth_risk | E | E | E | A | A | P | A | E / E | E | P | P |
| ai_tool_discovery | E | E | E | A | A | P | A | E / E | E | P | P |
| msgraph/import, ai-data-access-mapping/run, ai-vendor-governance/run | E | E | E | — (no outbound I/O) | — | — | — | — | — | — | existing |
| Scheduled scans | — | — | — | — | — | — | — | — | — | — | — |
| Retries / orphan recovery | — | — | — | — | — | — | — | — | E (CAS) | E | — |

Notes:

- **Graph family:** the existing authorization basis is the customer administrator completing an interactive Microsoft device-code login for read-only Graph scopes, plus an operator HMAC acknowledgment (`msgraph/acknowledgment.py`). That acknowledgment is **operator**-side and is deliberately not treated as customer consent. Binding Graph runs to a customer receipt (a new `operation` such as `m365_read` scoped to an Azure tenant id) is follow-up work.
- **Scheduled scans:** `services/connectors/drift/scheduler.py` stores schedules but nothing in this codebase dispatches scans from them. Any future executor **must** dispatch through the initiate routes or call `ScanExecutionGuard.worker_start()`.
- **Retries:** `mark_failed` records `next_retry_at`, but no retry executor exists and `recover_orphans()` is not wired to a caller. Any future retry path re-enters `worker_start()`, which re-reads authorization, so a retry after authorization loss is denied (`test_retry_after_authorization_loss_is_denied`).

## 14. Legacy migration behaviour

- Existing `fa_scan_authorizations` rows get `customer_receipt_id = NULL`. They are **not** grandfathered: decisions report `consent_status=LEGACY_OPERATOR_ASSERTED`.
- In production and staging, legacy scopes **stop authorizing scans** and cannot be activated (`CUSTOMER_AUTHORIZATION_REQUIRED`). Operators must obtain a customer receipt and create a bound scope. **This is a deliberate fail-closed rollout step and must be planned before deploy.**
- No approvals are fabricated and no rows are rewritten.

## 15. Key management requirements

| Variable | Purpose |
|---|---|
| `FG_SCAN_CONSENT_ATTESTATION_KEYS` | JSON `{kid: hex}`. Keys shorter than 32 bytes are ignored. |
| `FG_SCAN_CONSENT_ATTESTATION_ACTIVE_KID` | Key id used for new approvals |
| `FG_SCAN_CONSENT_ATTESTATION_REVOKED_KIDS` | Comma-separated revoked key ids. A revoked key fails verification of receipts it attested and cannot be used for new approvals. |

- **Rotation:** add the new kid, switch the active kid, and keep the old kid in the ring until its receipts' windows close.
- **Compromise:** add the kid to the revoked list. Receipts it attested immediately stop authorizing, so the customer must re-approve.
- Keys must come from the secret store at runtime. **No key is committed to this repository**, and production has no default. Without a key, production approval fails closed.
- Key material is never logged; keyring parse errors do not echo values.
- An HSM or Vault Transit-backed asymmetric signer (customer-verifiable) is L14-SCAN-VAULT-001.

## 16. Operational failure scenarios

| Failure | Behaviour |
|---|---|
| DB unavailable at dispatch | `check_scan_authorized` → `*_LOOKUP_FAILED`/`*_CHECK_FAILED` → 403 |
| DB unavailable at worker start or checkpoint | `AUTHORIZATION_STORE_UNAVAILABLE` → no new outbound work; best-effort denial record |
| Attestation key missing in production | Approval refused (`ATTESTATION_KEY_UNAVAILABLE`); existing attested receipts still verify if their kid stays in the ring |
| Keyring malformed | Approval and verification fail closed (`ATTESTATION_KEYRING_MALFORMED`) |
| Process restart mid-scan | Stop and cancel state is durable; a cancelled job can never be revived |
| Environment undeterminable | Treated as production (consent and attestation required) |

## 17. Remaining limitations

1. **Customer-held signature not implemented.** The proof level is a server attestation (§4).
2. **Graph-family connectors** have no customer receipt binding, no per-page checkpoints, and still emit `scan.completed` after a refused CAS (§13).
3. **DNS rebinding:** the SSRF validator resolves and validates each hop, but httpx re-resolves on connect (no IP pinning). A rebinding window between validation and connect remains. Scope is bound to hostnames, so a rebound IP stays attributed to the approved host. Pinning is a follow-up (L14-SCAN-SAFETY-002).
4. **In-flight requests are not aborted;** the observation boundary is per target or hop (§8).
5. **No database RLS on 0200/0201/0203 tables.** Tenant isolation is enforced by mandatory application predicates. (Observed and not changed here: migration 0095's FA RLS policy reads `app.current_tenant_id`, while `set_tenant_context` sets `app.tenant_id`.)
6. **Receipt-to-evidence binding** is carried in the raw scan payload (`authorization_context`), not yet in the PR #810 `ScannerEvidenceEnvelope`. That is L14-SCAN-RUNNER-INTEGRITY-001.
7. `recover_orphans()` is not wired; worker-crash finalization relies on the next delivery.
8. Migration 0203 replay is validated in CI only. Local replay requires resetting the dev database, which was not done.

## 18. FVA-01 status and proof

**Status: `PARTIALLY_IMPLEMENTED`** (unchanged, with a narrowed remaining scope).

Proven for network, DNS/email and web-header scanners:

- authenticated customer approval;
- exact engagement, target and operation binding;
- operator authority;
- dispatch, worker-start and per-boundary revalidation;
- revocation, expiry and emergency stop block new work;
- cancellation cannot be overwritten;
- cross-tenant denial;
- audit evidence.

Not proven, which blocks `IMPLEMENTED`:

- the seven Graph-family connector paths (§13);
- a customer-verifiable signature;
- DNS rebinding pinning.

## 19. First-client assessment implications

- **Target-based external scanning** (network, DNS, web headers) for a first client can now be run with authenticated, attested customer consent and execution-time enforcement, once the attestation key ring is provisioned.
- Before deploying, **migrate active engagements:** each needs a customer receipt approved by a `tenant_admin` or `client_security_owner` using interactive SSO, and a re-created bound scope. Legacy scopes stop authorizing in production.
- **M365/Graph assessments** remain authorized by the customer administrator's interactive device-code login. Reports must not describe them as covered by a FrostGate customer receipt.
- Reports can cite `authorization_context` (receipt id, proof level, scope version) from each scan's raw payload as the authorization basis for collection.
