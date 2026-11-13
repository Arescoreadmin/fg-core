# CODEQL-REMEDIATE-005: CodeQL burn-down inventory and remediation waves

Baseline: `main` `3024ad92` (#869 merged), refreshed by CODEQL-REMEDIATE-006. Python analysis 2164346692 and JavaScript analysis 2164327094 were both run on that commit and read 2026-11-13. There are **96 open alerts and 0 dismissed**.

The original baseline was `main` `7102fd5e` with 102 open alerts. Wave 1 (#100–#105, PR #869) is **confirmed `fixed`** by analysis 2164346692 on `3024ad92`, with 0 dismissals.

Machine-readable inventory: `docs/security/CODEQL_REMEDIATE_005_INVENTORY.json`, schema `fg.codeql.burndown.v1`. It has one row per open alert, with:
- rule, location and SARIF source;
- cluster and wave;
- classification and evidence level;
- production reachability, auth, tenant impact and secret exposure.

## How to read this

- **Classification:**
  - `GENUINE`: a real weakness on a production path.
  - `GENUINE_LOW`: real, but bounded impact.
  - `FALSE_POSITIVE_CANDIDATE`: an existing control CodeQL does not model. **Dismissal needs operator approval;** nothing has been dismissed.
  - `NEEDS_VERIFICATION`, `NON_PRODUCTION` and `DEV_ONLY` mean what they say.
- **Evidence:**
  - `VERIFIED_EXPLOIT`: reproduced with synthetic inputs.
  - `VERIFIED_CODE`: source-to-sink read in code, including the controls.
  - `PATTERN_ESTIMATE`: classified from the rule, source and location only. These are **estimates**; verify before acting on them.
- Scores and waves are analyst judgement. Alert counts and states are facts from the API.

| Classification | Count |
|---|---|
| GENUINE | 5 |
| GENUINE_LOW | 7 |
| NEEDS_VERIFICATION | 18 |
| FALSE_POSITIVE_CANDIDATE | 45 |
| NON_PRODUCTION | 19 |
| DEV_ONLY | 2 |

## #10 (first investigation target): dev-only, not exploitable in production

`GET /ui/token` copies the caller's `x-api-key` into the `fg_api_key` cookie, so the raw API key does sit in a cookie. Every other part of the reported concern was checked:

| Question | Finding | Evidence |
|---|---|---|
| Reachable in production? | **No.** `build_app` mounts the UI routers only when `FG_ENV` is not `prod`/`production`/`staging`. The Dockerfile, Helm values and compose all default `FG_ENV=prod`. | Prod-profile build: 0 `/ui` routes mounted |
| Cookie accepted as a credential in production? | **No.** `api/auth_scopes/resolution.py` and `api/main.py` refuse cookie keys in prod-like envs (same three-value predicate). | Code |
| Raw long-lived credential? | Yes in dev: the key the caller already presented, after the auth gate validated it. An invalid key gets 401 and no cookie. | Dev build: 401 for an invalid key; a valid key is echoed into the cookie |
| Readable by JS? | No: `HttpOnly`, `SameSite=Lax`, `Max-Age=28800`. `Secure` is set only in prod, where the route is not mounted. | Dev `Set-Cookie` |
| Revocation and expiry | The key is re-validated on every request, so revocation applies at once. The cookie expires after 8 h. There is no logout route. | Code |
| Cross-tenant | None: the cookie carries the caller's own key and is checked per request. | Code |

Disposition: `DEV_ONLY`, no code change. A future identity migration to opaque UI sessions is optional hardening, not a security fix.

## Clusters and waves (one PR each; predictions are labelled)

| Wave | Cluster | Alerts | Root cause, fix boundary | Severity, exploitability | Effort | Predicted CodeQL result |
|---|---|---|---|---|---|---|
| 1 (**fixed**, #869, confirmed on `main`) | C1 | #100–#105 | `POST /evidence/anchors` (`compliance:read`) and `POST /evidence/runs/register` (`admin:write`) hash a **caller-supplied server path**. Fix: `services/artifact_paths.py` containment in the artifact root. | **High.** Any tenant key with a read scope gets a server-wide existence oracle, the SHA-256 of any readable file, a forged provenance record and an unbounded read. Reproduced. | S | #100–#105 close (prediction) |
| **2 (CODEQL-REMEDIATE-006)** | C2 | #95–#97 | Audit export file name is built from raw query `start`/`end` (`/` allowed) and has no tenant segment; exam export reads the file back by path. Fix: strict UTC window validation, a tenant namespace, a contained path, and an in-memory exam payload. | **High.** Write outside the export root; a concurrent same-window export by another tenant lands in an exam archive. Both reproduced. Needs `audit:export` + capability. | S–M | #95–#97 close (prediction) |
| 3 | C3 | #1, #72 | Backtracking-prone regex over unbounded input. #1 is the **unauthenticated** portal `POST /api/assessment/start` email check (per-IP rate limit keyed on proxy headers; spoofable only where the platform does not overwrite them). Fix: bound the length before matching, and use an unambiguous pattern. | **Medium.** Unauthenticated CPU burn on Vercel. | XS | #1, #72 close (prediction) |
| 4 | C4 | #91–#94, #3 | Billing evidence directories use client-chosen `invoice_id`/`credit_note_id`. Path params limit HTTP reach to `.`/`..`. Fix: validate the id format at creation, and contain the path. | Low–medium. Escape to the shared billing root. | S | #91–#94 close; #3 may close (prediction) |
| 5 | C5 | #71 | Tenant-supplied regex run with `re.search` and no timeout. Fix needs an **operator decision**: allow regex with an `re2`-style engine (new dependency), or restrict to literal/prefix plus a length cap. | **Medium.** An `admin:write` holder can stall a shared worker for all tenants. | S | #71 closes (prediction) |
| 6 | C6 | #68–#70 | `str(exc)` returned to clients. Fix: generic error plus a correlation id; detail goes to the log only. | Low–medium. Information disclosure to authenticated callers. | S | #68–#70 close (prediction) |
| 7 | C7 | #20, #21, #28–#30, #32, #45, #49–#51, #54 | Auth- and credential-adjacent log lines. #28–#30 and #49–#51 are verified to carry `key_prefix`/normalized fields only; the rest need checking. | Low. | S | Mostly an evidence pack; code only where a full value is found |
| 8 | C8 | #58–#67 | SHA-256 over values CodeQL names as passwords. Expected to be high-entropy tokens (lookup digests). Verify every input; use a keyed hash where any is low-entropy. | Unknown until verified. | S | Evidence pack; possible dismissals (operator) |
| 9 | C9, C10 | 39 alerts | Controls CodeQL does not model (`change_id` fullmatch, `sort_dir` allowlist, default TLS context), plus `trusted_tenant_id` logged as a "secret". #98–#99 need verification. | None verified. | S | Dismissal decision only, with evidence (**operator approval required**) |
| 10 | C11 | 19 alerts | Tests, CI tools, offline scripts. | Not production. | S | Hygiene |
| — | C12 | #10, #73, #125 | Dev-only surfaces and the CSRF token cookie. | Dev only. | — | Tracked |

Risk eliminated is tracked separately from alert count: waves 1–3 remove the verified high and medium exposures (11 alerts; 6 confirmed fixed). Waves 7–10 mostly turn into evidence for operator decisions, not code.

## Wave 2 (CODEQL-REMEDIATE-006): audit export authority

### Trust boundary as found on `main` `3024ad92`

| Step | Finding |
|---|---|
| Request | `GET /audit/export` (`audit:export` + capability `audit.export`) passed raw `start`/`end` to `AuditEngine.export_bundle`. No format, length or order check. `POST /audit/exams/run` (`audit:write`) stored raw `window_start_utc`/`window_end_utc` the same way. |
| Tenant | Taken from the bound key (`require_bound_tenant`); records are tenant-filtered. **The file name had no tenant part.** |
| Filesystem | Name `audit_export_{start}_{end}.json` with only `:` and `-` stripped. `atomic_write` creates parents, so `/` and `..` (also as `%2F`) wrote anywhere the service can write, over existing `*.json` files. **Reproduced**: `end=../../../escaped/pwn` wrote a tenant audit bundle outside the export root. |
| Integrity | Two tenants exporting the same window wrote one file. `export_exam_bundle` re-read that file by path before archiving it, so a concurrent export by tenant B landed in tenant A's signed exam archive. **Reproduced.** A failed write left a temporary file beside the target. |
| Retrieval | No route serves files by path. The exam lookup is tenant-filtered, but a missing exam raised an unhandled error (500). |

### Correction (in the existing audit engine; no new authority)

- `validate_export_window`: each bound must be a strict ISO-8601 UTC `...Z` timestamp of at most 32 characters (ASCII digits only), and `start <= end`. Otherwise one fixed `AUDIT_EXPORT_WINDOW_INVALID` (400). Applied on export **and** at exam creation.
- The file name is built from the **parsed** integers, never the caller's string. It sits in a tenant namespace `t-<sha256(tenant_id)[:32]>` under the realpath of `FG_AUDIT_EXPORT_DIR`. A symlinked tenant directory or any resolved path outside it is refused (`AUDIT_EXPORT_STORAGE_INVALID`, 409). The namespace is not an authorization control; no route serves these files.
- Exam export archives the payload it just built in memory; it no longer re-reads the shared file.
- `atomic_write` removes its temporary file on any failure.
- `GET /audit/exams/{id}/export`: an unknown and another tenant's exam both return the same 404 `AUDIT_EXAM_NOT_FOUND`; chain failure returns 409.
- Unchanged: bundle and manifest format, signatures, hashes, the `start`/`end` strings recorded in the bundle, the ledger queries, and the response shape (`path` keeps the configured-root form).

### Residual risk and follow-up: EVIDENCE-ARTIFACT-TENANT-AUTH-001 (P1)

Wave 1 confined `POST /evidence/anchors` and `POST /evidence/runs/register` to `FG_ARTIFACTS_DIR`, but that root is **shared by all tenants**. It holds `decision_evidence/<sequential id>.json` (every tenant), `anchor_receipts/`, and by default `audit_exports/`. **Verified** with a synthetic probe on this branch: a `compliance:read` key for tenant B anchored tenant A's decision evidence and got 200, the correct SHA-256, and an anchor record stored in tenant B. A missing id returned 404, so ids are enumerable.

- Impact: cross-tenant fingerprint and existence disclosure, plus forged provenance. No content is disclosed.
- Treat it as **release-blocking for external multi-tenant use** of these two routes until it is fixed or contained.
- Required change: resolve artifacts through a tenant-owned authority, not a path. `DecisionEvidenceArtifact` already binds `tenant_id` to `storage_path`; anchors and runs need an equivalent owner check, or per-tenant subtrees plus a platform-artifact allowlist. Not in this PR, because it changes the evidence-anchor authority and may need a schema change.

## Repeatable loop for the next waves

Run this after each merge, before branching the next wave:

1. `git fetch origin` and branch from the new `origin/main` only. Never stack waves on an unmerged branch.
2. Refresh the inputs:
   - `gh api --paginate "repos/Arescoreadmin/fg-core/code-scanning/alerts?state=open&per_page=100" > alerts.json`;
   - the SARIF of the latest `main` analyses (`gh api -H "Accept: application/sarif+json" repos/Arescoreadmin/fg-core/code-scanning/analyses/<id>`);
   - confirm the analysis `commit_sha` equals `origin/main`.
3. Regenerate the inventory. The classification script fails closed on any **unclassified** (new) or **stale** (fixed) alert number. Classify new alerts before choosing work, and remove fixed ones.
4. Confirm the previous wave's predictions against the `main` analysis: alert `state == fixed` and `dismissed == 0`. Only then record them as fixed.
5. Pick the highest unfinished wave. Re-score it if new genuine alerts appeared.
6. Red before green with synthetic inputs, then Tier A (focused tests, ruff, mypy), then Tier B gates once, then the PR. Do not push or merge automatically.

## Per-alert table

| # | Rule | Location | Cluster | Class | Evidence | Prod | Note |
|---|---|---|---|---|---|---|---|
| 1 | `polynomial-redos` | `apps/portal/app/api/assessment/start/route.ts:60` | C3 | GENUINE | VERIFIED_CODE | yes (portal, unauthenticated) | ambiguous email regex over unbounded body field: quadratic CPU |
| 2 | `incomplete-sanitization` | `apps/console/tests/workspace-integration.test.js:2333` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 3 | `clear-text-storage-sensitive-data` | `api/billing.py:83` | C4 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | same _atomic_write sink; 'private' label is a name heuristic on credit_note_id |
| 4 | `clear-text-storage-sensitive-data` | `tests/test_customer_zero_e2e/browser_acceptance.py:998` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 5 | `clear-text-storage-sensitive-data` | `scripts/contracts_gen_core.py:163` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 6 | `clear-text-storage-sensitive-data` | `scripts/contracts_gen_core.py:164` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 7 | `clear-text-storage-sensitive-data` | `scripts/patch_compliant_surfaces.py:137` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 10 | `clear-text-storage-sensitive-data` | `api/ui.py:992` | C12 | DEV_ONLY | VERIFIED_EXPLOIT | no (UI routers unmounted; cookie refused in prod-like envs) | verified: prod build mounts 0 /ui routes; dev echoes gate-validated key |
| 11 | `clear-text-logging-sensitive-data` | `api/rag/answering.py:279` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 12 | `clear-text-logging-sensitive-data` | `api/rag/answering.py:346` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 13 | `clear-text-logging-sensitive-data` | `api/rag/answering.py:362` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 14 | `clear-text-logging-sensitive-data` | `api/rag/answering.py:394` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 15 | `clear-text-logging-sensitive-data` | `api/rag/answering.py:440` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 16 | `clear-text-logging-sensitive-data` | `api/rag/answering.py:458` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 17 | `clear-text-logging-sensitive-data` | `api/rag/answering.py:477` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 18 | `clear-text-logging-sensitive-data` | `api/rag/answering.py:496` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 19 | `clear-text-logging-sensitive-data` | `api/rag/answering.py:515` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 20 | `clear-text-logging-sensitive-data` | `services/ops_governance/audit.py:142` | C7 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | yes | provider / policy / webhook / ops-governance logs; verify field contents |
| 21 | `clear-text-logging-sensitive-data` | `api/identity_authority/providers/auth0_provider.py:262` | C7 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | yes | provider / policy / webhook / ops-governance logs; verify field contents |
| 22 | `clear-text-logging-sensitive-data` | `api/behavior_logging.py:350` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 23 | `clear-text-logging-sensitive-data` | `api/behavior_logging.py:366` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 24 | `clear-text-logging-sensitive-data` | `api/behavior_logging.py:367` | C10 | FALSE_POSITIVE_CANDIDATE | PATTERN_ESTIMATE | yes | literal/heuristic sources (behavior_logging, usage_attribution) |
| 25 | `clear-text-logging-sensitive-data` | `api/billing_integration.py:332` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 26 | `clear-text-logging-sensitive-data` | `api/billing_integration.py:401` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 27 | `clear-text-logging-sensitive-data` | `tools/ci/check_github_repo_security.py:824` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 28 | `clear-text-logging-sensitive-data` | `api/control_plane.py:723` | C7 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | ws auth logs carry key_prefix, tenant, actor |
| 29 | `clear-text-logging-sensitive-data` | `api/control_plane.py:770` | C7 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | ws auth logs carry key_prefix, tenant, actor |
| 30 | `clear-text-logging-sensitive-data` | `api/control_plane.py:779` | C7 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | ws auth logs carry key_prefix, tenant, actor |
| 32 | `clear-text-logging-sensitive-data` | `api/identity_authority/providers/entra_provider.py:419` | C7 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | yes | provider / policy / webhook / ops-governance logs; verify field contents |
| 33 | `clear-text-logging-sensitive-data` | `api/rag/ingest.py:184` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 34 | `clear-text-logging-sensitive-data` | `api/rag/ingest.py:198` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 35 | `clear-text-logging-sensitive-data` | `api/rag/ingest.py:213` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 36 | `clear-text-logging-sensitive-data` | `api/rag/ingest.py:228` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 37 | `clear-text-logging-sensitive-data` | `api/rag/ingest.py:253` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 38 | `clear-text-logging-sensitive-data` | `api/rag/ingest.py:272` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 39 | `clear-text-logging-sensitive-data` | `api/rag/lifecycle.py:219` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 40 | `clear-text-logging-sensitive-data` | `api/rag/lifecycle.py:276` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 41 | `clear-text-logging-sensitive-data` | `api/rag/lifecycle.py:290` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 42 | `clear-text-logging-sensitive-data` | `api/rag/lifecycle.py:355` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 43 | `clear-text-logging-sensitive-data` | `scripts/patch_compliant_surfaces.py:151` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 44 | `clear-text-logging-sensitive-data` | `api/rag/provenance.py:255` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 45 | `clear-text-logging-sensitive-data` | `api/rag_retrieval_policy.py:164` | C7 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | yes | provider / policy / webhook / ops-governance logs; verify field contents |
| 46 | `clear-text-logging-sensitive-data` | `api/rag/retrieval.py:312` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 47 | `clear-text-logging-sensitive-data` | `api/rag/retrieval.py:368` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 48 | `clear-text-logging-sensitive-data` | `api/rag/retrieval.py:414` | C10 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | source is trusted_tenant_id; CODEQL-002 classified P2 metadata |
| 49 | `clear-text-logging-sensitive-data` | `api/auth_scopes/resolution.py:230` | C7 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | auth_event / tenant_denial structured logs |
| 50 | `clear-text-logging-sensitive-data` | `api/auth_scopes/resolution.py:287` | C7 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | auth_event / tenant_denial structured logs |
| 51 | `clear-text-logging-sensitive-data` | `api/auth_scopes/resolution.py:289` | C7 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | auth_event / tenant_denial structured logs |
| 54 | `clear-text-logging-sensitive-data` | `api/stripe_webhooks.py:186` | C7 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | yes | provider / policy / webhook / ops-governance logs; verify field contents |
| 55 | `clear-text-logging-sensitive-data` | `api/usage_attribution.py:259` | C10 | FALSE_POSITIVE_CANDIDATE | PATTERN_ESTIMATE | yes | literal/heuristic sources (behavior_logging, usage_attribution) |
| 56 | `clear-text-logging-sensitive-data` | `api/usage_attribution.py:275` | C10 | FALSE_POSITIVE_CANDIDATE | PATTERN_ESTIMATE | yes | literal/heuristic sources (behavior_logging, usage_attribution) |
| 57 | `insecure-protocol` | `services/connectors/network_scan/runner.py:84` | C9 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | ssl.create_default_context(): TLS>=1.2 on Python 3.10+ |
| 58 | `weak-sensitive-data-hashing` | `api/identity_authority/audit.py:79` | C8 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | yes | SHA-256 lookup digests; confirm every input is high-entropy |
| 59 | `weak-sensitive-data-hashing` | `api/credential_authority.py:619` | C8 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | yes | SHA-256 lookup digests; confirm every input is high-entropy |
| 60 | `weak-sensitive-data-hashing` | `services/connectors/msgraph/findings/derivation.py:16` | C8 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | yes | SHA-256 lookup digests; confirm every input is high-entropy |
| 61 | `weak-sensitive-data-hashing` | `services/identity_assurance/engine.py:93` | C8 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | yes | SHA-256 lookup digests; confirm every input is high-entropy |
| 62 | `weak-sensitive-data-hashing` | `agent/app/rate_limit/keys.py:7` | C8 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | yes | SHA-256 lookup digests; confirm every input is high-entropy |
| 63 | `weak-sensitive-data-hashing` | `api/identity_authority/session_authority.py:194` | C8 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | yes | SHA-256 lookup digests; confirm every input is high-entropy |
| 64 | `weak-sensitive-data-hashing` | `services/field_assessment/store.py:46` | C8 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | yes | SHA-256 lookup digests; confirm every input is high-entropy |
| 65 | `weak-sensitive-data-hashing` | `services/field_assessment/store.py:52` | C8 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | yes | SHA-256 lookup digests; confirm every input is high-entropy |
| 66 | `weak-sensitive-data-hashing` | `services/field_assessment/store.py:57` | C8 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | yes | SHA-256 lookup digests; confirm every input is high-entropy |
| 67 | `weak-sensitive-data-hashing` | `api/token_useage.py:88` | C8 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | yes | SHA-256 lookup digests; confirm every input is high-entropy |
| 68 | `stack-trace-exposure` | `api/main.py:1130` | C6 | GENUINE_LOW | VERIFIED_CODE | yes | /health/detailed returns str(exc) |
| 69 | `stack-trace-exposure` | `api/main.py:1174` | C6 | GENUINE_LOW | VERIFIED_CODE | yes | _debug/status path returns exception text |
| 70 | `stack-trace-exposure` | `api/rag_corpus_ingestion.py:498` | C6 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | yes | rag corpus ingestion error field |
| 71 | `regex-injection` | `api/workforce.py:1281` | C5 | GENUINE | VERIFIED_CODE | yes | re.search(user_regex) with no timeout |
| 72 | `polynomial-redos` | `api/tenant_identity_authority.py:54` | C3 | GENUINE_LOW | VERIFIED_CODE | yes | constant regexes over tenant id; bound length |
| 73 | `cookie-injection` | `admin_gateway/auth/csrf.py:182` | C12 | FALSE_POSITIVE_CANDIDATE | PATTERN_ESTIMATE | yes | CSRF cookie value from generated token |
| 74 | `incomplete-url-substring-sanitization` | `tools/testing/production/auth_harness_001.py:209` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 75 | `incomplete-url-substring-sanitization` | `tools/testing/production/auth_harness_001.py:1137` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 76 | `incomplete-url-substring-sanitization` | `tests/test_scan_accuracy/test_dns_email_accuracy.py:426` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 77 | `incomplete-url-substring-sanitization` | `tests/identity_authority/test_entra_provider.py:35` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 78 | `incomplete-url-substring-sanitization` | `tests/identity_authority/test_entra_provider.py:41` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 79 | `incomplete-url-substring-sanitization` | `tests/agent/test_release_signing_deployment_guide.py:141` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 80 | `incomplete-url-substring-sanitization` | `tests/agent/test_requests_advisory_regression.py:149` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 81 | `incomplete-url-substring-sanitization` | `tests/test_security_hardening.py:166` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 82 | `incomplete-url-substring-sanitization` | `tests/test_security_hardening.py:167` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 83 | `incomplete-url-substring-sanitization` | `tests/test_security_middleware.py:283` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 84 | `incomplete-url-substring-sanitization` | `tests/test_security_middleware.py:284` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 85 | `incomplete-url-substring-sanitization` | `tests/agent/test_silent_enrollment_install_flow.py:380` | C11 | NON_PRODUCTION | PATTERN_ESTIMATE | no | tests, CI tooling and offline scripts |
| 86 | `path-injection` | `api/admin.py:339` | C9 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | change_id fullmatch ^[A-Za-z0-9_-]{16,64}$ + resolved-parent check |
| 87 | `path-injection` | `api/admin.py:342` | C9 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | change_id fullmatch ^[A-Za-z0-9_-]{16,64}$ + resolved-parent check |
| 88 | `path-injection` | `api/admin.py:345` | C9 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | change_id fullmatch ^[A-Za-z0-9_-]{16,64}$ + resolved-parent check |
| 89 | `path-injection` | `api/admin.py:3107` | C9 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | change_id fullmatch ^[A-Za-z0-9_-]{16,64}$ + resolved-parent check |
| 90 | `path-injection` | `api/admin.py:3111` | C9 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | change_id fullmatch ^[A-Za-z0-9_-]{16,64}$ + resolved-parent check |
| 91 | `path-injection` | `api/billing.py:80` | C4 | GENUINE_LOW | VERIFIED_CODE | yes | path params cannot carry '/', so reach is '.'/'..' only |
| 92 | `path-injection` | `api/billing.py:82` | C4 | GENUINE_LOW | VERIFIED_CODE | yes | path params cannot carry '/', so reach is '.'/'..' only |
| 93 | `path-injection` | `api/billing.py:86` | C4 | GENUINE_LOW | VERIFIED_CODE | yes | path params cannot carry '/', so reach is '.'/'..' only |
| 94 | `path-injection` | `api/billing.py:86` | C4 | GENUINE_LOW | VERIFIED_CODE | yes | path params cannot carry '/', so reach is '.'/'..' only |
| 95 | `path-injection` | `services/audit_engine/engine.py:549` | C2 | GENUINE | VERIFIED_EXPLOIT | yes | fix in CODEQL-REMEDIATE-006 (validated UTC window, tenant namespace, contained path); open until a main analysis confirms |
| 96 | `path-injection` | `services/audit_engine/engine.py:550` | C2 | GENUINE | VERIFIED_EXPLOIT | yes | fix in CODEQL-REMEDIATE-006 (validated UTC window, tenant namespace, contained path); open until a main analysis confirms |
| 97 | `path-injection` | `services/audit_engine/engine.py:555` | C2 | GENUINE | VERIFIED_EXPLOIT | yes | fix in CODEQL-REMEDIATE-006 (validated UTC window, tenant namespace, contained path); open until a main analysis confirms |
| 98 | `path-injection` | `services/ai/policy.py:145` | C9 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | unknown | AI policy path from tenant id; UI router unmounted in prod; verify other callers |
| 99 | `path-injection` | `services/ai/policy.py:540` | C9 | NEEDS_VERIFICATION | PATTERN_ESTIMATE | unknown | AI policy path from tenant id; UI router unmounted in prod; verify other callers |
| 124 | `sql-injection` | `api/rag_corpus_ingestion.py:964` | C9 | FALSE_POSITIVE_CANDIDATE | VERIFIED_CODE | yes | sort_dir allowlist check before interpolation |
| 125 | `url-redirection` | `admin_gateway/routers/auth.py:91` | C12 | DEV_ONLY | VERIFIED_CODE | dev-bypass only | tracked since CODEQL-001: dev-bypass redirect, _safe_return_to not modelled |
