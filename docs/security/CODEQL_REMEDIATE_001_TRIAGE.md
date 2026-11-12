# CODEQL-REMEDIATE-001: CodeQL alert triage

Snapshot: **125 open alerts** on `main` at `7d39e51c`, read from the code-scanning API on 2026-11-12. CodeQL default setup was enabled that day; its first analyses ran at 20:14–20:17Z, and every alert has `created_at` 2026-11-12. These are pre-existing code newly scanned, not regressions. 120 are high and 5 medium. All come from CodeQL and cover 54 files.

No alert has been dismissed, and no rule, path or severity has been changed. A false-positive *candidate* stays open until its site has been verified individually. CodeQL alerts close only when a fix reaches `main` and is re-analysed.

## Dispositions

| Disposition | Count | Meaning |
|---|---|---|
| FIXED_THIS_PR | 1 | Remediated by this PR, with exploit tests |
| CONFIRMED_MEDIUM | 1 | Exploitable; fix scheduled |
| LIKELY_REAL_MEDIUM | 1 | Sampled site leaks a sensitive value; fix scheduled |
| CONFIRMED_LOW | 7 | Exploitable but contained; hardening scheduled |
| IN_FLIGHT_OTHER_BRANCH | 18 | Being fixed on branch `security/codeql-remediate-001-ui-path-containment` |
| DESIGN_REVIEW | 1 | Intentional design that needs a security decision |
| FALSE_POSITIVE | 14 | Verified at the site: not a vulnerability |
| FALSE_POSITIVE_CANDIDATE | 24 | Group evidence says not exploitable; per-site check pending |
| NEEDS_TRIAGE | 58 | Not yet inspected at the site |

## By rule

| Rule | Severity | Count |
|---|---|---|
| `py/clear-text-logging-sensitive-data` | high | 46 |
| `py/path-injection` | high | 38 |
| `py/incomplete-url-substring-sanitization` | high | 12 |
| `py/weak-sensitive-data-hashing` | high | 10 |
| `py/clear-text-storage-sensitive-data` | high | 8 |
| `py/stack-trace-exposure` | medium | 3 |
| `js/polynomial-redos` | high | 1 |
| `js/incomplete-sanitization` | high | 1 |
| `py/insecure-protocol` | high | 1 |
| `py/regex-injection` | high | 1 |
| `py/polynomial-redos` | high | 1 |
| `py/cookie-injection` | medium | 1 |
| `py/sql-injection` | high | 1 |
| `py/url-redirection` | medium | 1 |

## Root-cause groups and evidence

1. **Unvalidated post-login redirect** (`py/url-redirection` #125). **Confirmed and fixed here.**
   - `/auth/login` stored any `return_to` value, and after a successful OIDC login `/auth/callback` redirected to it unvalidated. That callback sink is the production path.
   - CodeQL flagged only the dev-bypass sink. It missed the callback because the value passes through `app.state`.
   - Exploit: without authentication, `…/auth/login?return_to=https://evil.example` lands the operator on the attacker's site after a genuine SSO login. On `main` the callback returns `Location: https://evil.example/phish`.
2. **SQL built with f-strings from validated inputs** (`py/sql-injection` #124). **False positive.**
   - `sort_dir` is checked against `frozenset({"asc","desc"})`, with a 422 otherwise, before it is interpolated.
   - The `WHERE` parts are fixed literals with bound parameters, `tenant_id` included.
   - Column names come from the database's own schema metadata, never the client.
   - Optional hardening: map `sort_dir` to the literals `ASC`/`DESC`, as `api/rag_corpus_console.py` already does.
3. **Filesystem paths from identifiers** (`py/path-injection`, 38):
   - **`api/ui_dashboards.py` (18): in flight on another branch.** `packet_id` is a single path segment and downloads need a per-packet token, so a `..` traversal reaches only the parent of the packet root. There is a defence-in-depth gap: the tenant check is skipped when `metadata.json` is absent.
   - **`api/billing.py` (4): confirmed, low.**
     - `invoice_id` and `credit_note_id` are client-chosen at creation and never format-validated.
     - The evidence exports write to `artifacts/billing/<tenant>/<id>/`, where `<tenant>` is the bound tenant. The id comes from a `{param}` path segment, which cannot contain `/`, so the worst case is `..`: it writes the fixed evidence filenames one level up, still inside the caller's own tenant directory.
     - Fix: validate ID format at creation and add a containment check before writing.
   - **`api/admin.py` (5): false-positive candidate.** Each site does `.resolve()` and checks that the parent equals the resolved base (400 otherwise), and the load path also uses `_sanitize_change_id` (regex `fullmatch`).
   - **`services/*` (11): needs triage.** The sinks are in `services/ai/policy.py`, `services/audit_engine/engine.py`, `services/evidence_anchor_extension/service.py` and `services/evidence_index/service.py`.
4. **User-supplied regular expression** (`py/regex-injection` #71, `api/workforce.py`). **Confirmed, medium.** `match_type="regex"` runs a caller pattern with `re.search`, which has no timeout, so an authenticated caller can pin a worker with catastrophic backtracking.
5. **Sensitive values in logs** (`py/clear-text-logging-sensitive-data`, 46). **Needs triage, site by site.** Of the sampled sites, most log tenant IDs or truncated identifiers, but `api/identity_authority/session_authority.py:249` logs a raw `session_id`, so it is likely real.
6. **Hashing flagged as weak** (`py/weak-sensitive-data-hashing`, 10). **False-positive candidates.** These are SHA-256 over high-entropy tokens or API keys used as identifiers or rate-limit keys, over canonical payloads, or as HMAC-SHA256. None stores a password.
7. **Clear-text storage** (`py/clear-text-storage-sensitive-data`, 8):
   - Generator scripts, seed tooling, test artefacts and the billing evidence writer are false-positive candidates.
   - **#10, design review:** `/ui/token` stores the raw API key as an `httponly`, `samesite=lax` cookie that is `secure` in production.
8. **Test and harness code** (`py/incomplete-url-substring-sanitization`, 12; `js/incomplete-sanitization` #2). **False positive:** every site is a test assertion or production-test harness, not a sanitiser.
9. **Smaller groups:**
   - **#72 ReDoS:** the input is a validated, length-bounded tenant ID, so it is a candidate false positive.
   - **#73 cookie injection:** the CSRF token is server-generated, so it is a candidate false positive.
   - **#68–#70 stack-trace exposure:** exception text sits behind status auth or in an error field. Confirmed, low.
   - **#57 TLSv1 allowed:** in the network scanner, likely intentional for probing; needs triage.
   - **#1 JS polynomial ReDoS:** in the Portal route; needs triage.

## Remediation sequence

| # | PR | Alerts |
|---|---|---|
| 1 | **This PR:** open redirect in the admin-gateway login flow | #125 (plus the unreported callback sink) |
| 2 | UI audit-packet path containment (in flight on another branch) | #106–#123 |
| 3 | Billing evidence ID validation and containment | #91–#94 |
| 4 | Bound user-supplied regex (`api/workforce.py`) | #71 |
| 5 | Sensitive-logging triage and fixes, starting with session IDs | 46 logging alerts |
| 6 | `services/*` path-injection triage | #95–#105 |
| 7 | Remaining low items and documented false-positive evidence | the rest |

## Per-alert ledger

| Alert | Rule | Severity | Location | Disposition |
|---|---|---|---|---|
| #1 | `js/polynomial-redos` | high | `apps/portal/app/api/assessment/start/route.ts:60` | NEEDS_TRIAGE |
| #2 | `js/incomplete-sanitization` | high | `apps/console/tests/workspace-integration.test.js:2333` | FALSE_POSITIVE |
| #3 | `py/clear-text-storage-sensitive-data` | high | `api/billing.py:83` | FALSE_POSITIVE_CANDIDATE |
| #4 | `py/clear-text-storage-sensitive-data` | high | `tests/test_customer_zero_e2e/browser_acceptance.py:998` | FALSE_POSITIVE_CANDIDATE |
| #5 | `py/clear-text-storage-sensitive-data` | high | `scripts/contracts_gen_core.py:163` | FALSE_POSITIVE_CANDIDATE |
| #6 | `py/clear-text-storage-sensitive-data` | high | `scripts/contracts_gen_core.py:164` | FALSE_POSITIVE_CANDIDATE |
| #7 | `py/clear-text-storage-sensitive-data` | high | `scripts/patch_compliant_surfaces.py:137` | FALSE_POSITIVE_CANDIDATE |
| #8 | `py/clear-text-storage-sensitive-data` | high | `tools/seed/run_seed.py:292` | FALSE_POSITIVE_CANDIDATE |
| #9 | `py/clear-text-storage-sensitive-data` | high | `tools/seed/run_seed.py:330` | FALSE_POSITIVE_CANDIDATE |
| #10 | `py/clear-text-storage-sensitive-data` | high | `api/ui.py:992` | DESIGN_REVIEW |
| #11 | `py/clear-text-logging-sensitive-data` | high | `api/rag/answering.py:279` | NEEDS_TRIAGE |
| #12 | `py/clear-text-logging-sensitive-data` | high | `api/rag/answering.py:346` | NEEDS_TRIAGE |
| #13 | `py/clear-text-logging-sensitive-data` | high | `api/rag/answering.py:362` | NEEDS_TRIAGE |
| #14 | `py/clear-text-logging-sensitive-data` | high | `api/rag/answering.py:394` | NEEDS_TRIAGE |
| #15 | `py/clear-text-logging-sensitive-data` | high | `api/rag/answering.py:440` | NEEDS_TRIAGE |
| #16 | `py/clear-text-logging-sensitive-data` | high | `api/rag/answering.py:458` | NEEDS_TRIAGE |
| #17 | `py/clear-text-logging-sensitive-data` | high | `api/rag/answering.py:477` | NEEDS_TRIAGE |
| #18 | `py/clear-text-logging-sensitive-data` | high | `api/rag/answering.py:496` | NEEDS_TRIAGE |
| #19 | `py/clear-text-logging-sensitive-data` | high | `api/rag/answering.py:515` | NEEDS_TRIAGE |
| #20 | `py/clear-text-logging-sensitive-data` | high | `services/ops_governance/audit.py:142` | NEEDS_TRIAGE |
| #21 | `py/clear-text-logging-sensitive-data` | high | `api/identity_authority/providers/auth0_provider.py:262` | NEEDS_TRIAGE |
| #22 | `py/clear-text-logging-sensitive-data` | high | `api/behavior_logging.py:350` | NEEDS_TRIAGE |
| #23 | `py/clear-text-logging-sensitive-data` | high | `api/behavior_logging.py:366` | NEEDS_TRIAGE |
| #24 | `py/clear-text-logging-sensitive-data` | high | `api/behavior_logging.py:367` | NEEDS_TRIAGE |
| #25 | `py/clear-text-logging-sensitive-data` | high | `api/billing_integration.py:332` | NEEDS_TRIAGE |
| #26 | `py/clear-text-logging-sensitive-data` | high | `api/billing_integration.py:401` | NEEDS_TRIAGE |
| #27 | `py/clear-text-logging-sensitive-data` | high | `tools/ci/check_github_repo_security.py:824` | NEEDS_TRIAGE |
| #28 | `py/clear-text-logging-sensitive-data` | high | `api/control_plane.py:723` | NEEDS_TRIAGE |
| #29 | `py/clear-text-logging-sensitive-data` | high | `api/control_plane.py:770` | NEEDS_TRIAGE |
| #30 | `py/clear-text-logging-sensitive-data` | high | `api/control_plane.py:779` | NEEDS_TRIAGE |
| #31 | `py/clear-text-logging-sensitive-data` | high | `tools/seed/demo_tenants.py:1224` | NEEDS_TRIAGE |
| #32 | `py/clear-text-logging-sensitive-data` | high | `api/identity_authority/providers/entra_provider.py:419` | NEEDS_TRIAGE |
| #33 | `py/clear-text-logging-sensitive-data` | high | `api/rag/ingest.py:184` | NEEDS_TRIAGE |
| #34 | `py/clear-text-logging-sensitive-data` | high | `api/rag/ingest.py:198` | NEEDS_TRIAGE |
| #35 | `py/clear-text-logging-sensitive-data` | high | `api/rag/ingest.py:213` | NEEDS_TRIAGE |
| #36 | `py/clear-text-logging-sensitive-data` | high | `api/rag/ingest.py:228` | NEEDS_TRIAGE |
| #37 | `py/clear-text-logging-sensitive-data` | high | `api/rag/ingest.py:253` | NEEDS_TRIAGE |
| #38 | `py/clear-text-logging-sensitive-data` | high | `api/rag/ingest.py:272` | NEEDS_TRIAGE |
| #39 | `py/clear-text-logging-sensitive-data` | high | `api/rag/lifecycle.py:219` | NEEDS_TRIAGE |
| #40 | `py/clear-text-logging-sensitive-data` | high | `api/rag/lifecycle.py:276` | NEEDS_TRIAGE |
| #41 | `py/clear-text-logging-sensitive-data` | high | `api/rag/lifecycle.py:290` | NEEDS_TRIAGE |
| #42 | `py/clear-text-logging-sensitive-data` | high | `api/rag/lifecycle.py:355` | NEEDS_TRIAGE |
| #43 | `py/clear-text-logging-sensitive-data` | high | `scripts/patch_compliant_surfaces.py:151` | NEEDS_TRIAGE |
| #44 | `py/clear-text-logging-sensitive-data` | high | `api/rag/provenance.py:255` | NEEDS_TRIAGE |
| #45 | `py/clear-text-logging-sensitive-data` | high | `api/rag_retrieval_policy.py:164` | NEEDS_TRIAGE |
| #46 | `py/clear-text-logging-sensitive-data` | high | `api/rag/retrieval.py:312` | NEEDS_TRIAGE |
| #47 | `py/clear-text-logging-sensitive-data` | high | `api/rag/retrieval.py:368` | NEEDS_TRIAGE |
| #48 | `py/clear-text-logging-sensitive-data` | high | `api/rag/retrieval.py:414` | NEEDS_TRIAGE |
| #49 | `py/clear-text-logging-sensitive-data` | high | `api/auth_scopes/resolution.py:230` | NEEDS_TRIAGE |
| #50 | `py/clear-text-logging-sensitive-data` | high | `api/auth_scopes/resolution.py:287` | NEEDS_TRIAGE |
| #51 | `py/clear-text-logging-sensitive-data` | high | `api/auth_scopes/resolution.py:289` | NEEDS_TRIAGE |
| #52 | `py/clear-text-logging-sensitive-data` | high | `tools/seed/run_seed.py:337` | NEEDS_TRIAGE |
| #53 | `py/clear-text-logging-sensitive-data` | high | `api/identity_authority/session_authority.py:249` | LIKELY_REAL_MEDIUM |
| #54 | `py/clear-text-logging-sensitive-data` | high | `api/stripe_webhooks.py:186` | NEEDS_TRIAGE |
| #55 | `py/clear-text-logging-sensitive-data` | high | `api/usage_attribution.py:259` | NEEDS_TRIAGE |
| #56 | `py/clear-text-logging-sensitive-data` | high | `api/usage_attribution.py:275` | NEEDS_TRIAGE |
| #57 | `py/insecure-protocol` | high | `services/connectors/network_scan/runner.py:84` | NEEDS_TRIAGE |
| #58 | `py/weak-sensitive-data-hashing` | high | `api/identity_authority/audit.py:79` | FALSE_POSITIVE_CANDIDATE |
| #59 | `py/weak-sensitive-data-hashing` | high | `api/credential_authority.py:619` | FALSE_POSITIVE_CANDIDATE |
| #60 | `py/weak-sensitive-data-hashing` | high | `services/connectors/msgraph/findings/derivation.py:16` | FALSE_POSITIVE_CANDIDATE |
| #61 | `py/weak-sensitive-data-hashing` | high | `services/identity_assurance/engine.py:93` | FALSE_POSITIVE_CANDIDATE |
| #62 | `py/weak-sensitive-data-hashing` | high | `agent/app/rate_limit/keys.py:7` | FALSE_POSITIVE_CANDIDATE |
| #63 | `py/weak-sensitive-data-hashing` | high | `api/identity_authority/session_authority.py:176` | FALSE_POSITIVE_CANDIDATE |
| #64 | `py/weak-sensitive-data-hashing` | high | `services/field_assessment/store.py:46` | FALSE_POSITIVE_CANDIDATE |
| #65 | `py/weak-sensitive-data-hashing` | high | `services/field_assessment/store.py:52` | FALSE_POSITIVE_CANDIDATE |
| #66 | `py/weak-sensitive-data-hashing` | high | `services/field_assessment/store.py:57` | FALSE_POSITIVE_CANDIDATE |
| #67 | `py/weak-sensitive-data-hashing` | high | `api/token_useage.py:88` | FALSE_POSITIVE_CANDIDATE |
| #68 | `py/stack-trace-exposure` | medium | `api/main.py:1130` | CONFIRMED_LOW |
| #69 | `py/stack-trace-exposure` | medium | `api/main.py:1174` | CONFIRMED_LOW |
| #70 | `py/stack-trace-exposure` | medium | `api/rag_corpus_ingestion.py:498` | CONFIRMED_LOW |
| #71 | `py/regex-injection` | high | `api/workforce.py:1281` | CONFIRMED_MEDIUM |
| #72 | `py/polynomial-redos` | high | `api/tenant_identity_authority.py:54` | FALSE_POSITIVE_CANDIDATE |
| #73 | `py/cookie-injection` | medium | `admin_gateway/auth/csrf.py:182` | FALSE_POSITIVE_CANDIDATE |
| #74 | `py/incomplete-url-substring-sanitization` | high | `tools/testing/production/auth_harness_001.py:209` | FALSE_POSITIVE |
| #75 | `py/incomplete-url-substring-sanitization` | high | `tools/testing/production/auth_harness_001.py:1137` | FALSE_POSITIVE |
| #76 | `py/incomplete-url-substring-sanitization` | high | `tests/test_scan_accuracy/test_dns_email_accuracy.py:426` | FALSE_POSITIVE |
| #77 | `py/incomplete-url-substring-sanitization` | high | `tests/identity_authority/test_entra_provider.py:35` | FALSE_POSITIVE |
| #78 | `py/incomplete-url-substring-sanitization` | high | `tests/identity_authority/test_entra_provider.py:41` | FALSE_POSITIVE |
| #79 | `py/incomplete-url-substring-sanitization` | high | `tests/agent/test_release_signing_deployment_guide.py:141` | FALSE_POSITIVE |
| #80 | `py/incomplete-url-substring-sanitization` | high | `tests/agent/test_requests_advisory_regression.py:149` | FALSE_POSITIVE |
| #81 | `py/incomplete-url-substring-sanitization` | high | `tests/test_security_hardening.py:166` | FALSE_POSITIVE |
| #82 | `py/incomplete-url-substring-sanitization` | high | `tests/test_security_hardening.py:167` | FALSE_POSITIVE |
| #83 | `py/incomplete-url-substring-sanitization` | high | `tests/test_security_middleware.py:283` | FALSE_POSITIVE |
| #84 | `py/incomplete-url-substring-sanitization` | high | `tests/test_security_middleware.py:284` | FALSE_POSITIVE |
| #85 | `py/incomplete-url-substring-sanitization` | high | `tests/agent/test_silent_enrollment_install_flow.py:380` | FALSE_POSITIVE |
| #86 | `py/path-injection` | high | `api/admin.py:339` | FALSE_POSITIVE_CANDIDATE |
| #87 | `py/path-injection` | high | `api/admin.py:342` | FALSE_POSITIVE_CANDIDATE |
| #88 | `py/path-injection` | high | `api/admin.py:345` | FALSE_POSITIVE_CANDIDATE |
| #89 | `py/path-injection` | high | `api/admin.py:3107` | FALSE_POSITIVE_CANDIDATE |
| #90 | `py/path-injection` | high | `api/admin.py:3111` | FALSE_POSITIVE_CANDIDATE |
| #91 | `py/path-injection` | high | `api/billing.py:80` | CONFIRMED_LOW |
| #92 | `py/path-injection` | high | `api/billing.py:82` | CONFIRMED_LOW |
| #93 | `py/path-injection` | high | `api/billing.py:86` | CONFIRMED_LOW |
| #94 | `py/path-injection` | high | `api/billing.py:86` | CONFIRMED_LOW |
| #95 | `py/path-injection` | high | `services/audit_engine/engine.py:549` | NEEDS_TRIAGE |
| #96 | `py/path-injection` | high | `services/audit_engine/engine.py:550` | NEEDS_TRIAGE |
| #97 | `py/path-injection` | high | `services/audit_engine/engine.py:555` | NEEDS_TRIAGE |
| #98 | `py/path-injection` | high | `services/ai/policy.py:145` | NEEDS_TRIAGE |
| #99 | `py/path-injection` | high | `services/ai/policy.py:540` | NEEDS_TRIAGE |
| #100 | `py/path-injection` | high | `services/evidence_anchor_extension/service.py:83` | NEEDS_TRIAGE |
| #101 | `py/path-injection` | high | `services/evidence_anchor_extension/service.py:83` | NEEDS_TRIAGE |
| #102 | `py/path-injection` | high | `services/evidence_anchor_extension/service.py:85` | NEEDS_TRIAGE |
| #103 | `py/path-injection` | high | `services/evidence_index/service.py:32` | NEEDS_TRIAGE |
| #104 | `py/path-injection` | high | `services/evidence_index/service.py:32` | NEEDS_TRIAGE |
| #105 | `py/path-injection` | high | `services/evidence_index/service.py:31` | NEEDS_TRIAGE |
| #106 | `py/path-injection` | high | `api/ui_dashboards.py:292` | IN_FLIGHT_OTHER_BRANCH |
| #107 | `py/path-injection` | high | `api/ui_dashboards.py:296` | IN_FLIGHT_OTHER_BRANCH |
| #108 | `py/path-injection` | high | `api/ui_dashboards.py:303` | IN_FLIGHT_OTHER_BRANCH |
| #109 | `py/path-injection` | high | `api/ui_dashboards.py:791` | IN_FLIGHT_OTHER_BRANCH |
| #110 | `py/path-injection` | high | `api/ui_dashboards.py:802` | IN_FLIGHT_OTHER_BRANCH |
| #111 | `py/path-injection` | high | `api/ui_dashboards.py:846` | IN_FLIGHT_OTHER_BRANCH |
| #112 | `py/path-injection` | high | `api/ui_dashboards.py:854` | IN_FLIGHT_OTHER_BRANCH |
| #113 | `py/path-injection` | high | `api/ui_dashboards.py:865` | IN_FLIGHT_OTHER_BRANCH |
| #114 | `py/path-injection` | high | `api/ui_dashboards.py:873` | IN_FLIGHT_OTHER_BRANCH |
| #115 | `py/path-injection` | high | `api/ui_dashboards.py:879` | IN_FLIGHT_OTHER_BRANCH |
| #116 | `py/path-injection` | high | `api/ui_dashboards.py:913` | IN_FLIGHT_OTHER_BRANCH |
| #117 | `py/path-injection` | high | `api/ui_dashboards.py:917` | IN_FLIGHT_OTHER_BRANCH |
| #118 | `py/path-injection` | high | `api/ui_dashboards.py:917` | IN_FLIGHT_OTHER_BRANCH |
| #119 | `py/path-injection` | high | `api/ui_dashboards.py:920` | IN_FLIGHT_OTHER_BRANCH |
| #120 | `py/path-injection` | high | `api/ui_dashboards.py:927` | IN_FLIGHT_OTHER_BRANCH |
| #121 | `py/path-injection` | high | `api/ui_dashboards.py:928` | IN_FLIGHT_OTHER_BRANCH |
| #122 | `py/path-injection` | high | `api/ui_dashboards.py:938` | IN_FLIGHT_OTHER_BRANCH |
| #123 | `py/path-injection` | high | `api/ui_dashboards.py:941` | IN_FLIGHT_OTHER_BRANCH |
| #124 | `py/sql-injection` | high | `api/rag_corpus_ingestion.py:964` | FALSE_POSITIVE |
| #125 | `py/url-redirection` | medium | `admin_gateway/routers/auth.py:61` | FIXED_THIS_PR |
