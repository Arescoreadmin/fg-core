# CODEQL-REMEDIATE-002: sensitive-data logging inventory

Snapshot: `main` at `7483d15b` (after #865), read from the code-scanning API on 2026-11-13.

- **107 open alerts** in total. After #865 the 18 path-injection alerts #106–#123 read `fixed`; none are dismissed.
- **46** of them are `py/clear-text-logging-sensitive-data`, all rated high by CodeQL. This matches the 46 in the CODEQL-REMEDIATE-001 triage.
- No alert has been dismissed, and no rule, path or severity has been changed.

CodeQL picks its sources by **variable name**: `password`, `secret`, `private`, `token`, `key`. Each site below was therefore classified by reading what actually reaches the sink, not by the label CodeQL attached.

## Result

| Class | Count | Alerts |
|---|---|---|
| P0: raw credential, token, session secret or auth header in a service log | **0** | none confirmed |
| P1: fixed in this PR | 1 | #53, plus four sibling sinks CodeQL did not report |
| P1: deferred | 2 | #31, #52 |
| P2 | 40 | see the ledger |
| FALSE_POSITIVE (complete source-to-sink check) | 2 | #43, #54 |
| FALSE_POSITIVE_CANDIDATE | 1 | #27 |
| **Total** | **46** | |

**No P0 was confirmed.** No sink logs a bearer token, API-key secret, password, cookie or `Authorization` header. The closest case, `key_prefix` in `_log_auth_event` (#49–#51), is always one of three things:
- the literal `"fgk"`;
- the literal `"ag_internal"`;
- the pre-`.` segment of a presented canary credential, truncated to 8 characters.

That last one is the honeytoken detection signal by design, and no `fgk.<token>.<secret>` secret material reaches the log.

## Selected group: session identifiers in `api/identity_authority` (this PR)

**Why this group first.** It is the highest-sensitivity class actually reaching central logs, and it is the session-identifier category the mission names first. It is one service boundary, three modules, with a single fix.

Session ids are the revocation key (`fg:session:revoked:<sid>`) and the per-session correlation handle. They are not bearer credentials, because tokens are HMAC-signed and a `sid` alone does not authenticate. Hence P1 rather than P0.

| Sink | Level | CodeQL | Before | After |
|---|---|---|---|---|
| `session_authority.create_session` (`session_created`) | DEBUG | **#53** | raw `sid` | `sid_ref` |
| `session_authority.revoke_session` (`session_revoked`) | **INFO** | not reported | raw `sid` | `sid_ref` |
| `SessionRevokedError` message (re-raised as `ValueError` by `portal_identity`) | exception | not reported | `session <sid> has been revoked` | `session has been revoked` |
| `IdentityAuditor.emit` log line for `SESSION_CREATED` (`IdentityAuthority.create_session`) | **INFO** | not reported (found in review of #866) | raw `sid` via `**safe_details` | `sid_ref`; raw `sid` omitted from the line |
| `IdentityAuditor.emit` log line for `LOGOUT` | **INFO** | not reported | raw `sid` via `**safe_details` | `sid_ref`; raw `sid` omitted from the line |

The hash-chained identity audit record is unchanged: it is still hashed over, and persisted with, the raw `sid`, because it is the governed forensic store.

**CodeQL on the PR.**
- The first PR analysis flagged **#126**: the `session_created` DEBUG dict, where the name heuristic treats `mfa_verified` as "password".
- Copilot Autofix (`3d4c79f43`, committed by the repo owner) removed `mfa` from that DEBUG line, and #126 then read `fixed`.
- `sid_ref` itself was not flagged.
- MFA status remains on the authoritative `identity.session.created` audit line, which a test asserts.

**`sid_ref` design.**
- `sid_ref = HMAC-SHA256(K_log, sid)[:16]`, where `K_log = HMAC-SHA256(FG_SESSION_SECRET, "fg.identity.session.log-ref.v1")`.
- It is keyed, so a log reader cannot recompute it from a candidate `sid`; an unsalted hash would allow that.
- It is domain-separated from token signing.
- It rotates with `FG_SESSION_SECRET`.
- It is stable for one session, so `session_created`, `identity.session.created`, `session_revoked` and `identity.logout` correlate across the log stream.
- `event_id` still links the log line to the persisted audit record.

## Deferred P1: operator seed tooling prints live API keys (#31, #52)

- `tools/seed/demo_tenants.py` prints newly minted **production demo-tenant API keys** to stdout for an operator to paste into Vercel (`FG_PORTAL_DEMO_TENANT_KEYS`). An `--output` file option exists alongside.
- `tools/seed/run_seed.py` prints local seed credentials.
- Neither runs in CI or in Docker Compose; both are operator- or developer-run.
- Fixing them changes the operator handoff UX and the documented tester flow (`docs/tester_quickstart.md`). The proposed fix: write credentials only to a `0600` file and print redacted references. That needs an operator decision, so it is the **recommended next PR** and not folded in here.

## Remediation groups

| # | Group | Alerts | Class | Recommendation |
|---|---|---|---|---|
| 1 | **This PR:** identity session identifiers | #53 (+4 unreported) | P1 | Fixed: keyed `sid_ref` |
| 2 | Operator seed tooling credential output | #31, #52 | P1 | Next PR: write to a `0600` file, print redacted; needs operator sign-off |
| 3 | Auth-event logging consistency | #49–#51, #28–#30 | P2 | `_log_auth_event` logs raw `tenant_id` and `client_ip`, while `log_tenant_denial_event` hashes both in prod. Align them with a keyed reference. Also confirm the `key_prefix` and `actor_id` invariants in a test. |
| 4 | Identity-provider debug attributes | #21, #32 | P2 | 16-character subject/oid prefix and roles at DEBUG. Consider dropping roles or using keyed refs. |
| 5 | Tenant-scoped operational metadata (RAG, usage, billing, behavior) | #11–#19, #33–#42, #44–#48, #22–#26, #55, #56 | P2 | Logs `tenant_id`, counts, error codes and 8-character id prefixes, mostly at DEBUG. Candidate for one policy decision on `tenant_id` in logs, rather than per-site edits. |
| 6 | Ops-governance audit log line | #20 | P2 | The audit record is filtered by `_SAFE_DETAIL_KEYS` by design. Needs a design review, not a code change. |
| 7 | False-positive evidence | #43, #54, #27 | FP | Keep open with documented evidence; never dismiss to manufacture progress. |

## Unreported sinks outside this boundary

A sweep for every `"sid"`/`"session_id"` dict key and session-id log argument in `api/`, `admin_gateway/` and `services/` found one more authentication-session sink, which CodeQL did not report:

- `admin_gateway/auth/session.py:180` logs `session.session_id` at DEBUG, only for already-expired sessions.
- Admin-gateway sessions are HMAC-signed cookies, so the id is not a bearer credential.
- P2, a separate service boundary, so a separate PR.

The other hits use "session" for unrelated things (audit-engine cycles, AI-console chat, cp-terminal, workforce) or are serialisation, not logging.

## Related finding outside this mission

**#125 (`py/url-redirection`) is still open on `main`.** It has moved to `admin_gateway/routers/auth.py:91`, the dev-bypass redirect. The #864 fix validates the redirect value with `_safe_return_to`, but CodeQL does not model that function as a sanitizer. The PR-head analysis for #864 did not count as confirmation. Track this as its own follow-up.

## Per-alert ledger

| Alert | Location | Logged value (verified) | Class | Group |
|---|---|---|---|---|
| #11 | `api/rag/answering.py:279` | trusted `tenant_id`, error code (mixed-tenant rejection) | P2 | 5 |
| #12 | `api/rag/answering.py:346` | `tenant_id`, reason code | P2 | 5 |
| #13 | `api/rag/answering.py:362` | `tenant_id`, reason code | P2 | 5 |
| #14 | `api/rag/answering.py:394` | `tenant_id`, counts | P2 | 5 |
| #15 | `api/rag/answering.py:440` | `tenant_id`, reason code | P2 | 5 |
| #16 | `api/rag/answering.py:458` | `tenant_id`, reason code | P2 | 5 |
| #17 | `api/rag/answering.py:477` | `tenant_id`, reason code | P2 | 5 |
| #18 | `api/rag/answering.py:496` | `tenant_id`, reason code | P2 | 5 |
| #19 | `api/rag/answering.py:515` | `tenant_id`, reason code | P2 | 5 |
| #20 | `services/ops_governance/audit.py:142` | audit record; details filtered by `_SAFE_DETAIL_KEYS` | P2 | 6 |
| #21 | `api/identity_authority/providers/auth0_provider.py:262` | `sub[:16]`, roles, MFA flag (DEBUG) | P2 | 4 |
| #22 | `api/behavior_logging.py:350` | `tenant_id`, `event_id[:8]` (DEBUG) | P2 | 5 |
| #23 | `api/behavior_logging.py:366` | `tenant_id` (DEBUG) | P2 | 5 |
| #24 | `api/behavior_logging.py:367` | event type (DEBUG) | P2 | 5 |
| #25 | `api/billing_integration.py:332` | `tenant_id`, `invoice_id[:8]` (DEBUG) | P2 | 5 |
| #26 | `api/billing_integration.py:401` | `tenant_id`, `customer_id[:8]`, totals (DEBUG) | P2 | 5 |
| #27 | `tools/ci/check_github_repo_security.py:824` | policy finding descriptions (CLI) | FALSE_POSITIVE_CANDIDATE | 7 |
| #28 | `api/control_plane.py:723` | WS auth reason, `key_prefix` (`fgk`/canary/None) | P2 | 3 |
| #29 | `api/control_plane.py:770` | `tenant_id`, `actor_id` (= `key_prefix[:32]`) | P2 | 3 |
| #30 | `api/control_plane.py:779` | subscriber id, `tenant_id`, `actor_id` | P2 | 3 |
| #31 | `tools/seed/demo_tenants.py:1224` | **minted demo-tenant API keys** (CLI stdout) | P1 | 2 |
| #32 | `api/identity_authority/providers/entra_provider.py:419` | `sub[:16]`, `oid[:16]`, tid, roles (DEBUG) | P2 | 4 |
| #33 | `api/rag/ingest.py:184` | `tenant_id`, error code | P2 | 5 |
| #34 | `api/rag/ingest.py:198` | `tenant_id`, doc index, error code | P2 | 5 |
| #35 | `api/rag/ingest.py:213` | `tenant_id`, doc index, error code | P2 | 5 |
| #36 | `api/rag/ingest.py:228` | `tenant_id`, doc index, error code | P2 | 5 |
| #37 | `api/rag/ingest.py:253` | `tenant_id`, error code | P2 | 5 |
| #38 | `api/rag/ingest.py:272` | `tenant_id`, counts | P2 | 5 |
| #39 | `api/rag/lifecycle.py:219` | `tenant_id`, `source_id`, `document_id`, counts (INFO) | P2 | 5 |
| #40 | `api/rag/lifecycle.py:276` | `tenant_id`, operation | P2 | 5 |
| #41 | `api/rag/lifecycle.py:290` | `tenant_id`, operation | P2 | 5 |
| #42 | `api/rag/lifecycle.py:355` | `tenant_id`, counts | P2 | 5 |
| #43 | `scripts/patch_compliant_surfaces.py:151` | constant repo path `api/billing.py` | FALSE_POSITIVE | 7 |
| #44 | `api/rag/provenance.py:255` | `tenant_id`, counts, flags (DEBUG) | P2 | 5 |
| #45 | `api/rag_retrieval_policy.py:164` | `tenant_id`, actor key prefix, policy flags | P2 | 5 |
| #46 | `api/rag/retrieval.py:312` | `tenant_id`, counts (DEBUG) | P2 | 5 |
| #47 | `api/rag/retrieval.py:368` | `tenant_id`, counts | P2 | 5 |
| #48 | `api/rag/retrieval.py:414` | `tenant_id`, counts | P2 | 5 |
| #49 | `api/auth_scopes/resolution.py:230` | tenant-denial event: hashed tenant, `key_id` prefix, route | P2 | 3 |
| #50 | `api/auth_scopes/resolution.py:287` | auth event: `key_prefix[:8]`, raw `tenant_id`, `client_ip`, path | P2 | 3 |
| #51 | `api/auth_scopes/resolution.py:289` | same as #50 (failure branch) | P2 | 3 |
| #52 | `tools/seed/run_seed.py:337` | **local seed API keys** (CLI stdout) | P1 | 2 |
| #53 | `api/identity_authority/session_authority.py:249` | **raw session id** (plus 4 unreported sibling sinks) | P1 | **1: fixed in this PR** |
| #54 | `api/stripe_webhooks.py:186` | one of four module-constant reason codes | FALSE_POSITIVE | 7 |
| #55 | `api/usage_attribution.py:259` | `tenant_id`, `usage_id[:8]` (DEBUG) | P2 | 5 |
| #56 | `api/usage_attribution.py:275` | `tenant_id`, action, units (DEBUG) | P2 | 5 |
