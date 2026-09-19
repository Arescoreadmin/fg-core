# TENANT-ISOLATION-E2E-001

## Scope and evidence language

Base: `c1afe4d0b040f9cf4f3faec95eadfe92e6b11bfd` (the synchronized
`origin/main` on 2026-09-19).

This proof covers the production Console authority decisions and the Core
administrative routes reachable through them. It does not claim universal
side-channel noninterference or prove unrelated public information is hidden.

- **PROVEN**: exercised through a real route/dependency/persistence path.
- **TESTED**: exercised through the production decision function or a focused
  source-wiring regression.
- **INSPECTED**: traced in production code, without a live external dependency.
- **INFERRED**: conclusion follows from inspected composition, not a full run.
- **NOT TESTED**: technically applicable but unavailable in the local harness.
- **DEFERRED**: valid follow-up outside this PR.

## Threat model

The adversary is an authenticated or unauthenticated browser caller who can
control URLs, duplicate query keys, JSON/form bodies, ordinary browser headers,
cookies sent by the browser, and stale client-side UI state. The caller cannot
read server-only credentials or the gateway delegation HMAC secret. Tenant A is
`high-table-financial` (The High Table Financial), Tenant B is
`continental-holdings` (Continental Holdings), and the operator context is
`frostgate` (FrostGate). The response sentinels are `ALPHA_ONLY_706`,
`BRAVO_ONLY_706`, and `OPERATOR_ONLY_706`.

The invariant is that requested tenant context is never authority. Missing,
empty, malformed, duplicate, foreign, or contradictory context cannot increase
human authority, and specifically cannot turn a client human into
`CORE_TENANT_ID` operator authority.

## Authority classes

| Repository class | Meaning | Tenant behavior |
| --- | --- | --- |
| `console_enabled_client` + `tenant_admin` | Tenant Admin human | Exactly the valid canonical session tenant; missing request context derives that tenant |
| `internal_console` + `Administrator`/`Support` | Platform Admin human | Explicit cross-tenant selection; configured operator fallback only when context is absent |
| Other `internal_console` roles | Internal operational human | No gateway-backed human administration; existing non-admin operational policies remain |
| Tenant credential | Service-to-service | Credential-bound tenant in Core |
| Public invitation | Token/named-user acceptance workflow | Tenant-independent at BFF; invitation resolves tenant in Core |
| Anonymous/portal-only/unsupported | No Console authority | Denied |

Support remains a Platform Admin because `PLATFORM_ADMIN_ROLES` canonically
contains `Support` and `Administrator`. Developer, Operator, FieldAssessor, and
future internal roles are not promoted to Platform Admin.

## Console BFF route inventory

| Browser route | BFF route | Core/persistence target | Methods | Mode | Tenant source and conflicts | Missing behavior | Core/persistence boundary |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `/admin/tenants` | `/api/tenants` | Edge Config tenant registry | GET | Tenant Admin own-org or Platform Admin global | Session only for Tenant Admin; no query/body/header authority | Tenant Admin without a valid session binding: 403 | Tenant Admin short-circuits before registry fetch; Platform Admin may read registry |
| `/admin/tenants` | `/api/admin/provision-tenant` | Core provisioning plus Edge Config/Upstash registry | POST | Platform Admin | Session positive allowlist; requested tenant is provisioning input, not caller authority | N/A | Tenant Admin denied before secrets or writes |
| Tenant administration | `/api/email` | Email provider | POST | Platform Admin | Session positive allowlist; body is content, not tenant authority | N/A | Generic arbitrary dispatch remains Platform Admin only |
| Console pages | `/api/core/[...path]` | Dynamic Core allowlist | GET/POST/PUT/PATCH/DELETE/HEAD | Per `CORE_API_POLICIES` | Path + all query `tenant_id` values + canonical session; browser `X-Tenant-ID` ignored; body aliases stripped | Client human derives session tenant; internal operator fallback is explicit | Canonical query/header injected server-side; credential or delegated gateway mode selected after authorization |
| Field Assessment detail | `/api/field-assessment/audio-url` | Core artifact metadata then signed object storage | GET | Tenant scoped | All query `tenant_id` values + session; artifact ID is resource input | Client human derives session tenant; internal can explicitly use operator fallback | Resolves tenant-bound API credential before Core call; Core receives canonical query/header |
| Field Assessment detail | `/api/field-assessment/transcribe` | Transcription provider then Core artifact registry | POST | Tenant scoped | All query `tenant_id` values + session; multipart form has no tenant authority | Same as audio-url | Artifact registration uses resolved tenant-bound credential/query/header |
| Login/logout | `/api/auth/**` | NextAuth/session | GET/POST | Non-tenant authentication | Cookie/session protocol | N/A | No tenant data target |
| Any | `/api/health` | Console health | GET | Public/non-tenant | N/A | N/A | No tenant data target |

### Dynamic Core family inventory

| Core family | Methods exposed | Read/mutation | Client authority | Core authentication | Persistence classification |
| --- | --- | --- | --- | --- | --- |
| `decisions` | GET/HEAD | Read | Client-safe | Tenant credential | RLS + application scope |
| `ingest/assessment` | GET/POST/PATCH/HEAD | Both; client mutations are not allowlisted | Client-safe read | Tenant credential | RLS + application scope |
| `control-plane/readiness/{frameworks,assessments,domains,controls,maturity-tiers}` | GET/HEAD | Read | Client-safe | Tenant credential | RLS + application scope |
| `ui/audit/{overview,status,chain-integrity}` | GET/HEAD | Read | Client-safe | Tenant credential | RLS + application scope |
| `field-assessment/engagements/**` | GET/POST/PATCH/DELETE/HEAD | Both | Tenant Admin mutation; permitted client reads | Tenant credential | RLS + application scope |
| `workforce/users/**` | GET/POST/PATCH/HEAD | Both | Tenant Admin own tenant; Platform Admin cross-tenant | Delegation v3 | RLS + application scope |
| `portal/grants/**` | GET/POST/DELETE/HEAD | Both | Tenant Admin own tenant; Platform Admin cross-tenant | Delegation v3 | RLS + application scope |
| `admin/identity/tenants/**` | GET/POST/PUT/HEAD | Both | Tenant Admin own tenant; Platform Admin cross-tenant | Delegation v3 | RLS + application scope |
| `admin/identity/invitations/**` | GET/POST/HEAD | Both | Tenant Admin own tenant; Platform Admin cross-tenant | Delegation v3 | RLS + application scope |
| `admin/tenants/{tenant}/users`, `portal-access`, `lifecycle`, `credential-administration` | GET/POST/PATCH/DELETE/HEAD as allowlisted | Both | Tenant Admin own tenant; Platform Admin cross-tenant | Delegation v3 plus route-specific Core authority | RLS + application scope |
| `admin/tenants/{tenant}/invite-initial-admin`, `bootstrap-admin` | POST | Mutation | Platform Admin only | Delegation v3 plus Core platform authority | RLS + application scope |
| `api/executive/**` | GET/HEAD | Read | Client-safe | Tenant credential | RLS + application scope |
| Internal-only proxy families (`keys`, connectors, agent, RAG, provider, forensics, governance, control tower) | Per explicit allowlist | Both | Not client accessible | Tenant credential or internal policy | Inspected per service; outside client-admin acceptance matrix |
| `identity/invitations/**` | GET/POST | Both | Token/named-user flow | Invitation token; accept adds named-user session | RLS + application scope |

No route was left with **AMBIGUOUS AUTHORITY** after the changes in this PR.

## P-62a: Missing-Tenant Fallback Authority Audit

The original resolver mixed two modes: absent context always called
`resolveConfiguredOperatorTenant()`. That made a missing client-human tenant
stronger than an explicit own-tenant request.

The shared `resolveTenantRequestAuthority()` now makes the mode structural:

1. Duplicate query keys are rejected with 422, including equal duplicates.
2. Path/query disagreement is rejected with 403.
3. Empty, whitespace, malformed, or overlong identifiers are rejected with 422.
4. A client human must have a valid canonical session tenant. An absent request
   derives that tenant; an explicit mismatch is denied.
5. Only `internal_console` may return the explicit `operatorFallback` result.
6. Only that result calls `resolveConfiguredOperatorTenant()`.

The direct Field Assessment audio routes previously bypassed this resolver and
always used the configured operator credential. They now share the same
decision and retrieve the selected tenant's credential.

| Input channel/case | Result |
| --- | --- |
| Correct own query/path | Allowed for Tenant Admin |
| Foreign or nonexistent query/path | Uniform authority denial before selection |
| Missing query/path | Canonical session tenant, never operator, for client human |
| Empty/whitespace/malformed | 422 fail-closed |
| Duplicate/equal duplicate/conflicting duplicate | 422 ambiguous-context denial |
| Path vs query | Must agree |
| Query vs JSON body | Body `tenant_id` and `tenantId` removed; canonical query wins |
| Query vs browser `X-Tenant-ID` | Browser header is not forwarded; canonical server header wins |
| Body vs header | Neither browser value becomes authority |
| Session vs requested | Client mismatch denied |
| Configured operator vs client session | Client session wins; operator fallback unreachable |
| Tenant in multipart form | N/A; direct transcription route takes tenant context only from canonical query/session resolution |

## Actor-bound delegation proof

**PROVEN/TESTED:** Delegation v3 HMAC-binds version, request ID, tenant ID,
method, canonical path, issued/expiry timestamps, named actor subject, and
authority class. Core independently derives request fields and rejects missing,
altered, expired, future-dated, overlong-lifetime, or malformed proofs.

For `tenant_human`, Core queries `tenant_users` joined to `fg_principals` before
tenant binding. Exactly one matching row must have `role='tenant_admin'`,
`active=TRUE`, `identity_binding_status='bound'`, a non-null principal, and an
active principal lifecycle. Foreign, nonexistent, missing, inactive, unbound,
wrong-role, duplicate, or inactive-principal results receive the same 403.

For `internal_console`, repository policy remains the canonical platform
credential path, but the BFF now admits only Support/Administrator to
gateway-backed human administration. The gateway credential without a named
actor and signed authority class is rejected by the production BFF.

The integration suite altered actor subject and authority class independently,
proving both changes invalidate the proof. The existing #703 tests cover tenant,
method, path, request ID, expiry, replay window, missing proof, and secret
rotation.

## Browser-controlled state

**TESTED/INSPECTED:** URL query/path values are requested context only. JSON
tenant aliases are stripped. Browser `X-Tenant-ID` is not copied. Session
cookies select a server-verified NextAuth session; they do not directly carry a
trusted tenant parameter into Core. React state and cached selections only
build URLs that are re-authorized. Theme localStorage and invitation-intent
sessionStorage exist but are not tenant authority. Direct URLs and hidden
routes pass the same BFF/Core checks. Back/forward navigation is **INFERRED** to
be equivalent to a repeated direct URL request; no browser automation timing
test was run.

## Global-fetch and filtering result

**INSPECTED/TESTED:** Tenant Admin `/api/tenants` returns the canonical session
tenant before calling the global registry. Tenant Admin detail and dynamic Core
calls resolve authority before `fetch()`. No tested Tenant Admin path retrieves
global customer data and filters it in JavaScript. Platform Admin global listing
remains intentional.

## Credentials and one-time secrets

**INSPECTED/TESTED:** Credential administration routes consume the canonical
`TenantAdminAuthority.tenant_id`; foreign lookup/mutation cannot substitute a
body/query/header tenant. Canonical credential persistence stores fingerprints
and hashes. Plaintext is returned only by legitimate issue/rotate responses and
is not available from list/get. Missing client-human context cannot select
operator credentials. Logs and tests contain no generated plaintext secrets.

## Error and enumeration semantics

Client-human foreign, nonexistent, missing-membership, inactive, unbound,
wrong-role, and inactive-principal delegated requests return the same 403 body
before tenant existence validation. BFF 401/403/5xx responses are normalized and
do not forward Core internals. Malformed or ambiguous context returns 422 because
it is a request-shape error, not a tenant-existence response. Platform Admins
retain deliberate tenant existence visibility.

Timing indistinguishability was **NOT TESTED** because database/cache timing is
not deterministic in the local harness.

## Persistence and RLS census

| Surface | Boundary | Evidence |
| --- | --- | --- |
| Tenant membership/principal resolution | RLS + application scope | `tenant_users` is tenant-context scoped; v3 query sets PostgreSQL `app.tenant_id` before lookup |
| Tenant invitations/identity configuration | RLS + application scope | RLS census/migrations plus explicit tenant predicates in identity stores |
| Field Assessment engagements, evidence, findings, reports, remediation | RLS + application scope | `api/db_migrations.py` policies plus tenant predicates in `services/field_assessment/store.py` |
| Tenant/service credentials and credential events | RLS + application scope | migration `0159_tenant_credentials.sql` and later credential-event/RBAC migrations |
| Portal grants/access | RLS + application scope | canonical tenant credential authority plus tenant-scoped portal service |
| Edge Config tenant registry | Global/platform table | Platform Admin only; Tenant Admin never fetches it |
| Console rate-limit store | Application scope only | Keyed after canonical tenant resolution; not an authority source |
| Signed object storage URL | Application scope only plus Core metadata authority | Storage key is obtained from tenant-authorized Core artifact lookup, not caller URL |

No tested application-scope-only persistence path accepts attacker-controlled
tenant authority. A universal RLS migration was not attempted.

## Findings and corrections

| Severity | Finding | Correction |
| --- | --- | --- |
| P1 | Missing client-human tenant fell through to configured operator tenant | Central authority-mode resolver derives the canonical session tenant and makes operator fallback explicit |
| P1 | Direct audio/transcription BFF routes used the operator tenant/key for every authenticated session | Added local route authorization and tenant credential resolution; UI propagates selected tenant |
| P1 | Delegated gateway proof carried a subject but no authority class; identity routes did not require current tenant-human membership | Delegation v3 signs authority class; Core requires unique active bound canonical tenant_admin membership and active principal |
| P1 | Broad `admin/tenants` and delegated proxy policies could reach platform-only bootstrap/invite or grant non-admin internal roles gateway-backed administration | Added positive Platform Admin guards and a Tenant Admin-or-Platform Admin gateway guard |
| P2 | Duplicate query parameters were collapsed with `get()` | Reject all duplicates with `getAll()` before authority selection |
| P3 | Primary `TenantSwitcher.tsx` implementation was dead | Removed after reference search; stale duplicate tree was not broadened into this cleanup |

No unresolved P0/P1 finding remains in the tested scope.

## Pre-commit security review

Answers are scoped to the inventoried and tested Console administrative paths.

| # | Review question | Answer and evidence |
| ---: | --- | --- |
| 1 | Can Tenant Admin A obtain Tenant B data? | No; foreign access is denied before selection, and sentinel tests observed no Tenant B data. |
| 2 | Can Tenant Admin A mutate Tenant B data? | No; the denied foreign PUT left Tenant B persistence unchanged. |
| 3 | Can Tenant Admin A obtain operator data? | No; a client human cannot reach the explicit operator fallback. |
| 4 | Can missing tenant context produce `CORE_TENANT_ID` authority? | No; it derives the canonical client-session tenant. |
| 5 | Can empty tenant context produce operator authority? | No; it receives 422. |
| 6 | Can malformed tenant context produce operator authority? | No; it receives 422. |
| 7 | Can duplicate tenant parameters alter authority? | No; all duplicates receive 422 before selection. |
| 8 | Can query/header disagreement alter authority? | No; browser tenant headers are discarded and rebuilt from canonical authority. |
| 9 | Can body/query disagreement alter authority? | No; body tenant aliases are stripped and the authorized query tenant is canonical. |
| 10 | Can path/query disagreement alter authority? | No; disagreement receives 403. |
| 11 | Can browser storage become tenant authority? | No; inspected storage is UI state and every resulting request is independently authorized. |
| 12 | Can a direct hidden route bypass UI restrictions? | No; direct platform-only and foreign requests are independently denied. |
| 13 | Can the gateway credential manufacture human authority? | No; gateway-backed human administration requires a named actor and signed authority class. |
| 14 | Can actor identity be substituted independently of proof? | No; actor substitution invalidates the v2/v3 HMAC. |
| 15 | Does Core independently establish canonical actor authority? | Yes for delegated administrative v3 paths: current canonical membership and principal state are queried in Core. |
| 16 | Is active tenant membership required? | Yes for delegated Tenant Admin paths. |
| 17 | Do unknown roles fail closed? | Yes. |
| 18 | Do non-admin internal roles remain non-platform-admin? | Yes; Developer, Operator, and FieldAssessor fail the positive gateway-administration guard. |
| 19 | Can Tenant Admin access the global tenant registry? | No; its own-tenant response returns before registry access. |
| 20 | Can Tenant Admin create tenants? | No. |
| 21 | Can Tenant Admin invoke generic arbitrary email? | No; `/api/email` remains Platform Admin only. |
| 22 | Can Tenant Admin operate on foreign credentials? | No; credential authority consumes the canonical authorized tenant. |
| 23 | Can a rejected mutation change foreign persistence? | No; tested foreign mutation left its sentinel row unchanged. |
| 24 | Can foreign/nonexistent requests reveal protected existence? | No protected distinction was observed; both receive the same authority denial. |
| 25 | Does a tested Tenant Admin BFF path global-fetch then filter? | No; authority resolves before fetch and the tenant registry short-circuits. |
| 26 | Does an inventoried tenant route rely solely on caller `tenant_id`? | No; the value is requested context checked against session or explicit platform authority. |
| 27 | Does a tested persistence path lose canonical tenant scope? | No. |
| 28 | Are one-time secrets still one-time? | Yes; plaintext remains issue/rotate-only and is neither persisted nor retrievable. |
| 29 | Did #706 weaken #703/#704/#705? | No; all three regression suites pass. |
| 30 | Did #706 weaken result-truth or production qualification? | No; those gates were untouched. |
| 31 | Are legitimate Platform Admin workflows still functional? | Yes; global listing, cross-tenant detail, creation, and explicit context selection remain tested. |
| 32 | Are Support semantics preserved? | Yes; Support remains in the canonical Platform Admin allowlist. |
| 33 | Are all operator fallbacks explicitly justified? | Yes; only `internal_console` can return the explicit fallback result, which direct routes additionally validate. |
| 34 | Are residual application-only boundaries documented? | Yes, in the persistence census and residual-risk section. |
| 35 | Would deleting a critical authority check make a #706 test fail? | Yes; a manual role-check weakening made the real Core suite fail and was restored. |

## Test evidence

- **PROVEN:** `tests/security/test_tenant_isolation_e2e.py` exercises real Core
  middleware, proof verification, canonical membership/principal lookup,
  identity route, and SQLite persistence. It also proves a denied foreign PUT
  leaves Tenant B unchanged.
- **TESTED:** `apps/console/tests/tenant-isolation-e2e.test.js` exercises the real
  shared BFF authority resolver and pins route, delegation, credential, secret,
  persistence, and RLS wiring.
- **TESTED:** a manual mutation changed the role predicate from
  `role == tenant_admin` to any non-empty role. The new Core suite failed on
  `client_read_only` receiving 200; restoring the predicate returned it to green.
- **PROVEN:** existing #703 Core and Node delegation tests remain green.
- **TESTED:** #704 (45/45) and #705 (66/66) remain green.

## Residual risks and deferred work

- Tenant-credential Core families authenticate the tenant service credential,
  not the named browser human. The Console BFF session resolver is therefore the
  current application authority boundary for those non-administrative calls.
  Extending v3 named-human delegation to every tenant credential route is
  **DEFERRED** as a separate protocol/authorization migration; this PR does not
  claim it has happened.
- PostgreSQL RLS behavior is **INSPECTED** and covered by existing optional
  Postgres suites, but the #706 focused run uses SQLite. The final repository
  gates determine whether an available Postgres job ran.
- Cache and log review is scoped to the routes above. Universal timing,
  microarchitectural, CDN, and third-party provider noninterference is **NOT
  TESTED**.

Scoped conclusion: no cross-tenant access was observed across the #706-tested
Console administrative surfaces and authority paths.

## Validation results

- Focused #706: Console 81/81; Core 5/5.
- #703: Core 49/49 and Console delegation contract 14/14.
- #704: 45/45. #705: 66/66. Full Console: 3043/3043.
- `make fg-fast`: 496 passed, 2 skipped. `make fg-security`: 1239 passed,
  1 skipped. `make fg-contract`: PASS.
- Console ESLint and TypeScript: PASS. Repository format and changed-file ruff:
  PASS. `git diff --check`: PASS.
- Single strict run: ruff PASS; format PASS (2128 files); mypy PASS (2127
  source files); pytest 5 failed, 22592 passed, 92 skipped in 11749.02 seconds.
  The four report-delivery failures exactly match the known
  `RESULT_TRUTH_GATE_BLOCKED` baseline. The fifth strict failure was the MCIM
  changed-path allowlist rejecting the then-unregistered #706 paths. Those paths
  were registered after strict and the focused MCIM check passed. Strict was not
  rerun and is not represented as green.
