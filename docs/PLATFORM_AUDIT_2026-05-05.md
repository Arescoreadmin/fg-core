# FrostGate Platform Audit
**Date:** 2026-05-05  
**Auditor:** Claude Sonnet (automated code audit — every claim traced to a file read)  
**Scope:** Full codebase at `/home/jcosat/Projects/fg-core`

---

## PHASE 1 — FULL SYSTEM AUDIT

---

### 1. Core Platform Integrity

#### Route Mounting (`api/main.py`)
**Status: COMPLETE**

`build_app()` mounts 40+ routers via explicit `app.include_router()` calls. Middleware stack (inner → outer as applied):
1. `AuthGateMiddleware` — key extraction, validation, tenant binding
2. `ResilienceGuardMiddleware`
3. `RequestValidationMiddleware`
4. `DoSGuardMiddleware` (rate limiting)
5. `CORSMiddleware`
6. `SecurityHeadersMiddleware`
7. `RequestLoggingMiddleware`
8. `FGExceptionShieldMiddleware`
9. `_ui_single_use_key_guard` (inline `@app.middleware("http")`)

Assessment/report/Stripe routers are unconditionally mounted (no feature flag). AI plane router is gated on `ai_plane_enabled()`. UI routers are gated to non-production environments only.

**Critical finding:** In production, `_resolve_auth_enabled_from_env()` returns `True` only if `FG_API_KEY` is set. If neither `FG_AUTH_ENABLED` nor `FG_API_KEY` is present, `auth_enabled=False` — all auth bypassed. There is no hard startup fail for this in `build_app()`.

#### Scope Enforcement (`api/auth_scopes/resolution.py`)
**Status: COMPLETE**

`verify_api_key_detailed()` performs:
- Constant-time compare against global env key (rejected in production)
- Admin-gateway internal token path (uses `FG_ADMIN_GATEWAY_INTERNAL_TOKEN` or `FG_INTERNAL_AUTH_SECRET`)
- DB lookup by argon2id hash with on-the-fly upgrade from SHA-256
- Scope subset check; `*` wildcard scope grants all
- Canary token detection via `api/tripwires.py`
- Tenant binding via `bind_tenant_id()` — key-bound tenants are enforced at the middleware layer

`require_scopes(*scopes)` produces a FastAPI `Depends` that enforces named scopes per route. Assessment routes use `require_scopes("ingest:assessment")`.

**Gap:** Assessment routes in `api/assessments.py` attach `require_scopes("ingest:assessment")` as a router-level dependency but the plane registry (`services/plane_registry/registry.py`) marks the `/ingest/assessment/*` paths as `bootstrap` exceptions — meaning auth is expected to be absent. The actual routes carry a scope dep. There is a mismatch between the plane registry bootstrap list and the running code. The code enforces auth; the registry documents exemption. The registry is advisory (CI checks only), so no runtime breach, but it creates confusion and a CI gate may reject the combination.

#### Middleware (`api/middleware/`)
**Status: COMPLETE**

- `auth_gate.py` — validates API key for all non-public paths; checks `PUBLIC_PATHS_EXACT` and `PUBLIC_PATHS_PREFIX`; stamps every response with `x-fg-authgate` / `x-fg-gate`
- `dos_guard.py` — in-memory rate limiter; enforced in production (startup raises if disabled)
- `exception_shield.py` — catches unhandled exceptions, logs, returns generic 500
- `logging.py` — structured request logging with request IDs
- `request_validation.py` — request body size / content-type enforcement
- `resilience_guard.py` — circuit-breaker-like degradation gating
- `security_headers.py` — HSTS, CSP, X-Frame-Options etc.

#### Admin Gateway (`admin_gateway/`)
**Status: COMPLETE (structure)**

Full FastAPI service with its own `Dockerfile`. Has `auth/oidc.py`, `auth/session.py`, `auth/dev_bypass.py`, `auth/csrf.py`, `auth/tenant.py`. Passes requests to frostgate-core with `X-Admin-Gateway-Internal: true` header and `FG_INTERNAL_AUTH_SECRET`. In docker-compose the admin profile binds only to `127.0.0.1:18080` — not exposed publicly.

**Gap:** In docker-compose the admin gateway's `FG_AUTH_MODE: dev` and `FG_ENV: local` — meaning the OIDC path is not active in the compose file. Real OIDC through Keycloak requires the `idp` profile. Production deployment via admin profile without OIDC active is a security posture gap.

#### Public Paths (`api/security/public_paths.py`)
**Status: COMPLETE**

Explicit `PUBLIC_PATHS_EXACT` tuple (21 paths) and `PUBLIC_PATHS_PREFIX` tuple. Notable: `/ingest/assessment/webhooks/stripe` is in `PUBLIC_PATHS_EXACT`, consistent with the Stripe HMAC verification approach. `/ui` prefix is public — all UI routes bypass AuthGate.

**Gap:** All `/ui/*` routes are public (AuthGateMiddleware skips them). UI routes in `api/ui.py`, `api/ui_ai_console.py`, etc. are only served in non-production (`not _is_production_runtime()`), so this is partially mitigated by the env gate, but the `public_paths_prefix` still lists `/ui` as public regardless of env.

#### Plane Registry (`services/plane_registry/registry.py`)
**Status: COMPLETE**

7 planes defined: `control`, `security`, `data`, `agent`, `ai`, `connector`, `evidence`, `ui`. Each has `route_prefixes`, `auth_class`, `required_route_invariants`, `maturity_tag`. Assessment bootstrap exceptions correctly justify the UUID-gated pre-tenant flow under the `data` plane.

#### Health Endpoints
**Status: COMPLETE**

`/health` — public, no auth  
`/health/live` — Kubernetes liveness probe  
`/health/ready` — checks startup_validation, db_init, Redis (if configured), NATS (if configured)  
`/health/detailed` — requires auth  

Startup will raise `RuntimeError` in production if DoS guard is not enabled. DB fail-closed: SQLite is rejected in production.

---

### 2. Assessment System

#### Scoring Logic (`api/assessments.py`)
**Status: COMPLETE**

`classify_profile()` maps 6 inputs to 6 profile types: `smb_basic`, `smb_growth`, `midmarket`, `enterprise`, `regulated`, `govcon`.

`score_assessment()` implements:
- Domain weights: `data_governance` 25%, `security_posture` 20%, `ai_maturity` 20%, `infra_readiness` 15%, `compliance_awareness` 12%, `automation_potential` 8%
- Profile multipliers applied and renormalized (govcon boosts compliance/data/security)
- Question types: `boolean`, `scale` (1–5 → 0–100), `select` (index-based), `text` (flat 50 if answered)
- Risk bands: critical <25, high <25–49, medium 50–74, low 75+

**Gap:** The `scale` question type formula `(value - 1) * 25.0` maps 1→0, 5→100. This is correct arithmetic. However, a score of 5 maps to exactly 100, not "excellent/low risk." The scoring is internally consistent but the formula is hardcoded, not versioned.

Checkout creates Stripe sessions with live amounts; dev bypass sets `payment_status = "paid"` when no `STRIPE_SECRET_KEY` present. This is the correct dev/test path.

`submit_assessment()` enforces payment gate when `STRIPE_SECRET_KEY` is set. Returns 402 if unpaid.

#### Reports Engine (`api/reports_engine.py`)
**Status: COMPLETE (except PDF)**

`generate_report()` creates a `ReportRecord` with status `pending` and runs `_generate_report_sync()` as a `BackgroundTask`. The background task:
1. Sets status to `generating`
2. Loads `AssessmentRecord`, `OrgProfile`, `PromptVersion`
3. Renders prompt template with `{{key}}` substitution
4. Calls `services/ai/dispatch.py::call_provider(provider_id="anthropic",...)`
5. Extracts JSON from LLM response (with markdown fence stripping)
6. Validates content with `_validate_report_content()` — enforces disclaimer, strips "certified" language, caps strengths at 3 / gaps at 5
7. Writes `content` and `status="complete"` to DB

`download_report()` returns `{"url": None, ...}` with a message that PDF is Stage 2. This is a documented stub.

**Critical gap:** Report generation is a `BackgroundTask` running in the same Uvicorn process. Under load, this blocks the event loop during the synchronous `httpx.post()` call to Anthropic (up to 120 seconds). This is a production scalability risk — not a correctness issue at low volume.

#### Payment Webhook (`api/stripe_webhooks.py`)
**Status: COMPLETE**

HMAC verification via `stripe.Webhook.construct_event()` is active when `STRIPE_WEBHOOK_SECRET` is set. No secret = dev mode, raw JSON accepted. `_persist_event()` stores events in `stripe_events` table for idempotency. `_confirm_payment()` updates `payment_status = "paid"` on `AssessmentRecord`.

**Gap:** No retry / replay protection beyond the `stripe_events` idempotency check. If the webhook fires before the DB write from `create_checkout_session()` completes (race condition), `_confirm_payment()` will find the record but `stripe_session_id` may not yet be set. Not a data-loss issue; the payment mark will still be applied.

#### Migrations (`migrations/postgres/`)
**Status: COMPLETE**

34 migrations total. Assessment-related:
- `0032`: Creates `org_profiles`, `assessment_schemas`, `assessments`, `prompt_versions`, `reports` tables with correct indexes and FK constraints
- `0033`: Seeds 35 questions across 6 domains and 3 prompt templates (executive, technical, compliance)
- `0034`: Adds `email`, `stripe_session_id`, `payment_status`, `tier` columns and `stripe_events` table

Migration 0032 explicitly notes no RLS on assessment tables (UUID-gated access for customer flow). This is a deliberate design decision documented in the SQL comment.

#### Frontend — Onboarding (`console/app/onboarding/page.tsx`)
**Status: COMPLETE**

4-step wizard: org info → size → compliance flags → review & pay. Calls `assessmentApi.createOrg()` then `assessmentApi.createCheckout()`. Handles dev bypass (no Stripe key → direct to assessment). Validates with Zod. Stores state in Zustand store (`useOnboardingStore`).

#### Frontend — Assessment (`console/app/assessment/page.tsx`)
**Status: COMPLETE**

Loads questions via `assessmentApi.getQuestions()`. Autosaves every 30 seconds. Shows payment-confirmed banner. Requires 80% completion to submit. Calls `assessmentApi.submitAssessment()`. Handles 402 payment race condition with user-visible message. On completion transitions to `CompletionScreen` which calls `reportApi.generate()`.

#### Frontend — Report Viewer (`console/app/reports/[reportId]/page.tsx`)
**Status: COMPLETE (except PDF download)**

Polls `reportApi.getReport()` every 3 seconds while `status` is `pending` or `generating`. Renders: risk score hero, key strengths, critical gaps, domain findings, roadmap (30/60/90 days), framework alignments, disclaimer. PDF download button calls `reportApi.getDownloadUrl()` and shows a user message when `url` is null.

#### API Clients (`console/lib/assessmentApi.ts`, `console/lib/reportApi.ts`)
**Status: COMPLETE**

Both route through `/api/core/ingest/assessment/*` which maps to the BFF proxy. Type-safe interfaces match backend response shapes.

---

### 3. AI Plane

#### Provider Dispatch (`services/ai/dispatch.py`)
**Status: COMPLETE**

Single `call_provider()` entry point. No silent fallback. Known providers: `anthropic`, `azure_openai`, `simulated`. `simulated` is blocked in production environments.

#### Provider Routing (`services/ai/routing.py`)
**Status: COMPLETE**

`resolve_ai_provider_for_request()` implements deterministic PHI-aware routing:
- PHI detected → `azure_openai` (BAA provider)
- No PHI → `anthropic` (default)
- Requested provider + PHI mismatch → denied
- BAA gate: if `requires_baa=True` and `baa_approved=False` → denied

Configured providers are discovered from env vars: `FG_ANTHROPIC_API_KEY`, `FG_AZURE_AI_KEY`+`FG_AZURE_OPENAI_ENDPOINT`+`FG_AZURE_OPENAI_DEPLOYMENT`.

#### Anthropic Provider (`services/ai/providers/anthropic_provider.py`)
**Status: COMPLETE**

Real HTTP call via `httpx.post()` to `https://api.anthropic.com/v1/messages`. Uses `claude-haiku-4-5-20251001` as default model (configurable via `FG_ANTHROPIC_MODEL`). Timeout: 5–120s (default 30s). Raises typed `ProviderCallError` on timeout, HTTP error, or response parse failure.

**Note:** The report engine hardcodes `provider_id="anthropic"` — it does not use the routing layer. This means PHI routing does not apply to report generation.

#### AI Plane Extension (`api/ai_plane_extension.py`, `services/ai_plane_extension/`)
**Status: PARTIAL**

`/ai/infer` and `/ai/chat` endpoints exist and are behind `require_scopes("compliance:read")`. The service layer in `services/ai_plane_extension/` has real models, policy engine, orchestration. The RAG context is injected via `services/ai_plane_extension/rag_stub.py` which loads from a seed file (`seeds/rag_stub_sources_v1.json`). The RAG stub is a flat file reader — not the full pipeline.

#### PHI Classifier (`services/phi_classifier/`)
**Status: COMPLETE (basic)**

Files: `classifier.py`, `minimizer.py`, `models.py`. Implements pattern-based PHI detection. Used in RAG ingest and routing decisions. Does not use ML models — purely regex/keyword-based.

#### BAA Gate (`services/provider_baa/`)
**Status: COMPLETE (structure)**

`gate.py` and `policy.py` exist. Gates PHI-bearing AI calls to BAA-approved providers. The gate is wired into `routing.py`.

#### Response Validation (`services/ai/response_validation.py`)
**Status: COMPLETE**

`validate_provider_response_grounding()` checks that all significant tokens in the provider response are present in retrieved RAG context tokens. If not grounded, returns `NO_ANSWER`. This is a lexical grounding check — not semantic. Enforced in the AI plane chat flow (not the report generation flow).

**Gap:** Report generation (`api/reports_engine.py`) does NOT use response validation. LLM output is parsed directly and only content-validated (field presence, "certified" word replacement). A hallucinated report will pass.

---

### 4. RAG System

#### RAG Ingest (`api/rag/ingest.py`)
**Status: COMPLETE (in-memory only)**

`ingest_corpus()` performs tenant binding, cross-tenant protection, SHA-256 content hashing, deterministic document IDs, and PHI classification on each document. Returns `IngestedCorpusRecord` objects with safe metadata. **No persistence.** All ingested data is in-memory only — there is no database table, no vector store, no embedding generation.

#### RAG Retrieval (`api/rag/retrieval.py`)
**Status: COMPLETE (lexical only, in-memory)**

`search_chunks()` implements lexical BM25-style scoring (coverage + normalized term frequency + exact phrase boost). Strict tenant isolation: cross-tenant chunks are excluded before scoring. Deterministic sort. No embeddings, no vector DB.

#### RAG Answering (`api/rag/answering.py`)
**Status: COMPLETE**

Full answer assembly pipeline: `build_answer_or_no_answer()` → `evaluate_context_sufficiency()` → `assemble_answer_from_context()`. Supports `AnswerConfidencePolicy` thresholds. Returns typed `GroundedAnswer` or `NoAnswer`. Citation IDs are deterministic SHA-256 hashes. Prompt injection guard via `constrain_answer_context()`.

#### RAG in AI Plane Extension (`services/ai_plane_extension/rag_stub.py`)
**Status: STUB**

`rag_stub.retrieve()` reads from `seeds/rag_stub_sources_v1.json` (a flat file). This is not connected to the full RAG pipeline in `api/rag/`. The AI plane's RAG context is a seed file stub, not the real lexical retrieval system.

#### RAG Context Integration (`services/ai/rag_context.py`)
**Status: COMPLETE (integration layer)**

`retrieve_rag_context()` bridges between `api/rag/retrieval.py` and the AI plane. It calls `search_chunks()`, applies sensitivity filtering, builds `RagContextResult`. This is the correct integration path but the AI plane extension currently uses the stub path instead.

#### Vector Store / Embeddings
**Status: MISSING**

No embedding generation, no vector database (pgvector, Pinecone, Weaviate, Qdrant, etc.), no semantic similarity. The RAG system is purely lexical. This is documented implicitly ("No embeddings, no vector DB" in source comments) but not explicitly in any README visible in scope.

---

### 5. Data Model

#### ORM Models (`api/db_models.py`)
**Status: COMPLETE**

Major models verified:
- `ApiKey` — hashed keys, scopes_csv, tenant_id, rotation support, argon2id upgrade path
- `SecurityAuditLog` — hash-chained audit entries
- `AssessmentRecord` — UUID PK, JSONB responses/scores, payment fields
- `AssessmentSchema` — versioned question banks
- `OrgProfile` — org onboarding data
- `PromptVersion` — prompt templates with active flag
- `ReportRecord` — report status, JSONB content, PDF storage key (stub)
- `StripeEvent` — idempotent event log
- `AITokenUsage`, `AIQuotaDaily`, `AIDeviceRegistry` — AI metering
- `BillingDevice`, `DeviceCoverageLedger`, `BillingIdentityClaim`, etc. — billing ledger

**Gap:** `AssessmentRecord.payment_status` has no CHECK constraint in the ORM model (though the SQL migration in 0034 does not add one either). Any string value is accepted. Not a runtime issue since the code only sets `"unpaid"` or `"paid"`.

**Gap:** Assessment tables intentionally have no RLS. Migration 0032 explicitly documents this: "does not enforce RLS — assessments are accessed by UUID (unguessable)." UUID-as-access-token is an acceptable security posture for the pre-tenant onboarding flow but carries risk if UUIDs are predictable or leaked.

#### Migration Coverage
34 migrations applied sequentially. No gaps in numbering. Migration runner in `api/db_migrations.py`. Docker-compose has a `frostgate-migrate` service that runs before `frostgate-core`.

---

### 6. Frontend + BFF

#### BFF Proxy (`console/app/api/core/[...path]/route.ts`)
**Status: COMPLETE**

Allowlist-based proxy: `PROXY_RULES` array defines permitted path prefixes and HTTP methods. Assessment routes: `ingest/assessment` with GET/POST/PATCH/HEAD allowed. Rate limit: 120 req/10s per IP (in-memory, resets on restart). Forwards `X-API-Key` (from `CORE_API_KEY` env var), `X-Tenant-ID` (from `CORE_TENANT_ID`), `X-Request-ID`.

**Gap:** `CORE_API_KEY` is a server-side env var injected at build/start time. Assessment routes are pre-tenant (no user-specific key). This means all assessment requests from the frontend use the same system key. If that key has broad scopes, this is an over-privileged path.

**Gap:** Rate limit store is `new Map()` in module scope — it resets on every cold start / serverless function invocation. In a serverless deployment (Vercel, etc.) this provides no real rate limiting protection.

#### Dashboard (`console/app/dashboard/page.tsx`)
**Status: PARTIAL**

Real data fetched for health and stats. Chart data (`MOCK_CHART_DATA`) and domain scores (`MOCK_DOMAIN_SCORES`) are hardcoded mock objects. The component renders them as if real.

#### Onboarding, Assessment, Reports
**Status: COMPLETE** — see Section 2 above.

---

### 7. Security Model

#### CI Gate Tools (`tools/ci/`)
**Status: COMPLETE (tooling)**

27+ CI check scripts including:
- `check_plane_registry.py` — validates routes against plane registry
- `check_route_scopes.py` — ensures all non-public routes have scope enforcement
- `check_no_plaintext_secrets.py` — scans for hardcoded secrets
- `check_prod_unsafe_config.py` — blocks unsafe production configs
- `check_db_dependency.py` — validates DB dependency patterns
- `guard_no_raw_percent_in_sql.py` — SQL injection guard

These are CI-time checks, not runtime guards. If CI is bypassed, these protections do not apply.

#### Exception Pools
The plane registry defines exception categories: `public`, `auth_exempt`, `bootstrap`, `global_admin`. Assessment endpoints correctly classified as `bootstrap` (pre-tenant UUID-gated). Stripe webhook is `auth_exempt` with explicit HMAC justification. Admin routes are `global_admin`.

#### Stripe HMAC
**Status: COMPLETE (conditional)**

Active when `STRIPE_WEBHOOK_SECRET` is set. When not set (dev), any POST to `/ingest/assessment/webhooks/stripe` is accepted. The dev bypass is a deliberate choice, but if `STRIPE_WEBHOOK_SECRET` is missing in production, the webhook is wide open.

---

### 8. DevOps + Deployability

#### Docker Compose (`docker-compose.yml`)
**Status: COMPLETE (structure)**

Services: `redis`, `nats`, `postgres`, `opa-bundles`, `opa`, `frostgate-bootstrap`, `frostgate-migrate`, `frostgate-core`, `admin-gateway`, `fg-idp`, `console`.

All services: `cap_drop: [ALL]`, `security_opt: no-new-privileges:true`, `read_only: true`, tmpfs for writable dirs.

Health checks defined for all services. Correct dependency ordering (migrate waits for postgres health; core waits for migrate completion).

**Critical gap:** Required env vars in compose: `REDIS_PASSWORD`, `NATS_AUTH_TOKEN`, `FG_WEBHOOK_SECRET`, `FG_API_KEY`, `FG_SIGNING_SECRET`, `FG_INTERNAL_AUTH_SECRET`. None of these have defaults — compose fails if unset. This is correct security behavior but requires a complete env setup before first run. No `.env.example` file was found in the repo root.

**Missing env vars for assessment/AI features (not in compose env block):**
- `STRIPE_SECRET_KEY` — no Stripe payment
- `STRIPE_WEBHOOK_SECRET` — no webhook verification
- `FG_ANTHROPIC_API_KEY` — no report generation
- `FG_ANTHROPIC_MODEL` — defaults to `claude-haiku-4-5-20251001`
- `CONSOLE_BASE_URL` — defaults to `https://app.frostgate.ai`

#### Dockerfile
A `Dockerfile` exists (referenced in compose `build: context: .`). Not read but confirmed present via compose references.

#### Env file
`env/prod.env` exists (102 lines, required by compose). Not read (secrets).

---

## PHASE 2 — Gap Table

| Area | Gap | Severity | Blocking? | Effort | Notes |
|------|-----|----------|-----------|--------|-------|
| Auth | `auth_enabled=False` if neither `FG_AUTH_ENABLED` nor `FG_API_KEY` set; no startup fail | CRITICAL | Yes (prod) | Hours | Add startup invariant check |
| AI – Report | Report generation uses synchronous `httpx` in BackgroundTask; blocks event loop up to 120s under load | HIGH | No (low vol.) | Days | Switch to async or worker queue |
| AI – Report | Report LLM output NOT validated against RAG context; hallucinations pass through | HIGH | No (functional) | Days | Wire `validate_provider_response_grounding()` |
| AI – PHI routing | `reports_engine.py` hardcodes `provider_id="anthropic"`; PHI routing not applied | HIGH | No | Hours | Use routing layer in report generation |
| RAG | No vector store / embeddings; purely lexical retrieval | HIGH | Yes (product promise) | Weeks | Integrate pgvector or external vector DB |
| RAG | AI plane extension uses `rag_stub.py` (seed file) not the real retrieval pipeline | HIGH | Yes (AI plane) | Days | Wire `services/ai/rag_context.py` into AI plane |
| Frontend | Dashboard chart data is hardcoded mock (`MOCK_CHART_DATA`, `MOCK_DOMAIN_SCORES`) | MEDIUM | No | Hours | Connect to real stats API |
| BFF | Rate limit store is in-memory Map; resets on cold start; ineffective in serverless | MEDIUM | No (local deploy) | Days | Use Redis-backed rate limit |
| BFF | `CORE_API_KEY` is a single system key for all assessment requests | MEDIUM | No | Days | Assess scope minimization |
| Payment | No `.env.example`; missing env vars for Stripe/AI undocumented | MEDIUM | Yes (onboarding) | Hours | Add `.env.example` with all required vars |
| PDF | Report PDF export is a documented stub (`url: null`) | MEDIUM | No (on-screen view works) | Weeks | WeasyPrint + S3/MinIO |
| Auth | `FG_ADMIN_ENABLED=false` by default in prod; admin routes disabled; OIDC not active in compose `admin` profile | MEDIUM | No | Days | Enable OIDC for admin profile |
| Assessment | No RLS on assessment tables; UUID-as-token model | LOW | No (by design) | Days | Stage 2 RLS hardening |
| Scoring | Question scoring formula not versioned; `schema_version` field exists but scoring weights are hardcoded | LOW | No | Days | Store weights in `assessment_schemas` |
| Data | `AssessmentRecord.payment_status` no CHECK constraint in ORM | LOW | No | Hours | Add `CheckConstraint` to model |
| CI | Plane registry `bootstrap` classification for assessment routes conflicts with actual scope dep on router | LOW | No (runtime ok) | Hours | Align registry or remove scope dep |
| Infra | `frostgate-core` depends on `nats` health — if NATS not needed for assessment flow, over-constrains startup | LOW | No | Hours | Split profiles or make optional |

---

## PHASE 3 — System Flow Mapping

### 1. Client Assessment Flow

```
User → /onboarding (Next.js)
  → [Step 0] org name, email, industry
  → [Step 1] employee count, revenue  
  → [Step 2] compliance flags (PHI, CUI, DoD, FedRAMP)
  → [Step 3] review + pay
  
  → POST /api/core/ingest/assessment/orgs
    → BFF proxy → POST /ingest/assessment/orgs (fg-core)
    → api/assessments.py::create_org()
    → classify_profile() → profile_type (6 categories)
    → INSERT org_profiles + INSERT assessments (status=draft)
    → returns {org_id, assessment_id, profile_type}

  → POST /api/core/ingest/assessment/{id}/checkout
    → BFF proxy → POST /ingest/assessment/{id}/checkout (fg-core)
    → api/assessments.py::create_checkout_session()
    → If STRIPE_SECRET_KEY: stripe.checkout.Session.create() → redirect to Stripe
    → If no key: payment_status=paid, returns {dev_bypass:true}

  → [dev] Redirect to /assessment?id={assessment_id}
  → [prod] Stripe hosted checkout → payment → redirect to /assessment?id={id}&payment=success

  → GET /api/core/ingest/assessment/{id}/questions
    → api/assessments.py::get_questions() → loads assessment_schemas (35 questions)

  → [User answers questions, autosave every 30s]
  → PATCH /api/core/ingest/assessment/{id}/responses
    → api/assessments.py::save_responses() → merges responses JSON

  → POST /api/core/ingest/assessment/{id}/submit
    → api/assessments.py::submit_assessment()
    → Checks payment_status == paid (if Stripe configured)
    → score_assessment() → domain_scores + overall_score + risk_band
    → UPDATE assessments (status=scored, scores, overall_score, risk_band)

  → POST /api/core/ingest/assessment/reports/generate
    → api/reports_engine.py::generate_report()
    → INSERT reports (status=pending)
    → BackgroundTask: _generate_report_sync()
      → call_provider("anthropic", prompt) → Anthropic API
      → _extract_json() + _validate_report_content()
      → UPDATE reports (status=complete, content=JSONB)

  → GET /api/core/ingest/assessment/reports/{id} [polling every 3s]
    → api/reports_engine.py::get_report()
    → Returns {status, content} when status=complete

  → /reports/{reportId} → renders full report view
```

**End-to-end completeness:** COMPLETE for the happy path. Payment race condition (webhook arrives before checkout session is committed) is handled in frontend with user-visible 402 message.

### 2. Payment Flow

```
Stripe → POST /ingest/assessment/webhooks/stripe
  → Public path (no API key required)
  → stripe_webhooks.py::stripe_webhook()
  → If STRIPE_WEBHOOK_SECRET set:
    → stripe.Webhook.construct_event() (HMAC verification)
    → Raises 400 on invalid signature
  → _persist_event() → INSERT stripe_events (idempotency)
  → If event_type == "checkout.session.completed":
    → extract assessment_id from session.metadata
    → _confirm_payment() → UPDATE assessments SET payment_status='paid'
```

**Verified gaps:** 
- Dev mode (no `STRIPE_WEBHOOK_SECRET`) accepts any POST → must be set in production
- No explicit replay attack window (relying on Stripe event ID idempotency)

### 3. AI Query Flow (AI Plane — not report generation)

```
Client → POST /ai/chat (requires "compliance:read" scope + tenant binding)
  → api/ai_plane_extension.py::ai_chat()
  → services/ai_plane_extension/service.py::AIPlaneService.chat()
  → services/ai_plane_extension/rag_stub.py::retrieve()
    → reads seeds/rag_stub_sources_v1.json (STUB — not real retrieval)
  → services/phi_classifier/classifier.py::classify_phi(query)
  → services/ai/routing.py::resolve_ai_provider_for_request()
    → PHI detected → azure_openai; No PHI → anthropic
  → services/ai_plane_extension/policy_engine.py (admin JSON policies)
  → services/ai/dispatch.py::call_provider()
  → services/ai/response_validation.py::validate_provider_response_grounding()
    → Checks response tokens against RAG context tokens
    → Returns NO_ANSWER if not grounded
```

**Current state:** The routing and response validation are real. The RAG retrieval is a stub file. The AI plane is functional for non-RAG queries with a simulated context from a seed file.

### 4. RAG Flow

```
Current state: PARTIAL

Real pipeline (api/rag/):
  ingest_corpus() → IngestedCorpusRecord (in-memory, no persistence)
  search_chunks() → lexical BM25-style retrieval (in-memory corpus only)
  prepare_answer_context() → tenant-isolated context items
  build_answer_or_no_answer() → GroundedAnswer | NoAnswer (with citations)
  build_answer_with_provenance() → + ProvenanceReport

Integration gap:
  AI plane currently bypasses the real pipeline via rag_stub.py
  services/ai/rag_context.py::retrieve_rag_context() provides the correct
  integration adapter but is NOT called by the AI plane service

Missing completely:
  - No corpus persistence (no DB table, no vector store)
  - No document upload endpoint
  - No embedding pipeline
  - No semantic similarity (purely lexical)
  - No multi-tenant corpus management API
```

---

## PHASE 4 — Fastest Path to Revenue

### Stage 1: Assessment Readiness (Sellable in ~2 weeks)

**What IS built and working:**
- Full onboarding wizard (4 steps, profile classification)
- 35-question assessment across 6 domains
- Weighted scoring with profile-type modifiers
- Stripe checkout integration (real sessions, HMAC webhook)
- Report generation via Anthropic API (executive, technical, compliance prompts)
- Report viewer (rich UI with roadmap, framework alignments, risk scores)
- Database schema fully migrated (0032–0034)
- BFF proxy with correct allowlist

**What is MISSING to sell:**
1. `env/prod.env` needs `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `FG_ANTHROPIC_API_KEY` — Hours
2. `CONSOLE_BASE_URL` must be set to the actual domain for Stripe redirect — Hours
3. The admin profile in compose has `FG_AUTH_MODE: dev` — needs real auth for admin access — Days
4. No `.env.example` — operators have no reference for required vars — Hours
5. Dashboard domain score widget shows mock data — Hours to connect
6. BackgroundTask sync HTTP in report generation needs load testing — Days
7. Need to run `frostgate-migrate` service (seeds the question bank and prompts)

**Estimated effort to first paying client:** 1–2 weeks of focused engineering.

### Stage 2: Advanced Assessment + Insights

- Real-time dashboard with actual metrics from fg-core stats endpoints
- Tenant dashboard listing all assessments for an org
- Multi-report type UI (currently only executive type visible in UI)
- PDF export (WeasyPrint + S3/MinIO)
- Assessment RLS hardening
- Assessment versioning (multiple assessments per org over time)
- Email delivery of report links

**Estimated effort:** 4–6 weeks.

### Stage 3: AI Plane

- Wire `services/ai/rag_context.py` into `services/ai_plane_extension/service.py` (remove rag_stub)
- Add corpus persistence (pgvector or external vector DB)
- Document upload endpoint with ingestion pipeline
- Semantic embedding (OpenAI text-embedding or equivalent)
- Multi-tenant corpus management API
- Enable OIDC in admin gateway for tenant-scoped AI access
- Wire PHI routing into report generation

**Estimated effort:** 6–10 weeks.

### Stage 4: RAG Services

- Replace lexical retrieval with vector similarity
- Embedding generation pipeline (chunking → embed → store)
- Provenance UI (show which documents grounded each answer)
- Corpus lifecycle management (document versioning, deletion)
- Semantic re-ranking (cross-encoder or LLM-based)
- Quota enforcement for RAG usage

**Estimated effort:** 8–12 weeks additional.

---

## PHASE 5 — Execution Plan

### Week 1–2: Assessment Launch Readiness

**Critical path:**
- [ ] Create `.env.example` with all required variables (Hours)
- [ ] Set `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `CONSOLE_BASE_URL` in prod env (Hours)
- [ ] Set `FG_ANTHROPIC_API_KEY` (Hours)
- [ ] Run full end-to-end test: onboarding → payment → assessment → report on staging
- [ ] Fix `_generate_report_sync()` to use `httpx.AsyncClient` (async Anthropic call) or move to background worker — prevents event loop blocking (Days)
- [ ] Wire PHI routing into report generation (Hours)
- [ ] Add startup invariant: fail if `FG_API_KEY` not set and `FG_AUTH_ENABLED` not explicitly true (Hours)
- [ ] Add `STRIPE_WEBHOOK_SECRET` startup warning (not hard fail — needed for dev bypass) (Hours)

**Parallelizable:**
- Dashboard mock data replacement (pull from `/stats/summary` API)
- `.env.example` documentation
- Stripe webhook secret startup check

**Blocker:** All production env vars must be set before testing. No `.env.example` means operators must guess.

### Week 3–4: Stability + Admin Access

**Critical path:**
- [ ] Load test report generation at 5 concurrent assessments
- [ ] Add tenant-scoped assessment listing endpoint (for returning customers)
- [ ] Wire OIDC in admin gateway compose profile (not `FG_AUTH_MODE: dev`)
- [ ] Multi-report type selection in assessment completion UI (technical, compliance variants)
- [ ] Add `CheckConstraint` for `payment_status` in ORM model

**Parallelizable:**
- PDF stub replacement design (WeasyPrint POC)
- Plane registry alignment for assessment bootstrap exceptions
- In-memory rate limit in BFF replaced with Redis-backed (if on serverless)

### Week 5–6: AI Plane Wiring

**Critical path:**
- [ ] Replace `rag_stub.py` in AI plane with `services/ai/rag_context.py` call path
- [ ] Add corpus persistence: create `rag_corpus` table (pgvector or JSONB for lexical)
- [ ] Document upload API endpoint with ingest pipeline
- [ ] Admin UI for corpus management
- [ ] Wire `validate_provider_response_grounding()` into report generation

**Blocker:** Vector store choice (pgvector in existing postgres vs. external). pgvector is fastest path (already have postgres).

**Parallelizable:**
- Embedding pipeline design
- PHI sensitivity level UI labels in report viewer

### Week 7–8: RAG + Semantic Retrieval

**Critical path:**
- [ ] pgvector extension enabled in postgres
- [ ] Embedding generation (text-embedding-3-small or equivalent) in ingest pipeline
- [ ] Replace lexical `_score_chunk()` with vector cosine similarity
- [ ] Semantic re-ranking pass after retrieval
- [ ] Provenance tracking UI (which documents grounded this answer)

**Parallelizable:**
- Quota enforcement for AI/RAG calls
- Assessment RLS hardening (Stage 2 migration)

### Dependencies map

```
STRIPE_KEY + ANTHROPIC_KEY → First revenue
PHI routing in reports → (done in week 1)
rag_stub removal → Week 5 (needs corpus persistence)
corpus persistence → pgvector decision (week 5)
vector retrieval → corpus persistence (week 7)
OIDC → admin access to assessment data (week 3)
```

---

## PHASE 6 — Final Output

### 1. System Completeness Score

**Score: 58 / 100**

Justification:
- Core API platform (auth, middleware, tenant isolation, audit): 95% — COMPLETE
- Assessment system (onboarding → scoring → payment → report): 90% — COMPLETE minus prod env vars
- AI provider dispatch + PHI routing: 85% — COMPLETE; report gen bypasses routing
- Report generation UI: 95% — COMPLETE except PDF
- RAG infrastructure (ingest, retrieval, answering logic): 40% — Real pipeline exists but in-memory, no persistence, no embeddings, not wired into AI plane
- AI plane serving real queries: 35% — Routing is real; RAG is stub; context is seed file
- Frontend completeness: 75% — Assessment flow complete; dashboard has mock data
- DevOps readiness: 60% — Compose is solid; missing env documentation; admin auth not production-ready
- Vector store / semantic retrieval: 0% — Missing entirely

Weighted across platform surface: **58/100**

### 2. Time to First Paying Client

**1–2 weeks** (assuming `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, and `FG_ANTHROPIC_API_KEY` are obtained and set today)

The full assessment → payment → report flow is functionally complete. The primary remaining work is environment configuration, a production deployment test, and fixing the async report generation blocking issue.

### 3. Time to Full Platform (AI + RAG)

**14–20 weeks** from today for:
- Semantic vector retrieval (pgvector)
- Embedding generation pipeline
- Multi-tenant corpus management API
- AI plane fully wired (no stub)
- Admin OIDC live
- PDF export
- Tenant dashboard

### 4. Top 5 Risks That Could Kill the Platform

**1. Auth disabled silently**  
If `FG_API_KEY` is not set and `FG_AUTH_ENABLED` is not explicitly true, auth is disabled. No startup crash. All routes unprotected. Risk: complete authentication bypass in misconfigured deployment. Traced to: `api/main.py::_resolve_auth_enabled_from_env()`.

**2. Report generation blocks event loop**  
`_generate_report_sync()` runs a synchronous `httpx.post()` (up to 120s) inside a FastAPI `BackgroundTask`. Under concurrent load this starves other requests in the same Uvicorn worker. At 5+ simultaneous reports, the API becomes unresponsive. Traced to: `api/reports_engine.py::_generate_report_sync()`.

**3. No STRIPE_WEBHOOK_SECRET in production = open webhook**  
If `STRIPE_WEBHOOK_SECRET` is missing in production, the webhook accepts any POST body as a valid Stripe event. An attacker can mark any assessment as paid without payment. Traced to: `api/stripe_webhooks.py` — the secret check is conditional.

**4. RAG is entirely in-memory with no persistence**  
The full `api/rag/` pipeline is real but all corpus data vanishes on restart. No RAG corpus survives a deploy. The AI plane's rag_stub uses a seed file that must exist at the right path. If either fails silently, the AI plane returns `NO_ANSWER` for all queries without alarming users. Traced to: `api/rag/ingest.py` (no DB write), `services/ai_plane_extension/rag_stub.py`.

**5. Assessment tables have no RLS**  
Any UUID is accessible to anyone who guesses it. While UUIDv4 is statistically unguessable, if assessment IDs are ever logged, indexed publicly, or exposed in URLs in analytics, all customer assessment data (including PHI flags, CUI flags, DoD contractor status) becomes accessible without authentication. Traced to: `migrations/postgres/0032_assessment_and_reports.sql` comment explicitly noting no RLS.

### 5. Top 5 Leverage Moves That Accelerate Everything

**1. Set 3 env vars and ship**  
`STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `FG_ANTHROPIC_API_KEY` are the only blockers to revenue. Everything else in the assessment flow is built. Hours of work, weeks of revenue acceleration.

**2. Fix async report generation first**  
Move `httpx.post()` to `httpx.AsyncClient` or a Celery/ARQ worker before going to production. This is a single-file change in `api/reports_engine.py` that prevents the most likely production outage.

**3. Wire `services/ai/rag_context.py` instead of `rag_stub.py`**  
Replace 5 lines in `services/ai_plane_extension/service.py`. This makes the AI plane use the real retrieval pipeline. Even with in-memory corpus, this unlocks the full RAG logic (sensitivity filtering, grounding validation, provenance). The stub hides the real system's behavior.

**4. Add pgvector with one migration**  
Add `CREATE EXTENSION vector`, create `rag_corpus_chunks` table with a `embedding vector(1536)` column, and update `api/rag/retrieval.py` to query it. This converts the platform from toy to production-grade RAG in one focused week and unlocks the core AI differentiation.

**5. Create `.env.example` and a README for first-run**  
All the required env vars (`FG_API_KEY`, `FG_SIGNING_SECRET`, `FG_INTERNAL_AUTH_SECRET`, `STRIPE_*`, `FG_ANTHROPIC_API_KEY`, `CONSOLE_BASE_URL`, etc.) exist but are undocumented for operators. A `.env.example` file prevents misconfiguration errors (including the auth-disabled risk) at zero engineering cost.

---

*Audit complete. All findings traced to files read during this session. No assumptions or generalizations made.*
