# FrostGate — Unified System Document

**Version:** 1.0  
**Last updated:** 2026-05-05  
**Branch:** `claude/merge-frontend-fg-core-6fjVg`  
**Author:** Jason Cosat  
**Status:** Active Development — Stage 1 complete, Stage 2 in progress

---

## What this document is

This is the single source of truth for the unified FrostGate platform. It replaces any confusion
between the original `fg-core` codebase and the `AIEG` (AI Enterprise Gateway) design document.
Those two systems have been merged. There is one codebase, one backend, one frontend.

If this document contradicts any other `.md` file in this repo, this document wins for
system-level decisions. `BLUEPRINT_STAGED.md` remains authoritative for governance compliance gates.
`CODEX.md` remains authoritative for AI coding standards.

---

## Table of Contents

1. [What FrostGate is](#1-what-frostgate-is)
2. [What was merged and why](#2-what-was-merged-and-why)
3. [Architecture](#3-architecture)
4. [Technology stack](#4-technology-stack)
5. [Running locally](#5-running-locally)
6. [Service and API reference](#6-service-and-api-reference)
7. [Database schema](#7-database-schema)
8. [Assessment engine](#8-assessment-engine)
9. [Report engine](#9-report-engine)
10. [Frontend](#10-frontend)
11. [Compliance frameworks](#11-compliance-frameworks)
12. [Tier system and pricing](#12-tier-system-and-pricing)
13. [Target markets](#13-target-markets)
14. [Build status — what is done](#14-build-status--what-is-done)
15. [What needs to be built next](#15-what-needs-to-be-built-next)
16. [Environment variables](#16-environment-variables)
17. [Key design decisions](#17-key-design-decisions)
18. [File map](#18-file-map)

---

## 1. What FrostGate is

FrostGate is a four-tier AI governance platform targeting regulated industries — community banking,
healthcare, legal, and government contracting. It is a SaaS product with a clear upsell path:

| Tier | Name | What it does | Price |
|------|------|-------------|-------|
| 1 | Snapshot | Guided AI risk assessment + AI-generated advisory PDF report | $299–999 |
| 2 | Intelligence | Dashboard, benchmarking, compliance mapping, RAG recommendations | $5K–15K/yr |
| 3 | Control | Runtime AI gateway — every model request classified, policy-checked, audited | $50–100K/yr |
| 4 | Autonomous | Continuous monitoring, drift detection, auto-remediation | $100–250K+/yr |

**The core problem it solves:** Small and mid-market orgs in regulated industries are using AI
tools (ChatGPT, Copilot, Claude) without governance, policy, or visibility. Every community bank,
medical group, and law firm in America has this problem right now. FrostGate is the first product
they can actually afford to fix it.

**Primary market:** Central Florida (Volusia, Flagler, Orange, Brevard counties). Local presence
is a competitive advantage in trust-dependent industries.

---

## 2. What was merged and why

The original `fg-core` codebase had a strong, production-grade backend — policy enforcement,
decision engine, HMAC audit chain, multi-tenant isolation, OPA integration — but no
customer-facing features: no assessment, no scoring, no AI report generation, no marketing
landing page.

The `AIEG` design document described the customer-facing features: assessment wizard, 6-domain
scoring, Claude-powered advisory reports, onboarding wizard, report viewer. But it was a separate
system with separate databases, separate processes, and separate Anthropic clients.

**The merge decision:** Build AIEG's customer-facing features directly inside fg-core as new API
modules. No separate processes. No duplicated infrastructure. One FastAPI app, one PostgreSQL
database, one Anthropic provider, one frontend.

What was preserved from fg-core:
- All existing API modules, decision engine, audit chain, compliance registry, governance
- Multi-tenant isolation (RLS, `tenant_id` everywhere)
- OPA policy engine
- Agent subsystem
- Billing infrastructure
- All migrations 0001–0031

What was added from AIEG:
- `api/assessments.py` — org creation, 6-domain scoring engine, assessment lifecycle
- `api/reports_engine.py` — AI advisory report generation via fg-core's Anthropic provider
- `migrations/postgres/0032` — assessment and report tables
- `migrations/postgres/0033` — question bank seed + AI prompt templates
- `console/` — complete Next.js 14 frontend (Tailwind, Radix UI, Recharts, Zustand, TanStack Query)
- 4 new pages: landing, onboarding wizard, assessment wizard, report viewer
- Upgraded dashboard with Recharts charts and sidebar navigation

---

## 3. Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    FrostGate Console (Next.js 14)                     │
│  localhost:3000                                                        │
│                                                                        │
│  /               Landing page + pricing                                │
│  /onboarding     Org profile wizard (4 steps)                          │
│  /assessment     Question wizard + autosave                            │
│  /reports/[id]   Report viewer + polling                               │
│  /dashboard      Decision engine stats, risk radar, event feed         │
│  /dashboard/control-tower, /decisions, /forensics, /alignment          │
│  /audit          Audit log viewer                                      │
│  /keys           API key management                                    │
│  /products       Product management                                    │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ /api/* → HTTP proxy
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                   admin-gateway (FastAPI, port 8080)                  │
│                   Auth: JWT/API key, OIDC                             │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    fg-core API (FastAPI, port 8080)                   │
│                                                                        │
│  Customer-facing (no auth, UUID access control):                       │
│    /assessment/orgs                  POST — create org + assessment    │
│    /assessment/assessments/{id}/*    GET/PATCH/POST                    │
│    /assessment/reports/*             POST generate / GET poll          │
│                                                                        │
│  Tenant-authenticated (API key + scopes):                              │
│    /defend  /decisions  /feed  /forensics  /stats                      │
│    /audit   /compliance  /governance  /keys  /ai/*                     │
│    /agent/* /billing/* /planes/* /connectors/*                         │
│                                                                        │
│  Decision engine: engine/evaluate.py → rules.py                        │
│  AI provider:     services/ai/dispatch.py → AnthropicProvider          │
│  Policy engine:   OPA/Rego (policy/rego/)                              │
│  Audit:           HMAC-chained AuditLedgerRecord                       │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         PostgreSQL 16                                  │
│                         localhost:5432                                 │
│                                                                        │
│  33 migrations applied (0001–0033)                                     │
│  New (0032): org_profiles, assessments, assessment_schemas,            │
│              prompt_versions, reports                                  │
│  RLS enforced on all tenant-owned tables                               │
└──────────────────────────────────────────────────────────────────────┘

Supporting infrastructure:
  Redis     :6379  — sessions, rate limits, cache
  NATS      :4222  — inter-service events (JetStream)
  MinIO     :9000  — report PDFs, uploaded documents (Stage 2)
  OPA       :8181  — policy evaluation
```

### Stage 3 AI Gateway (not yet built)

When the AI gateway is built, every employee AI request will flow through:

```
Employee request
  → Rate limiter (Redis token bucket)
  → Auth (JWT / API key)
  → Input classification (Presidio — PII/PHI/CUI detection)
  → Policy engine (OPA/Rego — allow / block / redact)
  → PII tokenizer (reversible, before AI boundary)
  → RAG injector (org policy context)
  → Provider router (Anthropic / OpenAI / Ollama by sensitivity)
  → Model call
  → Response validator (hallucination check, de-tokenize PII)
  → HMAC audit logger
  → Employee response
```

---

## 4. Technology stack

### Frontend (`console/`)
| Layer | Technology |
|-------|-----------|
| Framework | Next.js 14.2.5 (App Router) |
| Language | TypeScript 5 strict |
| State | Zustand 4 |
| Forms | React Hook Form + Zod |
| Data fetching | TanStack Query 5 |
| UI primitives | Radix UI (headless) |
| Styling | Tailwind CSS 3.4 |
| Charts | Recharts 2 |
| Icons | lucide-react |
| Variants | class-variance-authority + clsx + tailwind-merge |

### Backend (`api/`, `services/`, `engine/`)
| Component | Technology |
|-----------|-----------|
| Framework | FastAPI 0.120 + Python 3.12 |
| ORM | SQLAlchemy 2.0 |
| DB driver | psycopg (PostgreSQL), aiosqlite (dev SQLite) |
| AI provider | Anthropic API via `services/ai/dispatch.py` |
| Policy engine | OPA/Rego |
| Auth | JWT (PyJWT), API keys (Argon2) |
| Async events | NATS JetStream |
| Cache | Redis 7 |
| HTTP client | httpx |

### Infrastructure
| Component | Technology |
|-----------|-----------|
| Primary DB | PostgreSQL 16 |
| Vector search | pgvector (planned, Stage 2) |
| Object storage | MinIO (dev) / S3 (prod) |
| Message queue | NATS JetStream |
| Container | Docker + Docker Compose |
| Orchestration | Kubernetes + Helm (deploy/) |
| Agent | SystemD (deploy/systemd/) |

### AI Models in use
| Role | Model | Where used |
|------|-------|-----------|
| Report generation | `claude-sonnet-4-20250514` (recommended) | `api/reports_engine.py` |
| Fast / classification | `claude-haiku-4-5-20251001` (default) | `FG_ANTHROPIC_MODEL` env |
| AI plane | Configurable via `FG_AI_DEFAULT_PROVIDER` | `services/ai/dispatch.py` |
| Air-gap fallback | Ollama (planned) | Stage 3 |

---

## 5. Running locally

### Prerequisites
- Python 3.12+
- Node.js 22+ (use nvm)
- Docker Desktop running

### One-time setup
```bash
# 1. Start infrastructure
cd ~/fg-core
docker compose up -d

# 2. Install Python deps
pip install -r requirements.txt

# 3. Run migrations (PostgreSQL)
# Migrations run automatically on startup when FG_DB_MIGRATIONS_REQUIRED=true
# Or manually via any PostgreSQL client:
#   psql $FG_DB_URL -f migrations/postgres/0032_assessment_and_reports.sql
#   psql $FG_DB_URL -f migrations/postgres/0033_seed_assessment_data.sql

# 4. Install frontend deps
cd console && npm install
```

### Starting services (every session)

**Terminal 1 — fg-core API**
```bash
cd ~/fg-core
FG_ENV=development FG_AUTH_ENABLED=0 uvicorn api.main:app --reload --port 8080
```

**Terminal 2 — Console (Next.js)**
```bash
cd ~/fg-core/console
npm run dev
# Runs on http://localhost:3000
```

### Service URLs
| Service | URL |
|---------|-----|
| Console | http://localhost:3000 |
| Landing page | http://localhost:3000 |
| Onboarding | http://localhost:3000/onboarding |
| Assessment | http://localhost:3000/assessment?id={id} |
| Report | http://localhost:3000/reports/{id} |
| Dashboard | http://localhost:3000/dashboard |
| fg-core API | http://localhost:8080 |
| API docs | http://localhost:8080/docs |
| MinIO Console | http://localhost:9001 |
| NATS Monitor | http://localhost:8222 |

### End-to-end flow (dev)
1. Open http://localhost:3000 → click "Start Assessment"
2. Complete 4-step onboarding wizard → "Launch Assessment"
3. Answer questions → "Submit & Score"
4. Click "Generate AI Advisory Report" → waits for Claude
5. View full report with risk score, domain findings, roadmap, framework alignments

---

## 6. Service and API reference

### Customer-facing assessment endpoints (no auth required)

These endpoints are open by design. The assessment UUID is the access token.

```
POST   /assessment/orgs
       Body: {name, industry, employee_count, revenue, handles_phi, handles_cui,
              is_dod_contractor, fedramp_required}
       Returns: {org_id, assessment_id, profile_type, schema_version}

GET    /assessment/assessments/{id}/questions
       Returns: [{id, domain, text, type, options?, weight}]

GET    /assessment/assessments/{id}
       Returns: {id, org_id, profile_type, status, overall_score, risk_band,
                 scores, responses, created_at, submitted_at}

PATCH  /assessment/assessments/{id}/responses
       Body: {responses: {question_id: value}}
       Returns: {saved: true, response_count: N}

POST   /assessment/assessments/{id}/submit
       Returns: {assessment_id, overall_score, risk_band, domain_scores}

POST   /assessment/reports/generate
       Body: {assessment_id, prompt_type: "executive"|"technical"|"compliance"}
       Returns: {report_id, status: "pending"}  — 202 Accepted

GET    /assessment/reports/{id}
       Returns: {id, status, content, error_message, created_at, completed_at}
       Poll every 3s while status is "pending" or "generating"

GET    /assessment/reports/{id}/download
       Returns: {url, expires_in, message}  — PDF URL (Stage 2)
```

### Tenant-authenticated endpoints (require X-API-Key + scopes)

```
POST   /defend                  — Submit event for policy decision
GET    /decisions               — List decisions (decisions:read)
GET    /decisions/{id}          — Get decision detail
GET    /feed/live               — Live event feed (feed:read)
GET    /forensics/chain/verify  — Verify audit chain integrity
GET    /stats/summary           — Dashboard stats (stats:read)
POST   /ai/infer                — AI policy inference (compliance:read)
POST   /ai/chat                 — AI chat with policy gate
GET    /keys                    — List API keys (keys:admin)
POST   /keys                    — Create API key
POST   /audit/cycle/run         — Run audit cycle
GET    /compliance/requirements — Compliance registry
POST   /governance/changes      — Submit governance change request
```

Full contract: `contracts/core/openapi.json`

---

## 7. Database schema

### Migrations applied: 0001–0033

| Migration | Description |
|-----------|-------------|
| 0001 | Base schema: api_keys, security_audit_log, decisions |
| 0002 | Append-only triggers |
| 0003 | Tenant RLS policies |
| 0004–0011 | Auth hardening, config versions, decision binding |
| 0012–0015 | Billing, compliance registry, enterprise extensions |
| 0016–0023 | AI plane, AI hardening, quotas, agent MVP1 |
| 0024–0031 | Agent Phase 2, connectors, control plane v2, provider BAA records |
| **0032** | **org_profiles, assessment_schemas, assessments, prompt_versions, reports** |
| **0033** | **Seed: 35-question bank + 3 AI prompt templates** |

### Assessment tables (migration 0032)

```sql
org_profiles        — One row per customer org created in onboarding
                      tenant_id, org_name, industry, employee_count, revenue,
                      profile_type, handles_phi, handles_cui, is_dod_contractor

assessment_schemas  — Versioned question banks (seeded by 0033)
                      schema_version (UNIQUE), profile_type, questions (JSONB),
                      is_current

assessments         — One row per assessment session (UUID primary key)
                      tenant_id, org_id, profile_type, status, responses (JSONB),
                      scores (JSONB), overall_score, risk_band

prompt_versions     — AI prompt templates (seeded by 0033)
                      prompt_key, version, system_prompt, user_prompt_template,
                      is_active

reports             — Generated advisory reports (UUID primary key)
                      tenant_id, assessment_id, org_id, status, prompt_type,
                      content (JSONB), error_message
```

### Key existing tables (from migrations 0001–0031)

```sql
api_keys              — Tenant-scoped authentication keys
decisions             — Policy decision records (HMAC evidence chain)
audit_ledger_record   — Append-only HMAC-chained audit log
compliance_requirement_record — Compliance registry entries
compliance_finding_record     — Finding tracking
policy_change_requests        — Governance approval workflow
agent_device_registry         — Device agent enrollment
billing_*             — 15 billing/metering tables
ai_token_usage        — AI request tracking and quota enforcement
provider_baa_records  — Vendor BAA enforcement (HIPAA, etc.)
```

### Critical DB rules (do not violate)
- **No SQLAlchemy session on assessment endpoints** — use `_get_db()` not `tenant_db_required()` (assessment flow is auth-free)
- **Never use named parameters** in raw SQL — use positional (`$1`, `$2`)
- **audit_ledger_record is append-only** — no UPDATE or DELETE ever
- **SET LOCAL** for tenant context uses f-string — not bind parameters
- **UUID primary keys** for assessments and reports — stored as TEXT, generated in Python

---

## 8. Assessment engine

**File:** `api/assessments.py`

### Profile classification

The org's profile type drives question count, scoring weights, and report language.
Classification runs at org creation from the onboarding wizard answers:

```
is_dod_contractor OR handles_cui OR fedramp_required  → govcon
handles_phi OR industry in {banking, healthcare, insurance}  → regulated
employees > 1000   → enterprise
employees > 200    → midmarket
employees > 50     → smb_growth
else               → smb_basic
```

| Profile | Questions | Typical org | Key frameworks |
|---------|-----------|-------------|----------------|
| `smb_basic` | 35 | <50 employees, no IT dept | CISA CPG, STATE_BREACH |
| `smb_growth` | 35 | 50–200 employees | + SOC 2 readiness |
| `midmarket` | 35 | 200–1000 employees | SOC 2, ISO 27001 |
| `enterprise` | 35 | 1000+ employees | NIST AI RMF, SOC 2, ISO 27001 |
| `regulated` | 35 | Banks, hospitals | + FFIEC CAT, HIPAA, SR 11-7 |
| `govcon` | 35 | DoD contractors | + CMMC 2.0, NIST 800-171, DFARS |

Note: Currently 35 questions (base schema). Stage 2 adds profile-specific question banks
(60–130 questions). The schema supports this via `assessment_schemas` table versioning.

### Scoring algorithm

**Domain weights (base):**
```
data_governance:      25%
security_posture:     20%
ai_maturity:          20%
infra_readiness:      15%
compliance_awareness: 12%
automation_potential:  8%
```

**Profile weight multipliers** (applied then renormalized):
```
smb_basic:   compliance_awareness × 0.50, automation_potential × 0.50
regulated:   data_governance × 1.30, security_posture × 1.15, compliance_awareness × 1.25
govcon:      data_governance × 1.40, security_posture × 1.30, compliance_awareness × 1.50
```

**Question scoring:**
- `boolean`: Yes = 100, No = 0
- `scale` (1–5): score = (value − 1) × 25
- `select`: position / max-position × 100
- `text`: any response = 50

**Risk bands:**
- Critical: 0–25
- High: 25–50
- Medium: 50–75
- Low: 75–100

---

## 9. Report engine

**File:** `api/reports_engine.py`

### Generation flow

1. `POST /assessment/reports/generate` — creates `reports` row with `status=pending`, enqueues `BackgroundTask`, returns 202 immediately
2. Background task runs `_generate_report_sync(report_id)`:
   - Opens its own DB session (request session is closed)
   - Marks `status=generating`
   - Loads assessment scores and org profile
   - Loads active `prompt_versions` row for `executive_report`, `technical_report`, or `compliance_report`
   - Renders prompt template with org context
   - Calls `call_provider("anthropic", ...)` from `services/ai/dispatch.py`
   - Extracts JSON from response, validates structure, enforces language rules
   - Marks `status=complete` or `status=failed` with `error_message`
3. Frontend polls `GET /assessment/reports/{id}` every 3 seconds until `status=complete`

### Output contract (validated on every generation)

```json
{
  "executive_summary": "string",
  "key_strengths": ["max 3 items"],
  "critical_gaps": ["max 5 items"],
  "domain_findings": {
    "data_governance": "string",
    "security_posture": "string",
    "ai_maturity": "string",
    "infra_readiness": "string",
    "compliance_awareness": "string",
    "automation_potential": "string"
  },
  "roadmap": {
    "days_30": [{"title", "description", "effort", "impact"}],
    "days_60": [...],
    "days_90": [...]
  },
  "framework_alignments": [
    {"framework": "NIST AI RMF", "alignment_pct": 0, "gap_count": 0, "notes": ""}
  ],
  "disclaimer": "must contain 'alignment with, not certification to'"
}
```

### Language rules (enforced in code)
- Never say "certified" — always "aligned with"
- Never say "compliant with" — always "designed to support compliance with"
- `key_strengths` capped at 3
- `critical_gaps` capped at 5

### Prompt templates

Three templates stored in `prompt_versions` table (seeded by migration 0033):

| Key | Audience | Language |
|-----|----------|----------|
| `executive_report` | CEO, CFO, Board | Business language, ROI framing |
| `technical_report` | CISO, CTO | Control IDs, implementation steps |
| `compliance_report` | CCO, Legal, Auditors | Regulatory citations, evidence gaps |

To update a prompt: INSERT a new row with `version='v1.1'`, set `is_active=TRUE`, set old row `is_active=FALSE`. No deployment needed.

---

## 10. Frontend

**Directory:** `console/`  
**Framework:** Next.js 14 App Router  
**Dev server:** `npm run dev` → http://localhost:3000

### Pages

| Route | File | Purpose |
|-------|------|---------|
| `/` | `app/page.tsx` | Marketing landing: hero, features, pricing, CTAs |
| `/onboarding` | `app/onboarding/page.tsx` | 4-step org wizard → creates org + assessment |
| `/assessment` | `app/assessment/page.tsx` | Question wizard, 30s autosave, submit + score |
| `/reports/[reportId]` | `app/reports/[reportId]/page.tsx` | Report viewer, 3s polling, roadmap, framework bars |
| `/dashboard` | `app/dashboard/page.tsx` | Stats, Recharts charts, event feed |
| `/dashboard/alignment` | `app/dashboard/alignment/page.tsx` | Alignment metrics |
| `/dashboard/control-tower` | `app/dashboard/control-tower/page.tsx` | Boot timeline, module status |
| `/dashboard/decisions` | `app/dashboard/decisions/page.tsx` | Decision history table |
| `/dashboard/forensics` | `app/dashboard/forensics/page.tsx` | Forensic chain analysis |
| `/audit` | `app/audit/page.tsx` | Audit log |
| `/keys` | `app/keys/page.tsx` | API key management |
| `/products` | `app/products/page.tsx` | Product management |

### Key components

| Component | Purpose |
|-----------|---------|
| `components/layout/Sidebar.tsx` | Persistent nav sidebar with active-state |
| `components/layout/TopBar.tsx` | Page header with notification bell |
| `components/dashboard/DomainScores.tsx` | Recharts RadarChart (6 domains) |
| `components/dashboard/RequestsChart.tsx` | Recharts AreaChart (allowed vs blocked) |
| `components/ui/{button,card,badge,progress,input,label,select,checkbox}` | Design system primitives |

### API routing (no separate services)

```
Frontend /api/core/* → Next.js proxy → admin-gateway:8080 → fg-core
```

All assessment and report API calls use `/api/core/assessment/*` — the same
fg-core backend. No `NEXT_PUBLIC_ASSESSMENT_URL` or `NEXT_PUBLIC_REPORT_URL` env vars needed.

### State management

| Store | File | What it holds |
|-------|------|--------------|
| `useOnboardingStore` | `lib/store.ts` | Wizard step, org data, org_id, assessment_id |
| `useAssessmentStore` | `lib/store.ts` | Questions, responses, currentIndex, lastSaved |
| QueryClient | `lib/providers.tsx` | TanStack Query global cache |

---

## 11. Compliance frameworks

Frameworks mapped in assessments and report framework_alignments:

| Framework | Applies to |
|-----------|-----------|
| NIST AI RMF | All profiles |
| SOC 2 Type II | Midmarket, Enterprise |
| ISO/IEC 27001:2022 | Enterprise |
| HIPAA + HHS OCR AI Guidance | Healthcare (regulated) |
| HITRUST CSF r2 | Healthcare (regulated) |
| FFIEC Cybersecurity Assessment Tool | Banking (regulated) |
| Federal Reserve SR 11-7 | Banking (regulated) |
| DORA | EU Finance |
| CMMC 2.0 Level 1 (17 practices) | GovCon |
| CMMC 2.0 Level 2 (110 practices) | GovCon |
| NIST SP 800-171 | GovCon |
| DFARS 252.204-7012 | GovCon |
| FedRAMP Moderate | GovCon / Cloud |
| CISA Cyber Performance Goals | SMB |
| State breach notification laws | SMB |

**Language rule (non-negotiable):** Always say "aligned with" or "designed to support compliance with."
Never "certified" or "compliant with" until formal certification is obtained.

---

## 12. Tier system and pricing

### Tier 1 — Snapshot ($299–999, one-time)
- AI governance assessment (35 questions base, 130 for govcon in Stage 2)
- AI-generated advisory report (executive, technical, or compliance variant)
- Risk scoring across 6 domains
- 30/60/90 day remediation roadmap
- Framework alignment percentages
- **Status: BUILT — end-to-end flow functional**

### Tier 2 — Intelligence ($5,000–15,000/year)
- Everything in Tier 1
- Dashboard with trend tracking (risk score over time)
- Industry benchmarking (anonymized dataset)
- Compliance mapping dashboard with control-level detail
- RAG-grounded recommendations from org's own uploaded policies
- Multi-user RBAC (exec/auditor/admin/operator/viewer)
- Assessment delegation across departments
- **Status: NOT BUILT — Stage 2**

### Tier 3 — Control ($50,000–100,000/year)
- Everything in Tier 2
- Drop-in Anthropic/OpenAI-compatible API proxy (AI gateway)
- Real-time OPA policy enforcement on every AI request
- PII/PHI/CUI tokenization at AI boundary
- Provider routing by data classification
- HMAC-chained forensic audit log (already exists in fg-core, expose to customers)
- Response validation (hallucination detection)
- **Status: PARTIAL — fg-core has audit chain, OPA, forensics. Gateway proxy not built.**

### Tier 4 — Autonomous ($100,000–250,000+/year)
- Everything in Tier 3
- Continuous risk monitoring (drift detection already in fg-core)
- Auto-remediation suggestions
- Predictive risk modeling
- Custom compliance modules
- Dedicated customer success
- **Status: NOT BUILT — Stage 4**

---

## 13. Target markets

### Primary (current focus)

**Community Banking — Volusia/Flagler Counties FL**
- Profile: `regulated`, banking, $500M–$2B assets
- Buyer: Compliance officer or CTO
- Pain: Staff using ChatGPT with customer NPI, no policy, examiner scrutiny
- Entry price: $299–999 Snapshot
- Referral: Florida Bankers Association, ICBA

**Medical Groups — Central Florida**
- Profile: `regulated`, healthcare, 5–20 physicians
- Buyer: Practice administrator
- Pain: PHI entering AI tools without BAAs
- Entry price: $299–599 Snapshot
- Referral: FMA, medical office buildings

**Regional Law Firms — Daytona Beach / DeLand**
- Profile: `midmarket`, legal, 10–50 attorneys
- Buyer: Managing partner
- Pain: Client data in AI tools, Florida Bar ethics exposure
- Entry price: $299–999 Snapshot
- Referral: Florida Bar, county bar associations

### Secondary (6–18 months)
- Defense contractors (CMMC Level 2 mandates — govcon profile ready)
- Mid-market technology companies (SOC 2 aspirational)
- Insurance companies (state regulatory pressure)
- Credit unions (NCUA AI guidance emerging)

---

## 14. Build status — what is done

### Infrastructure ✅
- [x] FastAPI backend with all middleware (auth, CORS, DoS guard, logging, resilience)
- [x] PostgreSQL with RLS, append-only triggers, HMAC audit chain
- [x] Redis, NATS JetStream, OPA policy engine (docker-compose)
- [x] Docker Compose + Helm/K8s deployment configs
- [x] CI/CD pipelines (GitHub Actions)
- [x] Device agent (enrollment, telemetry, phase 2 enterprise)
- [x] Migrations 0001–0033 (33 total)

### Customer-facing (Tier 1) ✅
- [x] Marketing landing page with pricing tiers and CTAs
- [x] 4-step onboarding wizard (org profile collection)
- [x] Assessment wizard (35 questions, 30s autosave, domain color coding)
- [x] 6-domain scoring engine with profile-aware weights
- [x] AI advisory report generation (Claude, BackgroundTask, polling)
- [x] Report viewer (executive summary, strengths/gaps, roadmap, framework alignment)
- [x] Assessment and report tables (migrations 0032 + 0033)

### Dashboard / internal ✅
- [x] Recharts dashboard (domain radar, request volume area chart)
- [x] Sidebar navigation with active state
- [x] Stats, alignment, control tower, decisions, forensics, audit pages (wired to fg-core)
- [x] API key management

### Backend governance ✅
- [x] Decision engine (evaluate.py, rules.py)
- [x] HMAC-chained audit chain
- [x] Compliance registry
- [x] Governance change approval workflow
- [x] OPA/Rego policy engine wired
- [x] Forensics chain verification
- [x] Billing and metering infrastructure
- [x] AI plane extension (quota tracking, policy gate)

---

## 15. What needs to be built next

### Stage 1 — Complete the customer funnel (immediate)

- [ ] **Stripe checkout** — $299/$599/$999 tiers wired to `/onboarding` final step
  - Add `stripe_session_id` to `assessments` table (migration 0034)
  - Gate report generation behind payment confirmation
  - Webhook handler for `checkout.session.completed`

- [ ] **Email delivery** — Send completed report link via Resend
  - Collect email in onboarding Step 1
  - Trigger on `reports.status = complete` in `_generate_report_sync`
  - Template: link to `/reports/{id}` + executive summary preview

- [ ] **Production deployment** — VPS (DigitalOcean or Hetzner)
  - Provision PostgreSQL, Redis, NATS, MinIO
  - Apply migrations 0001–0033
  - Set `FG_ENV=production`, `FG_AUTH_ENABLED=1`
  - Configure domain + TLS

- [ ] **Profile-specific question banks** — Currently 35 base questions for all profiles
  - Add 60-question midmarket bank (migration 0034)
  - Add 110-question regulated bank (migration 0034)
  - Add 130-question govcon bank (migration 0034)
  - `GET /assessment/assessments/{id}/questions` already serves from schema table — no code change

- [ ] **PDF export** — Currently returns a stub
  - WeasyPrint or Playwright → PDF from report content
  - Upload to MinIO, return signed URL from `GET /reports/{id}/download`

### Stage 2 — Intelligence tier ($5K–15K/year)

- [ ] **Auth system** — JWT + refresh tokens for multi-user access
  - Users table (migration 0035)
  - RBAC roles: exec, auditor, admin, operator, viewer
  - Link assessments/reports to user who created them

- [ ] **SAML/OIDC enterprise SSO** — Already have Keycloak config in `/keycloak/`

- [ ] **RAG service** — Org policy document upload + retrieval
  - `documents` + `document_chunks` tables (add to 0035)
  - pgvector extension (text-embedding-3-small, 1536 dimensions)
  - Upload endpoint → chunk → embed → store
  - Retrieval in report generation to ground recommendations in org's own policies

- [ ] **Benchmarking service** — Anonymous cross-org scoring
  - Aggregate scores by profile_type + industry (no PII)
  - Dashboard widget: "Your org vs. community banking median"

- [ ] **Compliance mapping dashboard** — Per-framework control-level detail
  - Map each question to specific control IDs per framework
  - Store mapping in assessment_schemas questions (add `framework_mappings` field)

- [ ] **Assessment delegation** — Department-level assessment splitting
  - Allow assessment to be split into sections by department
  - Each section has a separate share link (UUID)

- [ ] **Trend tracking** — Risk score over time
  - Multiple assessments per org → score history chart

### Stage 3 — Control tier ($50K–100K/year)

- [ ] **AI gateway proxy** — Drop-in Anthropic/OpenAI-compatible API
  - Go/Fiber or Python FastAPI — new service or module in fg-core
  - Employees point their AI tools at this endpoint instead of Anthropic directly
  - fg-core's existing decision engine, OPA, and audit chain already support this

- [ ] **Input classification** — Presidio for PII/PHI/CUI detection
  - `services/phi_classifier/` already exists — extend it
  - Block or redact before AI boundary

- [ ] **PII tokenization** — Reversible tokens before AI boundary
  - Token store in Redis (TTL-bound)
  - De-tokenize in response before returning to client

- [ ] **Provider routing** — Route to different models by classification
  - Public → any provider
  - PHI → HIPAA-approved only + BAA check (provider_baa_records already exists)
  - CUI → air-gap mandatory

- [ ] **Response validation** — Hallucination detection
  - Grounding check against org's RAG context

- [ ] **Expose audit chain to customers** — Dashboard for Tier 3 clients showing every AI request

### Stage 4 — Autonomous tier

- [ ] Continuous drift detection (fg-core has drift infra — surface to customers)
- [ ] Auto-remediation suggestions
- [ ] Predictive risk modeling
- [ ] Custom compliance module builder

---

## 16. Environment variables

### fg-core API

```bash
# Environment
FG_ENV=development          # development | staging | production
FG_AUTH_ENABLED=0           # 0 in dev (no API key required)
FG_API_KEY=                 # Global API key for production

# Database
FG_DB_URL=postgresql://frostgate:password@localhost:5432/frostgate
# If not set, falls back to SQLite at $FG_SQLITE_PATH

# AI (report generation)
FG_ANTHROPIC_API_KEY=sk-ant-...
FG_ANTHROPIC_MODEL=claude-haiku-4-5-20251001   # override for report generation
FG_AI_PLANE_ENABLED=1
FG_AI_DEFAULT_PROVIDER=anthropic

# Redis (rate limiting, sessions)
FG_REDIS_URL=redis://localhost:6379

# NATS (async events)
FG_NATS_ENABLED=false       # set true when NATS is running

# Payments (Stage 1)
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...

# Email (Stage 1)
RESEND_API_KEY=re_...
RESEND_FROM_EMAIL=reports@frostgate.ai
```

### Console (Next.js)

```bash
# No NEXT_PUBLIC_ASSESSMENT_URL or NEXT_PUBLIC_REPORT_URL needed.
# All API traffic routes through the single fg-core proxy at /api/core/*.
# These are the only env vars needed:

# Only needed if overriding the default proxy target:
NEXT_PUBLIC_API_URL=http://localhost:8080   # used for health display only
```

---

## 17. Key design decisions

| Decision | Choice | Reason |
|----------|--------|--------|
| One backend, not two | fg-core FastAPI | Eliminate duplicate DB, duplicate Anthropic client, duplicate auth |
| Assessment auth model | UUID as access token (no auth gate) | Customer onboarding must be frictionless before they've paid |
| Assessment tenant_id | `"public"` for onboarding flow | Stage 1 reality — auth and tenant binding added in Stage 2 |
| DB layer on assessment endpoints | SQLAlchemy (not asyncpg) | fg-core is entirely SQLAlchemy — consistency over AIEG's asyncpg choice |
| Report generation | FastAPI BackgroundTask | No Celery/NATS overhead; sufficient for <100 concurrent generations |
| AI provider | `call_provider("anthropic", ...)` | Reuse fg-core's existing provider with timeout, error handling, logging |
| No Instructor library | Raw JSON extraction | Instructor not in fg-core deps; Claude reliably returns JSON when asked |
| Question bank in DB | `assessment_schemas` table | Update questions without deployment; A/B testable |
| Prompt templates in DB | `prompt_versions` table | Rollback a bad prompt with one SQL UPDATE |
| PDF export | Stub returning null URL | Avoid WeasyPrint/Playwright complexity until Stripe pays for it |
| No SQLAlchemy named params | Positional `$N` in raw SQL | asyncpg compatibility (matters for future asyncpg migration) |
| pgvector dimensions | 1536 (text-embedding-3-small) | pgvector IVFFlat/HNSW index limit is 2000 dimensions |
| Audit log | Append-only + HMAC chain | Tamper-evident without blockchain complexity |
| Policy engine | OPA (Rego) | Auditable, testable, version-controllable, microsecond eval |
| Message queue | NATS JetStream | 10x simpler ops than Kafka, same at-least-once guarantees |

---

## 18. File map

```
fg-core/
├── api/
│   ├── main.py                    FastAPI app, all router registration, middleware
│   ├── db.py                      SQLAlchemy engine, session, tenant context
│   ├── db_models.py               All ORM models (54 existing + 5 new assessment models)
│   ├── deps.py                    FastAPI dependencies (get_db, tenant_db_required)
│   ├── assessments.py             ★ NEW — assessment engine (org, questions, scoring)
│   ├── reports_engine.py          ★ NEW — report generation (Anthropic, BackgroundTask)
│   ├── decisions.py               Decision pipeline
│   ├── audit.py                   Audit chain endpoints
│   ├── compliance.py              Compliance registry
│   ├── governance.py              Change approval workflow
│   ├── ai_plane_extension.py      AI policy enforcement endpoints
│   └── [28 other modules]
│
├── services/
│   ├── ai/
│   │   ├── dispatch.py            call_provider() — single AI call boundary
│   │   └── providers/
│   │       ├── anthropic_provider.py   Anthropic via httpx (FG_ANTHROPIC_API_KEY)
│   │       ├── azure_openai_provider.py
│   │       └── simulated_provider.py   Dev/test fallback
│   ├── ai_plane_extension/        AI quota, policy, RAG context
│   └── phi_classifier/            PII/PHI detection (Presidio-based)
│
├── engine/
│   ├── evaluate.py                Decision evaluation pipeline
│   ├── rules.py                   Rule definitions
│   └── types.py                   Core type definitions
│
├── migrations/postgres/
│   ├── 0001–0031_*.sql            Existing migrations (do not modify)
│   ├── 0032_assessment_and_reports.sql  ★ NEW — assessment schema
│   └── 0033_seed_assessment_data.sql    ★ NEW — question bank + prompts
│
├── policy/rego/
│   ├── default.rego               Base OPA policy
│   └── govcon.rego                CUI/ITAR overlay
│
├── console/
│   ├── app/
│   │   ├── page.tsx               ★ NEW — Landing page
│   │   ├── layout.tsx             Root layout + QueryClientProvider
│   │   ├── globals.css            Tailwind + CSS vars
│   │   ├── onboarding/page.tsx    ★ NEW — Onboarding wizard
│   │   ├── assessment/page.tsx    ★ NEW — Assessment wizard
│   │   ├── reports/[reportId]/page.tsx  ★ NEW — Report viewer
│   │   └── dashboard/
│   │       ├── layout.tsx         ★ UPGRADED — Sidebar layout
│   │       ├── page.tsx           ★ UPGRADED — Charts + stats
│   │       └── [alignment, control-tower, decisions, forensics]/
│   │
│   ├── components/
│   │   ├── ui/                    ★ NEW — button, card, badge, progress, input,
│   │   │                                   label, select, checkbox
│   │   ├── layout/                ★ NEW — Sidebar, TopBar
│   │   └── dashboard/             ★ NEW — DomainScores (Radar), RequestsChart (Area)
│   │
│   ├── lib/
│   │   ├── assessmentApi.ts       ★ NEW — typed client → /api/core/assessment/*
│   │   ├── reportApi.ts           ★ NEW — typed client → /api/core/assessment/reports/*
│   │   ├── store.ts               ★ NEW — Zustand onboarding + assessment stores
│   │   ├── providers.tsx          ★ NEW — QueryClientProvider
│   │   └── cn.ts                  ★ NEW — clsx + tailwind-merge
│   │
│   ├── tailwind.config.ts         ★ NEW — FrostGate brand tokens
│   ├── postcss.config.js          ★ NEW
│   └── package.json               ★ UPGRADED — added Tailwind, Radix, Zustand, Recharts, etc.
│
├── SYSTEM.md                      ★ THIS FILE — unified system reference
├── CLAUDE.md                      Repo rules (do not modify)
├── BLUEPRINT_STAGED.md            Governance compliance gates (authoritative)
├── CODEX.md                       AI coding standards (authoritative)
└── docker-compose.yml             PostgreSQL, Redis, NATS, MinIO, OPA
```

---

*FrostGate — AI Governance for Regulated Industries*  
*Built with Claude Code + Anthropic API*  
*Deltona, Florida*
