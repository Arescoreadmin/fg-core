# FrostGate Console — Operator User Guide

**Audience:** FrostGate operators — technically capable, new to this platform.  
**Purpose:** Reference guide for every section of the console at `console.frostgate.ai`.  
**Navigation tip:** Each section header matches the sidebar label exactly. Use Ctrl+F to jump.

---

## Navigation Overview

The left sidebar groups all pages into six sections:

| Sidebar group | Pages |
|---------------|-------|
| **Operations** | Command Center, Control Tower |
| **AI & Knowledge** | AI Workspace, Corpus, Retrieval, Provenance |
| **Governance** | Policies, Providers, Readiness, Field Assessments |
| **Compliance** | Audit & Forensics, Decisions, Evaluation Lab |
| **Workforce** | Workforce Intel |
| **System** | Settings, Assessments |

The active page is highlighted in the sidebar. The **Sign out** button is at the bottom of the sidebar and calls Auth0 OIDC sign-out.

---

## Operations

### Command Center

`/dashboard` — Real-time operational overview of the platform. Use this as your daily starting point to confirm the system is healthy and scan for active alerts before beginning any other work.

The page refreshes health data every 30 seconds and the control tower snapshot every 60 seconds automatically.

#### Operational Status

Three cards across the top row:

- **System Health** — Polls `/api/core/health/ready`. Shows a green "Healthy" indicator when the core API is reachable, or "Core unreachable" in red if the admin-gateway is down. Dependency statuses (Redis, NATS, etc.) are listed under the main status.
- **Retrieval Health** — Reads the control tower snapshot and reports the status of any registered retrieval plane. Shows "No retrieval plane registered" if none is configured.
- **Audit Status** — Shows the current HMAC chain integrity status and the chain head hash prefix. If `first_bad` is set, a warning appears. A clean chain shows "ok" with the truncated head hash.

#### Governance & Tenancy

Three cards in the second row:

- **Tenant Context** — Displays the active `tenant_id` from the control tower snapshot. Read-only — does not allow tenant switching.
- **Provider Health** — Shows the count of enabled connectors from the snapshot. If connector errors exist, the count of errors is shown in amber.
- **Active Alerts** — Shows how many recent audit incidents exist. If alerts are present, a link to **Audit & Forensics** appears.

#### Quality Metrics

Three cards showing platform-level metrics. These currently display "Not yet measured" until a metric source is configured:

- **Grounded Answer Rate**
- **Provenance Failures**
- **Readiness Summary**

#### Future Capabilities

Four dashed-border placeholder cards for metrics not yet active: SLA Health, Retrieval Latency, Hallucination Trends, Drift Metrics.

#### Platform Activity

- **Billing Status** — Banner showing billing provider readiness. Lists any missing configuration items if billing is not ready.
- **Stats row** — Four stat cards: **Total Requests**, **Blocked** (with block-rate percentage), **Active Tenants**, **Active API Keys**.
- **Request Volume chart** — Area chart of allowed vs. blocked decisions from the live feed, bucketed by hour. Populates once traffic flows through FrostGate.
- **Risk Domain Scores** — Radar chart of the six AI governance domains from the last completed assessment. Populated from `sessionStorage` after running an assessment. Shows an empty state with a **Run Assessment** button if no scores exist.
- **Quick action cards** — Three clickable cards: **Run Assessment** (→ `/onboarding`), **View Reports** (→ `/reports`), **Audit Log** (→ `/audit`).
- **Recent Events** — Scrollable feed of the last 10 live decisions. Each entry shows a severity badge, event label, and relative timestamp.

---

### Control Tower

`/dashboard/control-tower` — Tenant control plane: API key lifecycle, agent device management, connector management, evidence export, locker management, and audit incident review. Use this page to perform any administrative action that changes tenant state.

All actions open a confirmation modal. Destructive actions (revoke, quarantine, restart) are shown in red. Every action that changes state is automatically audit-logged by the backend.

The **Refresh** button at the top right reloads the control tower snapshot.

#### Trust Indicator

At the top of the page, a **TrustIndicator** component shows the current HMAC chain status (verified / degraded) and the request ID and chain head hash of the snapshot. This confirms that the data you are viewing is a real backend snapshot, not cached or fabricated.

#### System Planes

An **EvidenceCard** shows the status of all registered system planes from the snapshot.

#### API Keys

Displays the current active key count and last rotation timestamp.

- **Create key** — Opens a modal with fields for **Scopes** (comma-separated, e.g. `admin:read,ingest:write`) and **TTL** (seconds). Returns the new key material — copy it immediately, it is not shown again.
- **Revoke key** — Destructive. Enter the **Key prefix** (e.g. `fgk_...`). Revocation is immediate; active requests using the key fail immediately.
- **Rotate key** — Destructive. Enter the **Current key material** and a **New TTL**. Issues a new key and revokes the current one after a grace window.

#### Evidence & Chain

- **Replay verify** — Re-runs HMAC chain verification from the last known good state. Returns the verification result in the modal.
- **Export evidence bundle** — Exports a tamper-evident JSON bundle of all audit records for this tenant. Use this to provide chain-of-custody evidence to auditors.

#### Connectors

Shows the count of enabled connectors and the last sync timestamp.

- **Disable connector** — Destructive. Enter the **Connector ID** (e.g. `conn_...`). Revokes the connector and stops all inbound events from it.

#### Agent Devices

Shows total registered devices, quarantine count, and update channel status.

- **List agents** — Fetches and displays the full device list in the modal.
- **Quarantine device** — Destructive. Enter the **Device ID** (e.g. `dev_...`). Isolates the device — all requests from it are blocked.
- **Restore device** — Lifts quarantine. Enter the **Device ID**.

#### Lockers

Shows locker status, count, and last restart time.

- **List lockers** — Fetches the current locker inventory.
- **Restart locker** — Destructive. Drops in-flight requests. Enter the **Locker ID** (e.g. `lck_...`).
- **Resume locker** — Re-enables a paused locker. Enter the **Locker ID**.

#### Recent Incidents

An **AuditTimeline** showing recent audit events from the snapshot. Each event shows the event type, actor, action, status, and timestamp. Empty if no incidents exist.

---

## AI & Knowledge

### AI Workspace

`/dashboard/assistant` — Governed AI chat interface. Use this to ask questions that run through the full FrostGate policy stack: classification, OPA enforcement, RAG retrieval, provider routing, and provenance tracking. Use it to test that policy enforcement is working correctly, or to answer governance questions using org-specific context.

The workspace has three columns:

#### Left column — Conversation

The chat thread. User messages appear right-aligned in the primary color; assistant responses appear left-aligned in a bordered card.

- Type a message in the textarea. **Enter** sends; **Shift+Enter** adds a newline.
- **Send** button submits the prompt.
- **Retry** re-sends the last user message.
- **Copy** copies the latest assistant answer text to the clipboard.
- **Export** exports a safe JSON payload of the latest response (answer, provider, model, request ID, provenance status, confidence, chunk IDs) — no raw vectors, no secrets, no provider internals.

Every request is routed through the backend at `/api/core/ui/ai/chat` with a session ID for correlation.

#### Center column — Response Metadata

Updates after each assistant response. Shows:

- **Provider** — Which AI provider was used and which model. Includes latency in ms and the policy decision action.
- **Confidence** — A confidence meter (0–100) from the retrieval layer.
- **Provenance** — One of: `Sources verified`, `Source not retrieved`, `Source not in prompt`, `No context available`.
- **Context** — Count of corpus chunks used in the response.
- **Retrieval Trace** — Expandable step-by-step trace of the retrieval pipeline.
- **Trace IDs** — Request ID, correlation ID, and retrieval trace ID for investigation in Forensics.

#### Right column — Evidence & Sources

Lists the source documents and citations used to ground the answer. Each citation shows the source name, excerpt, and URL if available.

---

### Corpus

`/dashboard/corpus` — Document corpus browser. Use this to inspect what documents are loaded into the knowledge base, their ingestion status, chunk counts, and embedding state. Use it before running Retrieval to confirm source material is indexed.

#### Corpus & Document Browser

The **CorpusManagementConsole** component provides:

- **Corpus browser** — Lists all tenant-scoped corpora with document count and chunk count.
- **Document browser** — Click a corpus to see its paginated document list. Each document row shows ingestion status, chunk count, embedding state.
- **Ingestion status badges** — `received`, `validating`, `chunking`, `embedding`, `indexed`, `failed`, `quarantined`, `superseded`. Failed and quarantined states are always visible.
- **Version filter** — Toggle between current and superseded document versions.
- **Document detail** — Click a document to see chunk summary, embedding state distribution, and source hash prefix.

Raw vectors, prompts, and provider secrets are never exposed in this view.

---

### Retrieval

`/dashboard/retrieval` — Retrieval policy configuration. Use this to control how the AI workspace retrieves documents from the corpus: which corpora are accessible, what retrieval strategy is used, and whether grounded answers are enforced.

All changes require an explicit save. Invalid configurations are rejected before saving. Every change is audit-logged.

#### Retrieval Governance Policy

The **RetrievalPolicyCenterContainer** component provides:

- **Corpus access control** — Set each corpus to `allowed`, `denied`, or `inherited`. Denied overrides allowed — a corpus marked denied is never accessible regardless of other settings.
- **Retrieval strategy** — Select one of: `lexical`, `semantic`, `hybrid`, `hybrid_rrf`. Validated before saving.
- **Top-K** — Number of chunks returned per query. Integer, validated within bounds (1–20).
- **Semantic toggle** — Enable or disable semantic search. Cannot bypass denied corpora or tenant isolation.
- **Grounded-answer enforcement** — When enabled, answers must be grounded in retrieved context. Matches backend verifier behavior.
- **Lexical fallback** — When enabled, lexical search is used if semantic retrieval returns no results. Never bypasses denied corpora.
- **Policy preview** — Explains the effective state of the current configuration without executing live retrieval.
- **Audit summary** — Shows the last save time and audit record reference.

---

### Provenance

`/dashboard/provenance` — Evidence explorer for tracing how answers were grounded. Use this to investigate provenance failures reported in the AI Workspace, or to produce chain-of-custody records for a specific evidence item.

#### Investigation Filters

Filter the evidence list by:

- **Evidence type** — e.g. `scan_result`, `document_analysis`, `field_observation`
- **Classification** — sensitivity classification of the evidence item

#### Evidence List

Paginated list of evidence references. Click an item to open its detail panel.

#### Evidence Detail Panel

Shows the full metadata for the selected evidence item: source ID, chunk ID, chunk index, PHI sensitivity level, and PHI type flags.

#### Audit Chain Panel

Displays the HMAC audit chain entries associated with the selected evidence item. Confirms the item has not been tampered with.

#### Evidence Timeline

Chronological view of all evidence events for the current assessment, showing when each piece of evidence was collected and by whom.

#### Chain of Custody Panel

A structured view of who touched the evidence item and when.

#### Snapshot Replay Panel

Allows replaying the evidence state at a specific point in time. Use this for audit investigations where you need to reconstruct the state as it existed at a prior timestamp.

---

## Governance

### Policies

`/dashboard/policies` — **Placeholder.** This module will provide OPA policy administration workflows including enforcement rule management and compliance policy visibility. Not yet configured.

---

### Providers

`/dashboard/providers` — **Placeholder.** This module will provide AI provider governance including provider routing rules, classification-based routing, and provider connectivity status. Not yet configured.

---

### Readiness

`/dashboard/readiness` — Compliance readiness scoring against a specific framework and assessment. Use this to see which controls are passing, which have evidence gaps, and what remediation steps are recommended. Select a framework and assessment before any data loads.

#### Framework Selector

Choose a compliance framework (e.g. NIST AI RMF, SOC 2, HIPAA). Then select an assessment. The dashboard clears and reloads when the selection changes.

#### Readiness Overview

Shows the overall readiness score for the selected framework and assessment. Includes a readiness band and threshold failure count.

#### Evidence Completeness

Shows which domains have full evidence, partial evidence, or no evidence. Used to identify where the evidence collection effort is incomplete.

#### Governance Drift

Lists any threshold failures and scoring warnings from the assessment. Threshold failures are controls that scored below the acceptable minimum for the selected framework.

#### Domain Heatmap

Grid of domain-level scores showing which governance domains are strong and which are at risk. Higher scores are cooler colors; lower scores are warmer.

#### High-Risk Gaps and Remediation Queue

- **High-Risk Gaps** — Controls that are failing and have been flagged as readiness blockers.
- **Remediation Queue** — Ordered list of remediation recommendations from the gap analysis engine.

#### Evidence Basis Panel

Per-control evidence scores. Shows how each individual control was scored and what evidence contributed.

#### Snapshot Context

Metadata about the assessment snapshot used to generate the readiness view. Includes the replay contract (used to reproduce the score from the same inputs) and the assessment date.

#### Evidence Lineage

Freshness records for evidence items. Flags stale evidence that may affect score reliability.

---

### Field Assessments

`/field-assessment` — Engagement management list. Use this page to create new client engagements, filter existing engagements by status, and navigate into the workspace for a specific engagement.

#### Creating an Engagement

Click **New Engagement** to expand the creation form. Required fields:

- **Client / Org Name** — The client organization name.
- **Assessment Type** — One of: AI Governance, CMMC, HIPAA, SOC 2, ISO 27001, Comprehensive.
- **Assessor ID** — The operator's email or identifier.

Optional fields:

- **Client Domain** — The client's domain (e.g. `acme.com`).
- **Scheduled Date** — Date picker for the planned assessment date.

Click **Create Engagement** to submit. On success, the console navigates directly to the new engagement's workspace.

#### Engagement List

A table showing all engagements with columns: Client, Type, Status, Assessor, Created, Updated. Click any row to open the engagement workspace.

#### Status Filter

Use the **Filter by status** dropdown to narrow the list. Available statuses: `scheduled`, `pre_visit`, `in_progress`, `evidence_collected`, `report_generation`, `delivered`, `remediation`, `monitoring`, `closed`, `cancelled`.

---

### Field Assessment — Engagement Workspace

`/field-assessment/[id]` — The core field assessment workflow. All evidence collection, scanning, observation capture, questionnaire responses, and report generation happen here. This is the most-used page in the console.

#### Header

Shows the client name, domain, assessment type, assessor ID, and a **Status Badge** (color-coded by current status).

Below the name, four metadata fields: Engagement ID (UUID), Schema Version, Created timestamp, Last Updated timestamp.

#### Status Transition Bar

A clickable progress bar showing all lifecycle states in sequence:

`Scheduled → Pre-Visit → In Progress → Evidence Collected → Report Generation → Delivered → Remediation → Monitoring → Closed`

Click the next state to advance. A reason field is required on transition. The backend records the transition in the audit log.

#### Left Sidebar

Two cards:

- **Guided Execution Panel** — Checklist of assessment checkpoints driven by the playbook engine. Checkpoints are grouped by phase (pre-visit, evidence, review). Clicking a checkpoint label navigates to the corresponding tab. Completion indicators update as evidence is added.
- **Aggregate Counts** — Running totals: scan results, document analyses, observations, evidence links, findings. Counts update after each data entry action.

#### Tabs

The main workspace area has ten tabs. Tab counts update as data is added.

---

##### Overview

Displays the scheduled date and any engagement metadata stored in the `engagement_metadata` JSON field. This is a read-only summary. No data entry happens here — use the other tabs to capture evidence.

---

##### Scans

Ten panels total — nine scan runners and one manual import. Panels are ordered by recommended execution sequence: no-auth scans first (run pre-meeting), device-code scans second (run in-meeting with client admin present).

---

**Run MS Graph Scan** *(device-code flow)*

Authenticates via browser device code and scans the Microsoft 365 tenant for MFA status, Conditional Access policies, guest accounts, and AI governance controls. Checks 39 NIST AI RMF controls.

1. Enter the client **Tenant ID** (Directory ID from Azure Portal).
2. Click **Run MS Graph Scan**.
3. A device code and URL appear — open the URL, sign in with a Global Admin account, enter the code, and accept the consent prompt.
4. The panel polls while the scan runs (~2–5 min). Results appear in the scan list on completion.

---

**Run Entra ID Governance Scan** *(device-code flow)*

Scans PIM role assignments, Access Review definitions, Identity Protection risky users, and Conditional Access policy gaps. Requires Azure AD P2 for full results; P1 tenants complete with partial data.

Same authentication flow as MS Graph Scan — use the same tenant ID and admin session.

---

**Run SharePoint & OneDrive Scan** *(device-code flow)*

Enumerates SharePoint sites and OneDrive drives for anonymous sharing links, external sharing enabled at tenant level, and links with no expiry. Surfaces data-access risk for AI tools with Files.Read.All grants.

Same authentication flow as MS Graph Scan.

---

**Run OAuth Inventory Scan** *(device-code flow)*

Enumerates all OAuth app registrations, enterprise applications, and service principal consent grants in the tenant. Maps which apps have access to what data scopes. Output is used as input to the OAuth Risk scan.

Same authentication flow as MS Graph Scan.

---

**Run OAuth Risk Deep Scan** *(device-code flow)*

Analyzes OAuth grants for high-risk patterns: illicit consent grants, AI tools with broad data access (Mail.Read, Files.ReadWrite.All), write-all permission grants, and apps with no expiry. Run after OAuth Inventory.

Same authentication flow as MS Graph Scan.

---

**Run Endpoint Inventory Scan** *(device-code flow)*

Enumerates Azure AD registered devices and Intune-managed endpoints. Checks device compliance policy assignment, encryption status, and OS version currency. Requires Intune (Microsoft 365 Business Premium or Intune standalone) for full results.

Same authentication flow as MS Graph Scan.

---

**Run Network Scan** *(no authentication required)*

Port scan and TLS inspection against a target host or IP. Enter the target hostname or IP address and click **Run Network Scan**. No client credentials needed — run this pre-meeting.

Checks: open ports, TLS version and certificate validity, weak cipher suites.

---

**Run DNS & Email Security Scan** *(no authentication required)*

Checks DMARC, SPF, DKIM, MX records, and DNSSEC for the client domain. Enter the client domain (e.g. `contoso.com`) and click **Run DNS & Email Security Scan**. No client credentials needed — run this pre-meeting.

---

**Run Web Security Headers Scan** *(no authentication required)*

Fetches the client's public web presence and checks for HSTS, Content-Security-Policy, X-Frame-Options, and Referrer-Policy headers. Enter the client URL and click **Run Web Security Headers Scan**. No client credentials needed — run this pre-meeting.

---

**Import Scan Result** — Paste a previously-exported scan result JSON to register it manually. Use this to import scans run from the CLI or from another system.

---

Below all panels: a list of registered scans showing source type, object count, evidence hash, and collection date.

---

##### Documents

Register supporting documents reviewed during the engagement.

The **DocumentRegistrationPanel** accepts:

- **Document Name** — Name of the document.
- **Document Classification** — e.g. `policy`, `procedure`, `training_record`.
- **Version Label** — (optional) version string.
- **Approved By** — (optional) approver name.

Registered documents appear in a list below. Documents are used by the playbook engine to verify that required document classes are present.

---

##### Observations

Capture manual field observations. Observations are typed notes tied to a specific governance domain and severity.

The **ObservationForm** accepts:

- **Title** — Short description of the observation.
- **Description** — Full text.
- **Observation Type** — e.g. `technical_review`, `process_review`, `documentation_review`.
- **Domain** — The governance domain this observation relates to.
- **Severity** — `low`, `medium`, `high`, `critical`.
- **Assessor ID** — Pre-filled from the engagement.
- **Linked Finding IDs** — (optional) UUIDs of findings this observation supports.
- **Structured Evidence** — (optional) key-value pairs for machine-readable evidence.

Recorded observations appear below the form as collapsible cards. Click a card to expand the full detail including domain, assessor, linked findings, and structured evidence.

---

##### Interviews

Record interview notes as a distinct observation type. Interviews are stored as `observation_type: interview` and appear in this tab only, not the Observations tab.

The **InterviewForm** accepts:

- **Title** — Subject of the interview.
- **Description** — Full notes from the interview.
- **Domain** — Governance domain covered.
- **Interview Role** — The interviewee's role (e.g. `CISO`, `Privacy Officer`).

Recorded interviews appear below as cards showing title, role, domain, and a truncated description.

---

##### Evidence Links

Create explicit links between evidence items (scans, documents, observations) and specific NIST AI RMF controls or findings.

The **EvidenceLinkPanel** allows:

- **Source Type** — The type of evidence being linked.
- **Source ID** — UUID of the scan result, document analysis, or observation.
- **Target Type** — What the evidence is linked to (e.g. `finding`, `nist_control`).
- **Target ID** — UUID of the target.
- **Link Type** — e.g. `supports`, `contradicts`, `resolves`.
- **Notes** — Free-text explanation.

Existing links are listed in the panel. Use evidence links to build the chain of custody between raw evidence and specific control assessments.

---

##### Findings

Read-only view. Findings are generated by the backend governance substrate from scan results, observations, and questionnaire responses — not created manually in this UI.

The **FindingPreviewPanel** shows each finding with: title, severity, domain, description, and linked evidence references. Click a finding to expand its detail.

To see the plain-language AI explanation for a finding, use the Portal client view.

---

##### Questionnaire

Structured per-control evidence input for all 69 NIST AI RMF 1.0 controls across four functions:

| Function | Control range |
|----------|---------------|
| GOVERN | GV.1 – GV.6 |
| MAP | MP.1 – MP.5 |
| MEASURE | MR.1 – MR.6 |
| MANAGE | MG.1 – MG.4 |

The **QuestionnairePanel** shows each control with:

- **Control ID and title**
- **Status** — `not_applicable`, `not_implemented`, `partial`, `implemented`
- **Evidence Notes** — Free text describing the evidence for this control
- **Evidence Source** — The type of evidence (document, scan, interview, etc.)

Click **Submit** on any control to save its response. Submitting a control response automatically links it to relevant findings and updates the Guided Execution Panel checkpoint state.

Controls that were answered `not_implemented` and then have a remediation closed-loop action applied are automatically advanced to `partial` by the backend.

---

##### History

Append-only audit log of all mutations on this engagement. Every create, update, status transition, and evidence addition is recorded automatically by the backend.

Each event shows: event type (monospace), actor, reason code, timestamp, and the mutation payload as collapsed JSON. The log cannot be edited or deleted.

Use this tab to answer questions like "when did this engagement transition to In Progress?" or "who added this scan result?"

---

##### Reports

Signed, versioned governance report generation.

**Generate Report** — Click **Generate** in the **ReportGenerationPanel** to trigger backend report compilation. The report engine normalizes all findings, scans, questionnaire responses, and evidence links into a structured governance deliverable. Generation is backend-authoritative — the console cannot inject content.

**Report Version History** — A list of all generated versions for this engagement. Each version shows the version number, report type, generation timestamp, and section hash. Click a version to load it in the viewer below.

**Report Export Bar** — Appears when a version is selected. Provides:

- **Export JSON** — Downloads the full report as a JSON file.
- **Export PDF** — Generates and downloads the multi-page client-ready PDF. The PDF includes a cover page, AI executive summary, confidence assessment, severity-sorted findings, remediation plan, framework coverage matrix, evidence appendix, and per-page footer with manifest hash.

**Report Viewer** — Inline rendered view of the selected report version. Sections include: executive summary, risk posture, key concerns, findings list, and framework summary.

**Control Gap Matrix** — Generated from the `framework_summary` field of the report. Shows which NIST AI RMF controls have evidence and which are gaps, organized by function (GOVERN/MAP/MEASURE/MANAGE).

---

## Compliance

### Audit & Forensics

`/dashboard/forensics` — Audit investigation tool. Use this when you need to verify chain integrity, look up a specific event by ID, retrieve a snapshot, or produce an audit trail for a forensic investigation.

#### Chain Verify

Runs HMAC chain verification. The **TrustIndicator** shows the result: verified or degraded. If degraded, the first bad record ID is reported.

#### Event Lookup

Enter an **event_id** to retrieve a specific audit record. The result is displayed in an **EvidenceCard** showing the safe metadata fields: event ID, tenant ID, source, threat level, created at, explain summary, severity, action, decision type, policy, reason, confidence.

#### Snapshot Lookup

Enter an **event_id** to retrieve the full snapshot at that point in the audit chain. The snapshot is displayed as a filtered evidence card (raw internal fields are suppressed).

#### Audit Trail Lookup

Enter an **event_id** to retrieve the sequence of audit events from that point. Results are displayed in an **AuditTimeline** with actor, action, status, and timestamp for each event.

The **AuditForensicsConsole** component combines all lookup forms on the page. Use the input fields and action buttons to run lookups. All results include the request ID for correlation with API logs.

---

### Decisions

`/dashboard/decisions` — Policy outcome log. Use this to see every request that flowed through the FrostGate decision engine, filtered by event type or threat level, and to inspect the detail of any specific decision.

#### Filters

Two text inputs: **Event type** and **Threat level**. Type and press Enter, or click **Filter**. Filters are applied together (AND). Clear both fields and re-apply to reset.

#### Decisions Table

Paginated table (10 per page) showing decisions in reverse chronological order. Columns vary by decision type but always include the event ID, action taken, threat level, and timestamp.

Click any row to load the **Decision Panel** below the table.

#### Pagination

**Previous** and **Next** buttons. The current range and total count are shown between them.

#### Decision Panel

Detail view of the selected decision. Shows the full policy decision record including: event type, action, threat level, reason, policy applied, confidence score, and the full evidence payload. Use this to explain to a stakeholder why a specific request was blocked or allowed.

---

### Evaluation Lab

`/dashboard/evaluation` — Retrieval quality testing workspace. Use this to run test queries against the corpus and measure retrieval accuracy before deploying changes to the retrieval policy. All operations are tenant-scoped and exports exclude secrets and provider payloads.

The **EvaluationLabConsole** component provides an operator-grade workspace for running test queries, viewing retrieval results, and comparing different retrieval strategy configurations.

---

## Workforce

### Workforce Intel

`/dashboard/workforce` — Per-user AI activity monitoring and risk profiling. Use this to identify high-risk users, manage user accounts, configure custom content classification keywords, and set up threshold-based alert rules.

A red alert strip at the top shows the count of critical and high risk users in the last 30 days. Click **View** to jump to the Risk Profiles tab.

The page has four tabs:

#### Risk Profiles tab

Table of all users who have made AI queries, ranked by risk score. Columns:

| Column | Meaning |
|--------|---------|
| **User** | Display name and email |
| **Risk** | Risk band badge: Low, Medium, High, Critical |
| **Score** | Numeric risk score (0–100) |
| **Queries** | Total AI queries in the period |
| **Violations** | Count of policy violations (shown in red if > 0) |
| **Personal %** | Percentage of queries classified as personal use (shown in amber if > 30%) |
| **PII Hits** | Queries where PII was detected (shown in red if > 0) |
| **Last Active** | Last query date |

Click **Review** on any row to open the **Activity Drawer** for that user.

**Activity Drawer** — A right-side panel showing:

- **Risk Score — Last 30 Days** — Area chart of daily risk score snapshots.
- **Risk summary** — Six stat tiles: Risk Score, Total Queries, Policy Violations, Personal Ratio, Sensitive Topics, PII Detected.
- **Query History** — Last 50 queries. Each query shows: policy decision (ALLOW/BLOCK/REDACT), subject category, work relevance classification, timestamp, query text. Queries with sensitivity flags show the flag tags. Click **Show response** to expand the response text (capped at 500 characters).

#### User Management tab

Table of all tenant users (invited or active). Columns: User (name + email), Role, Status (Active / Inactive), Invite (Pending / Accepted), Last Active, Added.

- **Deactivate** — Disables an active user. They can no longer authenticate.
- **Reactivate** — Re-enables an inactive user.

**Invite User** button (top right) — Opens a modal to invite a new user:

- **Email** — Required.
- **Display Name** — Required.
- **Role** — `user`, `auditor`, or `admin`.

On success, a one-use invite link is shown (72-hour expiry). Copy it and send it to the user out of band. The link format is: `{portal_host}/accept-invite?token={token}`.

#### Keywords tab

Custom classification triggers that extend the built-in classification rules.

Click **+ Add Keyword** to open the creation form:

- **Keyword / Pattern** — The string or regex pattern.
- **Match Type** — `contains`, `exact`, `word_boundary`, `prefix`, `regex`.
- **Flag Value** — The tag name applied when the keyword matches (e.g. `financial_leak`).
- **Flag Type** — `sensitivity`, `subject`, or `custom`.
- **Action** — `flag`, `block`, or `escalate`.
- **Case sensitive** — Checkbox.
- **Description** — Optional explanation.

Existing keywords appear in a table with **Preview** and **Delete** actions.

**Preview** runs a backtest of the keyword against recent query history and shows how many queries would have matched. Use this to calibrate keyword rules before activating them in a production tenant.

#### Alerts tab

Threshold-based alert rules and their fired alerts.

**Alert Rules** — Click **+ New Rule** to create a rule:

- **Rule Name** — Required.
- **Score ≥** — Numeric threshold (0–100). Rule fires when a user's risk score meets or exceeds this.
- **Band** — One or more risk bands (comma-separated, e.g. `high,critical`). Rule fires when the user's band matches.
- **Cooldown (hours)** — Minimum hours between firings for the same user. Default: 24.

Rules appear in a table with **Pause / Resume** and **Delete** actions.

**Fired Alerts** — Table of alerts that have fired. Columns: Rule, User, Score, Band, Fired timestamp. Click **Dismiss** to acknowledge and remove an alert from the active list.

Toggle **Show dismissed** to view the alert history.

---

## System

### Settings

`/dashboard/settings` — **Placeholder.** This module will provide console configuration, tenant-scoped preferences, and platform administration settings. Not yet configured.

---

### Assessments

`/assessment` — The Tier 1 AI governance assessment wizard. This is the customer-facing assessment flow, accessible from the System group in the sidebar. Operators can use it to run assessments for their own tenant or on behalf of a client. For production client engagements, use **Field Assessments** instead.

---

## Ingestion

`/dashboard/ingestion` — Document upload and ingestion lifecycle tracking. Use this to load new documents into a corpus for the AI workspace to retrieve from.

> **Note:** Ingestion is reached directly by URL or via the AI & Knowledge group in the sidebar on some console builds. If it does not appear in your sidebar, navigate to it directly.

#### Upload & Ingestion Workflow

1. **Select a corpus** — Use the corpus selector to choose the target corpus. Cross-tenant upload is blocked by the backend.
2. **Drop or select files** — Drag files into the drop zone, or click to open a file picker. Supported formats: `.txt`, `.md`.
3. **Monitor ingestion** — The lifecycle badge for each document progresses through: `received → validating → chunking → embedding → indexed`. Failed and quarantined states are always shown.
4. **Inspect state** — Click a document to see its chunk count, embedding state, and source hash prefix.

The ingestion state is polled from the backend on load. Reload the page to re-query current state if the browser was closed during a long ingestion.

---

## Common Workflows

### Starting a New Client Engagement

1. Navigate to **Field Assessments**.
2. Click **New Engagement**, enter the client name, assessment type, and assessor ID.
3. Click **Create Engagement** — the console opens the workspace automatically.
4. In the workspace, use the **Guided Execution Panel** to work through checkpoints in order.
5. Run the MS Graph scan from the **Scans** tab, register client documents in the **Documents** tab, and capture observations in the **Observations** tab.
6. Complete the **Questionnaire** tab with per-control evidence.
7. Advance the status to **Evidence Collected** via the Status Transition Bar.
8. Generate a report from the **Reports** tab. Export PDF for client delivery.
9. Advance to **Delivered**.

### Investigating a Blocked Request

1. Navigate to **Decisions**.
2. Filter by **Event type** or **Threat level** if you know either value.
3. Click the row for the request in question.
4. The **Decision Panel** shows the action, reason, policy applied, and full evidence payload.
5. For deeper chain analysis, copy the event ID and use it in **Audit & Forensics**.

### Revoking a Compromised API Key

1. Navigate to **Control Tower**.
2. In the **API Keys** section, click **Revoke key**.
3. Enter the key prefix in the modal. Confirm.
4. Revocation is immediate — no grace window.
5. Create a replacement key using **Create key** if needed.

### Checking Retrieval Configuration Before a Demo

1. Navigate to **Retrieval**.
2. Confirm that the target corpus is set to `allowed`.
3. Confirm the retrieval strategy and Top-K match the expected behavior.
4. Use **Policy preview** to confirm the effective state.
5. Navigate to **AI Workspace** and send a test query. Confirm the **Retrieval Health** widget on Command Center shows `ok`.

---

*FrostGate Console — Operator User Guide*  
*Last updated: 2026-05-30*
