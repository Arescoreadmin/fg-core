# Moat Assessment

Frame per FOUNDER_DIRECTIVE: classify capabilities by defensibility **and** state the compounding mechanism. Core judgment first:

> **The moat is real and is already over-built relative to client count. The scarce input is no longer engineering — it is engagements flowing through the system.** Launching is the moat action.

---

## Classification

### Deeply defensible (protect; stop deepening pre-launch)

| Asset | Evidence | Compounding mechanism | Verdict |
|-------|----------|----------------------|---------|
| Deterministic evidence chain: SHA-256 payload hashes → Ed25519-signed provenance (fail-closed prod) → lifecycle locks/legal hold → append-only ledgers with DB triggers → verification bundles with tamper detection | E10–E12, E15, E46 | Every engagement adds records that cannot be retroactively fabricated — a competitor cannot backfill years of signed history | **Shipped beyond what any first-10 client will test.** Freeze the expansion arc (FG-LR-024) |
| Governance decision ledger with human actor attribution + SoD | H14 series | Assessor-verified closure records regulators want live only here; switching cost grows per decision | Shipped; sell it |
| Authority architecture (canonical tenants, platform service principal, internal authority tenant, credential authority) | R-series, #585/#586 | Structural trust chain competitors bolt on later at great pain | Shipped; converging after July incidents — validate, don't extend |

### Differentiated (the actual sales wedge)

| Asset | Evidence | Compounding | Verdict |
|-------|----------|-------------|---------|
| Assessor-led field evidence: 13 scan types incl. AI tool discovery, AI data-access mapping, external AI risk register, AI vendor governance (8-state workflow) | E44; PRs 1–4 (June) | Each engagement enriches vendor registry patterns + finding bridges; the *service capability* (runbooks + connector policy + disclosure) compounds as institutional practice | This is what closes deals in the target segment. Invest in polish, not breadth |
| Remediation closed loop w/ evidence capture + NIST auto-update | PR 31/32 | Longitudinal remediation velocity data per client = retention lock | Shipped; automate the follow-through (FG-LR-014) at stage 3 |
| NIST AI RMF 69-control questionnaire with scan-evidence fusion | PR 26/28 | Control-mapping corpus improves with every engagement | Shipped |

### Useful but copyable (don't over-invest)

- Playbooks (HIPAA/SOC2/CMMC/ISO/…) — content, replicable by any consultancy; value is in the *gates wiring*, not the text.
- Risk dashboards, coverage heatmaps, PDF report — table stakes presentation.
- Workforce intelligence (AI query attribution, keywords, alerts) — sellable now, but SIEM/DLP vendors can approximate; its moat value comes from fusion with the evidence chain, not standalone.

### Potentially defensible but underdeveloped (deliberately)

- **Longitudinal drift/reassessment intelligence** — drift detection exists (PR 6) but isn't client-surfaced (`/changes` stub); becomes irreplicable only once real clients have month-over-month history. **Right time: after clients exist.**
- **Cross-tenant benchmarks (CGIN)** — the entire CGIN stack (privacy fingerprints, trust, transparency Merkle ledger, key mgmt) is built, but benchmarks without tenant volume are empty math. **Data advantage requires data.**
- **Customer-specific RAG corpus / governed AI workspace** — portal assistant gated on QA approval exists; corpus depth compounds per client upload. Underdeveloped is correct for now.

### Commodity (never differentiate on these)

Auth/OIDC plumbing, dashboards, PDF generation, Stripe billing, uptime monitoring — buy/standard patterns; zero moat investment.

## Where investment should shift

**Less (freeze pre-launch):** trust-layer expansion PRs (1.6+ open items), enterprise KMS stubs (FG-LR-021), CGIN extensions, subscription/capability metering (FG-LR-022), further bounded contexts (91 service packages already).

**More (post-launch order):**
1. Client-visible before/after delta (turns the drift asset into perceived value — feeds retention).
2. CG v0 is already a launch motion, not post-launch (revision 1.1 — FG-LR-020): the manual baseline/drift/quarterly-review subscription starts the longitudinal clock — the irreversible asset — from client one. The post-launch investment here is its automation (FG-LR-014, the /changes delta view).
3. Report/explanation polish (the compounding *trust* channel with buyers).
4. Second-operator enablement (console gating → training → the operational advantage becomes transferable, i.e., a business not a founder).

## The deepest layer: decision history as institutional memory

Revision 1.2 adds the layer the earlier cuts of this assessment undersold. The compounding asset is not just *longitudinal data* (what was observed over time) — it is **decision history** (what the organization *chose*, *why*, and *who* stood behind it). What accumulates per client, per year:

| Accumulating record | Where it already lives (shipped) |
|---------------------|----------------------------------|
| Evidence, with provenance and lifecycle state | `fa_evidence` + Ed25519-signed provenance + lifecycle locks |
| Findings and their full status history | `fa_findings` + append-only audit events |
| Remediation choices — what was fixed, what was deferred, in what order | remediation loop + roadmap phases + closure evidence notes |
| Governance decisions with reviewer rationale | `fa_governance_decisions` — `decision_reason` is a first-class field, actor-attributed from JWT, approval chain recorded (H14) |
| Accepted risks and granted exceptions | `FaRiskAcceptance` + `FaGovernanceException`, append-only, `exception_granted` preserved across re-scans |
| Policy evolution | governance change workflow + policy versioning |
| Assessment cadence and reassessment triggers | engagement history + (CG v0) drift cycles |
| AI usage change over time | AI tool discovery / vendor governance re-scans; workforce query attribution |
| Reviewer reasoning texture | `fa_governance_events` with `review_duration_seconds`, `decision_reason`, delegation fields |

Two properties make this the hardest layer to compete with:

1. **It cannot be reconstructed, even by the client.** Observational data can be re-scanned by a competitor on day one of a switch. *Why the 2026 risk acceptance was granted, by whom, against which evidence, and what the reviewer weighed* exists nowhere else — not in the client's heads two staff-turnovers later, not in any competitor's onboarding import. After a few years, FrostGate holds the only complete account of the client's governance reasoning — which is precisely the artifact a regulator, an acquirer's due-diligence team, or a new CISO asks for first.
2. **It appreciates on the client's side of the ledger.** Most switching costs are friction the vendor imposes; this one is value the *client* loses by leaving. That is the strongest form of retention, and it compounds without any additional engineering — every QA approval, risk acceptance, and remediation closure is already writing to append-only, attributed, signed ledgers.

The schema for all of it is shipped (see table). The moat action is therefore unchanged and sharpened: **every month of live client operation deposits irreplaceable decision history; nothing on the pre-launch backlog deposits any.**

## What competitors can copy vs. cannot

- **Can copy in a quarter:** scan connectors individually, dashboards, playbook content, PDF formats.
- **Cannot copy:** an installed base of signed, append-only, assessor-attributed governance history — above all the **decision history** (rationale, acceptances, exceptions, reviewer reasoning) that neither a competitor nor the client can reconstruct; plus the combination (field evidence + deterministic chain + governed workflow + remediation loop) as an *operating practice* with runbooks and reference clients in a local trust-dependent market.
- **The unreplicable combination** (FOUNDER_DIRECTIVE) is architecturally present today. Its compounding term is zero until client one. Every week of pre-launch deepening is negative moat ROI relative to a week of client evidence accrual.

**Moat score: 7/10** (architecture 9, accrued data 1, weighting toward what a buyer can verify today).
