# Frost Gate Core — Buildout Blueprint (vNext Improvements)

*Drop this file into `/docs/FrostGateCore_Buildout_vNext.md`. It merges the current, locked blueprint with the latest upgrades so the team can implement immediately and stage heavier changes for V2.*

---

## 0) Executive Summary
- **Mission:** Real‑time, self‑healing, IL5‑ready defense microservice for Frost Gate Foundry.
- **MVP Focus:** `/defend` ≤ **300 ms** p95 @ 500 RPS; immutable WORM logging with dual blockchain anchors; zero‑trust mesh; supply‑chain integrity; chaos resilience; explainability.
- **North Star:** Open, auditable, edge‑deployable defense fabric with **post‑quantum crypto**, **autonomic patching**, **predictive threat‑twin**, **confidential edge**, **quantum‑noise watermarking**, and **AI‑adversarial robustness** (detect & resist AI‑generated attacks).

---

## 1) Success Criteria (SLOs, DoR/DoD)
**Service SLOs**
- Availability ≥ **99.9%** monthly
- p95 `/defend` ≤ **300 ms** (MVP) → **100–120 ms** target in V2 (sidecar‑less mesh)
- Log anchors ≥ **1/hour**; verification errors **0**; deferred anchors < **2h**
- 100% mesh mTLS; **PQ‑TLS negotiated** *or* clean fallback header `X-PQ-Fallback: true`
- **AI Detection SLOs:** FPR ≤ **5%**, FNR ≤ **8%** on golden set (incl. AI‑augmented attacks)

**Definition of Ready**
- Golden telemetry updated (benign + brute force + polymorphic/AI artifacts)
- Threat model updated; OPA/Conftest policies defined

**Definition of Done**
- Unit + load + chaos + security scans **green**
- **CIS K8s v1.9 (2025)** ≥ **95%** pass in CI
- Evidence bundle contains **SBOM**, **cosign attestation**, **STIG/SCAP XML**, **Trivy report**, **Helm values**, **SLSA provenance**
- Runbooks current

---

## 2) Architecture Overview
```
Kubernetes (GovCloud IL5)
  ├─ frostgatecore-api (FastAPI → V2 Rust/Go)
  │    └─ Ensemble (rules + anomaly + LLM) → V2: AI Guardrail (WASM)
  ├─ supervisor-sidecar (Go)
  ├─ istio-proxy (FIPS + PQ hybrid TLS) → V2: Cilium (sidecar‑less)
  ├─ fluent-bit → Loki (WORM, Object‑Lock)
  ├─ merkle-anchor (dual L2 anchors, deferred status)
  ├─ chaos-monkey / Litmus v3 (staged)
  └─ Vault (24h JWT), OPA/Conftest, eBPF policies
```

---

## 3) Modules & Responsibilities (with upgrades)
| Module | Lang | Responsibility | Interfaces | Upgrades |
|---|---|---|---|---|
| **API** | Python (→ Rust/Go V2) | Validate telemetry; call ensemble; return mitigation + explain; emit logs | `/defend`, `/health`, `/status` | Add `/simulate` (threat‑twin) in Roadmap; PQ fallback header passthrough |
| **Ensemble** | Py (rules + anomaly + LLM) | Majority vote + confidence | in‑proc; model files | V2: transformer/graph anomaly; predictive previews; guardrail WASM between ensemble & API |
| **Supervisor** | Go | Detect latency/OOM; pod restart | K8s API | Track LLM/GPU spikes (labels/metrics); PSA integration for dynamic restrict |
| **Log Forwarder** | Fluent‑bit | JSON → Loki WORM | OTLP/HTTP | V2 option: eBPF forwarding |
| **Merkle Anchor** | Python job | Hourly Merkle root → dual L2; status | Loki; RPC | High‑risk tenants: 30‑min; optional ZK proofs (Roadmap) |
| **Chaos** | Bash/kubectl | Pod/node kill | K8s RBAC | Litmus v3 scenarios incl. model‑poison drills (Roadmap) |
| **Evidence Bundler** | Bash | Zip SBOM/cosign/STIG/Trivy/Helm | CI artifacts | Add SLSA + in‑toto attestations |

---

## 4) API Contract (MVP+)
**POST `/defend`**
- **Output additions:**
```json
{
  "threat_level": "high",
  "mitigations": [ ... ],
  "explain": { ... },
  "ai_adversarial_score": 0.0,
  "pq_fallback": false,
  "clock_drift_ms": 12
}
```
- **Headers:** `X-PQ-Fallback: true` (set by gateway if PQ not negotiated). Prepare for HQC hybrid in V2.

---

## 5) Data & Models
- **Rules:** deterministic patterns (SSH brute force, ephemeral sweeps)
- **Anomaly (MVP):** Isolation‑Forest → **V2:** autoencoder or GNN for sequence/relationship attacks
- **LLM heuristic:** small instruct model; deterministic decoding; cache prompts
- **AI adversarial detector:** lightweight heuristic (MVP) → upgrade to learned classifier V2
- **Golden Telemetry:** include AI‑deepfake lures, polymorphic logs, and benign noise

---

## 6) Security & Compliance
**Runtime**
- Distroless‑FIPS, rootless, read‑only FS, `seccomp=RuntimeDefault`
- **Pod Security Standards (Restricted)** via PSA/OPA
- eBPF default‑deny egress; allow only Loki/Vault/anchor RPCs
- Vault 24h JWT secrets with **auto‑rotation every 12h**

**Supply Chain**
- Buildx/Bazel → SBOM (Syft) → cosign sign; admission verifies digest/signature
- Trivy gate (HIGH/CRITICAL fail); **OpenSCAP/STIG** in CI
- **SLSA provenance + in‑toto** attestations included in Evidence Bundle

**Audit & Forensics**
- Loki + S3 Object‑Lock; hourly (or 30‑min) anchors; `anchored`/`deferred`
- (Roadmap) AI‑assisted triage summaries for PCAP/process maps

---

## 7) Observability & Demo UX
- **Grafana Scene:** p95 latency, error rate, mTLS %, PQ cipher/fallback ratio, supervisor restarts, chaos events, anchor txids/status
- **AI Panels:** detection precision/recall, 24‑h ROC snapshot
- **Alerts:** model drift anomaly; PQ‑fallback ratio > threshold; anchor `deferred` > 2h; Kubecost daily spend cap

---

## 8) Environments
| Env | Purpose | Notes |
|---|---|---|
| Dev (K3s/kind) | Local iteration | Minimal secrets; no mesh |
| Stage | Integration & chaos | Istio mTLS; Vault; anchors on testnets |
| **Prod Shadow** | Threat‑twin simulations | Mirrored traffic + mutations; read‑only decisions |
| IL5 Pilot | Design partner | FIPS nodes; dual anchors on mainnets; SCAP in CI |

---

## 9) Deployment (Helm)
- Namespace: `frostgatecore`; Replicas: 3; PDB `maxUnavailable:1`
- Probes: `/health` readiness/liveness
- Secrets: `API_KEY`, `LOG_INDEXER_URL`
- CronJobs: `merkle-anchor` hourly (30‑min for high‑risk), `chaos-monkey` daily (randomized window)

**Hardened securityContext (apply to all containers):**
```yaml
securityContext:
  runAsNonRoot: true
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  seccompProfile: { type: RuntimeDefault }
  capabilities: { drop: ["ALL"] }
```

---

## 10) CI/CD Pipeline & Gates
1. **Build:** image → SBOM → cosign → SLSA provenance
2. **Scan:** Trivy (HIGH/CRITICAL block) + OpenSCAP + CIS K8s v1.9 ≥ 95%
3. **Deploy:** Helm/Argo canary (10%→100%) with k6 smoke
4. **Evidence:** bundle artifacts (zip) with SLSA

**Promotion Gates**
- Golden telemetry ≥ **95%** precision
- mTLS **100%**; PQ negotiated or fallback header present
- p95 latency pass
- Anchor job healthy in last **2h**
- CIS ≥ **95%**; SLSA provenance verified

---

## 11) Testing Strategy
- **Unit:** rules, anomaly scoring, schema validation
- **Load:** k6 500 RPS 10 min → p95 ≤ 300 ms
- **Chaos:** pod kill; net latency; (V2) disk fill, node pressure via Litmus v3
- **Security:** unsigned image admission test; PQ negotiation failure → TLS1.3 fallback + header
- **Tamper:** flip log byte → verifier flags; AI‑generated forgery → mismatch detected
- **Adversarial:** small suite of AI‑crafted inputs; enforce FPR/FNR SLOs

---

## 12) Runbooks (condensed)
**Rotate Secrets** → Issue Vault JWT → rollout restart → verify mTLS

**Verify Anchor** → Query Loki batch → recompute Merkle → compare to L2 tx payload(s)

**Kill & Recover** → `kubectl delete pod` → supervisor restarts < 2s → Grafana latency steady

**AI Retraining** → drift > threshold → retrain on expanded golden set → shadow‑serve → canary → promote on SLO pass

---

## 13) Roadmap
**MVP (now):** Core API, ensemble v0, supervisor, WORM + dual anchor, mTLS + PQ fallback, chaos, evidence CI + SLSA, Grafana scene, golden pack.

**V2 (4–6 wks post‑MVP):**
- **Cilium** sidecar‑less mesh; **WASM** rule plug‑ins; **OTel** native exporters
- Anomaly model upgrade (autoencoder/GNN); AI guardrail; p95 target **100–120 ms**

**Advanced Phases:**
1) Post‑Quantum crypto: Kyber/Dilithium (+ prepare for HQC hybrids)
2) Autonomic self‑patching AI (SBOM diff → PRs → gated merge)
3) Predictive threat‑twin (nightly mirror + mutation engine)
4) Confidential‑edge kit (ARM/RISC‑V TEEs; 512 MB image)
5) Quantum‑noise watermarking (tamper‑evident augmentation)
6) AI‑vs‑AI defense simulations (GANs / red‑team generators)

---

## 14) Governance & Policies
- OPA/Conftest: signed images only; no privileged/hostPath; FIPS tag; **PSS Restricted**; **SLSA provenance annotation required**; model‑version labels required
- Branch protection: required checks = build, scan, deploy‑canary, evidence
- Change control: versioned Helm values; emergency rollback playbook

---

## 15) Risks & Mitigations
| Risk | Mitigation |
|---|---|
| PQ‑TLS instability | Automatic TLS1.3 fallback + header; branch‑cluster testing |
| Mesh misconfig | Hardened Helm profile; smoke tests; staged Cilium migration |
| Anchor RPC outage | Dual anchors + `deferred` status; buffer & backfill |
| AI model drift | Drift monitor; shadow‑serve; gated canary; retrain runbook |
| **AI‑assisted supply chain attacks** | Continuous SCA; signed deps; in‑toto chain; admission blocks on missing attestations |

---

## 16) Repo Skeleton (authoritative)
```
frostgatecore/
  api/                      # FastAPI → V2 Rust/Go
  supervisor-sidecar/
  jobs/ (merkle-anchor, chaos-monkey, evidence-bundle)
  tools/telemetry/ (golden.json, generator.py)
  deploy/helm/frostgatecore/
  observability/grafana/scenes/mvp_scene.json
  security/pss/ (PSA/OPA policies)
  ml/guardrails/ (WASM guardrails – staged)
  .github/workflows/ (build, scan, deploy, evidence)
  README.md
```

---

## 17) Configuration (Env Vars)
- `LOG_INDEXER_URL`, `API_KEY`
- `PQ_FALLBACK_HEADER` (default `x-pq-fallback`)
- `BASE_RPC_URL_A`, `BASE_RPC_URL_B` (anchors)
- `AI_MODEL_DRIFT_THRESHOLD`, `AI_ADV_SCORE_THRESHOLD`

---

## 18) Acceptance Checklist (release)
- [ ] Golden telemetry ≥ **95%** precision; FPR ≤ 5%, FNR ≤ 8%
- [ ] p95 ≤ **300 ms** @ 500 RPS (MVP); PQ negotiated or fallback header present
- [ ] Hourly anchors healthy; no `deferred` > 2h
- [ ] **CIS K8s ≥ 95%**; Evidence bundle includes **SLSA**
- [ ] Runbooks updated

---

## 19) Glossary
- **WORM:** Write‑Once Read‑Many
- **PQ‑TLS:** Post‑Quantum‑capable TLS hybrids
- **SLSA:** Supply Chain Levels for Software Artifacts (provenance)
- **HQC:** Post‑quantum KEM (prepare for hybrid)
- **SCA:** Software Composition Analysis
- **PSS:** Pod Security Standards

---

## 20) Federation, Agentic Learning & Frost Gate Foundry Integration

### Federation
- Introduce `federation-domain` config for cross‑Foundry clusters (Core ↔ Spear ↔ Edge).
- Signed OPA bundle sync for shared policies.
- Cross‑cluster Merkle reconciliation (`anchor_federate_job`).

### Agentic Learning
- Each Foundry environment hosts its own **Frost Gate Agent Loop**:
  1. Observe (telemetry)
  2. Explain (ensemble reasoning)
  3. Act (apply mitigation / chaos)
  4. Verify (evaluate effect)
  5. Commit (update golden telemetry)
- Guardrail agents packaged as WASM modules, invoked per-scenario.
- Drift, anomaly, and chaos feedback flow into Foundry’s adaptive retraining queue.

### Frost Gate Foundry Integration
- Foundry spins up **Core**, **Spear**, and **Twin** environments from declarative manifests.
- `/foundry-sync` job publishes SBOMs, anchors, and AI metrics back to Foundry vaults.
- Foundry Ontology schema links:
  - `threat_level` → `Foundry.Defense.Threat`
  - `ai_adversarial_score` → `Foundry.Metrics.AgentConfidence`
  - `anchor_txid` → `Foundry.Audit.AnchorRef`
- Foundry controller can trigger **Core → Spear → Core** replay cycles for adaptive hardening.

*End of Frost Gate Core vNext Blueprint.*

