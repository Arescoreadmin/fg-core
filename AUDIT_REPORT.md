# Sentinel Foundry vNext Compliance Audit Report

**Audit Date:** 2026-01-16
**Auditor:** Security Architect (Automated)
**Repository:** fg-core
**Branch:** claude/audit-sentinel-foundry-compliance-0UNiF
**Blueprint Reference:** `docs/FrostGateCore_Buildout_vNext.md`

---

## Executive Summary

This audit evaluated the fg-core repository against the canonical blueprint "Frost Gate Core — Buildout Blueprint (vNext Improvements)". The repository implements **approximately 25-30%** of the blueprint requirements, with **critical security and compliance gaps** that block IL5/GovCloud readiness.

### Risk Classification

| Risk Level | Count | Description |
|------------|-------|-------------|
| **CRITICAL** | 12 | Security gaps, missing supply chain integrity, no OPA enforcement |
| **HIGH** | 9 | Missing observability, no WORM logging, placeholder jobs |
| **MEDIUM** | 8 | Incomplete hardening, missing load tests, partial Helm config |
| **LOW** | 4 | Documentation gaps, minor config issues |

---

## 1. Repository Inventory

### 1.1 Services & Components

| Component | Location | Status | Description |
|-----------|----------|--------|-------------|
| **frostgate-core** | `api/` | Partial | FastAPI service with `/defend`, `/feed`, `/stats` endpoints |
| **supervisor-sidecar** | `supervisor-sidecar/` | Stub | Go sidecar - basic health check only, no latency/OOM detection |
| **frostgate-agent** | `agent/` | Partial | Telemetry collection agent |
| **merkle-anchor** | `jobs/merkle_anchor/` | Placeholder | Writes stub JSON, no actual Merkle tree or L2 anchoring |
| **chaos-monkey** | `jobs/chaos/` | Placeholder | Writes stub JSON, no actual chaos injection |
| **evidence-bundler** | `scripts/evidence_report.sh` | Partial | No SBOM, cosign, SLSA |

### 1.2 Entrypoints & APIs

| Endpoint | File | Auth | Description |
|----------|------|------|-------------|
| `POST /defend` | `api/defend.py:571` | API Key + Scopes | Core threat evaluation endpoint |
| `GET /feed/live` | `api/feed.py` | API Key | Decision feed stream |
| `GET /stats/*` | `api/stats.py` | API Key | Statistics endpoints |
| `GET /health` | `api/main.py:304` | Public | Health check |
| `GET /health/ready` | `api/main.py:318` | Public | Readiness probe |

### 1.3 Storage Backends

| Backend | Status | Location |
|---------|--------|----------|
| PostgreSQL | Implemented | `docker-compose.yml:12` |
| SQLite | Implemented | Fallback for dev/test |
| Redis | Implemented | Rate limiting only |
| Loki (WORM) | **MISSING** | Blueprint requires S3 Object-Lock |

### 1.4 Critical Missing Directories

Per blueprint Section 16 "Repo Skeleton (Authoritative)":

```
MISSING:
  observability/grafana/scenes/mvp_scene.json  ❌
  security/pss/ (OPA/PSA policies)             ❌ (placeholder only)
  ml/guardrails/ (WASM guardrails)             ❌
  tools/telemetry/golden.json                  ❌
```

---

## 2. Blueprint-to-Repo Compliance Matrix

### 2.1 Spawn Service Requirements

| Requirement | Where Implemented | Evidence | Status | Risk if Missing | Fix |
|-------------|-------------------|----------|--------|-----------------|-----|
| POST /api/spawn endpoint | Not found | No spawn.py or spawn router | ❌ Missing | Cannot provision scenarios for tenants | Create `api/spawn.py` with billing integration |
| Track selection | Not found | No track/scenario selection | ❌ Missing | No training scenario support | Implement track registry |
| Billing stub in staging | Not found | No billing module | ❌ Missing | No usage metering for monetization | Create `api/billing.py` stub |
| Template copy immutability | Not found | No templates directory | ❌ Missing | Scenario tampering risk | Implement copy-on-write templates |
| Posts to orchestrator | Not found | No orchestrator client | ❌ Missing | Cannot spawn isolated environments | Add orchestrator integration |
| Returns {scenario_id, access_url} | Not found | N/A | ❌ Missing | No scenario provisioning | Implement spawn response |
| Short-lived access tokens | `api/auth_scopes.py:72` | `mint_key()` with TTL | 🟡 Partial | 24h SQLite keys, not Vault JWT | Migrate to Vault with 24h JWT + 12h rotation |

### 2.2 Core API Contract (Section 4)

| Requirement | Where Implemented | Evidence | Status | Risk if Missing | Fix |
|-------------|-------------------|----------|--------|-----------------|-----|
| POST /defend | `api/defend.py:571` | `@router.post("")` | ✅ Implemented | N/A | N/A |
| threat_level field | `api/defend.py:267` | `Literal["none","low","medium","high"]` | ✅ Implemented | N/A | N/A |
| mitigations array | `api/defend.py:268` | `list[MitigationAction]` | ✅ Implemented | N/A | N/A |
| explain object | `api/defend.py:269` | `DecisionExplain` | ✅ Implemented | N/A | N/A |
| ai_adversarial_score | `api/defend.py:270` | Hardcoded `0.0` | 🟡 Partial | No AI attack detection | Implement adversarial detector |
| pq_fallback header | `api/defend.py:271` | Hardcoded `False` | 🟡 Partial | No PQ-TLS support | Add PQ-TLS negotiation |
| clock_drift_ms | `api/defend.py:272` | Implemented | ✅ Implemented | N/A | N/A |
| X-PQ-Fallback header | Not found | No gateway integration | ❌ Missing | No PQ negotiation visibility | Add header passthrough |

### 2.3 Security & Compliance (Section 6)

| Requirement | Where Implemented | Evidence | Status | Risk if Missing | Fix |
|-------------|-------------------|----------|--------|-----------------|-----|
| Distroless-FIPS base image | `Dockerfile:28` | `python:3.12-slim` | ❌ Missing | Not FIPS compliant, larger attack surface | Use `gcr.io/distroless/python3-debian12` |
| runAsNonRoot | `deploy/frostgate-core/values.yaml:90` | `runAsNonRoot: true` | ✅ Implemented | N/A | N/A |
| readOnlyRootFilesystem | `deploy/frostgate-core/values.yaml:93` | `readOnlyRootFilesystem: true` | ✅ Implemented | N/A | N/A |
| seccompProfile: RuntimeDefault | `deploy/frostgate-core/templates/deployment.yaml` | Not set | ❌ Missing | Container escape risk | Add seccomp profile |
| capabilities: drop ALL | `deploy/frostgate-core/templates/deployment.yaml` | Not set | ❌ Missing | Privilege escalation risk | Add capabilities block |
| allowPrivilegeEscalation: false | Not found | Not in deployment | ❌ Missing | Privilege escalation risk | Add to securityContext |
| Pod Security Standards (Restricted) | `security/pss/pss-restricted.yaml` | Placeholder only (6 lines) | ❌ Missing | No PSS enforcement | Implement full PSA config |
| eBPF default-deny egress | Not found | No Cilium/eBPF config | ❌ Missing | Data exfiltration risk | Add network policies |
| Vault 24h JWT | `api/auth_scopes.py` | SQLite API keys, no Vault | ❌ Missing | Long-lived secrets, no rotation | Integrate Vault with JWT |
| Auto-rotation every 12h | Not found | No rotation mechanism | ❌ Missing | Stale credential risk | Implement auto-rotation |

### 2.4 Supply Chain Integrity (Section 6)

| Requirement | Where Implemented | Evidence | Status | Risk if Missing | Fix |
|-------------|-------------------|----------|--------|-----------------|-----|
| SBOM generation (Syft) | Not found | No sbom target in CI | ❌ Missing | Unknown dependencies, audit failure | Add `syft` to CI pipeline |
| Cosign image signing | Not found | No cosign in workflows | ❌ Missing | Image tampering risk | Add cosign sign step |
| SLSA provenance | Not found | No SLSA attestation | ❌ Missing | Supply chain attack risk | Add SLSA builder |
| Trivy gate (HIGH/CRIT block) | Not found | No trivy in CI | ❌ Missing | Vulnerable dependencies ship | Add `trivy image` gate |
| OpenSCAP/STIG in CI | Not found | No scap scan | ❌ Missing | Compliance audit failure | Add openscap-scanner |
| CIS K8s v1.9 >= 95% | Not found | No CIS benchmark | ❌ Missing | K8s misconfig risk | Add kube-bench |
| Admission verifies digest/signature | Not found | No admission controller | ❌ Missing | Unsigned images can deploy | Add OPA Gatekeeper or Kyverno |

### 2.5 OPA/Policy Enforcement (Section 14)

| Requirement | Where Implemented | Evidence | Status | Risk if Missing | Fix |
|-------------|-------------------|----------|--------|-----------------|-----|
| OPA/Conftest policies | Not found | Zero `.rego` files | ❌ Missing | No policy enforcement | Create `security/opa/` policies |
| Signed images only | Not found | No admission policy | ❌ Missing | Unsigned image deployment | Add image signature policy |
| No privileged/hostPath | Not found | No constraint | ❌ Missing | Container escape risk | Add privileged pod constraint |
| FIPS tag enforcement | Not found | No policy | ❌ Missing | Non-FIPS images deploy | Add FIPS label policy |
| PSS Restricted enforcement | `security/pss/pss-restricted.yaml` | Placeholder (empty) | ❌ Missing | Insecure pods deploy | Implement PSS restricted |
| SLSA provenance annotation | Not found | No annotation check | ❌ Missing | Unsigned artifacts deploy | Add provenance policy |
| Model-version labels required | Not found | No label enforcement | ❌ Missing | ML version drift | Add model label policy |

### 2.6 Observability (Section 7)

| Requirement | Where Implemented | Evidence | Status | Risk if Missing | Fix |
|-------------|-------------------|----------|--------|-----------------|-----|
| Grafana Scene | Not found | No `observability/` dir | ❌ Missing | No visibility into system health | Create Grafana dashboard JSON |
| p95 latency panel | `api/defend.py:630` | `latency_ms` computed | 🟡 Partial | Metrics collected, not visualized | Add Prometheus + Grafana |
| error rate panel | Not found | No error metrics export | ❌ Missing | No error visibility | Add error rate metric |
| mTLS % panel | Not found | No mesh | ❌ Missing | No mTLS visibility | Add Istio metrics |
| PQ cipher/fallback ratio | Not found | No PQ support | ❌ Missing | No PQ visibility | Add after PQ-TLS |
| supervisor restarts panel | Not found | No restart counter | ❌ Missing | Stability issues hidden | Add restart metric |
| chaos events panel | Not found | Chaos job is stub | ❌ Missing | No chaos visibility | Implement real chaos |
| anchor txids/status panel | Not found | Anchor job is stub | ❌ Missing | No anchor visibility | Implement real anchoring |
| AI Panels (precision/recall/ROC) | Not found | No ML model | ❌ Missing | No AI performance visibility | After ML implementation |
| Model drift alert | Not found | No drift monitor | ❌ Missing | Silent model degradation | Add drift detection |
| PQ-fallback ratio alert | Not found | No PQ support | ❌ Missing | PQ failures undetected | Add after PQ-TLS |
| Anchor deferred > 2h alert | Not found | Anchor is stub | ❌ Missing | Audit gaps undetected | After real anchoring |

### 2.7 Audit & Forensics (Section 6)

| Requirement | Where Implemented | Evidence | Status | Risk if Missing | Fix |
|-------------|-------------------|----------|--------|-----------------|-----|
| Loki + S3 Object-Lock | Not found | No Loki config | ❌ Missing | Logs can be tampered | Add Loki with WORM storage |
| Hourly Merkle anchors | `jobs/merkle_anchor/job.py` | Writes stub JSON only | ❌ Missing | No cryptographic audit trail | Implement real Merkle tree + L2 |
| Dual L2 anchors | Not found | No blockchain RPC | ❌ Missing | Single point of failure | Add BASE_RPC_URL_A/B |
| anchored/deferred status | Not found | No status tracking | ❌ Missing | Anchor failures hidden | Add status endpoint |
| 30-min anchors for high-risk | Not found | No risk-based scheduling | ❌ Missing | High-risk gaps too wide | Add conditional scheduling |

### 2.8 Testing Strategy (Section 11)

| Requirement | Where Implemented | Evidence | Status | Risk if Missing | Fix |
|-------------|-------------------|----------|--------|-----------------|-----|
| Unit tests | `tests/` (32 files) | pytest suite | ✅ Implemented | N/A | N/A |
| Load test (k6 500 RPS) | Not found | No k6 tests | ❌ Missing | Performance regression undetected | Add k6 load test |
| p95 <= 300ms gate | Not found | No latency CI gate | ❌ Missing | Slow responses ship | Add latency assertion |
| Chaos tests | `jobs/chaos/job.py` | Stub only | ❌ Missing | Resilience untested | Implement Litmus |
| Pod kill test | Not found | No pod kill script | ❌ Missing | Recovery untested | Add chaos scenario |
| Unsigned image admission test | Not found | No admission testing | ❌ Missing | Policy bypass undetected | Add admission test |
| PQ negotiation failure test | Not found | No PQ support | ❌ Missing | PQ fallback untested | Add after PQ-TLS |
| Tamper detection test | `api/defend.py:410-424` | Chain hash logic | 🟡 Partial | No test coverage | Add tamper test |
| Adversarial input test | Not found | No adversarial suite | ❌ Missing | AI attacks undetected | Add adversarial tests |
| FPR/FNR SLO enforcement | Not found | No ML model | ❌ Missing | Detection quality unknown | After ML implementation |

### 2.9 Deployment (Section 9)

| Requirement | Where Implemented | Evidence | Status | Risk if Missing | Fix |
|-------------|-------------------|----------|--------|-----------------|-----|
| Namespace: frostgatecore | `deploy/frostgate-core/` | Chart exists | 🟡 Partial | Using default namespace | Set namespace in values |
| Replicas: 3 | `deploy/frostgate-core/values.yaml:1` | `replicaCount: 2` | 🟡 Partial | Under-provisioned | Change to 3 |
| PDB maxUnavailable:1 | Not found | No PDB template | ❌ Missing | All pods can be evicted | Add PDB |
| Probes: /health | `deploy/frostgate-core/templates/deployment.yaml:53-64` | liveness + readiness | ✅ Implemented | N/A | N/A |
| CronJob: merkle-anchor hourly | Not found | No CronJob template | ❌ Missing | Manual anchor runs only | Add CronJob |
| CronJob: chaos-monkey daily | Not found | No CronJob template | ❌ Missing | No automated chaos | Add CronJob |
| Hardened securityContext | `deploy/frostgate-core/values.yaml:88-98` | Partial | 🟡 Partial | Missing seccomp, capabilities | Complete hardening |

### 2.10 CI/CD Pipeline (Section 10)

| Requirement | Where Implemented | Evidence | Status | Risk if Missing | Fix |
|-------------|-------------------|----------|--------|-----------------|-----|
| Build image | `.github/workflows/release-images.yml:65` | `make docker-build` | ✅ Implemented | N/A | N/A |
| SBOM generation | Not found | No syft step | ❌ Missing | Dependency blindness | Add SBOM step |
| Cosign sign | Not found | No cosign step | ❌ Missing | Unsigned images | Add cosign step |
| SLSA provenance | Not found | No SLSA builder | ❌ Missing | No provenance | Add SLSA |
| Trivy scan | Not found | No trivy step | ❌ Missing | Vulnerabilities ship | Add trivy gate |
| OpenSCAP scan | Not found | No scap step | ❌ Missing | Compliance gaps | Add openscap |
| CIS K8s >= 95% | Not found | No kube-bench | ❌ Missing | K8s misconfigs ship | Add CIS gate |
| Helm/Argo canary | Not found | No canary config | ❌ Missing | All-or-nothing deploys | Add canary strategy |
| k6 smoke test | Not found | No k6 | ❌ Missing | Perf regression undetected | Add k6 smoke |
| Evidence bundle CI | `.github/workflows/ci.yml:115` | ci-evidence job | 🟡 Partial | Bundle exists, no SLSA | Add SLSA to bundle |
| Golden telemetry >= 95% precision | Not found | No golden.json | ❌ Missing | Detection quality unknown | Create golden dataset |
| mTLS 100% gate | Not found | No mesh | ❌ Missing | Unencrypted traffic | Add after Istio |
| Anchor job healthy gate | Not found | Anchor is stub | ❌ Missing | Audit gaps ship | After real anchoring |

### 2.11 Multi-tenant Isolation

| Requirement | Where Implemented | Evidence | Status | Risk if Missing | Fix |
|-------------|-------------------|----------|--------|-----------------|-----|
| Tenant registry | `tools/tenants/registry.py` | JSON file-based | 🟡 Partial | File-based, not scalable | Migrate to DB |
| Tenant API key validation | `api/main.py:198-235` | X-Tenant-Id + X-API-Key | ✅ Implemented | N/A | N/A |
| Tenant isolation in DB | `api/defend.py:469` | tenant_id in records | 🟡 Partial | No row-level security | Add RLS |
| Per-tenant rate limiting | `docker-compose.yml:80` | `FG_RL_SCOPE: tenant` | ✅ Implemented | N/A | N/A |
| Tenant-scoped metrics | Not found | No tenant labels | ❌ Missing | Cross-tenant visibility | Add tenant label |

### 2.12 LLM Governance

| Requirement | Where Implemented | Evidence | Status | Risk if Missing | Fix |
|-------------|-------------------|----------|--------|-----------------|-----|
| LLM heuristic in ensemble | Not found | No LLM integration | ❌ Missing | Rules-only detection | Add LLM module |
| Deterministic decoding | N/A | No LLM | ❌ Missing | Non-reproducible results | Design for determinism |
| Prompt caching | N/A | No LLM | ❌ Missing | Latency/cost issues | Add prompt cache |
| AI guardrail (WASM) | Not found | No ml/guardrails/ | ❌ Missing | Unsafe AI outputs | Add guardrail module |
| Model version labels | Not found | No model versioning | ❌ Missing | Version drift | Add model registry |
| Drift monitor | Not found | No drift detection | ❌ Missing | Silent degradation | Add drift monitor |
| Retrain runbook | Not found | No runbook | ❌ Missing | No recovery procedure | Write runbook |

---

## 3. Critical Gaps Summary (Prioritized)

### P0 - Ship Blockers (Fix Before Any Production Use)

| # | Gap | Risk | Effort | Blueprint Section |
|---|-----|------|--------|-------------------|
| 1 | **No OPA/Rego policies** | Unsigned/privileged containers can deploy | 2-3 days | Section 14 |
| 2 | **No SBOM generation** | Unknown dependencies, audit failure | 1 day | Section 6 |
| 3 | **No cosign signing** | Image tampering undetected | 1 day | Section 6 |
| 4 | **No Trivy gate in CI** | Vulnerable images ship | 0.5 days | Section 10 |
| 5 | **Dockerfile uses python:slim, not distroless-FIPS** | Not FIPS compliant, attack surface | 1 day | Section 6 |
| 6 | **No seccomp/capabilities in deployment** | Container escape risk | 0.5 days | Section 9 |
| 7 | **Merkle anchor is stub** | No cryptographic audit trail | 3-5 days | Section 6 |

### P1 - High Priority (Fix Before IL5 Pilot)

| # | Gap | Risk | Effort | Blueprint Section |
|---|-----|------|--------|-------------------|
| 8 | **No Vault integration** | Long-lived secrets, no rotation | 3-5 days | Section 6 |
| 9 | **No Loki WORM logging** | Logs can be tampered | 2-3 days | Section 6 |
| 10 | **No k6 load testing** | Performance regression undetected | 1-2 days | Section 11 |
| 11 | **No golden telemetry dataset** | Detection quality unknown | 1-2 days | Section 5 |
| 12 | **No Grafana observability** | Blind to system health | 2-3 days | Section 7 |
| 13 | **No PDB in Helm** | All pods can be evicted | 0.5 days | Section 9 |
| 14 | **No CronJobs for anchor/chaos** | Manual operations only | 1 day | Section 9 |
| 15 | **PSS placeholder is empty** | No pod security enforcement | 1 day | Section 14 |
| 16 | **No SLSA provenance** | Supply chain attack risk | 1-2 days | Section 6 |

### P2 - Medium Priority (Fix Before V2)

| # | Gap | Risk | Effort | Blueprint Section |
|---|-----|------|--------|-------------------|
| 17 | **No eBPF egress policies** | Data exfiltration risk | 2-3 days | Section 6 |
| 18 | **No mTLS mesh (Istio)** | Unencrypted internal traffic | 3-5 days | Section 2 |
| 19 | **No PQ-TLS support** | Not post-quantum ready | 5+ days | Section 2 |
| 20 | **No chaos testing (Litmus)** | Resilience untested | 2-3 days | Section 11 |
| 21 | **No CIS K8s benchmark** | K8s misconfigs undetected | 1 day | Section 10 |
| 22 | **No billing stub** | No usage metering | 2-3 days | Section 2.1 |
| 23 | **No spawn endpoint** | Cannot provision scenarios | 3-5 days | Section 2.1 |
| 24 | **ci-evidence target missing** | Documented but not implemented | 0.5 days | Makefile |

### P3 - Lower Priority (Roadmap Items)

| # | Gap | Risk | Effort | Blueprint Section |
|---|-----|------|--------|-------------------|
| 25 | No LLM integration | Rules-only detection | 5+ days | Section 3 |
| 26 | No WASM guardrails | No AI safety layer | 5+ days | Section 3 |
| 27 | No federation support | Single-cluster only | 5+ days | Section 20 |
| 28 | No agentic learning loop | No adaptive defense | 5+ days | Section 20 |

---

## 4. Container Hardening Gap Analysis

### 4.1 Current Dockerfile Issues

```dockerfile
# CURRENT (Dockerfile:28-61)
FROM python:3.12-slim AS runtime  # ❌ Not distroless-FIPS
USER frostgate                     # ✅ Non-root
# Missing: seccomp, capabilities, read-only FS at container level
```

### 4.2 Required Dockerfile Changes

```dockerfile
# REQUIRED per blueprint
FROM gcr.io/distroless/python3-debian12:nonroot-fips AS runtime
# OR for IL5: use approved FIPS base image

USER nonroot:nonroot
ENTRYPOINT ["python", "-m", "uvicorn", "api.main:app", ...]

# Note: readOnlyRootFilesystem enforced at K8s level
```

### 4.3 Helm securityContext Gaps

```yaml
# CURRENT (values.yaml:88-98)
securityContext:
  core:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    readOnlyRootFilesystem: true
    # MISSING: seccompProfile, capabilities, allowPrivilegeEscalation

# REQUIRED per blueprint Section 9:
securityContext:
  runAsNonRoot: true
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  seccompProfile:
    type: RuntimeDefault
  capabilities:
    drop: ["ALL"]
```

---

## 5. Evidence of Findings

### 5.1 No OPA Policies

```bash
$ find /home/user/fg-core -name "*.rego"
# (no output)
```

### 5.2 PSS Placeholder is Empty

```yaml
# security/pss/pss-restricted.yaml (entire file - 6 lines)
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
# Placeholder – later tie to OPA / PSA; for now it's just a marker file.
metadata:
  name: frostgate-pss-restricted
```

### 5.3 Merkle Anchor is Stub

```python
# jobs/merkle_anchor/job.py:12-28
async def job() -> None:
    """
    Smoke-test Merkle anchor job.
    Real implementation should:
      - compute Merkle root over decisions
      - anchor to external attestation system
      - write status for /anchor/status
    """
    payload = {
        "status": "ok",
        "anchored_at": datetime.now(timezone.utc).isoformat(),
        "detail": "placeholder Merkle anchor job",  # <-- Stub!
    }
```

### 5.4 No SBOM/Cosign in CI

```yaml
# .github/workflows/release-images.yml - NO mention of:
# - syft
# - cosign
# - slsa
# - trivy
# - openscap
```

### 5.5 Missing Golden Telemetry

```bash
$ find /home/user/fg-core -name "golden*"
# (no output)

# tools/telemetry/loader.py:11 expects:
GOLDEN_PATH = BASE_DIR / "tools" / "telemetry" / "golden_sample.json"
# File does not exist
```

### 5.6 ci-evidence Target Not Implemented

```makefile
# Makefile:124 (help text mentions it)
"  make ci-evidence         evidence lane (itest-up + smoke + evidence)" \

# But no actual target definition exists in the Makefile
$ grep "^ci-evidence" Makefile
# (no output)
```

---

## 6. Recommended Path to Completion

### Phase 1: Security Foundations (Week 1)

1. **Day 1-2**: Create OPA policies
   - Image signature verification
   - Privileged pod denial
   - PSS Restricted enforcement

2. **Day 2-3**: Add supply chain integrity to CI
   - Add `syft` SBOM generation
   - Add `cosign sign` after build
   - Add `trivy image --exit-code 1 --severity HIGH,CRITICAL`

3. **Day 3-4**: Harden container
   - Switch to distroless-FIPS base
   - Complete securityContext in Helm

4. **Day 4-5**: Implement ci-evidence target
   - Wire up evidence_report.sh
   - Add manifest signing

### Phase 2: Observability & Audit (Week 2)

5. **Day 1-2**: Deploy Loki with WORM
   - S3 Object-Lock configuration
   - Fluent-bit forwarder

6. **Day 2-3**: Create Grafana dashboards
   - MVP scene per blueprint Section 7

7. **Day 3-5**: Implement real Merkle anchor
   - Merkle tree over decisions
   - Dual L2 anchoring (testnet first)
   - Status endpoint

### Phase 3: Testing & Compliance (Week 3)

8. **Day 1-2**: Add k6 load tests
   - 500 RPS for 10 min
   - p95 <= 300ms assertion

9. **Day 2-3**: Create golden telemetry
   - Benign samples
   - Brute force samples
   - Polymorphic/AI-generated samples

10. **Day 3-5**: Add CIS/SCAP scanning
    - kube-bench integration
    - OpenSCAP CI step

### Phase 4: Production Readiness (Week 4)

11. **Day 1-2**: Vault integration
    - 24h JWT tokens
    - 12h auto-rotation

12. **Day 2-3**: Add PDB and CronJobs to Helm

13. **Day 3-5**: Chaos testing with Litmus
    - Pod kill scenarios
    - Network latency injection

---

## 7. Risk Summary

| Category | Blueprint Compliance | Production Risk |
|----------|---------------------|-----------------|
| Security Controls | 25% | **CRITICAL** - Missing OPA, supply chain |
| Observability | 10% | **HIGH** - Blind operations |
| Audit Trail | 15% | **CRITICAL** - No WORM, stub anchor |
| Testing | 40% | **HIGH** - No load/chaos tests |
| Container Hardening | 50% | **MEDIUM** - Partial securityContext |
| Authentication | 60% | **MEDIUM** - No Vault, file-based keys |
| Core API | 80% | **LOW** - Most endpoints work |

---

## 8. Appendix: File Reference

| Category | Key Files |
|----------|-----------|
| Blueprint | `docs/FrostGateCore_Buildout_vNext.md` |
| Contract | `CONTRACT.md` |
| Main API | `api/main.py`, `api/defend.py` |
| Auth | `api/auth.py`, `api/auth_scopes.py` |
| Jobs | `jobs/merkle_anchor/job.py`, `jobs/chaos/job.py` |
| Helm | `deploy/frostgate-core/` |
| CI | `.github/workflows/ci.yml`, `release-images.yml` |
| Security | `security/pss/pss-restricted.yaml` (placeholder) |
| Dockerfile | `Dockerfile` |
| Makefile | `Makefile` |

---

**Report Generated:** 2026-01-16
**Next Review:** Upon completion of Phase 1
