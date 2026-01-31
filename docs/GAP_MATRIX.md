# Gap Matrix — FrostGate Production Readiness

> **Source of Truth** for all production gaps.
> CI fails if ANY `Production-blocking` gaps remain open.

## Severity Classification Rules

Severity levels are **machine-enforced** by `scripts/gap_audit.py`.

### Production-blocking (CI FAILS)

A gap is `Production-blocking` if ANY of the following are true:

- Cross-tenant data access is possible
- Auth fallback is enabled in production config
- Audit or integrity claims are not verifiable
- CI cannot detect unsafe production configuration
- Security-critical blueprint promise is unimplemented

### Launch-risk (CI WARNS)

A gap is `Launch-risk` if:

- Incident response procedures are incomplete
- Compliance evidence collection is manual
- Placeholder jobs exist for resilience or integrity features

### Post-launch (INFORMATIONAL)

A gap is `Post-launch` if:

- Only affects UX, analytics, or optimizations
- No immediate security or compliance impact

---

## Gap Matrix

| ID | Gap | Severity | Evidence (file / test / CI lane) | Owner | ETA / Milestone | Definition of Done |
|----|-----|----------|----------------------------------|-------|-----------------|--------------------|
| G001 | Auth fallback defaults to true in docker-compose | Launch-risk | `docker-compose.yml:67` / `scripts/prod_profile_check.py` / `.github/workflows/ci.yml` / `unit` | repo | V2 | `FG_AUTH_ALLOW_FALLBACK` defaults to `false` in docker-compose.yml and prod_profile_check.py fails if truthy |
| G002 | ~~SLSA provenance attestations not generated~~ | ~~Launch-risk~~ | `scripts/provenance.py` / `tests/test_compliance_gates.py` / `.github/workflows/ci.yml:compliance` | infra | CLOSED | Evidence bundle includes SLSA provenance JSON; CI verifies provenance attestation |
| G003 | ~~OpenSCAP/STIG compliance scan not in CI~~ | ~~Launch-risk~~ | `scripts/scap_scan.py` / `tests/test_compliance_gates.py` / `.github/workflows/ci.yml:compliance` | infra | CLOSED | CI job runs SCAP-style static scan; results in evidence bundle |
| G004 | ~~CIS K8s v1.9 benchmark not enforced~~ | ~~Launch-risk~~ | `scripts/cis_check.py` / `tests/test_compliance_gates.py` / `.github/workflows/ci.yml:compliance` | infra | CLOSED | CI runs CIS-style config checks; gate fails if score < 70% |
| G005 | ~~Merkle anchor job placeholder~~ | ~~Launch-risk~~ | `jobs/merkle_anchor/job.py` / `tests/test_merkle_anchor.py` / `fg-fast` | repo | CLOSED | `merkle-anchor` job computes real Merkle root, anchors to hash-chained log; verification test passes |
| G006 | Chaos testing jobs not implemented | Post-launch | `docs/FrostGateCore_Buildout_vNext.md:57` | docs | V2+ | Litmus v3 chaos scenarios defined and pass in staging |
| G007 | AI model drift monitoring not implemented | Post-launch | `docs/FrostGateCore_Buildout_vNext.md:207` | docs | V2+ | Drift threshold alerts configured; retrain runbook tested |

---

## Closed Gaps (Implemented in This Release)

| ID | Gap | Closed Date | Evidence |
|----|-----|-------------|----------|
| G002 | SLSA provenance attestations | 2026-01-31 | `scripts/provenance.py` generates SLSA v1.0 format; `tests/test_compliance_gates.py::TestProvenanceGeneration` validates |
| G003 | Security static scan | 2026-01-31 | `scripts/scap_scan.py` performs SCAP-style code scanning; CI uploads `scap_scan.json` artifact |
| G004 | CIS config checks | 2026-01-31 | `scripts/cis_check.py` runs 10 CIS-aligned checks; CI fails if score < 70% |
| G005 | Merkle anchor job | 2026-01-31 | `jobs/merkle_anchor/job.py` computes Merkle root over audit entries; `tests/test_merkle_anchor.py::TestTamperDetection` proves tamper detection works |

---

## New Systems Implemented

| System | Files | Tests | CI Lane |
|--------|-------|-------|---------|
| Merkle Anchor (verifiable audit integrity) | `jobs/merkle_anchor/job.py` | `tests/test_merkle_anchor.py` | `fg-fast` |
| Simulation Validator (deterministic testing) | `jobs/sim_validator/job.py`, `docs/SIM_VALIDATION.md` | `tests/test_sim_validator.py` | `fg-fast` |
| Tripwire Delivery (async webhook + retry) | `api/tripwires.py` | `tests/test_tripwire_delivery.py` | `fg-fast` |
| Ingestion Bus (NATS messaging) | `api/ingest_bus.py`, `docker-compose.yml` | `tests/test_ingest_bus.py` | `fg-fast` |
| Compliance Gates (SBOM, provenance, CIS, SCAP) | `scripts/generate_sbom.py`, `scripts/provenance.py`, `scripts/cis_check.py`, `scripts/scap_scan.py` | `tests/test_compliance_gates.py` | `compliance` |

---

## Notes

- **Owner Values**: `repo` (code changes), `infra` (CI/deployment), `docs` (documentation)
- **ETA Values**: Version milestone (MVP, V2, V2+) or specific date
- All gaps MUST have evidence citing file path, test name, or CI lane
- All Definition of Done MUST be objectively testable
- To close a gap: implement fix, add test, update this matrix, run `make gap-audit`
