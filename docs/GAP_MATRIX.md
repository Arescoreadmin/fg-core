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
| G006 | Chaos testing jobs not implemented | Post-launch | `docs/FrostGateCore_Buildout_vNext.md:57` | docs | V2+ | Litmus v3 chaos scenarios defined and pass in staging |
| G007 | AI model drift monitoring not implemented | Post-launch | `docs/FrostGateCore_Buildout_vNext.md:207` | docs | V2+ | Drift threshold alerts configured; retrain runbook tested |

---

## Closed Gaps (Implemented in This Release)

The following gaps were closed on 2026-01-31:

- **Former G002 - SLSA provenance attestations**: Now generated via `scripts/provenance.py` (SLSA v1.0 format). Validated by `tests/test_compliance_gates.py::TestProvenanceGeneration`.

- **Former G003 - Security static scan**: SCAP-style scanning via `scripts/scap_scan.py`. CI uploads `scap_scan.json` artifact.

- **Former G004 - CIS config checks**: 10 CIS-aligned checks in `scripts/cis_check.py`. CI gate fails if score < 70%.

- **Former G005 - Merkle anchor job**: Real Merkle tree in `jobs/merkle_anchor/job.py`. Tamper detection proven by `tests/test_merkle_anchor.py::TestTamperDetection`.

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
