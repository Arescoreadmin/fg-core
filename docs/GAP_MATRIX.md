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
| G002 | SLSA provenance attestations not generated | Launch-risk | `Makefile:evidence` / `.github/workflows/ci.yml:evidence` | infra | V2 | Evidence bundle includes SLSA provenance JSON; CI verifies provenance attestation |
| G003 | OpenSCAP/STIG compliance scan not in CI | Launch-risk | `.github/workflows/ci.yml` | infra | V2 | CI job runs OpenSCAP against container images; results in evidence bundle |
| G004 | CIS K8s v1.9 benchmark not enforced | Launch-risk | `.github/workflows/ci.yml` | infra | V2 | CI runs kube-bench CIS scan; gate fails if score < 95% |
| G005 | Merkle anchor job placeholder | Launch-risk | `jobs/__init__.py` / `docs/FrostGateCore_Buildout_vNext.md:57` / `fg-fast` | repo | V2 | `merkle-anchor` CronJob exists and anchors hourly; verification test passes |
| G006 | Chaos testing jobs not implemented | Post-launch | `docs/FrostGateCore_Buildout_vNext.md:57` | docs | V2+ | Litmus v3 chaos scenarios defined and pass in staging |
| G007 | AI model drift monitoring not implemented | Post-launch | `docs/FrostGateCore_Buildout_vNext.md:207` | docs | V2+ | Drift threshold alerts configured; retrain runbook tested |

---

## Notes

- **Owner Values**: `repo` (code changes), `infra` (CI/deployment), `docs` (documentation)
- **ETA Values**: Version milestone (MVP, V2, V2+) or specific date
- All gaps MUST have evidence citing file path, test name, or CI lane
- All Definition of Done MUST be objectively testable
- To close a gap: implement fix, add test, update this matrix, run `make gap-audit`
