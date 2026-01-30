# Gap Scorecard — FrostGate Production Readiness

> **Deterministic scoring** generated from `docs/GAP_MATRIX.md`.
> Regenerate with: `python scripts/generate_scorecard.py`

---

## Readiness Scores

| Metric | Score | Status |
|--------|-------|--------|
| Production Readiness | 100.0% | READY |
| Launch Readiness | 0.0% | AT RISK |

### Scoring Rules

```
Production Readiness = 1 - (open Production-blocking gaps / total Production-blocking gaps)
Launch Readiness = 1 - (open Launch-risk gaps / total Launch-risk gaps)
```

- **Production Readiness < 100%** → Release BLOCKED
- **Launch Readiness < 100%** → Release proceeds with documented risk

---

## Gap Summary by Severity

| Severity | Open | Waived | Total |
|----------|------|--------|-------|
| Production-blocking | 0 | 0 | 0 |
| Launch-risk | 5 | 0 | 5 |
| Post-launch | 2 | 0 | 2 |

---

## Gap Summary by Owner

| Owner | Open | Total |
|-------|------|-------|
| repo | 4 | 4 |
| infra | 3 | 3 |
| docs | 0 | 0 |

---

## Release Gate Status

**Status: READY**

All Production-blocking gaps resolved. Release may proceed.

---

## Warnings

### Active Launch Risks

- **GAP-001**: Auth fallback defaults to true in docker-compose
- **GAP-002**: SLSA provenance attestations not generated
- **GAP-003**: OpenSCAP/STIG compliance scan not in CI
- **GAP-004**: CIS K8s v1.9 benchmark not enforced
- **GAP-005**: Merkle anchor job placeholder


---

## Detailed Gap List

### Launch-risk

- **GAP-001**: Auth fallback defaults to true in docker-compose
  - Evidence: ``docker-compose.yml:67` / `scripts/prod_profile_check.py` / `ci.yml:unit``
  - Owner: repo
- **GAP-002**: SLSA provenance attestations not generated
  - Evidence: ``Makefile:evidence` / `.github/workflows/ci.yml:evidence``
  - Owner: infra
- **GAP-003**: OpenSCAP/STIG compliance scan not in CI
  - Evidence: ``.github/workflows/ci.yml``
  - Owner: infra
- **GAP-004**: CIS K8s v1.9 benchmark not enforced
  - Evidence: ``.github/workflows/ci.yml``
  - Owner: infra
- **GAP-005**: Merkle anchor job placeholder
  - Evidence: ``jobs/` directory / `docs/FrostGateCore_Buildout_vNext.md:57``
  - Owner: repo

### Post-launch

- **GAP-006**: Chaos testing jobs not implemented
  - Evidence: ``docs/FrostGateCore_Buildout_vNext.md:57``
  - Owner: repo
- **GAP-007**: AI model drift monitoring not implemented
  - Evidence: ``docs/FrostGateCore_Buildout_vNext.md:207``
  - Owner: repo
