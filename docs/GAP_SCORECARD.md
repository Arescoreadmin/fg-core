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

- **G001**: Auth fallback defaults to true in docker-compose
- **G002**: SLSA provenance attestations not generated
- **G003**: OpenSCAP/STIG compliance scan not in CI
- **G004**: CIS K8s v1.9 benchmark not enforced
- **G005**: Merkle anchor job placeholder


---

## Detailed Gap List

### Launch-risk

- **G001**: Auth fallback defaults to true in docker-compose
  - Evidence: ``docker-compose.yml:67` / `scripts/prod_profile_check.py` / `ci.yml:unit``
  - Owner: repo
- **G002**: SLSA provenance attestations not generated
  - Evidence: ``Makefile:evidence` / `.github/workflows/ci.yml:evidence``
  - Owner: infra
- **G003**: OpenSCAP/STIG compliance scan not in CI
  - Evidence: ``.github/workflows/ci.yml``
  - Owner: infra
- **G004**: CIS K8s v1.9 benchmark not enforced
  - Evidence: ``.github/workflows/ci.yml``
  - Owner: infra
- **G005**: Merkle anchor job placeholder
  - Evidence: ``jobs/` directory / `docs/FrostGateCore_Buildout_vNext.md:57``
  - Owner: repo

### Post-launch

- **G006**: Chaos testing jobs not implemented
  - Evidence: ``docs/FrostGateCore_Buildout_vNext.md:57``
  - Owner: repo
- **G007**: AI model drift monitoring not implemented
  - Evidence: ``docs/FrostGateCore_Buildout_vNext.md:207``
  - Owner: repo
