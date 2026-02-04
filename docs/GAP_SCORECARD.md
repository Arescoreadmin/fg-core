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
| Launch-risk | 1 | 0 | 1 |
| Post-launch | 0 | 0 | 0 |

---

## Gap Summary by Owner

| Owner | Open | Total |
|-------|------|-------|
| repo | 1 | 1 |
| infra | 0 | 0 |
| docs | 0 | 0 |

---

## Release Gate Status

**Status: READY**

All Production-blocking gaps resolved. Release may proceed.

---

## Warnings

### Active Launch Risks

- **G001**: Auth fallback defaults to true in docker-compose


---

## Detailed Gap List

### Launch-risk

- **G001**: Auth fallback defaults to true in docker-compose
  - Evidence: ``docker-compose.yml:67` / `scripts/prod_profile_check.py` / `.github/workflows/ci.yml` / `unit``
  - Owner: repo
