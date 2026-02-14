# Gap Scorecard — FrostGate Production Readiness

> **Deterministic scoring** generated from `docs/GAP_MATRIX.md`.
> Regenerate with: `python scripts/generate_scorecard.py`

---

## Readiness Scores

| Metric | Score | Status |
|--------|-------|--------|
| Production Readiness | 100.0% | READY |
| Launch Readiness | 100.0% | READY |

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
| Launch-risk | 0 | 1 | 1 |
| Post-launch | 0 | 0 | 0 |

---

## Gap Summary by Owner

| Owner | Open | Total |
|-------|------|-------|
| repo | 0 | 1 |
| infra | 0 | 0 |
| docs | 0 | 0 |

---

## Release Gate Status

**Status: READY**

All Production-blocking gaps resolved. Release may proceed.

---

## Detailed Gap List

### Waived

- **G001**: Auth fallback must be OFF by default (compose + prod-like)
  - Approved by: secops@frostgate.dev
  - Expires: 2026-06-30
