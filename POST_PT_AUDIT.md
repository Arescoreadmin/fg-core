# Post PT Audit (FrostGate Core)

**Status:** PASS  \
**Merge confidence score:** 90

## Executive Summary
All critical and high priority audit items have been remediated. Admin Gateway builds now match repo paths, containers run as non-root, query-string API key auth is removed, default secrets are eliminated, environment variables are aligned, CI lanes are wired through Makefile, session cookies explicitly set HttpOnly, and release workflows now rely on Makefile lanes. No Critical or High findings remain.

## Checklist

| # | Control | Status | Evidence |
|---|---|---|---|
| 1 | Admin Gateway Dockerfile path alignment | PASS | `admin_gateway/Dockerfile` paths corrected to `admin_gateway/`. |
| 2 | Admin Gateway non-root container | PASS | Dedicated non-root user added and `USER` set in `admin_gateway/Dockerfile`. |
| 3 | Remove `/ui` query-string API key auth | PASS | `api/ui.py` now accepts only headers/cookies; scripts/tests updated. |
| 4 | Remove default secrets (legacy placeholder) | PASS | All legacy default key strings removed; placeholders used where needed. |
| 5 | Align `FG_ENV` usage | PASS | `docker-compose.yml` and `Makefile` now use `FG_ENV`. |
| 6 | Wire `ci-admin` + `ci-console` into CI | PASS | `.github/workflows/ci.yml` runs Makefile targets. |
| 7 | Add PT lane to Makefile + CI | PASS | `make ci-pt` added and wired in `.github/workflows/ci.yml`. |
| 8 | Align release workflow with Makefile | PASS | `.github/workflows/release-images.yml` runs `make ci`. |
| 9 | Explicit HttpOnly session cookies | PASS | Admin Gateway session middleware sets `httponly=True`. |
| 10 | Regenerate POST PT audit | PASS | This file updated with PASS summary and score. |

## Findings
- **Critical:** None
- **High:** None
- **Medium:** None
- **Low:** None

## Notes
- Production now fails closed on missing `FG_API_KEY` via startup validation when `FG_ENV=prod`.
- Query-string API key authentication has been removed from the UI surface.
