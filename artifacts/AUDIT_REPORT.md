# FrostGate Core — Full Automated Audit Report

**Date:** 2026-02-06
**Auditor:** Automated (Claude Opus 4.6)
**Repo:** fg-core
**Branch:** claude/audit-fg-core-SGeFD
**Python:** 3.11.14 | **Pip:** 24.0

---

## Executive Summary

**Overall Health: GOOD with targeted risks.**
578 tests pass (0 failures, 20 skipped). 62% code coverage. Clean ruff lint. No exploitable code injection patterns in production code. 14 known dependency vulnerabilities, 1 timing-attack surface in legacy auth path, and several hygiene issues need attention.

---

## A) STRENGTHS (Top 5, with evidence)

### 1. Strong Security Test Coverage
12 dedicated security test files in `tests/security/` covering tenant isolation, key hashing, scope enforcement, chain verification, immutability, and admin scoping.
**Evidence:** `tests/security/test_*.py` — all at 100% coverage.

### 2. Zero Test Failures, Solid Suite
578 passed, 20 skipped, 0 failed in ~70s. No flaky indicators across multiple runs.
**Evidence:** `artifacts/pytest_summary.txt`, `artifacts/pytest_durations.txt`

### 3. Clean Static Analysis
`ruff check .` passes with zero violations. Compilation check (`compileall`) succeeds.
**Evidence:** `artifacts/ruff_check.txt` — "All checks passed!"

### 4. Production-Grade Operational Patterns
- Multi-stage Docker build with non-root user (`Dockerfile:38,56`)
- Graceful shutdown with SIGTERM handling (`api/graceful_shutdown.py`)
- Circuit breaker pattern (`api/circuit_breaker.py`, 75% coverage)
- DoS guard middleware (`api/middleware/dos_guard.py`, 84% coverage)
- Startup validation (235 lines, `api/config/startup_validation.py`, 85% coverage)

### 5. Comprehensive CI Pipeline
10 parallel CI jobs: Guard, Unit, Integration, DB Postgres, Admin, Console, PT, Hardening, Compliance, Evidence. Path-filtered for efficiency.
**Evidence:** `.github/workflows/ci.yml` — 498 lines

---

## B) WEAKNESSES / RISKS (Top 10, severity + evidence)

### 1. [HIGH/SEC] Timing Attack in Legacy Tenant Auth
`api/main.py:356` uses `str(expected) != str(api_key)` for tenant key comparison — not constant-time. The modern `auth_scopes.py` correctly uses `hmac.compare_digest`.
**File:** `api/main.py:355-357`

### 2. [HIGH/SEC] 14 Known Dependency Vulnerabilities
- `cryptography==41.0.7`: 4 CVEs including PYSEC-2024-225 (key mismatch), CVE-2023-50782 (RSA decryption oracle)
- `starlette==0.38.6`: CVE-2024-47874 (multipart DoS), CVE-2025-54121 (large file spool)
- `ecdsa==0.19.1`: CVE-2024-23342 (Minerva timing attack on P-256)
- `setuptools==68.1.2`: path traversal (PYSEC-2025-49)
- `pip==24.0`: CVE-2025-8869, CVE-2026-1703
**Evidence:** `artifacts/pip_audit.json`

### 3. [MEDIUM/SEC] `python-jose` Dependency (Unmaintained)
`python-jose` is used in `admin_gateway/auth.py:283` but is considered unmaintained. The recommended replacement is `PyJWT` or `joserfc`.
**File:** `requirements.txt:14`, `admin_gateway/auth.py:283`

### 4. [MEDIUM/SEC] Committed SQLite Shared-Memory File
`frostgate_decisions.db-shm` (32KB) is tracked in git. While it contains no secrets, it's a WAL shared-memory file that should never be in version control. Other junk files also tracked: `main` (empty), `frostgate_tree.txt`, `frostgate_tree_everything.txt`.
**Evidence:** `git ls-files | grep -E 'db-shm|^main$|frostgate_tree'`

### 5. [MEDIUM/ARCH] Engine Depends on API (Inverted Dependency)
`engine/tied.py:5`, `engine/roe.py:4`, `engine/persona.py:3` all import from `api.schemas`. The engine (domain core) should not depend on the API layer. These types belong in `engine/types.py`.
**Evidence:** `artifacts/typecheck.txt` — mypy can't find `TIEDEstimate`, `ClassificationRing`, `Persona` in `api.schemas`

### 6. [MEDIUM/ARCH] Monolithic auth_scopes.py (1186 lines)
`api/auth_scopes.py` handles key generation, verification, rotation, usage tracking, RBAC, expiry checking, and admin functions in a single file. High coupling risk.
**Evidence:** Coverage report shows 79% coverage but 120 missed lines.

### 7. [MEDIUM/QUALITY] 0% Coverage on admin_gateway (entire module)
All `admin_gateway/` production code shows 0% coverage in the test run. The `admin_gateway/tests/` directory exists (with test files) but tests are not collected by the main pytest configuration.
**Evidence:** `artifacts/coverage.txt` — every `admin_gateway/` file except `__init__.py` at 0%

### 8. [MEDIUM/QUALITY] db_migrations.py Untested (0% Coverage)
`api/db_migrations.py` (134 lines) has 0% test coverage. Database migrations are high-risk for data loss.
**Evidence:** `artifacts/coverage.txt` line for `api/db_migrations.py`

### 9. [LOW/HYGIENE] .gitignore Duplication
`.gitignore` is 165 lines with extensive duplication — patterns like `__pycache__/`, `.venv/`, `state/`, `.env` appear 3-4 times.
**Evidence:** `.gitignore` — lines 1-165

### 10. [LOW/QUALITY] 22 Files Need Formatting
`ruff format --check` reports 22 files need reformatting, mostly in `agent/`, `backend/tests/`, `contracts/`, `engine/`, `jobs/`, `tools/`.
**Evidence:** `artifacts/ruff_format.txt`

---

## C) "Next ROI" Plan (ranked)

| # | Task | Impact | Effort | Risk Reduced | Payoff | Files Likely Touched |
|---|------|--------|--------|--------------|--------|---------------------|
| 1 | **Fix timing attack in legacy tenant auth** | Critical | S | Auth bypass timing side-channel | Security | `api/main.py:355-357` |
| 2 | **Upgrade `cryptography` to >=43.0** | Critical | S | 4 CVEs eliminated | Security | `requirements.txt` |
| 3 | **Upgrade `starlette` to >=0.40.0** | High | S | 2 CVEs (DoS) eliminated | Security | `requirements.txt` (may require `fastapi` upgrade) |
| 4 | **Replace `python-jose` with `PyJWT`/`joserfc`** | High | M | Unmaintained dep risk | Security | `requirements.txt`, `admin_gateway/auth.py` |
| 5 | **Move shared types from `api.schemas` to `engine/types.py`** | Medium | M | Inverted dependency fixed | Maintainability | `engine/tied.py`, `engine/roe.py`, `engine/persona.py`, `api/schemas.py`, `engine/types.py` |
| 6 | **Add admin_gateway tests to CI test collection** | Medium | S | 0% -> tested | Quality | `pyproject.toml`, `pytest.ini` |
| 7 | **Add `pip-audit` to CI pipeline** | Medium | S | Ongoing vuln detection | Security | `.github/workflows/ci.yml` |
| 8 | **Remove committed junk files** | Low | S | Repo hygiene | Velocity | `frostgate_decisions.db-shm`, `main`, `frostgate_tree*.txt`, `.gitignore` |
| 9 | **Enforce `ruff format` in CI** | Low | S | Consistent style | Velocity | `.github/workflows/ci.yml` |
| 10 | **Add coverage floor to CI (e.g., 60%)** | Low | S | Regression prevention | Quality | `.github/workflows/ci.yml` |

---

## D) Quick Wins (<2 hours)

### 1. Fix timing attack (15 min)
In `api/main.py:356`, replace:
```python
if expected is None or str(expected) != str(api_key):
```
with:
```python
import hmac
if expected is None or not hmac.compare_digest(str(expected), str(api_key)):
```

### 2. Pin `cryptography>=43.0.0` (5 min)
Update `requirements.txt` — add or update `cryptography>=43.0.0`.

### 3. Run `ruff format .` (2 min)
Fixes all 22 formatting violations. One command: `ruff format .`

### 4. Clean `.gitignore` + remove tracked junk (15 min)
Deduplicate `.gitignore` (165 -> ~50 lines). Run `git rm --cached frostgate_decisions.db-shm main frostgate_tree.txt frostgate_tree_everything.txt frostgate_context_snapshot.txt`.

### 5. Add `pip-audit` step to CI (10 min)
Add to `.github/workflows/ci.yml` Guard job:
```yaml
- name: Dependency vulnerability scan
  run: pip install pip-audit && pip-audit
```

---

## E) Gates to Enforce

### Enforce NOW (in current CI)
1. **`ruff format --check .`** — add to Guard job (prevents drift)
2. **`pip-audit`** — add to Guard job (catches vulnerable deps)
3. **`python -m compileall -q .`** — already enforced (good)

### Enforce NEXT (within 2 weeks)
4. **Coverage floor (60%)** — add `--cov-fail-under=60` to pytest
5. **admin_gateway test collection** — add to `testpaths` in `pyproject.toml`
6. **`bandit -ll`** — medium/high severity only, add to Compliance job

### Enforce LATER (when type coverage improves)
7. **mypy strict mode** — currently 48 errors; address incrementally with per-module `# type: ignore` exceptions

---

## Artifacts Index

| File | Contents |
|------|----------|
| `artifacts/pip_freeze.txt` | Full dependency snapshot |
| `artifacts/pytest_summary.txt` | Test run summary (578 passed, 20 skipped) |
| `artifacts/pytest_durations.txt` | Top 25 slowest tests |
| `artifacts/coverage.txt` | Full coverage report (62% overall) |
| `coverage.xml` | Machine-readable coverage XML |
| `artifacts/ruff_check.txt` | Ruff lint results (all passed) |
| `artifacts/ruff_format.txt` | Ruff format check (22 files need formatting) |
| `artifacts/compileall.txt` | Compilation check (clean) |
| `artifacts/typecheck.txt` | mypy results (48 errors) |
| `artifacts/bandit.json` | Bandit security scan (9 MEDIUM, 1549 LOW) |
| `artifacts/pip_audit.json` | Dependency vulnerability scan (14 vulns in 6 packages) |
| `artifacts/secrets_grep.txt` | Secret pattern grep (867 matches — mostly variable names, no hardcoded secrets) |
| `artifacts/danger_grep.txt` | Dangerous function grep (10 matches — all in test/scan code, none in production) |
| `artifacts/ops_readiness.txt` | Operational readiness findings |
| `artifacts/architecture_notes.txt` | Architecture and maintainability findings |
