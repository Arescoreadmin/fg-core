# Dependency Audit Exceptions

Advisory exceptions accepted for `pip-audit` scans in `make pip-audit` (CI and local).

Each exception is atomic. Exceptions do not combine or imply any other allowance.
All entries require: ID, package+version, reason, prior certification, controls,
removal condition, review cadence, owner, and date accepted.

---

## Active Exceptions

### EXC-DEP-001

| Field              | Value |
|--------------------|-------|
| **Advisory ID**    | MAL-2026-4750 |
| **Package**        | fastapi==0.136.3 |
| **Advisory type**  | Malware database (MAL-*) |
| **Fix versions**   | None published by pip-audit at time of exception |
| **Accepted date**  | 2026-05-26 |
| **Review cadence** | Every dependency PR, or at minimum every 14 days |
| **Owner**          | Platform & Security (EmpireOverloard) |

**Reason:**
`MAL-2026-4750` was raised by the pip-audit malware database against `fastapi==0.136.3`.
At the time of exception acceptance, pip-audit reports no fix version. No clean upgrade or
downgrade path exists that preserves the certified FastAPI + Starlette combination:
`fastapi==0.136.3` was explicitly certified in PR 12b (PYSEC-2026-161 closure), which
confirmed that this version resolves the prior starlette CVE.

**Prior certification:**
PR 12b (`feat/certify-fastapi-0136x`) — full gate suite passed, pip-audit clean at time
of certification. `MAL-` advisories are published asynchronously and may appear after
the certifying PR merges.

**Controls in place:**
- Version pinned exactly: `fastapi==0.136.3` in `requirements-shared.txt`
- Shared dependency authority enforced (PR 14 normalization)
- Full gate suite (ruff, pytest, plane registry, contract authority, codex gates) continues
  to run and must pass; only this one advisory ID is excepted
- pip-audit remains enabled and will fail on all other advisories
- No transitive version float: all shared deps are pinned in requirements-shared.txt

**Removal condition:**
Remove this exception entry **and** the corresponding `--ignore-vuln MAL-2026-4750` flags
from `Makefile` when **any** of the following is true:
1. pip-audit publishes a fix version for MAL-2026-4750 (upgrade to that version, certify, remove)
2. The advisory is withdrawn or reclassified
3. A certified replacement FastAPI version exists that is clean against this advisory
4. The advisory is confirmed false-positive by upstream (PyPI / pip-audit maintainers)

**Removal action:**
- Update `requirements-shared.txt` to the clean version (or remove pin if advisory withdrawn)
- Remove `--ignore-vuln MAL-2026-4750` from both `pip-audit` invocations in `Makefile`
- Delete this entry (or move to `## Closed Exceptions` with resolution note)
- Add entry to `docs/ai/PR_FIX_LOG.md`

---

## Closed Exceptions

_None._

---

## Exception Governance

- **Adding an exception:** requires documented reason, prior certification reference,
  controls, removal condition, and review cadence. Add to `Makefile` `--ignore-vuln`
  flags on both invocations simultaneously.
- **Removing an exception:** remove both the exception entry here and the `--ignore-vuln`
  flag(s) in `Makefile` in the same commit.
- **Review:** any dependency PR must check whether active exceptions can be closed.

_Last updated: 2026-05-26_
