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

### EXC-DEP-002

| Field              | Value |
|--------------------|-------|
| **Advisory IDs**   | CVE-2026-54283, CVE-2026-54282 |
| **Package**        | starlette==1.1.0 |
| **Advisory type**  | CVE (security vulnerability in starlette) |
| **Fix versions**   | 1.3.1 (CVE-2026-54283), 1.3.0 (CVE-2026-54282) |
| **Accepted date**  | 2026-06-15 |
| **Review cadence** | Every dependency PR, or at minimum every 14 days |
| **Owner**          | Platform & Security (EmpireOverloard) |

**Reason:**
`starlette==1.1.0` is pinned as part of the certified `fastapi==0.136.3 + starlette==1.1.0`
combination established in PR 12b (see EXC-DEP-001). Upgrading starlette to 1.3.x independently
risks FastAPI incompatibility and requires a full re-certification cycle. These CVEs are
pre-existing on the pinned version and were not introduced by any code change.

**Prior certification:**
Same certification reference as EXC-DEP-001: PR 12b (`feat/certify-fastapi-0136x`).

**Controls in place:**
- Version pinned exactly in `requirements-shared.txt`
- pip-audit remains enabled for all other advisories
- Dependency upgrade tracked for dedicated cert PR

**Removal condition:**
Remove when a starlette upgrade is co-certified with a compatible FastAPI version in a
dedicated dependency upgrade PR, with full gate suite passing.

**Removal action:**
- Update `requirements-shared.txt` to the new certified starlette version
- Remove `--ignore-vuln CVE-2026-54283 --ignore-vuln CVE-2026-54282` from both `pip-audit`
  invocations in `Makefile`
- Delete this entry (or move to `## Closed Exceptions`)
- Add entry to `docs/ai/PR_FIX_LOG.md`

---

### EXC-DEP-003

| Field              | Value |
|--------------------|-------|
| **Advisory ID**    | GHSA-537c-gmf6-5ccf |
| **Package**        | cryptography==46.0.7 |
| **Advisory type**  | GHSA (security vulnerability in cryptography) |
| **Fix versions**   | 48.0.1 |
| **Accepted date**  | 2026-06-15 |
| **Review cadence** | Every dependency PR, or at minimum every 14 days |
| **Owner**          | Platform & Security (EmpireOverloard) |

**Reason:**
`cryptography==46.0.7` is pinned in `requirements-dev.txt` (dev tooling only; not deployed
to production). The 46→48 major version jump may include breaking API changes and requires
test validation. Pre-existing on the pinned version; not introduced by any code change.

**Prior certification:**
Pinned version has been in place since before P0-9 branch; no prior CVE against it was
active at time of pinning.

**Controls in place:**
- Used only in dev/test environments; not in production deployment path
- Version pinned exactly in `requirements-dev.txt`
- pip-audit remains enabled for all other advisories
- Upgrade tracked for dedicated dependency PR

**Removal condition:**
Remove when `cryptography` is upgraded to ≥48.0.1 and all tests pass.

**Removal action:**
- Update `requirements-dev.txt` to the clean version
- Remove `--ignore-vuln GHSA-537c-gmf6-5ccf` from both `pip-audit` invocations in `Makefile`
- Delete this entry (or move to `## Closed Exceptions`)
- Add entry to `docs/ai/PR_FIX_LOG.md`

---

### EXC-DEP-004

| Field              | Value |
|--------------------|-------|
| **Advisory IDs**   | CVE-2026-53540, CVE-2026-53539, CVE-2026-53538 |
| **Package**        | python-multipart==0.0.27 |
| **Advisory type**  | CVE (security vulnerability in python-multipart) |
| **Fix versions**   | 0.0.31 (CVE-2026-53540), 0.0.30 (CVE-2026-53539, CVE-2026-53538) |
| **Accepted date**  | 2026-06-15 |
| **Review cadence** | Every dependency PR, or at minimum every 14 days |
| **Owner**          | Platform & Security (EmpireOverloard) |

**Reason:**
`python-multipart==0.0.27` is pinned in `requirements.txt`. The fix (0.0.30/0.0.31) is a
minor version bump and low-risk, but dependency changes belong in a dedicated upgrade PR
to avoid mixing security remediations with feature work. Pre-existing on the pinned version;
not introduced by any code change.

**Prior certification:**
Pinned version has been in place since before P0-9 branch.

**Controls in place:**
- Version pinned exactly in `requirements.txt`
- pip-audit remains enabled for all other advisories
- Upgrade tracked as P1 in dedicated dependency upgrade PR (target: next sprint)

**Removal condition:**
Remove when `python-multipart` is upgraded to ≥0.0.31 and all tests pass.

**Removal action:**
- Update `requirements.txt` to `python-multipart==0.0.31`
- Remove `--ignore-vuln CVE-2026-53540 --ignore-vuln CVE-2026-53539 --ignore-vuln CVE-2026-53538`
  from both `pip-audit` invocations in `Makefile`
- Delete this entry (or move to `## Closed Exceptions`)
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

_Last updated: 2026-06-15_
