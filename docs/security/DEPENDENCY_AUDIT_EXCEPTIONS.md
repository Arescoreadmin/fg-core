# Dependency Audit Exceptions

Advisory exceptions accepted for `pip-audit` scans in `make pip-audit` (CI and local).

Each exception is atomic. Exceptions do not combine or imply any other allowance.
All entries require: ID, package+version, reason, prior certification, controls,
removal condition, review cadence, owner, and date accepted.

---

## Active Exceptions

_No active exceptions. The pip-audit gate blocks on all advisories with no suppressions._

---

## Closed Exceptions

### EXC-DEP-001 (closed 2026-10-28)

| Field              | Value |
|--------------------|-------|
| **Advisory ID**    | MAL-2026-4750 |
| **Package**        | fastapi==0.136.3 |
| **Closed date**    | 2026-10-28 |
| **Resolution**     | Advisory no longer reported by pip-audit ≥2.10.1 (withdrawn or reclassified from malware database). The `--ignore-vuln MAL-2026-4750` suppression removed from `Makefile`. fastapi==0.136.3 remains pinned; full gate suite continues to pass. See P0-DEPENDENCY-REMEDIATION-001 in `docs/ai/PR_FIX_LOG.md`. |

---

### EXC-DEP-002 (closed 2026-10-28)

| Field              | Value |
|--------------------|-------|
| **Advisory IDs**   | CVE-2026-54283, CVE-2026-54282 |
| **Package**        | starlette==1.1.0 → starlette==1.3.1 |
| **Closed date**    | 2026-10-28 |
| **Resolution**     | Upgraded `starlette` to 1.3.1 in `requirements-shared.txt`. fastapi==0.136.3 requires `starlette>=0.46.0` with no upper bound, confirming compatibility. CVEs fixed at 1.3.1 and 1.3.0 respectively. `--ignore-vuln` flags removed from `Makefile`. See P0-DEPENDENCY-REMEDIATION-001 in `docs/ai/PR_FIX_LOG.md`. |

---

### EXC-DEP-004 (closed 2026-10-28)

| Field              | Value |
|--------------------|-------|
| **Advisory IDs**   | CVE-2026-53540, CVE-2026-53539, CVE-2026-53538 |
| **Package**        | python-multipart==0.0.27 → python-multipart==0.0.31 |
| **Closed date**    | 2026-10-28 |
| **Resolution**     | Upgraded `python-multipart` to 0.0.31 in `requirements.txt`. All three CVEs fixed at ≤0.0.31. `--ignore-vuln` flags removed from `Makefile`. See P0-DEPENDENCY-REMEDIATION-001 in `docs/ai/PR_FIX_LOG.md`. |

---

### EXC-DEP-003 (closed 2026-08-05)

| Field              | Value |
|--------------------|-------|
| **Advisory ID**    | GHSA-537c-gmf6-5ccf |
| **Package**        | cryptography==46.0.7 → cryptography==50.0.0 |
| **Closed date**    | 2026-08-05 |
| **Resolution**     | Upgraded `cryptography` to 50.0.0 in `requirements-shared.txt` and `requirements-dev.txt`. Fix version was ≥48.0.1; 50.0.0 also fixes PYSEC-2026-3552/3553/3554 (all three new CVEs). `msal` bumped 1.36.0→1.37.0 (`cryptography<51` compatible). `--ignore-vuln GHSA-537c-gmf6-5ccf` removed from both `pip-audit` invocations in `Makefile`. See P-52 in `docs/ai/PR_FIX_LOG.md`. |

---

## Exception Governance

- **Adding an exception:** requires documented reason, prior certification reference,
  controls, removal condition, and review cadence. Add to `Makefile` `--ignore-vuln`
  flags on both invocations simultaneously.
- **Removing an exception:** remove both the exception entry here and the `--ignore-vuln`
  flag(s) in `Makefile` in the same commit.
- **Review:** any dependency PR must check whether active exceptions can be closed.

_Last updated: 2026-10-28_
