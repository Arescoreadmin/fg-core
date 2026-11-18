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

## Frontend (npm) Exceptions — L14-FRONTEND-DEPENDENCY-SEC-001

Frontend advisories for `apps/portal`, `apps/console` and `apps/web` are gated by
`tools/ci/frontend_dependency_audit.py` (workflow `frontend-dependency-security`,
`make frontend-audit`). The machine-readable registry is
`tools/ci/frontend_dependency_exceptions.json`.

### Active frontend exceptions

#### FE-EXC-001 / FE-EXC-002 / FE-EXC-003: `picomatch` GHSA-fc5q-39xc-vjpf (Portal / Console / Web)

| Field | Value |
|---|---|
| **Advisory** | [GHSA-fc5q-39xc-vjpf](https://github.com/advisories/GHSA-fc5q-39xc-vjpf) / CVE-2026-112366, high: ReDoS through single-branch repeated extglob patterns such as `+(*)` |
| **Affected range** | `picomatch` <=4.0.7. **No patched release**: 4.0.7 (2026-08-24) is the latest. The upstream fix micromatch/picomatch#194 is open |
| **Approved by / owner** | `Arescoreadmin` (founder / security owner), 2026-11-17 |
| **Expires** | **2026-12-17**. Renewal requires separate founder approval; do not extend in place |
| **Scope** | Exactly app + package `picomatch` + this advisory. Nothing else is suppressed |

**Dependency paths** (every entry is `dev` in the lockfile):

| App | `node_modules/picomatch` | `node_modules/tinyglobby/node_modules/picomatch` |
|---|---|---|
| Portal | 2.3.2, via `tailwindcss` > (`fast-glob` >) `micromatch`, and `eslint-config-next` > `@next/eslint-plugin-next` > `fast-glob` > `micromatch` | 4.0.4, via `tailwindcss` > `sucrase` > `tinyglobby` (> `fdir`), and `eslint-config-next` > `@typescript-eslint/*` and `eslint-import-resolver-typescript` > `tinyglobby` |
| Console | 2.3.2, via `tailwindcss` > `micromatch`, `tailwindcss` > `chokidar` > `anymatch`, and `eslint-config-next` > `@next/eslint-plugin-next` > `fast-glob` > `micromatch` | 4.0.7, the same paths as Portal |
| Web | 2.3.2, via `tailwindcss` > `micromatch`, and `tailwindcss` > `chokidar` > `anymatch` | 4.0.4, via `tailwindcss` > `sucrase` > `tinyglobby` (> `fdir`) |

**Runtime exposure, verified 2026-11-17: none in production.**

- `npm ls picomatch --omit=dev` is empty in all three apps.
- No application source imports `picomatch`, `micromatch`, `minimatch`, `fast-glob`, `tinyglobby`, `anymatch`, `chokidar` or `glob`.
- The production server traces (`.next/**/*.nft.json`, which Vercel packages) and the Console `.next/standalone` Docker image contain no copy of the affected npm packages.
- The vulnerability needs an attacker-supplied glob **pattern**. The tools that load these copies (Tailwind, ESLint, the TypeScript resolver, the dev-server watcher) take patterns only from repository config.

**Compensating controls:**

- The affected code runs only during lint, build and local development, on repository-controlled patterns.
- A pull request that changes those patterns can already run arbitrary code in its own CI job, so the advisory gives it no extra privilege.
- Every other critical or high finding, the same advisory on any other package, and any `AUDIT_UNVERIFIED` result still fail the gate. `tests/tools/test_frontend_dependency_audit.py` proves each case.
- Excepted findings remain listed in the audit evidence.

**Residual, not covered by this exception:** Next vendors its own `next/dist/compiled/picomatch`, which `npm audit` cannot see. At runtime it compiles only `next.config` `images.remotePatterns` and `images.localPatterns`. None of the three apps configures these, and the request URL is only the matched string, never the pattern.

**Remediation and removal:**

1. Track micromatch/picomatch#194 and new `picomatch` releases.
2. When a patched 4.x is published (for `tinyglobby`), and a patched 2.x or a `micromatch`/`anymatch` release that leaves 2.x is published, update the lockfiles.
3. Confirm `make frontend-audit` passes with the records removed, and delete all three records in the same PR.
4. If nothing is patched by 2026-12-17, the gate blocks again automatically.

An entry suppresses a blocking (critical/high) advisory only when **all** hold:

- `approval_status` is `APPROVED` and `approved_by` names the approving founder or
  security owner. An exception drafted by an engineer or AI agent is not approved
  until the founder records it — unapproved entries are ignored and keep blocking;
- `owner`, `runtime_exposure`, `compensating_controls` and `remediation_plan` are set;
- `expires` is a date no more than 90 days ahead and not in the past (expired
  entries stop suppressing automatically);
- it names the exact `app`, `package` and `advisory` (GHSA id or npm advisory id).

An audit that cannot run (registry unreachable, malformed output, timeout) is
`AUDIT_UNVERIFIED` and fails the gate; it is never treated as clean.

---

## Exception Governance

- **Adding an exception:** requires documented reason, prior certification reference,
  controls, removal condition, and review cadence. Add to `Makefile` `--ignore-vuln`
  flags on both invocations simultaneously.
- **Removing an exception:** remove both the exception entry here and the `--ignore-vuln`
  flag(s) in `Makefile` in the same commit.
- **Review:** any dependency PR must check whether active exceptions can be closed.

_Last updated: 2026-11-17_
