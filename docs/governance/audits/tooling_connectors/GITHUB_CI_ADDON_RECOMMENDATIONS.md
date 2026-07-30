# GitHub & CI Add-On Recommendations — FrostGate Core

Evidence base: `.github/workflows/{ci,docker-ci,fg-required,testing-module,ai-ledger-guard,release-images}.yml` (2,469 lines total), `.github/actions/{fg-python-setup,fg-secrets}`, `Makefile` (300+ targets), `docs/ci/CI_OPTIMIZATION_PLAN.md`, `.pre-commit-config.yaml`, `codex_gates.sh`.

---

## 1. Current CI Architecture

Six workflows, path-filtered fan-out from a single `fg_guard` job:

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` (870 lines) | push/PR to `main` | Guard → enforcement-mode matrix → unit → contract-authority → integration → migrations-replay → postgres-verify → admin → console → PT → hardening → compliance → evidence → agent (Linux + Windows) |
| `fg-required.yml` | PR to `main` (docs-path-excluded) | The required-status-check surface, separate from `ci.yml`'s broader run |
| `docker-ci.yml` (585 lines) | PR/push touching Docker-relevant paths | Image build validation |
| `testing-module.yml` (431 lines) | manual + PR on `tools/testing/policy/**` + nightly cron | `fg-fast` lane + standalone `fg-contract`/`fg-security` jobs |
| `release-images.yml` | (not fully reviewed) | Image build/push |
| `ai-ledger-guard.yml` (106 lines) | (not fully reviewed) | AI-plane ledger invariant checks |

Notable design choices already in place: ephemeral per-run secrets (`fg-secrets` composite action generates fresh tokens, not static repo secrets, for `FG_API_KEY`/`REDIS_PASSWORD`/`POSTGRES_PASSWORD`/etc.), cached Python setup (`fg-python-setup` composite action), migration-replay against a real `pgvector/pgvector:pg16` service container, minisign-based evidence-bundle signing, and hard compliance-artifact existence checks (`test -f artifacts/sbom.json || exit 1`, etc.).

---

## 2. Duplication Analysis

The team has already self-diagnosed CI duplication in `docs/ci/CI_OPTIMIZATION_PLAN.md` (dated 2026-07-10, branch `audit/ci-gates-performance-and-assurance`):

- **DUP-01:** `make fg-contract` runs up to 4 times across different lanes (~6 min wasted/PR).
- **DUP-02 (highest priority):** `make fg-security` (~21 min) runs both as a standalone `testing-module.yml` job and again inside the `fg-fast` lane's `lane_runner.py` — zero unique assurance added the second time.
- **DUP-03:** `pytest tests/test_gap_audit.py` duplicates `make gap-audit`, already called by `make fg-fast`.

**Verified against current code:** `tools/testing/harness/lane_runner.py`'s `fg-fast` lane entry already reflects the fix — it now runs only `required_tests_gate.py`, with an in-code comment citing DUP-01/02/03 and "~23 min per PR" saved. **The plan's Priority 1 fix is already merged**, not merely proposed. This is worth stating explicitly because it changes the recommendation: there is no outstanding CI-duplication fix to prioritize as a "tooling" action item — the team already executed on its own diagnostic. No CI-time-reduction SaaS (remote build cache, test-splitting service, etc.) would have caught or fixed this faster than the first-party fix already in place. This is additional evidence (beyond the diagnostic doc alone) that this repo's own engineering process outperforms what a generic CI-optimization product would add.

---

## 3. Security Tooling Analysis

### What the repo already solves natively

| Concern | Existing gate | Assessment |
|---|---|---|
| Known-CVE dependency vulnerabilities | `pip-audit` (`Makefile:965`, run in `ci` target and `codex_gates.sh`) | Adequate for *known-CVE detection* in Python deps. Does not cover Node deps (console/portal/root each have a `package-lock.json`, no `npm audit` step found anywhere in CI). |
| Secrets in env files / URLs | `tools/ci/check_no_plaintext_secrets.py`, `check_secret_history.py` | Purpose-built for this repo's env-file conventions (URL-embedded creds, `_SECRET_SUFFIXES` regex, known-leaked-value blocklist), plus a git-history check. This is materially more precise for this codebase than a generic scanner would be out of the box. |
| Secrets in source (cheap tripwire) | `codex_gates.sh` ripgrep pattern for OpenAI keys / AWS secret keys / PEM headers / Slack tokens | Coarse but zero-dependency, runs locally before every gate pass. |
| SBOM | `scripts/generate_sbom.py` → `artifacts/sbom.json` (CycloneDX 1.5), gated as a required compliance artifact in `ci.yml`'s `compliance` job | Hand-rolled from `requirements.txt`/`package.json` parsing — captures direct dependencies but likely misses full transitive depth a real SBOM tool (Syft, `cyclonedx-py`) would resolve from the actual installed environment. |
| CIS/SCAP posture checks | `scripts/cis_check.py`, `scripts/scap_scan.py` | Hand-rolled, CI-gated as required artifacts. Not OpenSCAP-driven, so scope is whatever the script author encoded — worth a periodic manual review against a real CIS benchmark, but not worth replacing with OpenSCAP given the artifacts are already wired into the compliance evidence chain. |
| Contract/schema drift | `contract-authority-check`, `contracts-core-diff` | Prod OpenAPI spec hash-pinned in `BLUEPRINT_STAGED.md`; this is a stronger authority model than most generic API-contract-testing SaaS products offer, because it's wired into this repo's own governance doctrine rather than a separate tool's config. |

### What is genuinely missing

| Gap | Evidence | Why it matters |
|---|---|---|
| No automated dependency-update PRs | No `.github/dependabot.yml`, no Renovate config anywhere | `pip-audit` tells you *that* you have a vulnerable version; nothing opens a PR to fix it. Someone has to notice the `pip-audit` failure and manually bump. |
| No SAST (CodeQL, Semgrep, etc.) | No workflow, no config file, no reference anywhere in `.github/` or `tools/` | 230+ API modules handling multi-tenant auth, RLS, and regulated-industry evidence have no static analysis for injection, auth-bypass, or taint-flow classes of bug beyond what `ruff`/`mypy` catch (which are linting/typing tools, not security-focused SAST). |
| No container image vulnerability scanning | `docker-ci.yml` and `release-images.yml` build/push images with signing scaffolding (`FG_SIGNING_SECRET`, minisign) but no Trivy/Grype/Docker Scout step found | Base images (`redis:7-alpine`, `pgvector/pgvector:pg16`, `nginx:alpine`, `quay.io/keycloak/keycloak:24.0`, plus the custom `frostgate-core`/`frostgate-admin-gateway`/`frostgate-console` images) can carry known OS-package CVEs that `pip-audit` (Python-only) cannot see. |
| No Node dependency audit | `package-lock.json` at root, `apps/console/`, `apps/portal/` | Same class of gap as `pip-audit` fills for Python, unfilled for JS. |
| No coverage reporting | `pytest-cov` is a dev dependency (`requirements-dev.txt`) but no `--cov` flag, `coverage.xml`, or Codecov/Coveralls integration found in `Makefile` or any workflow | Coverage is measurable today (the library is installed) but not measured or trended — a one-line CI addition, not a new tool. |
| No flaky-test detection | 600+ test files, some named `test_*_replay*`/`test_*_smoke*` suggesting timing sensitivity; no `pytest-rerunfailures` or CI analytics for flake rate | At this test volume, flake accumulates silently and erodes trust in red CI runs over time. |

---

## 4. Build-Speed Opportunities

- **Caching:** already present — `fg-python-setup` composite action is explicitly named "(cached)" in every job step, and `console`/`docker-ci` jobs use `actions/setup-node@v4` with `cache: npm`. No gap here.
- **Changed-file detection:** already present and repo-native — `tools/ci/detect_changed_paths.py` gates console/compliance/python/core lanes via `dorny/paths-filter`-equivalent logic, avoiding unnecessary job fan-out. No gap here; a third-party equivalent would be a lateral move at best.
- **Test parallelization / splitting:** not evidenced. With 600+ test files across a ~110-minute critical path, `pytest-xdist` (already compatible with `pytest-asyncio`/`pytest-env`/`pytest-cov` already in `requirements-dev.txt`) or GitHub Actions' native test-matrix sharding could reduce the `unit`/`hardening`/`compliance` job wall-clock time — but only after the DUP-01/02/03 fixes are landed, since parallelizing duplicated work multiplies the waste instead of removing it.
- **Remote/distributed build cache (Turborepo, Nx Cloud, BuildKit remote cache):** not justified by current evidence. The console/portal Next.js builds are the only candidates, and neither showed build-time complaints or multi-package monorepo tooling (`packages/navigation`, `packages/ui` exist but are small, internal, TypeScript-only packages, not a large Turborepo/Nx graph). Revisit only if console/portal build time becomes a documented bottleneck.

---

## 5. GitHub App / CI Service Recommendations

| Candidate | Duplicates existing? | CI time added | Signal vs. noise | Private-repo safe? | Data leaving repo | Permissions | ROI | Vendor lock-in | Verdict |
|---|---|---|---|---|---|---|---|---|---|
| **Dependabot (security updates only)** | No — `pip-audit` detects, Dependabot *fixes* via PR | ~0 (runs outside PR CI, on its own schedule) | High signal — GitHub-native, scoped to actual advisories | Yes — GitHub-native feature, no third-party account, no code leaves GitHub | None (GitHub-native, same trust boundary as the repo host itself) | `contents:write` (to open PRs), scoped by GitHub itself | High — closes the "detect but don't fix" gap for both Python and Node in one native feature | None (GitHub-native, free, no contract) | **INSTALL NOW** |
| **CodeQL (Python + JS/TS)** | No — nothing else does taint-flow/injection-class SAST | Moderate (~5-15 min, path-filtered) | Needs a burn-in period to tune the query suite against 230+ modules before treating findings as blocking | Yes, but **requires GitHub Advanced Security license for private repos** (free only on public repos) — confirm licensing cost before enabling | Code is analyzed by GitHub's own infrastructure (same vendor as repo host); no third-party egress | `security-events:write` | Medium-High — closes a real SAST gap on auth/RLS/multi-tenant code, but cost-gated | Low (GitHub-native) | **PILOT** — enable in `report`/non-blocking mode first on `api/` and `admin_gateway/` only, confirm GHAS licensing is in place, then decide on blocking |
| **Trivy (container image scan)** | No — nothing scans built images today | Low (~1-3 min per image) | High signal for base-image CVEs (Alpine/Debian package advisories) | Yes — can run fully self-hosted/offline (Trivy has an air-gapped mode, notable given this repo's own `BLUEPRINT_STAGED.md` BP-C-004 requires an air-gapped mode for the *product itself* — philosophically consistent) | None if run in offline/self-hosted mode | None (scans local image, no external account required for the OSS scanner) | High — closes a real, currently-unfilled gap in `docker-ci.yml`/`release-images.yml` at low cost | None (Apache-2.0, no vendor) | **PILOT** — add as a non-blocking step in `release-images.yml` first, tune the ignore-list for accepted base-image risk, then promote to blocking |
| **`npm audit` (or `npm audit --omit=dev`) for console/portal** | No — Python has `pip-audit`, Node has nothing | Low (~30s) | High signal, low noise for a lockfile-pinned project | Yes — npm-native, no third-party account | None | None | Medium — closes the Node-side mirror of the existing Python gap | None | **INSTALL NOW** |
| **Renovate** | Yes — overlaps Dependabot | Low | N/A | Yes, but is a third-party GitHub App (not GitHub-native) requiring its own installation/config file and permissions grant | Dependency manifests are read by Renovate's hosted service unless self-hosted | `contents:write`, broader config surface than Dependabot | Low incremental value over Dependabot given this repo's needs are "get a PR when there's a known vuln," not "keep every dependency on latest" (which would conflict with the pinned-version discipline visible in `requirements*.txt` — every package is `==` pinned, not `>=`) | Medium (third-party app, own config DSL) | **REJECT** — Dependabot security-updates-only covers the actual evidenced need without introducing a second dependency-bot with overlapping scope |
| **Gitleaks / TruffleHog** | Yes — directly overlaps `check_no_plaintext_secrets.py` + `check_secret_history.py` | Low-moderate | Generic secret-pattern scanners tend to be noisier on this repo's `CHANGE_ME_*` placeholder convention than the purpose-built scanner already tuned to it | Yes (OSS, self-hostable) | None if self-hosted | Read-only | Low — the existing scanner is *more* precise for this repo's specific env-file conventions, not less | Low | **REJECT** — would duplicate an existing, better-tuned gate and add noise, not coverage |
| **SonarCloud / Snyk** | Partial — overlaps `ruff`/`mypy` (code quality) and `pip-audit` (vuln scanning) | Moderate-high | Would re-flag issues `ruff`/`mypy`/`pip-audit` already catch, plus new findings requiring triage | SonarCloud requires the code to be analyzed by a third-party SaaS (data egress); Snyk similarly requires sending manifests/code to a third-party service | Source code or dependency graphs sent to a third-party vendor — **this repo is an enterprise governance/evidence platform for regulated clients (healthcare, govcon per SYSTEM.md); sending its own source to an additional third-party SaaS is a decision that should be made explicitly by the founder/security owner, not defaulted into via a CI add-on audit** | Third-party SaaS account, org-wide OAuth typically requested | Medium (real net-new findings likely) but redundant with CodeQL if that's adopted, and introduces the exact kind of data-egress question this audit is required to flag explicitly | High (both are subscription SaaS with escalating tiers) | **REJECT** — CodeQL (GitHub-native, same trust boundary as the existing repo host) covers the SAST need without a second-vendor data-egress decision; revisit only if CodeQL's Python/TS query coverage proves insufficient |
| **OSSF Scorecard** | No | Low | Scorecard is designed to signal supply-chain hygiene to *external consumers* of a public/open-source project | Private repo — Scorecard's value proposition (public trust signal) doesn't apply | N/A | Read-only | Low — this is a private enterprise repo, not a public dependency other projects consume | None | **REJECT** — wrong tool class for a private repo; the internal-facing equivalent of what Scorecard measures is already covered by the BP-* blueprint gates |
| **Mutation testing (e.g. `mutmut`, `cosmic-ray`)** | No | High (mutation testing is CPU-intensive, multiplies test-suite runtime) | Could reveal weak assertions in the 600+ test files, but at real CI-time cost on top of an already ~110-min critical path the team is actively trying to shrink | Yes (OSS) | None | None | Low near-term — this repo's test-quality gap (per inventory) is *coverage breadth* (no browser E2E) more than *assertion depth* of existing unit tests | None | **DEFER** — revisit after CI critical path is shrunk per the team's own optimization plan, and after coverage reporting (below) identifies actual weak spots |
| **Coverage reporting (`pytest --cov`, uploaded as a CI artifact or to Codecov)** | No — `pytest-cov` is installed but unused | Low (~seconds, `--cov` flag) | High signal for identifying untested modules across 230+ API files | Self-hosted (artifact upload) is fully private; Codecov/Coveralls would send coverage XML (not source) to a third-party | Coverage percentages/line-hit data only if a SaaS is used; zero egress if kept as a CI artifact | None (artifact) or read-only repo access (if SaaS) | Medium — cheap to turn on, useful trend data, no new tool required since `pytest-cov` is already a dependency | None if self-hosted | **INSTALL NOW** (self-hosted artifact: `pytest --cov --cov-report=xml`, upload as a build artifact) — **DEFER** the third-party SaaS (Codecov) decision pending the same data-egress review flagged for SonarCloud/Snyk above |
| **Flaky-test detection / retry (`pytest-rerunfailures`, or GitHub's own re-run analytics)** | No | Low | At 600+ test files, flake tracking has real signal value | Yes (OSS) | None | None | Medium — improves trust in red CI without masking real failures if scoped to *detection* (tracking rerun rate) rather than blind auto-retry | None | **PLAN** — instrument detection (which tests get manually re-run today) before adding auto-retry, to avoid silently hiding genuine flakiness |

---

## 6. Rejected Tools and Reasons (Summary)

| Tool | Reason |
|---|---|
| Renovate | Overlaps Dependabot; conflicts with this repo's strict version-pinning discipline |
| Gitleaks / TruffleHog | Duplicates a purpose-built, already-tuned custom secret scanner |
| SonarCloud / Snyk | Redundant with `ruff`/`mypy`/`pip-audit`/CodeQL; introduces an additional third-party data-egress decision for an enterprise evidence platform that should be made explicitly, not incidentally |
| OSSF Scorecard | Designed for public-repo trust signaling; not applicable to a private enterprise repo |
| Mutation testing | Real CI-time cost on top of an already-long critical path the team is actively shrinking; lower priority than closing the browser-E2E coverage gap |
| Broad DAST / API fuzzers | No evidence of a staging environment safe to fuzz against; would need its own scoping exercise before consideration — out of scope for this audit's evidence base |

---

## 7. Answers to Required Topics (CI scope)

- **CI add-ons that reduce failure-diagnosis time without weakening gates:** GitHub MCP (read-only, see CLAUDE_CODE_MCP_RECOMMENDATIONS.md) for faster log triage; coverage reporting turned on (already-installed `pytest-cov`) to localize test gaps; flaky-test *detection* (not blind retry) to distinguish real failures from noise.
- **Security add-ons that add real coverage rather than duplicate current gates:** Dependabot (security updates), `npm audit`, Trivy (container images), CodeQL (pending GHAS licensing confirmation). Everything else evaluated either duplicates an existing purpose-built gate or introduces an unjustified third-party data-egress decision.
