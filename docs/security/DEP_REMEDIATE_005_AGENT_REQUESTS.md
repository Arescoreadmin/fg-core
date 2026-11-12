# DEP-REMEDIATE-005: Python agent `requests` advisories

Status: implemented on branch `fix/dep-remediate-005`. Not merged.
Base: `main` at `10924ed44` (after #850). Observed: 2026-11-11.
Guard and machine-readable evidence: `tools/ci/dep_remediation_final_inventory.py` → `dep_remediation_final_inventory.json` (alerts #1 and #2 now `IMPLEMENTED`).

## 1. Baseline (verified, read-only)

- Working tree clean; `main` equals `origin/main` at `10924ed44`; #844, #845, #847, #848 and #850 are ancestors.
- #850 outcome: all 21 IDs it resolved (16 targets plus #172, #177, #178, #183, #184, previously auto-dismissed by GitHub) are `state=fixed` with `dismissed_at` null (fixed 2026-11-12T02:01Z).
- GitHub reports exactly 4 open alerts:

| Alert | Manifest | Package | Advisory | Range | First patched | Owner |
|---|---|---|---|---|---|---|
| #1 | `agent/requirements.txt` | requests (runtime) | GHSA-9hjg-9r4m-mvj7 / CVE-2024-47081, .netrc credential leak via malicious URL | `< 2.32.4` | 2.32.4 | **this PR** |
| #2 | `agent/requirements.txt` | requests (runtime) | GHSA-gc5v-m9x4-r6x2 / CVE-2026-25645, predictable temp-file reuse in `extract_zipped_paths` | `< 2.33.0` | 2.33.0 | **this PR** |
| #88 | `apps/console/package-lock.json` | minimatch (dev) | GHSA-g3hv-75wg-m249 | `>= 7.0.0, < 11.0.1` | 11.0.1 | DEP-REMEDIATE-006 |
| #170 | `apps/portal/package-lock.json` | minimatch (dev) | GHSA-g3hv-75wg-m249 | `>= 7.0.0, < 11.0.1` | 11.0.1 | DEP-REMEDIATE-006 |

## 2. Change

One dependency line: `agent/requirements.txt` `requests==2.32.3` → `requests==2.34.2`.

- 2.34.2 is the latest release on PyPI (checked with `pip index versions`). The GitHub advisory database lists no active advisory affecting it; every requests advisory is patched at or below 2.33.0.
- Wheel metadata: `Requires-Python >=3.10` (the agent image is `python:3.12-slim`), `urllib3<3,>=1.26`, `idna<4,>=2.5`, `charset_normalizer<4,>=2`, `certifi>=2023.5.7`.
- 2.34.2 `extract_zipped_paths` uses `tempfile.mkstemp`, which is the #2 fix; `get_netrc_auth` uses the parsed hostname, which is the #1 fix.
- `windows-requirements.txt`, the Dockerfile and all other platform dependencies are unchanged.

## 3. Dependabot PR #851

PR #851 bumps the same line to 2.33.0, the minimum patched version. It is not used because:

- its `Guard (paths + syntax + fg-fast)` job fails at `verify-offline-simulation-evidence`, so `CI Required` fails and every downstream job (including Agent Linux and Agent Windows Build) is skipped. Dependabot cannot regenerate the governed evidence;
- it would also leave the remediation guard recording #1 and #2 as `PLANNED` while they resolve as fixed, which `tests/tools/test_dep_remediation_final_inventory.py` rejects;
- it carries no regression tests for either advisory.

DEP-005 supersedes it. Close #851 without merging after DEP-005 merges and GitHub reports #1 and #2 `fixed`. Do not merge both.

## 4. Evidence

**Install and conflicts (clean Python 3.12 venv, `pip install -r agent/requirements.txt`):** install OK; `pip check` reports no broken requirements; resolved requests 2.34.2, urllib3 2.8.0, certifi 2026.10.23, charset-normalizer 3.5.2, idna 3.20, redis 5.2.1. `import agent.core_client` works. `pip-audit -r agent/requirements.txt`: no known vulnerabilities.

**Behavioural regression tests:** `tests/agent/test_requests_advisory_regression.py` (7 tests, run by `make agent-unit` and the CI Agent Linux job). Each was run against shadowed copies of the library:

| requests | Result | Meaning |
|---|---|---|
| 2.32.3 (old pin) | 4 failed, 3 passed | pin test, both .netrc tests and the temp-file test catch the vulnerable behaviour |
| 2.32.4 | 2 failed, 5 passed | #1 fixed, #2 still caught |
| 2.33.0 (minimum) | 7 passed | both fixed |
| 2.34.2 (new pin) | 7 passed | both fixed |

What they assert:

- **#1:** `get_netrc_auth("https://core.example:@evil.example/")` returns nothing, while the genuine host still gets its `.netrc` entry. A `Session` (default `trust_env`) never attaches the `.netrc` secret to the malicious URL.
- **#2:** with a file pre-planted at the old predictable path, `extract_zipped_paths` returns a fresh private file (mode 0600) with the genuine content, different on every call, and leaves the planted file untouched.
- **Transport preserved:** the agent `CoreClient` sends one request to the configured Core host only, with `verify=True`, its configured timeout and the device Bearer token, and does not follow a 302 to another host. requests strips `Authorization` on a cross-host redirect.

**Guard:** `dep_remediation_final_inventory.py` now enforces #1 and #2. Four new tests: re-pinning 2.32.3 fails for #1 and #2, 2.32.4 and 2.32.5 fail for #2 only, and the minimum 2.33.0 passes.

## 5. Transport review

- **Deployed client:** the agent image runs `agent.app.agent_main`, which uses `agent/core_client.py`. That client validates the base URL (HTTPS only unless overridden, private and loopback hosts blocked), removes the `http://` adapter by default, supports certificate pinning, sets an explicit timeout and passes `allow_redirects=False`. No code path passes `verify=False`. Retry behaviour (`Retry(total=2, …)`) is unchanged.
- **Legacy client (finding, no change here):** `agent/app/core_client.py` follows redirects and sends a custom `X-API-Key` header. requests strips only `Authorization` on a cross-host redirect, so a redirecting Core would forward that key. It is reachable only via `agent/app/main.py`, which no Dockerfile, compose file, Make target or workflow launches. Removing it or setting `allow_redirects=False` is a behaviour change for a separate decision, not part of this dependency fix.
- **Test lane gap (finding, no change here):** `agent/tests/` (including `test_core_client_security.py`) is outside `pytest.ini` `testpaths` and no CI job runs it. The new regression tests live in `tests/agent`, which CI runs. Run locally, the full `agent/tests` directory did not finish within 600 s. Its two transport files give 19 passed and 1 failed: `test_core_transport_policy.py::test_cert_pin_mismatch_fails_closed` raises `AttributeError: 'list' object has no attribute 'strip'` identically on requests 2.32.3 and 2.34.2, so it is a pre-existing test defect, not an upgrade regression.
- **Correction to the DEP-004 plan:** the Windows build does have a CI lane, `Agent Windows Build` (`make agent-build-windows` on `windows-latest`). It builds `agent/main.py`, which uses stdlib `urllib`, and never installs `agent/requirements.txt`. It was not run locally (Linux workstation); the CI job on this PR is the evidence.

## 6. Deployment impact and rollback

- No repo-managed deployment. The agent image is built only by `agent/docker-compose.yml`, is not in `release-images` and is not in the root compose file. No Vercel project watches `agent/`.
- Operators running the Linux agent image must rebuild it to pick up 2.34.2.
- **Rollback:** revert the PR. That re-opens #1 and #2 and the guard will then fail, which is intended.

## 7. Residual risk

- Closure depends on GitHub's rescan of `main`. Nothing is claimed as fixed until #1 and #2 read `state=fixed` with `dismissed_at` null.
- Transitive dependencies (urllib3, certifi, idna, charset-normalizer) are not pinned in `agent/requirements.txt`, as before this PR; installs float within requests' declared ranges.
- #88 and #170 remain open until DEP-REMEDIATE-006.

## 8. Post-merge verification (operator, read-only)

```bash
gh api repos/Arescoreadmin/fg-core/dependabot/alerts/1 --jq '[.number,.state,.dismissed_at,.fixed_at]|@tsv'
gh api repos/Arescoreadmin/fg-core/dependabot/alerts/2 --jq '[.number,.state,.dismissed_at,.fixed_at]|@tsv'
# expect state=fixed, dismissed_at null
gh api --paginate "repos/Arescoreadmin/fg-core/dependabot/alerts?state=open&per_page=100" --jq '.[]|[.number,.dependency.manifest_path]|@tsv'
# expect exactly 88 and 170
python tools/ci/dep_remediation_final_inventory.py
gh pr view 851 --json state   # then close #851 as superseded
```
