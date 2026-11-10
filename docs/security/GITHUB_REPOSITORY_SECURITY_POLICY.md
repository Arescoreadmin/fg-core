# GitHub Repository Security Policy — `Arescoreadmin/fg-core`

**Work item:** P0-REPO-SECURITY-ENFORCEMENT-001 · **Class:** SECURITY / REPAIR (closes merge-bypass gaps) · **Baseline:** `751666a1` (main after #819) · **Date:** 2026-11-10

**Machine-readable desired state:**
- `.github/security/repository-policy.json`
- `.github/security/main-ruleset.json`, the exact ruleset API payload

**Checker:** `tools/ci/check_github_repo_security.py`. Make targets: `make repo-security-check` and `make repo-security-drift`.

> Desired state is **not** evidence of enforcement. A setting counts as active only when a live admin readback (`make repo-security-drift`) reports it COMPLIANT.

## 1. Two separate claims

| Claim | Meaning | Status |
|---|---|---|
| **ENGINEERING_PASS** | The repository-side controls are in place: required checks that cannot fail open, workflow hardening, drift detection, negative tests, and a ready activation plan. | Achieved by this PR (pending its CI). |
| **ENFORCEMENT_VERIFIED** | GitHub itself enforces the policy. That needs founder authorization, activation, an admin readback showing COMPLIANT, and a demonstrated blocked merge. | **Not yet.** It needs founder authorization (§7). |

## 2. Current state (independent read-only audit, 2026-11-10)

Captured with `gh` as `Arescoreadmin` (admin). Raw readback: `make repo-security-drift`.

| Area | Observed |
|---|---|
| Repository | public, owned by the User account `Arescoreadmin`; the only collaborator is `Arescoreadmin` (admin) |
| Branch protection (classic) | **none** (`Branch not protected`) |
| Rulesets / active branch rules | **none** (`[]`) |
| Merge methods | merge commit, squash and rebase all allowed; auto-merge off. History is squash-only. |
| Dependabot alerts | **disabled** |
| Dependabot security updates | **disabled** |
| Private vulnerability reporting | **disabled** |
| Secret scanning / push protection | enabled / enabled |
| Code scanning default setup | not configured |
| Actions | all actions allowed; SHA pinning not required; default token **read**; Actions cannot approve PRs; fork PRs need approval for first-time contributors; no self-hosted runners; artifact/log retention 90 days |
| Deployment environments | 9 (`Production`, `frostgate-core / production`, Vercel previews and others), **none** with protection rules or branch policy |
| Repository secrets | 7, all backup credentials, used only by `backup-scheduled` and `restore-drill-monthly` (schedule/dispatch, never on PRs) |
| CODEOWNERS | none |

**Consequence:** until activation, any push, force-push or merge with failing CI reaches `main`. Nothing on GitHub enforces the 25 green checks.

## 3. Desired state for `main`

The mechanism is a repository **ruleset**, `main-protection`, rather than classic branch protection. Rulesets are available for public user-owned repositories, layer cleanly, record their history, and can be disabled temporarily for recovery without deleting configuration.

| Control | Setting | Rationale |
|---|---|---|
| Target | `~DEFAULT_BRANCH` (main) | |
| Enforcement | `active` | |
| Bypass actors | **none** | No standing bypass for the admin, bots or apps. Recovery follows §8. |
| Deletion | blocked | |
| Force push (`non_fast_forward`) | blocked | |
| Linear history | required | Matches the existing squash-only history. |
| Pull request | required; **0 approvals**; dismiss stale reviews on push; review threads must be resolved; merge method **squash** only | See §4. |
| Required status checks | 5 contexts (§5), each bound to the GitHub Actions app (`integration_id` 15368); **strict** (branch must be up to date) | Binding stops another app or a commit status from satisfying a check by reusing its name. Strict mode makes checks evaluate the actual merge candidate. |
| Repository merge settings | squash only (merge commit and rebase disabled); auto-merge stays disabled | No unattended merges, including Dependabot. |

## 4. Founder-led review policy (honest limitation)

There is one collaborator, and every PR (human- or agent-prepared) is opened by that same account. GitHub forbids self-approval, so `required_approving_review_count ≥ 1` would make **every** PR unmergeable. The policy instead relies on:

- mandatory CI on the final merge candidate, with no bypass;
- the founder as the sole merge authority;
- dismissal of stale reviews and resolution of review threads, including automated Codex review threads;
- SOC review sync. `check_soc_review_sync.py` already requires a SOC record for `.github/workflows/` and `tools/ci` changes.

**This is not independent four-eyes review.** A PR authored with the founder's account can also modify the guards that check it (§10). When a second maintainer exists:

1. set `required_approving_review_count: 1`, `require_last_push_approval: true` and `require_code_owner_review: true`;
2. add `.github/CODEOWNERS` covering `.github/`, `tools/ci/`, `api/auth*`, `api/security/` and `migrations/`;
3. update both JSON files in a reviewed PR.

## 5. Mandatory status checks

### Inventory (real contexts from PR #819 and main)

| Context (job name) | Workflow | Runs on every PR? | Disposition |
|---|---|---|---|
| Guard (paths + syntax + fg-fast) | frostgate-core-ci | yes | member of **CI Required** |
| Enforcement Mode Matrix (prod/staging) | frostgate-core-ci | yes (`event == pull_request`) | member |
| Unit (ci) | frostgate-core-ci | yes | member |
| Contract Authority (prod-spec) | frostgate-core-ci | yes | member |
| Integration (itest-local) | frostgate-core-ci | only if Unit succeeded | member (a skip fails the aggregate) |
| Migrations Replay | frostgate-core-ci | yes | member |
| DB Postgres Verify | frostgate-core-ci | yes | member |
| Admin Gateway (ci-admin) | frostgate-core-ci | yes | member |
| Console (ci-console) | frostgate-core-ci | yes | member |
| Portal (ci-portal) | frostgate-core-ci | yes | member |
| PT (ci-pt) | frostgate-core-ci | yes | member |
| Hardening Gates (ci-hardening) | frostgate-core-ci | yes | member |
| Compliance Gates | frostgate-core-ci | yes | member |
| Evidence (ci-evidence) | frostgate-core-ci | only if Integration succeeded | member |
| Agent Linux (unit + contract) | frostgate-core-ci | only if Unit succeeded | member |
| Agent Windows Build | frostgate-core-ci | only if Unit succeeded | member |
| Coverage (advisory) | frostgate-core-ci | conditional; `continue-on-error` | **advisory**, excluded |
| **CI Required** *(new)* | frostgate-core-ci | yes (`if: always()`) | **required** |
| fg-required | fg-required | yes | **required** |
| Frontend Dependency Security | frontend-dependency-security | yes | **required** |
| Record failing frontend dependency gate | frontend-dependency-security | never on PRs (skipped) | advisory; requiring it would be satisfied by a skip |
| Docker Compose Validation | frostgate-docker-ci | **was path-filtered** | becomes a member of **Docker Compose Gate** |
| Docker Compose Relevance *(new)* | frostgate-docker-ci | yes | member |
| **Docker Compose Gate** *(new)* | frostgate-docker-ci | yes (`if: always()`) | **required** |
| pr-fix-log-guard | ai-ledger-guard | yes | **required** |
| fg-fast / fg-contract / fg-security / … | testing-module | path-filtered (`tools/testing/policy/**`) | not requirable; the same lanes run inside `fg-required` |
| Vercel – … | Vercel app | third-party status | advisory (not GitHub Actions, not bound) |

### Why aggregates

GitHub reports a **skipped** required check as passing. Before this change, a Unit failure skipped Integration, Evidence and the Agent jobs. Requiring them individually would have been unsafe, and requiring all 16 individually is brittle.

**CI Required** (`ci.yml`, `if: always()`):
- It `needs:` every mandatory job.
- On `pull_request`, it passes only if **every** result is `success`. Skipped, failed, cancelled and timed-out results all fail it, as does an empty result set.
- It also carries an explicit `EXPECTED_JOBS` list, kept identical to `needs:` and the policy by the checker. An expected job with no result fails the check at runtime, as a second line of defence beside the static guard.
- On push to main, path-scoped skips are tolerated but failures are not.

**Docker Compose Gate:** `docker-ci` previously had a workflow-level `paths` filter. A required Docker check would then never report on most PRs, which is why it could not be required. Now:
- the workflow runs on every PR;
- *Docker Compose Relevance* evaluates the same path list;
- the gate passes immediately when nothing relevant changed;
- otherwise it requires *Docker Compose Validation* = `success`.

The push trigger keeps its path filter, and the checker enforces that both lists are identical. The cost for documentation-only PRs is two jobs of a few seconds each.

### Aggregate correctness (proven by `tests/tools/test_github_repo_security.py`)

- The real aggregate and gate scripts are executed with synthetic results. Unexpected skips, failures or timeouts, cancellations, missing jobs and empty results all block; all-success passes. On push, path-scoped skips pass but failures and cancellations still block.
- The static checker, which runs in Guard on every PR, fails when:
  - a required job is renamed, given an `if:`, or given `continue-on-error`;
  - an aggregate member is given `continue-on-error`. That would turn a failure into `success`.
  - an aggregate loses or gains a member;
  - a new `ci.yml` job is not covered;
  - a required workflow gets `paths`/`paths-ignore`;
  - the policy or ruleset drops a mandatory context, adds a bypass actor, unbinds a check from the Actions app, or leaves `active` mode.

## 6. GitHub Actions security

**Fixed in this PR:**
1. **Secret masking.** Generated CI secrets (`fg-secrets` and docker-ci) were written to `GITHUB_ENV` unmasked and appeared in every step's `env:` dump. This repository's logs are public. They are now registered with `::add-mask::` before export. They were per-run synthetic values, not production credentials, but the pattern was unsafe.
2. **`prod-auth-smoke` trigger.** It runs with `VERCEL_TOKEN` and production test credentials on `workflow_run` with `branches: [main]`. That filter matches the triggering run's *head branch name*, which a fork PR named `main` also satisfies. It now also requires `workflow_run.event == 'push'` and `head_repository.full_name == github.repository`.
3. **Pinning.** The third-party actions that run with secrets or write tokens are pinned to full commit SHAs (each at least 10 months old): `docker/login-action` v3.7.0 and `docker/setup-buildx-action` v3.12.0 (release-images, which has `packages: write`), buildx in docker-ci, and `hashicorp/setup-terraform` v3.1.2. The checker now requires every non-`actions/*` action to be SHA-pinned. Dependabot `github-actions` updates are re-enabled (limit 3) so the pins stay current.

**Verified (no change needed):**
- every workflow declares top-level permissions, and the default token is read;
- write scopes exist only on `release-images/build-and-push` (`packages`) and the two issue-recording jobs (`issues`), which are on the allowlist;
- no `pull_request_target`;
- no self-hosted runners;
- `ai-ledger-guard` passes PR body and refs through `env:` (not injectable);
- backup secrets are used only by schedule and dispatch workflows.

**Cataloged for follow-up (not changed):**
- the first-party `actions/*` are tag-pinned; consider SHA-pinning them and enabling `sha_pinning_required`;
- `allowed_actions: all`; consider `selected` (GitHub-owned plus verified creators);
- the deployment environments have no reviewers or branch policy (Vercel-managed);
- docker-ci contains fixed CI-only literal keys (test values, not secrets);
- code scanning default setup (free for public repositories);
- artifact retention of 90 days is acceptable.

## 7. Activation plan (prepared; **NOT applied** — requires explicit founder authorization)

**Order matters.** Merge this PR **first**. Until then, `CI Required` and `Docker Compose Gate` do not exist on main, and activating the ruleset early would block every PR.

| Step | Command (run as the admin) | Verify |
|---|---|---|
| 1 | `make repo-security-drift` (before) | record the DRIFT baseline |
| 2 | `gh api -X PUT repos/Arescoreadmin/fg-core/vulnerability-alerts` | 204 from `GET …/vulnerability-alerts` |
| 3 | `gh api -X PUT repos/Arescoreadmin/fg-core/automated-security-fixes` | `{"enabled":true}` |
| 4 | `gh api -X PUT repos/Arescoreadmin/fg-core/private-vulnerability-reporting` | `{"enabled":true}` |
| 5 | `gh api -X PATCH repos/Arescoreadmin/fg-core -F allow_merge_commit=false -F allow_rebase_merge=false` | repo settings |
| 6 | `gh api -X POST repos/Arescoreadmin/fg-core/rulesets --input .github/security/main-ruleset.json` | `GET …/rules/branches/main` lists 5 rule types |
| 7 | `make repo-security-drift` (after) | **COMPLIANT** for every control |
| 8 | Negative merge test (§9) | merge blocked |

**Rollback, per step:**
- **Steps 2–4:** `-X DELETE` on the same endpoint.
- **Step 5:** `PATCH` the flags back to `true`.
- **Step 6:** `gh api -X PUT repos/Arescoreadmin/fg-core/rulesets/<id> -f enforcement=disabled` (preferred; keeps history), or `-X DELETE`.

**Lockout risk is nil:** the admin can always edit or disable a ruleset.

## 8. Emergency recovery (break-glass)

- **Allowed only when** main is broken in production *and* the fix cannot pass CI because of a CI or GitHub outage, or a required check is itself defective and blocking a security fix. Convenience or deadline pressure does not qualify.
- **Who:** the founder (repository admin) only. Agents never perform it.
- **How:**
  1. Open an issue titled `[break-glass] <reason>`.
  2. Set the ruleset `enforcement` to `disabled`.
  3. Merge the specific PR.
  4. **Re-enable within 2 hours, or immediately after the merge.**
- **Record:** the issue, plus the ruleset history and audit log, which GitHub keeps automatically. The daily `repo-security-drift` run also opens a DRIFT issue if protection is left off.
- **Retrospective:** within 2 business days, re-run full CI on the merged SHA, record the outcome in the issue and in `docs/SOC_EXECUTION_GATES_*.md`, and fix forward.

## 9. Negative acceptance test (pending activation)

After step 6:
1. Create the branch `test/required-check-negative`, with a commit that makes one required context fail deterministically. For example, add `continue-on-error: true` to the `fg-required` job in `.github/workflows/fg-required.yml`. Guard's security regression gate rejects it within about a minute, Guard fails, and **CI Required** therefore fails.
2. Open a **draft** PR labelled `do-not-merge`.
3. Wait for the checks to finish.
4. Record `gh pr view <n> --json mergeStateStatus`, which must be `BLOCKED`, and `gh pr checks`.
5. Close the PR **without merging** and delete the branch.

Do not push to main to test protection.

## 10. Residual risks

1. **Self-modifying guards.** A PR can edit both the policy checker and the workflows it checks, and the checks run from the PR's own code. The mitigations are founder review of every diff, SOC review sync on `.github/` and `tools/ci`, and the daily live drift check, which compares GitHub's actual ruleset against the committed policy. Full mitigation requires independent review (§4).
2. **No independent four-eyes review** while there is one maintainer.
3. **Admin can disable the ruleset.** This is intended for recovery and is detected daily by drift monitoring.
4. **Strict up-to-date checks** mean that re-running CI after every main change costs runner time. This is accepted for security at the current low PR volume.
5. **The drift workflow token cannot read admin-only settings** (alerts, security updates, private reporting, bypass list). Those controls report NOT_VERIFIED in CI and are verified by the founder's `make repo-security-drift`.

## 11. Dependabot

`.github/dependabot.yml` covers:
- pip;
- root npm;
- `apps/console`, `apps/portal` and `apps/web`;
- GitHub Actions.

Settings:
- **Version updates:** limit 3 for each frontend and for Actions, 2 for pip. Root npm (markdownlint only) stays at 0.
- **Grouping:** minor and patch updates are grouped. Each frontend also has a `*-security` group for grouped security updates.
- **Majors:** major versions arrive as individual PRs.
- **No `ignore` rules,** so security updates are never suppressed.

Every Dependabot PR runs the same required checks. Frontend Dependency Security runs on every PR, so a dependency update that introduces a critical/high advisory is blocked. Nothing auto-merges.

**Editing `dependabot.yml` does not enable alerts or security updates.** That is step 2–3 of §7, and stays NOT_VERIFIED until the readback confirms it.
