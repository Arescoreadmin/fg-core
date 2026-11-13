# CODEQL-REMEDIATE-004: seed credential storage audit (CodeQL #8, #9)

Baseline: `main` `bb513ebc` (#867 merged), code-scanning API read 2026-11-13. There are 102 open alerts (100 Python, 2 JavaScript) and 0 dismissed.

## 1. Alert state, and why it is not the answer

| Alert | Rule | Site on `4635376f` | State on `main` `bb513ebc` |
|---|---|---|---|
| #8 | `py/clear-text-storage-sensitive-data` | `tools/seed/run_seed.py:292`, rerun write of the state file | `fixed` (analysis 2162115661, 2026-11-13T15:44:33Z) |
| #9 | `py/clear-text-storage-sensitive-data` | `tools/seed/run_seed.py:330`, first-run write of the state file | `fixed` (same analysis) |

Both alerts closed when #867 replaced `Path.write_text` with `credential_output.write_private_text`, which writes through `os.write`. CodeQL stopped modelling that call as a sink. **The bytes on disk did not change.** The state file still holds non-expiring seed API keys in plaintext. The closure is a sink-modelling effect, not proof of safe storage, so this audit judges the storage on its own merits. No alert was dismissed.

No other open alert touches `tools/seed/`. The other six open `py/clear-text-storage-sensitive-data` alerts are outside the seed tooling and are listed in section 7.

## 2. What is stored

| Property | Value | Evidence |
|---|---|---|
| File | `state/seed/bootstrap_state.json` (override: `FG_SEED_STATE_PATH`) | `run_seed._set_default_env` |
| Content | `seed_credentials.{admin,agent,audit}_api_key`, `ag_core_api_key` | `_ensure_seed_credentials` |
| Generation | `secrets.token_urlsafe(32)`, 256 bits, per issue and rotation | `api/credential_authority.py` |
| Scope | tenant `tenant-seed-primary` only. Admin key: `admin:*`, `keys:write`, `audit:export` and more | `SEED_CREDENTIAL_SPECS` |
| Expiry | **none**: `SEED_CREDENTIAL_TTL_SECONDS = 0` means no `expires_at` | `issue_credential` TTL handling |
| Classification | local development credentials, live in whichever database minted them | section 3 |
| Consumers | testers (CTJ-1 in `docs/tester_quickstart.md`, `docs/tester_collection.json`) | docs |
| Tracking | `state/` is git-ignored; no file under `state/` is tracked; no CI workflow runs the seed or uploads `state/` | `.gitignore:120`, `git ls-files state`, `.github/workflows` |
| Containers | not mounted; compose uses the named volume `fg_state` at `/var/lib/frostgate/state` | `docker-compose.yml` |

## 3. Threat model and findings

Threat actors considered:
- another local user on the workstation;
- a process running as the operator with a confused environment;
- a crash or a full disk;
- backups and snapshots of the working tree.

Out of scope: an attacker who already runs as the operator, who can read anything the operator can.

| # | Finding | Before (`bb513ebc`) | Class | Status |
|---|---|---|---|---|
| F1 | **Rerun mints in another environment.** The first run pins the engine with `init_db(sqlite_path=…)`. The rerun path (state file present) called `get_engine()` with no path, so an inherited `FG_DB_URL` won. The demo-tenant operator flow exports one. | Reproduced with the real tool against two SQLite files. The rerun issued all three keys in the `FG_DB_URL` database (rotating out its existing seed keys) and wrote them to a state file that records the local `sqlite_path`. The keys were invalid locally and valid in the other database. The audit-ledger check in `_validate_existing_seed` blocks only databases with no seed-tenant rows; it is incidental, not a boundary. | **Vulnerability** (credential minted outside its environment; misattributed persistence) | Fixed |
| F2 | **Unsafe state file refused only after minting.** A symlinked state file was read through, keys were minted or rotated, and only then did the write refuse. A dangling symlink sent the tool down the first-run path, through database initialisation and seeding, before the refusal. | Red tests: minting ran before the refusal; `init_db` ran before the check. | Insufficient protection (issued credentials stranded) | Fixed |
| F3 | **Non-atomic rewrite.** `O_TRUNC` then write: a failure part-way left an empty or partial file. Keys rotated during that run were lost; every later run crashed with an uncaught `JSONDecodeError`. That error has no documented recovery; the nearest one, for `SEED_CONFLICT`, wipes the whole of `state/`. | Red test: an `ENOSPC` during the rewrite left the file `b''`. | Insufficient protection (loss of the only copy) | Fixed |
| F4 | **Write-through on a hardlink.** Truncating in place wrote the new keys into every name linked to the file. | Red test: the linked file received the new keys. It needs write access to `state/seed/`, which the parent check limits to the operator. | Hardening | Fixed |
| F5 | Confidentiality on disk: mode `0600`, exclusive and no-follow creation, and the safe-parent check have been in place since #867. | Existing tests, plus a successful-rewrite test asserting `0600` | **Intentional, adequately controlled** storage for local development credentials | No change |
| F6 | Plaintext at rest: the file is not encrypted. It is readable by the operator account, root, and any unencrypted backup of the working tree. | By design | Accepted residual (section 5) | Documented |

## 4. Lifecycle

```text
generation   secrets.token_urlsafe(32) via credential_authority.issue/rotate (no change)
capture      seed result dict; stdout is an allowlisted summary (#867)
persistence  0600 temporary file (O_EXCL|O_NOFOLLOW) -> fsync -> rename -> fsync of the directory   [F3, F4]
             target checked before anything is read or minted                                         [F2]
retrieval    tester reads the file locally; no API response contains it
runtime use  tenant API key for tenant-seed-primary in the database named by sqlite_path              [F1]
rotation     a stored key failing validation is rotated; credential_authority marks the predecessor `rotated` (terminal)
revocation   by rotation, or by the credential authority; no seed-specific path
cleanup      re-run to replace; delete state/ to reset; no expiry (TTL 0)
```

Recovery after any failure is idempotent. A rerun validates the stored keys against the recorded database, keeps those that are valid, and rotates the rest.

Concurrent runs are not serialised. If two runs race, the last writer's keys may already have been rotated by the other run. The file is still complete (rename is atomic), and the next run detects the invalid keys and rotates. This is accepted.

## 5. Options considered

| Option | Security gain | Cost and complexity | Verdict |
|---|---|---|---|
| A. Keep the owner-only file and harden it | Closes F2, and environment binding closes F1 | Minimal | Taken, with B |
| B. Atomic replace with ownership checks | Closes F3 and F4 | ~30 lines, standard library only | **Taken** |
| C. OS keyring or secret manager | Removes plaintext at rest | New dependency or service for every tester; breaks the documented jq/curl flow; the seed's keys are for a local SQLite database | Not justified for local development credentials |
| D. Envelope encryption under an external KMS | Removes plaintext at rest | Needs KMS reachability for local development; with a local key it is theatre (the key sits beside the ciphertext) | Rejected |

## 6. Future secret-management architecture (not in this PR)

These risks belong to the **production** credential path, `demo_tenants.py` and Vercel, not to this file:
- `FG_PORTAL_DEMO_TENANT_KEYS` is a long-lived Vercel environment variable holding a JSON map of tenant API keys.
- Operators hand-carry it through a local `0600` file (CODEQL-REMEDIATE-003).

Recommended direction:
- **Authority:** the existing Vault Transit / credential authority stays the issuer.
- **Delivery:**
  - the portal fetches a short-lived, service-scoped credential at runtime through workload identity (Vercel OIDC to a broker), instead of keeping a static key map in an environment variable;
  - Railway services use the same broker.
- **Rotation:** scheduled rotation in the credential authority. Consumers re-fetch, so no operator handling or redeploys are needed.
- **Audit:** every fetch is a credential-authority audit event, attributable to a service identity.
- **Separation:** one credential set per environment, bound to that environment's database. F1 is the local instance of this rule.
- **Local development:** the seed file stays as it is. It is the local equivalent and holds only local keys.

Track this as its own roadmap item. It touches deployment and authentication configuration and needs founder approval.

## 7. Remaining clear-text-storage alerts (not triaged here)

`#3` `api/billing.py:83`, `#10` `api/ui.py:992`, `#4` `tests/test_customer_zero_e2e/browser_acceptance.py:998`, `#5`/`#6` `scripts/contracts_gen_core.py:163-164`, `#7` `scripts/patch_compliant_surfaces.py:137`. `#3` and `#10` are in API code. Triage them next.
