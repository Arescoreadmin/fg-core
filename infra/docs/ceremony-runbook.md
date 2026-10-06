# CUSTOMER-ZERO-TRUST-001 Production Ceremony Runbook

**Ceremony ID:** `customer-zero-trust-2026-10-02-001`
**Work item:** CUSTOMER-ZERO-TRUST-001
**fg-core source authority:** Run `git rev-parse HEAD` at Checkpoint A1. It must equal `git rev-parse origin/main`. Record the actual SHA in the ceremony evidence manifest. Do not hardcode an expected SHA here — the authority is HEAD == origin/main, not a fixed value.
**Note:** `Arescoreadmin/frostgate-infra` is archived (read-only). Infrastructure authority has moved permanently to `fg-core/infra/`. The standalone repo SHA `8121d24252dd1e7e3945424fcdacc5a320611fea` is retained as a historical record only.

**Timebox targets:**
- Target completion: 8 hours
- Warning trigger: 10 hours
- Mandatory review / freeze: 12 hours
- Absolute maximum: 24 hours

**Prerequisite:** Stage 1.5 operator hardening complete (see `docs/operator-hardening.md`).

---

## CHECKPOINT A — Preflight

**Prerequisites:** None (start of ceremony)

**Actions:**

```bash
# A1. Verify fg-core
cd ~/Projects/fg-core
git status
git branch --show-current        # must be: main
git rev-parse HEAD               # record for evidence — must equal origin/main (see next line)
git fetch origin --prune
git rev-parse origin/main        # must equal HEAD

# A2. Confirm infrastructure authority is fg-core/infra (standalone repo is archived)
# Arescoreadmin/frostgate-infra is archived and read-only — do NOT use it as an apply source.
# Canonical infrastructure path: ~/Projects/fg-core/infra
ls ~/Projects/fg-core/infra/*.tf | head -5
# Expected: fg-core/infra Terraform files present

# A3. Confirm roadmap authority
cd ~/Projects/fg-core
python tools/ci/check_customer_one_roadmap.py --work-item CUSTOMER-ZERO-TRUST-001
# Expected: AUTHORIZED rc=0

# A4. Confirm non-root AWS identity
AWS_PROFILE=frostgate-terraform aws sts get-caller-identity
# Expected: ARN must NOT contain :root

# A5. Confirm account summary (run as operator profile — GetAccountSummary is in operator policy)
AWS_PROFILE=frostgate-terraform AWS_DEFAULT_REGION=us-east-1 aws iam get-account-summary \
  | python3 -c "import sys,json; s=json.load(sys.stdin)['SummaryMap']; print('MFA:', s.get('AccountMFAEnabled')); print('RootKeys:', s.get('AccountAccessKeysPresent'))"
# Expected: MFA: 1, RootKeys: 0

# A6. Confirm audit IAM user exists with no static access keys
# (user was created by Phase-1 partial apply 2026-10-02 and is retained in Terraform state)
AWS_PROFILE=frostgate-terraform AWS_DEFAULT_REGION=us-east-1 aws iam get-user --user-name frostgate-hcp-vault-audit 2>&1
# Expected: user exists, Path=/frostgate/vault/, UserName=frostgate-hcp-vault-audit
AWS_PROFILE=frostgate-terraform AWS_DEFAULT_REGION=us-east-1 aws iam list-access-keys --user-name frostgate-hcp-vault-audit 2>&1
# Expected: AccessKeyMetadata=[] (zero static keys; ceremony will create one transiently at CHECKPOINT Q)
```

**Expected result:** All checks pass, non-root identity confirmed.

**Evidence:** fg-core SHA, AUTHORIZED roadmap rc=0, operator ARN, MFA:1.

**Secret boundary:** None.

**Stop condition:** Any SHA mismatch, root identity, MFA:0, or roadmap NOT AUTHORIZED.

---

## CHECKPOINT B — Operator Identity Verification

**Prerequisites:** Checkpoint A complete.

**Actions:**

```bash
# B1. Confirm Terraform will use non-root identity
cd ~/Projects/fg-core/infra
AWS_PROFILE=frostgate-terraform terraform version
AWS_PROFILE=frostgate-terraform aws sts get-caller-identity

# B2. Confirm HCP Terraform authentication
terraform login
# (browser auth — does not expose credentials to terminal)
# Expected: "Success! Logged in to HCP Terraform"
```

**Expected result:** `sts:GetCallerIdentity` returns non-root ARN. Terraform authenticated.

**Evidence:** Non-root operator ARN (non-secret).

**Secret boundary:** Terraform login uses browser auth. No token is observed by Claude.

**Stop condition:** Root identity detected; missing HCP Terraform authentication.

---

## PRE-PLAN ENVIRONMENT — Required Terraform Variable Exports

**Prerequisites:** Checkpoint B complete.

These exports are required before any `terraform plan` or `terraform apply`.
Set them once in the terminal; they persist for the session.

```bash
# REQUIRED — operator IAM user ARN for FrostGateVaultAuditReader trust policy.
# Must be an IAM user ARN (arn:aws:iam::<account>:user/<name>) — NOT a role/assumed-role ARN.
# Checkpoint A4 (frostgate-terraform) returns an assumed-role ARN and is WRONG for this variable.
# Retrieve the human user ARN using the frostgate-human profile:
#   AWS_PROFILE=frostgate-human AWS_DEFAULT_REGION=us-east-1 aws sts get-caller-identity --query Arn --output text
# operator_iam_user_arn has no default; Terraform validation fails without this.
export TF_VAR_operator_iam_user_arn="arn:aws:iam::398915901105:user/<your-iam-username>"

# CONDITIONAL — Vault cluster address.
# Fresh ceremony (Checkpoint C): cluster does not exist yet; omit this export.
#   Vault provider will fail with connection refused for Vault resources — expected
#   for a first-run architecture-review plan. AWS resources plan cleanly.
# Post-Phase-1 (Checkpoint G, before Phase 2): set from the Phase 1 output:
#   export TF_VAR_vault_address="$(cd ~/Projects/fg-core/infra && terraform output -raw vault_address)"
# State reconciliation (post-merge plan): set from live output before planning.
```

**Stop condition:** Proceeding to Checkpoint C without `TF_VAR_operator_iam_user_arn` set will
cause Terraform validation to fail with: `operator_iam_user_arn must be a valid IAM user ARN`.

---

## CHECKPOINT C — Fresh Terraform Plan

**Prerequisites:** Checkpoint B complete. Ceremony ID matches `customer-zero-trust-2026-10-02-001`.

**Actions:**

```bash
cd ~/Projects/fg-core/infra
# Remove stale plan files (never apply a plan from a previous run)
rm -f ceremony-plan-phase1.tfplan ceremony-plan-phase2.tfplan

AWS_PROFILE=frostgate-terraform terraform plan \
  -out=ceremony-plan-phase1.tfplan 2>&1 | tee /tmp/ceremony-plan-output.txt

# Review plan summary
tail -5 /tmp/ceremony-plan-output.txt
```

**Expected result:**
- Plan: 19 to add, 0 to change, 0 to destroy (`aws_iam_user.vault_audit` already in state)
- Breakdown: 8 Phase-1 resources (2 HCP + 6 AWS) + 11 Phase-2 Vault resources = 19 total
- Phase-1 AWS resources (6): aws_cloudwatch_log_group.vault_audit, aws_iam_policy.vault_audit, aws_iam_user_policy_attachment.vault_audit, aws_iam_role.vault_audit_reader, aws_iam_policy.vault_audit_reader, aws_iam_role_policy_attachment.vault_audit_reader
- **Prior-apply context:** The 2026-10-02 partial apply created the HCP HVN and Vault cluster before failing on `aws_cloudwatch_log_group.vault_audit`. Those HCP resources were subsequently destroyed to contain costs; only `aws_iam_user.vault_audit` was retained in Terraform state. The fresh ceremony recreates the 2 HCP resources as additions (hence 19, not 17, to add).
- All 19 resources match the intended architecture
- No replacements, no destroys, no sensitive outputs
- Ceremony ID `customer-zero-trust-2026-10-02-001` appears in tags
- **Note:** The Phase-1 targeted apply plan generated at Checkpoint F will show **8 to add** — this is expected and correct. Checkpoint C plans all 19 resources for architecture review; Checkpoint F plans only the 8 Phase-1 targets for the first apply.

**Evidence:** Plan summary line (non-secret). Resource count and categories.

**Secret boundary:** Plan file may contain provider responses. Do not `cat` the binary plan.
Inspect via `terraform show ceremony-plan-phase1.tfplan` (text output is safe).

**Stop condition:** Unexpected destroys, replacements, or resources outside intended scope.

---

## CHECKPOINT D — Human Cost Authorization

**Prerequisites:** Checkpoint C complete. Live account-applicable pricing confirmed.

**HARD STOP — Human operator must explicitly authorize cost before proceeding.**

Required information before authorization:
1. HCP Standard Small / us-east-1 hourly rate (from HCP portal, not public estimate)
2. Per-client monthly rate and proration terms
3. Available HCP credits (balance, expiration, eligibility)
4. Maximum 8-hour ceremony exposure calculated

**Authorization record to capture (non-secret):**

```
COST AUTHORIZATION
Date: 2026-10-01
Ceremony: customer-zero-trust-2026-10-02-001
Operator: <operator name and ref>
HCP hourly rate: <confirmed from HCP portal>
Client rate: <confirmed>
Proration: <confirmed>
Credits available: <confirmed>
Maximum 8h exposure: <calculated>
Authorization: APPROVED
```

**Expected result:** Explicit written cost authorization from operator.

**Stop condition:** Cost not proven; operator does not approve; exposure exceeds acceptable limit.

---

## CHECKPOINT E — Explicit Authorization to Apply

**Prerequisites:** Checkpoint D complete with written cost authorization.

**HARD STOP — Second explicit confirmation.**

The operator must state explicitly before proceeding:

> "I authorize `terraform apply` with ceremony ID `customer-zero-trust-2026-10-02-001`
> against AWS account `398915901105` at the verified cost of approximately $[amount]."

**Stop condition:** Operator does not provide explicit verbal or written authorization.

---

## CHECKPOINT F — Terraform Provisioning (Two Phases)

**Prerequisites:** Checkpoint E explicit authorization received.

**Why two phases:** The Vault provider (`providers.tf`) requires `vault_address`, which is
only known after the HCP cluster is created. A single apply would attempt to configure
Vault resources against an unreachable endpoint. Phase 1 provisions HCP + AWS; Phase 2
provisions Vault resources once the address is available.

### Phase 1 — HCP cluster + AWS resources

```bash
cd ~/Projects/fg-core/infra
export AWS_PROFILE=frostgate-terraform

terraform plan \
  -target=hcp_hvn.frostgate \
  -target=hcp_vault_cluster.customer_zero \
  -target=aws_cloudwatch_log_group.vault_audit \
  -target=aws_iam_user.vault_audit \
  -target=aws_iam_policy.vault_audit \
  -target=aws_iam_user_policy_attachment.vault_audit \
  -target=aws_iam_role.vault_audit_reader \
  -target=aws_iam_policy.vault_audit_reader \
  -target=aws_iam_role_policy_attachment.vault_audit_reader \
  -out=ceremony-plan-phase1.tfplan \
  2>&1 | tee /tmp/ceremony-plan-phase1-output.txt
```

**STOP — Review Phase 1 plan before applying:**

```bash
terraform show ceremony-plan-phase1.tfplan 2>&1 | grep -E '^\s*(#|[~+]|Plan:|resource )' | head -80
echo "Phase 1 summary: $(tail -1 /tmp/ceremony-plan-phase1-output.txt)"
```

Expected: 8 resources to add (2 HCP + 6 AWS), 0 changes, 0 destroys. `aws_iam_user.vault_audit`
is already in state from the 2026-10-02 partial apply and will show 0 changes. No unexpected
resources. Confirm the output, then proceed to apply.

```bash
terraform apply ceremony-plan-phase1.tfplan
```

**Expected result:** 8 resources created (2 HCP + 6 AWS). No errors. (`aws_iam_user.vault_audit` was already present — 0 changes.)

**Collect vault_address immediately after Phase 1:**

```bash
terraform output vault_address
# Record this value — required for Phase 2 and Checkpoint G.
```

---

**HARD STOP — Complete Checkpoint G before Phase 2.**

Phase 2 provisions Vault resources and requires both:
- `VAULT_ADDR` exported from the Phase 1 `vault_address` output above
- `VAULT_TOKEN` generated in the HCP portal (see Checkpoint G)
- Vault cluster responding to `vault status`

Complete Checkpoint G now, then return here for Phase 2.

---

### Phase 2 — Vault resources

```bash
# Both exports must already be set from Checkpoint G before running this block
# export TF_VAR_vault_address="<vault_address from Phase 1>"   ← set in Checkpoint G
# export VAULT_TOKEN=<admin token>                             ← set in Checkpoint G

terraform plan \
  -out=ceremony-plan-phase2.tfplan \
  2>&1 | tee /tmp/ceremony-plan-phase2-output.txt
```

**STOP — Review Phase 2 plan before applying:**

```bash
terraform show ceremony-plan-phase2.tfplan 2>&1 | grep -E '^\s*(#|[~+]|Plan:|resource )' | head -80
echo "Phase 2 summary: $(tail -1 /tmp/ceremony-plan-phase2-output.txt)"
```

Expected: 11 resources to add (Transit engine, 3 keys, 3 policies, AppRole auth backend,
3 AppRoles), 0 changes, 0 destroys. Confirm the output, then proceed to apply.

```bash
terraform apply ceremony-plan-phase2.tfplan
```

**Expected result:** Remaining 11 resources created (Transit engine, keys, policies, AppRoles).
Total across both phases: 16 to add, 0 to change, 0 to destroy.

**Collect all non-secret outputs after Phase 2:**

```bash
terraform output -json | \
  python3 -c "import sys,json; o=json.load(sys.stdin); [print(f'{k}: {v[\"value\"]}') for k,v in o.items()]"
```

**Critical outputs to record in evidence manifest:**
- `vault_address` (non-secret HTTPS endpoint — from Phase 1)
- `vault_cluster_id`, `vault_cluster_tier`
- `transit_key_identity`, `transit_key_acceptance`, `transit_key_approval`
- `approle_role_id_identity`, `approle_role_id_acceptance`, `approle_role_id_approval`
- `policy_name_identity`, `policy_name_acceptance`, `policy_name_approval`
- `cloudwatch_log_group_name`, `cloudwatch_log_group_arn`
- `iam_audit_user_arn`

**Evidence:** All outputs (non-secret). Both plan files (gitignored; record SHA of applied commit).

**Secret boundary:** No secret outputs exist. If Terraform produces unexpected sensitive output, stop.

**Stop condition:** Any resource creation failure; unexpected sensitive output; vault_address empty after Phase 1.

---

## CHECKPOINT G — Vault Bootstrap / Operator Authentication

**Prerequisites:** Checkpoint F Phase 1 complete. `vault_address` output collected. Vault cluster endpoint available. (Phase 2 of Checkpoint F runs after this checkpoint.)

**Actions:**

```bash
export VAULT_ADDR=<vault_address from Checkpoint F output>
export VAULT_NAMESPACE=admin

# G1. Confirm cluster reachable
vault status 2>&1 | grep -E "Sealed|HA|Version|Cluster"
```

**HUMAN SECRET BOUNDARY — Vault admin token required for bootstrap.**

> **Operator action:** In the HCP portal → Vault cluster → Generate admin token.
> Set it via: `export VAULT_TOKEN=<token>` in the terminal.
> Do not share with Claude. Do not paste into chat.

```bash
# G2. Confirm authenticated (non-secret — shows token accessor, not token)
vault token lookup -format=json | python3 -c "import sys,json; d=json.load(sys.stdin)['data']; print('Policies:', d.get('policies',[])); print('Accessor:', d.get('accessor',''))"
# Expected: policies include 'root' or admin equivalent
```

**Evidence:** Vault version, cluster reachable (non-secret). Token accessor only.

**Secret boundary:** Admin token must not be observed by Claude. Operator sets it directly in terminal.

**Stop condition:** Cluster unreachable; authentication fails; unexpected policy set.

---

## CHECKPOINT H — Three Transit Authorities Verification

**Prerequisites:** Checkpoint G complete. Vault authenticated.

**Actions:**

```bash
# H1. Verify Transit mount exists
vault secrets list -format=json | python3 -c "import sys,json; mounts=json.load(sys.stdin); print('transit/' in mounts)"
# Expected: True

# H2. Verify each Transit key
for key in customer-zero-identity customer-zero-acceptance customer-zero-approval; do
  vault read -format=json transit/keys/$key | python3 -c "
import sys, json
d = json.load(sys.stdin)['data']
print(f'Key: $key')
print(f'  type: {d.get(\"type\")}')
print(f'  exportable: {d.get(\"exportable\")}')
print(f'  deletion_allowed: {d.get(\"deletion_allowed\")}')
print(f'  min_encryption_version: {d.get(\"min_encryption_version\")}')
print(f'  latest_version: {d.get(\"latest_version\")}')
# Collect public key for evidence manifest
keys = d.get('keys', {})
latest = str(d.get('latest_version', 1))
pub = keys.get(latest, {}).get('public_key', '')
print(f'  public_key (v{latest}): {pub}' if pub else '  public_key: MISSING')
  "
done
```

**Expected per key:**
- `type: ed25519`
- `exportable: false`
- `deletion_allowed: false`
- `min_encryption_version: 1`
- `latest_version: 1`
- `public_key`: non-empty Base64 string

**Collect for evidence manifest (non-secret):** key name, type, exportable, deletion_allowed, key version, public_key, public_key_fingerprint.

**Evidence:** Full key metadata. Public keys captured for `artifacts/trust/customer_zero_trust_evidence.json`.

**Secret boundary:** Ed25519 public keys are non-secret. No private key material ever leaves Vault.

**Stop condition:** Any key `type != ed25519`, `exportable != false`, `deletion_allowed != false`.

---

## CHECKPOINT I — Three AppRole Runtime Authorities

**Prerequisites:** Checkpoint H complete.

**Actions:**

```bash
# I1. Verify AppRole auth backend
vault auth list -format=json | python3 -c "import sys,json; mounts=json.load(sys.stdin); print('approle/' in mounts)"
# Expected: True

# I2. Verify each AppRole role (non-secret metadata)
for role in frostgate-cz-identity frostgate-cz-acceptance frostgate-cz-approval; do
  vault read -format=json auth/approle/role/$role | python3 -c "
import sys, json
d = json.load(sys.stdin)['data']
print(f'Role: $role')
print(f'  token_policies: {d.get(\"token_policies\")}')
print(f'  token_ttl: {d.get(\"token_ttl\")}')
print(f'  token_max_ttl: {d.get(\"token_max_ttl\")}')
print(f'  token_no_default_policy: {d.get(\"token_no_default_policy\")}')
print(f'  token_type: {d.get(\"token_type\")}')
print(f'  bind_secret_id: {d.get(\"bind_secret_id\")}')
  "
  # Retrieve role ID (non-secret identifier)
  vault read -format=json auth/approle/role/$role/role-id | python3 -c "
import sys, json; d=json.load(sys.stdin)['data']; print(f'  role_id: {d.get(\"role_id\",\"\")[:8]}...')
  "
done
```

**Expected per role:**
- `token_policies`: exactly one policy (matching role name)
- `token_ttl`: 3600
- `token_max_ttl`: 7200
- `token_no_default_policy`: true
- `bind_secret_id`: true
- `role_id`: non-empty (record prefix only above; full value is safe to record)

**Collect for evidence manifest (non-secret):** full `role_id` for each AppRole.

**Evidence:** Role metadata and role IDs (non-secret).

**Secret boundary:** Role IDs are non-secret identifiers. SecretIDs are NOT generated here.

**Stop condition:** Wrong policy binding; `bind_secret_id: false`; `token_no_default_policy: false`.

---

## CHECKPOINT J — Public Trust-Anchor Enrollment

**Prerequisites:** Checkpoint H complete. Public keys retrieved.

**Actions:**

Assemble `artifacts/trust/customer_zero_trust_evidence.json` with:

- `schema_version: "1.0"`
- `work_item: "CUSTOMER-ZERO-TRUST-001"`
- `ceremony_id: "customer-zero-trust-2026-10-02-001"`
- `environment: "hcp-vault-dedicated"`
- `generated_at`: current UTC timestamp
- `operator_identity`: `{name, ref, verification_method}` (operator fills in)
- `source_sha`: fg-core main SHA at ceremony time
- `tested_sha`: same as source_sha
- `vault_deployment`: `{identity: vault_cluster_id, region: "us-east-1"}`
- `trust_roles`: three role records with public keys from Checkpoint H

```bash
# Validate the assembled manifest
cd ~/Projects/fg-core
python tools/customer_zero_trust_evidence.py validate artifacts/trust/customer_zero_trust_evidence.json
python tools/customer_zero_trust_evidence.py verify-anchors artifacts/trust/customer_zero_trust_evidence.json
```

**Expected:** `validate` returns PASS on all non-ceremony dimensions. `verify-anchors` PASS.

**Evidence:** Validated manifest. Fingerprint hash (non-secret).

**Secret boundary:** No secret fields may appear in the manifest. `validate_manifest()` rejects
any manifest containing `token`, `secret_id`, `private_key`, or related field names.

**Stop condition:** `validate` returns FAIL. Public key fingerprint mismatch.

---

## CHECKPOINT K — Human-Only SecretID Creation and Railway Transfer

**Prerequisites:** Checkpoint I complete. AppRole roles verified. Railway API service accessible.

**HUMAN SECRET BOUNDARY — This checkpoint must be executed entirely by the operator.**
**Claude must not observe, receive, echo, or store any SecretID.**

**Operator actions (terminal only — no chat, no logs):**

```bash
# Generate SecretID for each role
vault write -force auth/approle/role/frostgate-cz-identity/secret-id
vault write -force auth/approle/role/frostgate-cz-acceptance/secret-id
vault write -force auth/approle/role/frostgate-cz-approval/secret-id
```

Each command returns `secret_id`. Immediately:
1. Copy the value from the terminal
2. Open Railway dashboard → `api` service → Variables
3. Set `FG_CUSTOMER_ZERO_IDENTITY_VAULT_SECRET_ID` directly (paste, confirm)
4. Set `FG_CUSTOMER_ZERO_ACCEPTANCE_VAULT_SECRET_ID` directly
5. Set `FG_CUSTOMER_ZERO_APPROVAL_VAULT_SECRET_ID` directly
6. Close the SecretID values from terminal (clear terminal history if needed)

**Do not:** copy to clipboard for extended periods, log to file, paste into chat, share with Claude.

**Non-secret confirmation:** "SecretIDs set in Railway Variables tab for all three roles."

**Stop condition:** Railway Variables tab inaccessible; SecretID generation fails.

---

## CHECKPOINT L — Railway Runtime Configuration

**Prerequisites:** Checkpoint K complete. All 13 production env vars set in Railway.

**Actions:**

Configure the remaining 10 non-secret Railway Variables from Terraform outputs (Checkpoint F):

| Variable | Value source |
|---|---|
| `FG_CUSTOMER_ZERO_VAULT_AUTH_MODE` | `approle` (static) |
| `FG_CUSTOMER_ZERO_VAULT_ADDR` | Terraform output `vault_address` |
| `FG_CUSTOMER_ZERO_VAULT_NAMESPACE` | `admin` (static) |
| `FG_CUSTOMER_ZERO_VAULT_ISSUER` | `vault-transit` (or custom label) |
| `FG_CUSTOMER_ZERO_IDENTITY_KEY_ID` | Terraform output `transit_key_identity` |
| `FG_CUSTOMER_ZERO_ACCEPTANCE_KEY_ID` | Terraform output `transit_key_acceptance` |
| `FG_CUSTOMER_ZERO_APPROVAL_KEY_ID` | Terraform output `transit_key_approval` |
| `FG_CUSTOMER_ZERO_IDENTITY_VAULT_ROLE_ID` | Terraform output `approle_role_id_identity` |
| `FG_CUSTOMER_ZERO_ACCEPTANCE_VAULT_ROLE_ID` | Terraform output `approle_role_id_acceptance` |
| `FG_CUSTOMER_ZERO_APPROVAL_VAULT_ROLE_ID` | Terraform output `approle_role_id_approval` |

After all 13 variables are set: **trigger a Railway redeploy** of the `api` service.

**Expected result:** Railway deployment succeeds. API service healthy.

**Evidence:** Railway deployment SHA (non-secret). Service health endpoint responds.

**Stop condition:** Deployment fails; health endpoint unresponsive.

---

## CHECKPOINT M — Positive Signing Tests

**Prerequisites:** Checkpoint G complete (admin VAULT_TOKEN set). Checkpoint L complete
(Railway SecretIDs generated). VAULT_ADDR and VAULT_NAMESPACE=admin set.
All three Transit keys exist (confirmed at Checkpoint H).

**Actions — each probe authenticates via its runtime AppRole path, not the admin token:**

```bash
# Requires: VAULT_ADDR, VAULT_NAMESPACE=admin, VAULT_TOKEN (admin) from Checkpoint G

# M1. Identity key — authenticate as frostgate-cz-identity AppRole, sign, confirm kv=1
IDENTITY_ROLE_ID=$(vault read -format=json auth/approle/role/frostgate-cz-identity/role-id \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['role_id'])")
# Admin generates one-time SecretID — do NOT echo or record this value
IDENTITY_SID=$(vault write -format=json -f auth/approle/role/frostgate-cz-identity/secret-id \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['secret_id'])")
IDENTITY_TOKEN=$(vault write -format=json auth/approle/login \
  role_id="${IDENTITY_ROLE_ID}" secret_id="${IDENTITY_SID}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
unset IDENTITY_SID

IDENTITY_PAYLOAD=$(echo -n "ceremony-probe-identity-$(date +%s)" | base64 -w0)
VAULT_TOKEN="${IDENTITY_TOKEN}" vault write -format=json transit/sign/customer-zero-identity \
  input="${IDENTITY_PAYLOAD}" \
  | python3 -c "
import sys, json
r = json.load(sys.stdin)
sig = r['data']['signature']
kv  = r['data']['key_version']
assert kv == 1, f'expected key_version=1, got {kv}'
assert sig.startswith('vault:v1:'), f'unexpected sig format: {sig[:20]}'
print(f'identity  key_version={kv}  sig={sig[:30]}...')
"
echo "identity_sign_rc=$?"
unset IDENTITY_TOKEN

# M2. Acceptance key — authenticate as frostgate-cz-acceptance AppRole
ACCEPTANCE_ROLE_ID=$(vault read -format=json auth/approle/role/frostgate-cz-acceptance/role-id \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['role_id'])")
ACCEPTANCE_SID=$(vault write -format=json -f auth/approle/role/frostgate-cz-acceptance/secret-id \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['secret_id'])")
ACCEPTANCE_TOKEN=$(vault write -format=json auth/approle/login \
  role_id="${ACCEPTANCE_ROLE_ID}" secret_id="${ACCEPTANCE_SID}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
unset ACCEPTANCE_SID

ACCEPTANCE_PAYLOAD=$(echo -n "ceremony-probe-acceptance-$(date +%s)" | base64 -w0)
VAULT_TOKEN="${ACCEPTANCE_TOKEN}" vault write -format=json transit/sign/customer-zero-acceptance \
  input="${ACCEPTANCE_PAYLOAD}" \
  | python3 -c "
import sys, json
r = json.load(sys.stdin)
sig = r['data']['signature']
kv  = r['data']['key_version']
assert kv == 1, f'expected key_version=1, got {kv}'
assert sig.startswith('vault:v1:'), f'unexpected sig format: {sig[:20]}'
print(f'acceptance  key_version={kv}  sig={sig[:30]}...')
"
echo "acceptance_sign_rc=$?"
unset ACCEPTANCE_TOKEN

# M3. Approval key — authenticate as frostgate-cz-approval AppRole
APPROVAL_ROLE_ID=$(vault read -format=json auth/approle/role/frostgate-cz-approval/role-id \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['role_id'])")
APPROVAL_SID=$(vault write -format=json -f auth/approle/role/frostgate-cz-approval/secret-id \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['secret_id'])")
APPROVAL_TOKEN=$(vault write -format=json auth/approle/login \
  role_id="${APPROVAL_ROLE_ID}" secret_id="${APPROVAL_SID}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
unset APPROVAL_SID

APPROVAL_PAYLOAD=$(echo -n "ceremony-probe-approval-$(date +%s)" | base64 -w0)
VAULT_TOKEN="${APPROVAL_TOKEN}" vault write -format=json transit/sign/customer-zero-approval \
  input="${APPROVAL_PAYLOAD}" \
  | python3 -c "
import sys, json
r = json.load(sys.stdin)
sig = r['data']['signature']
kv  = r['data']['key_version']
assert kv == 1, f'expected key_version=1, got {kv}'
assert sig.startswith('vault:v1:'), f'unexpected sig format: {sig[:20]}'
print(f'approval  key_version={kv}  sig={sig[:30]}...')
"
echo "approval_sign_rc=$?"
unset APPROVAL_TOKEN
```

All three `*_sign_rc` values must be 0.

**Expected result:** Three `vault:v1:` signatures produced via runtime AppRole paths.
`key_version=1` for all three. Each AppRole can sign only its own key (enforced by policy).

**Evidence:** Sign command output (non-secret — key_version and signature prefix only).
Record `key_version`, `signature` prefix, and rc for each role in the evidence manifest.

**Secret boundary:** Admin VAULT_TOKEN used only for SecretID generation. Runtime tokens
and SecretIDs are unset immediately after use. No secret values appear in evidence output.

**Stop condition:** Any sign rc != 0; `key_version != 1`; signature format not `vault:v1:`.

---

## CHECKPOINT N — Cross-Role Negative Tests

**Prerequisites:** Checkpoint M complete.

**Actions:**

Verify that each AppRole principal CANNOT sign using another role's Transit key:

```bash
cd ~/Projects/fg-core
python -m pytest tests/test_customer_zero_vault_auth.py -v -k "cross_role or role_separation" 2>&1 | tail -20
```

If no dedicated cross-role tests exist, confirm the policy structure prevents it:
- `frostgate-cz-identity` policy grants ONLY `transit/sign/customer-zero-identity`
- `frostgate-cz-acceptance` policy grants ONLY `transit/sign/customer-zero-acceptance`
- `frostgate-cz-approval` policy grants ONLY `transit/sign/customer-zero-approval`

**Expected result:** Cross-role signing attempts return 403/permission error.

**Evidence:** Test PASS or policy audit confirming structural prevention.

**Stop condition:** Cross-role signing succeeds; policy audit fails.

---

## CHECKPOINT O — Ephemeral / Raw / Test Authority Rejection

**Prerequisites:** Checkpoint N complete.

**Actions:**

```bash
cd ~/Projects/fg-core
# Confirm static-token path is blocked in production mode
python -m pytest tests/test_customer_zero_vault_auth.py -v -k "static_token or test_auth or raw" 2>&1 | tail -20

# Confirm FG_CUSTOMER_ZERO_VAULT_AUTH_MODE != approle raises correctly
python -c "
import os
os.environ['FG_CUSTOMER_ZERO_VAULT_AUTH_MODE'] = 'static_token'
os.environ['FG_CUSTOMER_ZERO_ENVIRONMENT'] = 'production'
from services.cgin.key_management.vault_transit import VaultTransitClient
try:
    VaultTransitClient.from_environment()
    print('FAIL: should have raised')
except ValueError as e:
    print(f'PASS: raised ValueError: {e}')
"
```

**Expected result:** Static-token path raises ValueError in production environment.

**Evidence:** Test PASS / ValueError raised.

**Stop condition:** Static-token path succeeds in production mode.

---

## CHECKPOINT P — Rotation / History Verification

**Prerequisites:** Checkpoint O complete.

**Actions:**

```bash
# P0. Capture v1 signature BEFORE rotation (evidence anchor — must run before P1)
PROBE_PAYLOAD=$(printf 'ceremony-rotation-probe-%s' "$(date +%s)" | base64 -w0)
PROBE_SIG=$(vault write -format=json transit/sign/customer-zero-identity \
  input="${PROBE_PAYLOAD}" \
  | python3 -c "
import sys, json
r = json.load(sys.stdin)
sig = r['data']['signature']
kv  = r['data']['key_version']
assert kv == 1, f'expected key_version=1 before rotation, got {kv}'
assert sig.startswith('vault:v1:'), f'unexpected sig format: {sig[:20]}'
print(sig)
")
echo "pre_rotation_payload=${PROBE_PAYLOAD}"
echo "pre_rotation_sig=${PROBE_SIG}"
# Record both values in the evidence manifest; they are required for P3.

# Guard: abort before the irreversible rotation if v1 capture failed.
# A failed pipeline leaves PROBE_SIG empty; rotation after that makes P3 impossible.
if [[ -z "${PROBE_SIG}" ]]; then
  echo "[ABORT] PROBE_SIG is empty — P0 signature capture failed." >&2
  echo "[ABORT] Do NOT rotate. Diagnose P0 before retrying." >&2
  exit 1
fi
echo "P0 capture verified non-empty — proceeding to rotation"

# P1. Rotate the identity key
vault write -force transit/keys/customer-zero-identity/rotate

# P2. Verify new key version and retained key history
vault read -format=json transit/keys/customer-zero-identity | python3 -c "
import sys, json
d = json.load(sys.stdin)['data']
latest = d.get('latest_version')
keys   = d.get('keys', {})
assert latest == 2, f'expected latest_version=2, got {latest}'
assert '1' in keys and '2' in keys, f'expected both v1 and v2 in keys map, got: {list(keys)}'
print('latest_version:', latest)
for v, info in sorted(keys.items(), key=lambda x: int(x[0])):
    pub = info.get('public_key', '')
    print(f'  v{v}: {pub[:40]}...')
"
echo "key_version_check_rc=$?"
# Expected: latest_version: 2, both v1 and v2 public keys present

# P3. Verify pre-rotation (v1) signature is still valid after rotation
#     Uses transit/verify which accepts an explicit key_version in the signature tag.
vault write -format=json transit/verify/customer-zero-identity \
  input="${PROBE_PAYLOAD}" \
  signature="${PROBE_SIG}" \
  | python3 -c "
import sys, json
r = json.load(sys.stdin)
valid = r['data']['valid']
assert valid is True, f'pre-rotation signature FAILED verification: valid={valid}'
print(f'historical_verify valid={valid}  (vault:v1: sig verifies against retained v1 public key)')
"
echo "historical_verify_rc=$?"

# P4. Confirm post-rotation signing uses v2
vault write -format=json transit/sign/customer-zero-identity \
  input="${PROBE_PAYLOAD}" \
  | python3 -c "
import sys, json
r = json.load(sys.stdin)
sig = r['data']['signature']
kv  = r['data']['key_version']
assert kv == 2, f'expected key_version=2 after rotation, got {kv}'
assert sig.startswith('vault:v2:'), f'unexpected format: {sig[:20]}'
print(f'post_rotation key_version={kv}  sig={sig[:30]}...')
"
echo "post_rotation_sign_rc=$?"
```

**Expected result:** Key version increments to 2. Pre-rotation (v1) signature passes
`transit/verify`. Post-rotation signing produces `vault:v2:` signatures. Both key
versions present in the key metadata map.

**Evidence:** `key_version_check_rc=0`, `historical_verify_rc=0`,
`post_rotation_sign_rc=0`. Pre-rotation payload + signature recorded in evidence
manifest (non-secret).

**Stop condition:** `historical_verify_rc` non-zero; `valid=false` from `transit/verify`;
latest_version not 2; v1 public key absent from key metadata.

---

## CHECKPOINT Q — Audit Authority Verification (16-Step Sequence)

**Prerequisites:** Checkpoint F Phase 1 complete. HCP cluster running (Checkpoint G). All
three Transit keys verified (Checkpoint H). Signing tests PASS (Checkpoint M).

**Destination model:** The CloudWatch log group is OPERATOR-CONFIGURED, not HCP-assigned.
The intended destination (`var.cloudwatch_log_group_name`, default `/frostgate/customer-zero/vault-audit`)
is pre-created by Terraform at Phase 1. When the operator enables HCP audit streaming
(Q-6 below), the operator explicitly enters this log group name in the HCP UI. HCP does
not pick a destination automatically — the operator chooses it and verifies it matches.

This checkpoint follows the 16-step authority sequence:

---

### Q-1. Confirm audit infrastructure is provisioned

```bash
cd ~/Projects/fg-core
AWS_PROFILE=frostgate-terraform AWS_DEFAULT_REGION=us-east-1 \
  aws logs describe-log-groups \
  --log-group-name-prefix "/frostgate/customer-zero" \
  | python3 -c "
import sys, json
groups = json.load(sys.stdin).get('logGroups', [])
for g in groups:
    print('logGroupName:', g['logGroupName'])
    print('retentionInDays:', g.get('retentionInDays', 'none'))
    print('arn:', g.get('arn', ''))
"
# Expected: exactly one group at /frostgate/customer-zero/vault-audit with retentionInDays=365
```

Also confirm the writer user exists with no static access keys:
```bash
AWS_PROFILE=frostgate-terraform AWS_DEFAULT_REGION=us-east-1 \
  aws iam get-user --user-name frostgate-hcp-vault-audit 2>&1 | grep -E "UserName|Path"
# Expected: UserName=frostgate-hcp-vault-audit, Path=/frostgate/vault/

AWS_PROFILE=frostgate-terraform AWS_DEFAULT_REGION=us-east-1 \
  aws iam list-access-keys --user-name frostgate-hcp-vault-audit \
  | python3 -c "import sys,json; keys=json.load(sys.stdin)['AccessKeyMetadata']; print('access_key_count:', len(keys))"
# Expected: access_key_count: 0 (ceremony will create one at Q-5)
```

Confirm the reader role exists:
```bash
AWS_PROFILE=frostgate-terraform AWS_DEFAULT_REGION=us-east-1 \
  aws iam get-role --role-name FrostGateVaultAuditReader \
  | python3 -c "import sys,json; r=json.load(sys.stdin)['Role']; print('RoleName:', r['RoleName']); print('Path:', r['Path'])"
# Expected: RoleName=FrostGateVaultAuditReader, Path=/frostgate/vault/
```

**Evidence:** Log group ARN, writer user (zero keys), reader role ARN (all non-secret).

---

### Q-2. Determine actual HCP CloudWatch destination

The actual destination is operator-configured at Q-6 (below). Before configuring,
confirm the intended destination from Terraform outputs:

```bash
cd ~/Projects/fg-core/infra
AWS_PROFILE=frostgate-terraform terraform output cloudwatch_log_group_name
# Expected: /frostgate/customer-zero/vault-audit
# RECORD THIS VALUE. You will enter it verbatim in the HCP portal at Q-6.
```

The operator must ensure the HCP-configured log group name EXACTLY matches this output.
If HCP assigns a different name or adds a prefix, that is the ACTUAL destination and
must be recorded in the evidence manifest.

---

### Q-3. Confirm dedicated writer identity

Writer identity is `frostgate-hcp-vault-audit` (verified at Q-1). This identity:
- Has exactly one attached policy (`frostgate-hcp-vault-audit-policy`)
- Has zero inline policies
- Has zero access keys (until Q-5)

```bash
AWS_PROFILE=frostgate-terraform AWS_DEFAULT_REGION=us-east-1 \
  aws iam list-attached-user-policies --user-name frostgate-hcp-vault-audit \
  | python3 -c "import sys,json; ps=json.load(sys.stdin)['AttachedPolicies']; [print(p['PolicyName']) for p in ps]"
# Expected: frostgate-hcp-vault-audit-policy

AWS_PROFILE=frostgate-terraform AWS_DEFAULT_REGION=us-east-1 \
  aws iam list-user-policies --user-name frostgate-hcp-vault-audit \
  | python3 -c "import sys,json; ps=json.load(sys.stdin)['PolicyNames']; print('inline_count:', len(ps))"
# Expected: inline_count: 0
```

---

### Q-4. Confirm dedicated reader identity

```bash
AWS_PROFILE=frostgate-terraform AWS_DEFAULT_REGION=us-east-1 \
  aws iam list-attached-role-policies --role-name FrostGateVaultAuditReader \
  | python3 -c "import sys,json; ps=json.load(sys.stdin)['AttachedPolicies']; [print(p['PolicyName']) for p in ps]"
# Expected: FrostGateVaultAuditReaderPolicy

# Confirm reader trust policy requires MFA
AWS_PROFILE=frostgate-terraform AWS_DEFAULT_REGION=us-east-1 \
  aws iam get-role --role-name FrostGateVaultAuditReader \
  | python3 -c "
import sys, json
role = json.load(sys.stdin)['Role']
import urllib.parse
doc = json.loads(urllib.parse.unquote(role['AssumeRolePolicyDocument']))
for stmt in doc['Statement']:
    print('Condition:', json.dumps(stmt.get('Condition', {})))
"
# Expected: Condition includes aws:MultiFactorAuthPresent = true
```

---

### Q-5. HUMAN-ONLY: Create persistent writer credential

**HARD STOP — HUMAN SECRET BOUNDARY. AWS access key must NOT be observed by Claude.**

This credential is persistent (not rotated each ceremony) while audit streaming is enabled.
It must be revoked and recreated when audit streaming is disabled or when rotation is required.

> **Operator action (terminal only — no chat, no logs):**
>
> 1. In AWS Console → IAM → Users → `frostgate-hcp-vault-audit` → Security credentials
> 2. Create access key (select "Application running outside AWS" → create)
> 3. Copy the **Access key ID** and **Secret access key** immediately (only shown once)
> 4. Do NOT paste these values into chat or terminal output visible to Claude
> 5. Proceed directly to Q-6

**Non-secret confirmation:** "Writer access key created. access_key_id prefix: AKIA..."
(share only the AKIA prefix — first 4 chars only — not the full key ID or secret)

**Credential lifecycle:**
- This key is persistent while HCP audit streaming remains enabled
- Revoke via AWS Console → IAM → Users → security credentials when no longer needed
- No rotation is required during normal operation; if key is compromised, revoke immediately
  and create a new key, then re-enter in HCP UI (see Q-6)
- The key never enters Terraform state, repository, chat, evidence, or shell history

**Stop condition:** Operator cannot authenticate to AWS Console; key creation fails.

---

### Q-6. HUMAN-ONLY: Credential transfer and stream enablement

**HARD STOP — credentials must not cross the Claude boundary.**

> **Operator action:**
> 1. In HCP portal → Vault cluster `frostgate-customer-zero` → Observability → Audit Logging
> 2. Enable CloudWatch streaming
> 3. Enter:
>    - AWS Region: `us-east-1`
>    - Log group name: (value from Q-2 output — exactly `/frostgate/customer-zero/vault-audit`)
>    - Access key ID: (the full key ID from Q-5 — enter directly, do not share with Claude)
>    - Secret access key: (the secret from Q-5 — enter directly, do not share with Claude)
> 4. Save and confirm HCP shows streaming as "Active"
> 5. Clear the secret from clipboard immediately after saving

**Non-secret confirmation:** "HCP audit streaming enabled. Status: Active. Log group confirmed: /frostgate/customer-zero/vault-audit."

**Stop condition:** HCP UI shows streaming error; log group name mismatch; HCP cannot connect to CloudWatch.

---

### Q-7. HUMAN-ONLY: Assume FrostGateVaultAuditReader and verify stream destination

`FrostGateTerraformOperator` intentionally lacks CloudWatch read actions (SoD invariant). All
log reads from this point use the `FrostGateVaultAuditReader` role assumed as the human IAM
user with MFA. This step is performed by the operator — NOT by Claude.

> **Operator action:**
> 1. Retrieve the reader role ARN from Terraform outputs:
>    ```bash
>    READER_ROLE_ARN="$(cd ~/Projects/fg-core/infra && AWS_PROFILE=frostgate-terraform terraform output -raw iam_audit_reader_role_arn)"
>    echo "Reader role ARN: ${READER_ROLE_ARN}"
>    ```
> 2. Assume the reader role as the human IAM user (NOT the operator role — trust policy names
>    the human user, not FrostGateTerraformOperator):
>    ```bash
>    eval "$(AWS_PROFILE=frostgate-human AWS_DEFAULT_REGION=us-east-1 aws sts assume-role \
>      --role-arn "${READER_ROLE_ARN}" \
>      --role-session-name "ceremony-evidence-verification" \
>      --serial-number "<your MFA device ARN>" \
>      --token-code "<current MFA code>" \
>      | python3 -c "
>    import sys, json
>    creds = json.load(sys.stdin)['Credentials']
>    print('export AWS_ACCESS_KEY_ID=' + creds['AccessKeyId'])
>    print('export AWS_SECRET_ACCESS_KEY=' + creds['SecretAccessKey'])
>    print('export AWS_SESSION_TOKEN=' + creds['SessionToken'])
>    ")"
>    unset AWS_PROFILE
>    ```
>    Reader credentials are now active via env vars. Do NOT set `AWS_PROFILE` for subsequent
>    log reads — doing so would override the assumed-role session.
> 3. Wait for HCP to establish the stream, then verify a log stream exists:
>    ```bash
>    sleep 60
>    AWS_DEFAULT_REGION=us-east-1 \
>      aws logs describe-log-streams \
>      --log-group-name "/frostgate/customer-zero/vault-audit" \
>      | python3 -c "
>    import sys, json
>    streams = json.load(sys.stdin).get('logStreams', [])
>    print('stream_count:', len(streams))
>    for s in streams[:3]:
>        print('  stream:', s.get('logStreamName', ''))
>    "
>    # Expected: stream_count >= 1 (HCP creates a stream upon first connection)
>    ```
> 4. Verify the log group name matches the intended destination:
>    ```bash
>    echo "Intended:  $(cd ~/Projects/fg-core/infra && AWS_PROFILE=frostgate-terraform terraform output -raw cloudwatch_log_group_name)"
>    echo "Actual: /frostgate/customer-zero/vault-audit"
>    # If these differ, record cloudwatch_actual_log_group_name in evidence manifest
>    ```

**Non-secret confirmation:** "Reader role assumed with MFA. stream_count: N (where N >= 1)."

**Stop condition:** assume-role fails with AccessDenied; stream_count remains 0 after 2 minutes.

---

### Q-8 to Q-9. Generate bounded non-rotating operational events

Generate a small set of bounded signing operations to produce audit evidence.
These are the events that will appear in CloudWatch — NOT the rotation event from Checkpoint P.
The rotation event (Checkpoint P) is separate rotation_history evidence; no second rotation
is required here.

```bash
# Run the ceremony signing tests (non-destructive, produces Vault audit events)
cd ~/Projects/fg-core
python -m pytest tests/test_customer_zero_trust_ceremony_readiness.py -v -k "test_a or test_m or test_g" 2>&1 | tail -20
```

Wait 60 seconds, then confirm events appear (reader credentials from Q-7 remain active):
```bash
AWS_DEFAULT_REGION=us-east-1 \
  aws logs filter-log-events \
  --log-group-name "/frostgate/customer-zero/vault-audit" \
  --start-time "$(python3 -c "import time; print(int((time.time()-600)*1000))")" \
  2>&1 | python3 -c "
import sys, json
data = json.load(sys.stdin)
events = data.get('events', [])
print('event_count:', len(events))
if events:
    print('first_event_timestamp:', events[0].get('timestamp', ''))
"
# Expected: event_count >= 1
```

---

### Q-10. Confirm reader role audit evidence verification

Reader credentials assumed at Q-7 remain active. Read the full 1-hour audit window and
confirm the independent reader view matches the event count from Q-9.

> **Operator action:**
> 1. Read recent audit events (reader credentials from Q-7 are already active):
>    ```bash
>    AWS_DEFAULT_REGION=us-east-1 aws logs filter-log-events \
>      --log-group-name "/frostgate/customer-zero/vault-audit" \
>      --start-time "$(python3 -c "import time; print(int((time.time()-3600)*1000))")" \
>      2>&1 | python3 -c "
>    import sys, json
>    data = json.load(sys.stdin)
>    events = data.get('events', [])
>    print('audit_event_count:', len(events))
>    "
>    ```
> 2. Confirm audit events are visible under the reader role (count >= 1)
> 3. Unset reader credentials: `unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN`

**Non-secret confirmation:** "audit_event_count: N (where N >= 1). Reader role verification complete."

**Stop condition:** Event count is 0 after confirmed streaming at Q-9.

---

### Q-11. Optionally recover historical rotation event from HCP archive

The identity key rotation performed at Checkpoint P produced audit evidence in the HCP
downloadable audit log archive. No second rotation is required to populate CloudWatch;
subsequent authentication and signing events (Q-8/Q-9) are the CloudWatch audit evidence.

If historical rotation evidence is needed:
- HCP portal → Vault cluster → Observability → Audit Logs → Download archive
- The archive contains the `transit/keys/customer-zero-identity/rotate` event
- This is optional rotation recovery, not a new rotation

**Evidence note:** `rotation_history` and `audit_evidence` are SEPARATE arrays in the
evidence manifest. The rotation event populates `rotation_history`; CloudWatch streaming
events populate `audit_evidence`. These are independent. Do NOT trigger a second rotation
merely to generate a CloudWatch event.

---

### Q-12 to Q-14. Populate and validate evidence manifest

```bash
cd ~/Projects/fg-core

# Q-12: Update artifacts/trust/customer_zero_trust_evidence.json with:
#   - audit_evidence: CloudWatch event refs (event IDs, timestamps, non-secret)
#   - rotation_history: from Checkpoint P pre/post rotation data
#   - dimensions.AUDITABILITY: "PASS" (events confirmed in CloudWatch by reader role)

# Q-13: Schema validate
python tools/customer_zero_trust_evidence.py validate artifacts/trust/customer_zero_trust_evidence.json
# Expected: all dimension checks PASS or NOT_PROVEN (no FAIL)

python tools/customer_zero_trust_evidence.py verify-anchors artifacts/trust/customer_zero_trust_evidence.json
# Expected: PASS

# Q-14: Schema validate
python tools/customer_zero_trust_evidence.py verify-role-separation artifacts/trust/customer_zero_trust_evidence.json
# Expected: PASS
```

---

### Q-15. Secret scan

```bash
cd ~/Projects/fg-core
# Confirm no secret values in evidence manifest or Terraform source
git diff --check
grep -rn "AKIA" infra/ artifacts/trust/ 2>/dev/null | grep -v ".terraform.lock" && echo "WARNING: found AWS key prefix" || echo "secret scan: PASS"
grep -rn -- "-----BEGIN" infra/ artifacts/trust/ 2>/dev/null && echo "WARNING: found PEM marker" || echo "PEM scan: PASS"
```

---

### Q-16. Final trust determination

All of the following must be confirmed before AUDITABILITY dimension is set to PASS:

| Check | Expected |
|---|---|
| Log group provisioned at intended name | PASS |
| HCP streaming status | Active |
| Writer has no read-event authority | CONFIRMED (policy structure) |
| Reader role exists with MFA trust | CONFIRMED (Q-4) |
| Reader assumed successfully with MFA | CONFIRMED (Q-7) |
| Audit events visible via reader role | CONFIRMED (event_count >= 1) |
| No second rotation required | CONFIRMED (rotation_history != audit_evidence) |
| Evidence manifest validates | PASS |
| Secret scan | PASS |

**Evidence:** All Q-1 through Q-15 outputs (non-secret). Operator records event count and reader confirmation.

**Secret boundary:** Writer access key created in Console (Q-5) and entered in HCP UI (Q-6) only.
Reader assumed-role credentials are transient and set/unset in terminal only. Neither cross the Claude boundary.

**Stop condition:** Log group absent; streaming not Active; reader role assumption fails; event count is 0; secret scan finds matches.

---

## CHECKPOINT R — Failure / Recovery Proof

**Prerequisites:** Checkpoint P and Q complete.

**Actions:**

```bash
# R1. Simulate cluster unavailability (test existing signatures verify offline)
cd ~/Projects/fg-core
python -c "
from services.cgin.key_management.vault_transit import TrustAnchor, TrustRole
import base64
# Simulate offline verification using a known public key + signature pair from tests
# (This confirms TrustAnchor.verify() does not require a live Vault connection)
print('Offline verification test: see test_trust_binding_vault_transit.py offline tests')
"

python -m pytest tests/ -v -k "offline or no_network or verify_without" 2>&1 | tail -10

# R2. Document recovery state
# Current: RESTORE_DOCUMENTED (not RESTORE_TESTED)
# A full drill requires a separate disposable Vault server (see recovery runbook)
# For ceremony completion, RESTORE_DOCUMENTED is the achievable state
```

**Expected result:** Offline verification confirmed. Recovery state documented.

**Evidence:** Offline verification PASS. `RECOVERY` dimension remains `NOT_PROVEN` until drill.

**Stop condition:** Offline verification fails.

---

## CHECKPOINT S — Evidence Manifest

**Prerequisites:** All previous checkpoints complete.

**Actions:**

```bash
cd ~/Projects/fg-core

# S1. Finalize the evidence manifest with all collected data
# Manually update artifacts/trust/customer_zero_trust_evidence.json with:
# - deployed_sha (Railway deployment SHA from Checkpoint L)
# - all dimension states
# - audit_evidence references
# - rotation_history (from Checkpoint P)
# - failure_evidence (from Checkpoint O/R)
# - recovery_evidence_ref (RESTORE_DOCUMENTED reference)

# S2. Validate
python tools/customer_zero_trust_evidence.py validate artifacts/trust/customer_zero_trust_evidence.json
# Expected: all dimension checks PASS or NOT_PROVEN (no FAIL)

python tools/customer_zero_trust_evidence.py verify-anchors artifacts/trust/customer_zero_trust_evidence.json
# Expected: PASS

python tools/customer_zero_trust_evidence.py verify-role-separation artifacts/trust/customer_zero_trust_evidence.json
# Expected: PASS

# S3. Run full regression suite against ceremony state
make fg-fast
# Expected: 496+ passed, 0 failed

make fg-security
# Expected: PASS

make fg-contract
# Expected: PASS
```

**Expected result:** Evidence manifest validates. All dimensions either PASS or NOT_PROVEN.
No FAIL. Full regression suite passes.

**Evidence:** Validated manifest fingerprint (non-secret). Test counts.

**Stop condition:** Any dimension FAIL; secret field detected in manifest; fg-fast failure.

---

## CHECKPOINT T — Customer-Zero Trust Completion Determination

**Prerequisites:** Checkpoint S complete. Evidence manifest committed.

**Actions:**

```bash
cd ~/Projects/fg-core

# T1. Commit evidence manifest (capture exact infra SHA at ceremony time)
CEREMONY_INFRA_SHA=$(git -C ~/Projects/fg-core rev-parse HEAD)
git add artifacts/trust/customer_zero_trust_evidence.json
git commit -m "feat(trust): CUSTOMER-ZERO-TRUST-001 production ceremony evidence

Ceremony ID: customer-zero-trust-2026-10-02-001
fg-core SHA: ${CEREMONY_INFRA_SHA}
Operator: <operator name>

All three Customer-Zero trust authorities provisioned and verified:
- customer-zero-identity (IDENTITY)
- customer-zero-acceptance (ACCEPTANCE)
- customer-zero-approval (APPROVAL)

Evidence manifest: artifacts/trust/customer_zero_trust_evidence.json"

# T2. Update roadmap
# In fg-core ROADMAP.md: mark CUSTOMER-ZERO-TRUST-001 as COMPLETED

# T3. Re-run roadmap checker
python tools/ci/check_customer_one_roadmap.py --work-item CUSTOMER-ZERO-ACCEPT-001
# Expected: AUTHORIZED (unblocked by CUSTOMER-ZERO-TRUST-001 completion)

# T4. Create PR to main
gh pr create --title "feat(trust): CUSTOMER-ZERO-TRUST-001 production ceremony complete" \
  --body "Production ceremony complete. Three Customer-Zero trust authorities provisioned."
```

**Expected result:** CUSTOMER-ZERO-TRUST-001 marked complete. CUSTOMER-ZERO-ACCEPT-001 unblocked.

**Evidence:** PR SHA. Committed evidence manifest fingerprint.

**Stop condition:** Evidence manifest fails validation; regression suite fails.

---

## CHECKPOINT U — Post-Ceremony Cluster Disposition

> **Scope distinction:** Option A below is **FULL FINAL TEARDOWN** only. It intentionally
> removes AWS audit authority and must not be used for emergency cost containment.
> To stop HCP/Vault charges while preserving AWS audit resources, use
> [Checkpoint V — Narrow Paid-Infrastructure Cost Containment](#checkpoint-v--narrow-paid-infrastructure-cost-containment).

**Prerequisites:** Checkpoint T complete. PR created. Evidence manifest committed and pushed.

**This checkpoint is MANDATORY.** The HCP Vault Dedicated cluster accrues hourly charges
from creation until deletion. At $1.84299/hour the trial credit balance ($500.00) is
exhausted approximately 113 cluster-hours after the first client authentication
(conservative, 4-client model: $208.32 remaining ÷ $1.84299/h), with
cash charges beginning automatically if no payment method is present. The operator must
make an explicit disposition decision here — not after the session ends.

**DECISION GATE — choose exactly one:**

---

### Option A — Teardown (cluster was ceremony-only)

**FULL FINAL TEARDOWN — deletes the AWS audit destination and IAM authority too.**
This is not a cost-containment shortcut. It requires separate final-decommission
authorization and an evidence-retention decision.

Choose this option if the cluster is not required for ongoing production signing.
The signed evidence manifest and public trust anchors remain independently verifiable
after cluster destruction. Future signing requires a new cluster.

**Pre-destruction checklist:**
```bash
# U-A1. Confirm all three public keys are in the evidence manifest (non-secret)
python tools/customer_zero_trust_evidence.py validate \
  artifacts/trust/customer_zero_trust_evidence.json
# Check: public_key fields for all three transit keys are non-empty

# U-A2. Confirm evidence manifest is committed and pushed to origin
git -C ~/Projects/fg-core log --oneline -3
git -C ~/Projects/fg-core status
# Must be: clean, no unpushed commits
```

**Override prevent_destroy and destroy:**

> **HUMAN OPERATOR ACTION — irreversible. Read completely before proceeding.**
>
> The Terraform configuration uses `prevent_destroy = true` on all HCP and Vault
> resources as protection against accidental destruction. Teardown requires a
> deliberate one-time override of these guards.

```bash
cd ~/Projects/fg-core/infra

# U-A3. In each of the following files, change every occurrence of
#        prevent_destroy = true   →   prevent_destroy = false
#   infra/hcp_cluster.tf      (hcp_hvn + hcp_vault_cluster)
#   infra/vault_transit.tf    (vault_mount + all 3 transit keys)
#   infra/vault_approle.tf    (vault_auth_backend + all 3 approle roles)
#   infra/vault_policies.tf   (all 3 trust policies)
#   infra/aws_audit.tf        (aws_cloudwatch_log_group)
#
# Verify the change:
grep -n "prevent_destroy" hcp_cluster.tf vault_transit.tf vault_approle.tf vault_policies.tf aws_audit.tf
# Expected: all show prevent_destroy = false

# U-A4. Apply the lifecycle change (no resources created or destroyed — plan should show
#        0 to add, 0 to change, 0 to destroy; only lifecycle metadata changes)
AWS_PROFILE=frostgate-terraform terraform plan -out=teardown-lifecycle.tfplan
terraform show teardown-lifecycle.tfplan | grep -E "Plan:|will be|must be"
# Confirm: zero resource mutations — lifecycle metadata change only
AWS_PROFILE=frostgate-terraform terraform apply teardown-lifecycle.tfplan

# U-A5. Destroy all resources
AWS_PROFILE=frostgate-terraform terraform destroy
# Type "yes" when prompted.
# Expected: all 20 resources destroyed (19 added + aws_iam_user.vault_audit already in state = 20 total).
```

**Post-destruction evidence:**
```bash
# U-A6. Record destruction timestamp
echo "cluster_destroy_timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# U-A7. Confirm HCP cluster is gone
hcp --help  # No vault subcommand — verify via HCP portal: cluster list should be empty.

# U-A8. Confirm AWS resources are gone
AWS_PROFILE=frostgate-terraform AWS_DEFAULT_REGION=us-east-1 \
  aws iam get-user --user-name frostgate-hcp-vault-audit 2>&1
# Expected: NoSuchEntityException

AWS_PROFILE=frostgate-terraform AWS_DEFAULT_REGION=us-east-1 \
  aws logs describe-log-groups --log-group-name-prefix "/frostgate/customer-zero" 2>&1
# Expected: empty or deleted
# Note: log group has prevent_destroy = true; may need separate deletion after terraform destroy
# if CloudWatch group is retained for 365-day audit evidence.
```

**Revert Terraform lifecycle guards:**
```bash
# U-A9. After destruction is confirmed, restore prevent_destroy = true in all files.
#        This is required before the next plan/apply cycle (future cluster creation).
#        Edit each file back: prevent_destroy = false  →  prevent_destroy = true
grep -n "prevent_destroy" hcp_cluster.tf vault_transit.tf vault_approle.tf vault_policies.tf aws_audit.tf
# Expected: all show prevent_destroy = true
git add hcp_cluster.tf vault_transit.tf vault_approle.tf vault_policies.tf aws_audit.tf
git commit -m "chore(infra): restore prevent_destroy guards post-ceremony teardown"
git push origin main
```

**Expected result:** All 20 resources destroyed. HCP billing stops. Audit logs retained
for 365 days in CloudWatch (if log group retained separately). Evidence manifest and
public trust anchors remain in fg-core permanently.

**Evidence:** Destruction timestamp (non-secret). Final HCP billing summary from portal.

**Stop condition:** Any resource fails to destroy; Terraform state shows orphaned resources.

---

### Option B — Authorize Ongoing Operation (cluster required for production signing)

Choose this option if runtime AppRoles will sign production governance artifacts
and the cluster must remain running.

**Cost implications of ongoing operation:**
- Cluster: $1.84299/hour × 730h/month ≈ $1,345/month
- 3–4 clients: $218.76–$291.68/month (flat, already locked for current period)
- **Monthly total: ~$1,564–$1,637/month**
- Trial credits ($500.00) will be exhausted approximately **~4.7 days** after first
  client authentication (conservative, 4-client model: 113 cluster-hours ÷ 24).
- After credits are exhausted: cash charges begin automatically IF a payment method
  is on file. If no payment method is present, HCP services terminate.

**Before authorizing ongoing operation, confirm:**
```bash
# U-B1. Confirm a valid payment method is on file
# HCP portal → Billing → Payment Methods
# Must show a valid credit card or other payment method.
# DO NOT add a payment method without explicit business authorization.

# U-B2. Record ongoing operation authorization
echo "Ongoing operation authorized by: <operator name>"
echo "Authorization date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Expected monthly cost: ~\$1,564–\$1,637"
echo "Credits-exhausted date: approximately $(date -d '+113 hours' +%Y-%m-%d)"
```

**Expected result:** Operator has explicitly acknowledged ongoing cost and confirmed
payment method. Cluster remains running. Periodic cost monitoring is in place.

**Stop condition:** No payment method on file and credits approaching exhaustion
without an explicit business decision to add one.

---

**Stop condition (either option):** Operator exits session without making a disposition
decision and the cluster continues accruing charges.

---

## CHECKPOINT V — NARROW PAID-INFRASTRUCTURE COST CONTAINMENT

**Purpose:** Stop Customer-Zero HCP charges while preserving the persistent AWS audit
authority. This is an operational/economic action only. It does not validate governance,
complete acceptance, or change the determination:

> **`CUSTOMER_ZERO_TRUST_NOT_PROVEN` remains unchanged by cost containment.**

This is the only procedure for cost containment. It does not use broad `terraform destroy`.
It generates four temporary self-contained Terraform configurations against the existing
`Frostgate/frostgate-customer-zero` remote workspace. It includes only resources present
in state and copies their definitions from reviewed source. To prevent unrelated drift
reconciliation, the private temporary configuration uses observed state values only for
the audit writer policy's `description` and `policy` fields, and (during
`enable-key-deletion` only) each Transit key's `min_encryption_version`. These are the
only known state/source discrepancies outside the authorized teardown mutation. The
generator extracts only those allowlisted, non-credential attributes in memory from
Terraform state; it never writes or prints raw state. Missing, malformed, or unexpected
state fails closed. All other source/state differences remain visible to the plan
verifier and abort the stage. No `ignore_changes` or broad drift suppression is used.
The normal `infra/` source remains authoritative for future repair and reprovisioning.
The helper does not change repository files or weaken the normal configuration's
`prevent_destroy` protections. Terraform `removed` blocks destroy the named addresses
and update state only after successful deletion; see the Terraform
[`removed` block reference](https://developer.hashicorp.com/terraform/language/block/removed).

### Resource boundaries and ordering

| Stage | Exact permitted action | Required ordering / authentication |
|---|---|---|
| `enable-key-deletion` | No destruction. Update only the three Transit keys' `deletion_allowed` from false to true; no other field may change. | First, while Vault is live; separate human authorization and Vault admin authentication required. This temporarily removes the key-level deletion guard only to permit the subsequent authorized deletion. |
| `vault-children` | Up to 11 Vault resources: Transit mount + 3 keys, AppRole backend + 3 roles, 3 policies; only addresses still in state | After the enablement stage is verified; while the Vault cluster is live; human Vault admin auth is required by the Vault provider. |
| `hcp-cluster` | `hcp_vault_cluster.customer_zero` only | After all Vault children are absent. The HVN and AWS audit resources remain configured. |
| `hvn` | `hcp_hvn.frostgate` only | After HCP confirms the Vault cluster is absent. No Vault provider/authentication is configured. |

Vault rejects Transit key deletion unless `deletion_allowed` is true. The temporary
enablement plan must prove that this is the only changed field on each key. Do not use
the Vault API or CLI as an unplanned bypass. The setting remains true only for the
short interval between two separately reviewed saved-plan operations; halt signing and
proceed directly to the authorized Vault-child plan. If teardown is abandoned, use the
ordinary configuration to plan and separately authorize restoration to false before
resuming service. See the [Vault Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit)
and the [Vault Terraform key resource](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/transit_secret_backend_key).

Every stage preserves the AWS resources present before teardown:
`aws_cloudwatch_log_group.vault_audit`, `aws_iam_user.vault_audit`,
`aws_iam_policy.vault_audit`, and `aws_iam_user_policy_attachment.vault_audit`.
If provisioned, the three #744 audit-reader resources are preserved as an all-or-none
trio. An extra managed address or partial reader trio fails closed. Railway, credentials,
and application resources are outside this boundary.

### V-1 — Authority and cost preconditions

1. Use `~/Projects/fg-core` on clean `main` with `HEAD == origin/main`; record its SHA and
   current UTC time. Run the CUSTOMER-ZERO-TRUST-001 roadmap checker and require
   `AUTHORIZED`.
2. Verify AWS account `398915901105` and the assumed `FrostGateTerraformOperator` role.
   Confirm the HCP organization, project, and workspace are the canonical target.
3. Review current HCP billing, live cluster status, and the authorized gross cap. This
   cost-containment action needs explicit human authorization; historical caps do not
   renew or extend expired ceremony authority.
4. If the Vault cluster exists, both `enable-key-deletion` and `vault-children` require
   valid human Vault admin authentication through the Vault provider. Do not create a
   token for convenience. Enter credentials only at the approved local secret boundary; never
   print, record, or put them in a saved plan or command argument. Later HCP stages do
   not configure the Vault provider and need no Vault authentication.
   Confirm the workspace's execution mode first: a local execution must use the
   human-approved local Vault environment, while remote execution requires the
   authorized sensitive workspace environment variable to reach the Vault provider.
   The same execution plane must be proven to use the expected AWS operator; a local
   AWS profile is not evidence for remote HCP Terraform credentials. Never pass
   `VAULT_TOKEN` as a `TF_VAR_*` input.
5. Verify the audit writer has zero IAM access keys. Do not create or revoke credentials
   as part of this procedure. If a writer key exists, stop for separate authority.

### V-2 — Generate and inspect a saved plan per stage

Do not edit Terraform source, switch branches, commit, or change the remote workspace
during the operation. The helper requires clean `main == origin/main`, roadmap
authorization, and an exact state inventory. It writes generated configurations only
under `/tmp`, to a path that does not already exist. Use a new directory and saved-plan
filename for each stage:

```bash
cd ~/Projects/fg-core
umask 077
STAGE=enable-key-deletion  # then vault-children, hcp-cluster, and hvn, separately
TMP_ROOT="$(mktemp -d /tmp/customer-zero-cost-containment.XXXXXX)"
CONFIG_DIR="$TMP_ROOT/$STAGE"
PLAN_FILE="$CONFIG_DIR/customer-zero-$STAGE.tfplan"

python tools/ci/check_customer_one_roadmap.py --work-item CUSTOMER-ZERO-TRUST-001
python infra/scripts/customer_zero_teardown.py prepare \
  --stage "$STAGE" --output-dir "$CONFIG_DIR"
cd "$CONFIG_DIR"
terraform init -input=false
terraform plan -input=false -out="$PLAN_FILE"
python ~/Projects/fg-core/infra/scripts/customer_zero_teardown.py verify \
  --stage "$STAGE" --plan "$PLAN_FILE"
sha256sum "$PLAN_FILE"
```

The verifier reads plan JSON and Terraform state without printing either. For
`enable-key-deletion`, it permits only the exact `deletion_allowed=true` updates on
Transit keys (with all other before/after fields identical) and no-op for other
resources. The temporary key configuration takes `min_encryption_version` from current
state (for example, `0`) so the stage cannot also reconcile the known canonical source
value (`1`). The writer policy declaration similarly uses only the observed description
and policy JSON so it cannot repair the unrelated #743 live-policy drift. For later
stages, it permits only `delete` for the current stage's remaining
allowlisted addresses and `no-op` for retained managed resources. It rejects create,
unexpected update, replacement, unexpected destroy, unexpected state, partial reader
trios, and unexpected output changes. Its output is the complete stage action set. If
a stage already completed, an empty action set is idempotently accepted. Do not invent
another target.

Output `no-op` entries are accepted because Terraform reports unchanged configured
outputs in `output_changes`; they do not alter state or authority. Output deletion is
accepted only for the exact stage-specific names listed by the verifier. Output create,
update, replacement, and unapproved deletion remain rejected.

Record outside the repository: stage, source SHA, plan filename and SHA-256, UTC plan
time, Terraform/provider versions, workspace, AWS account/operator, exact actions,
verifier result, and human authorization. Treat the saved plan as sensitive: keep it
under the private temporary directory, do not upload/commit it, and remove it securely
after the operation. If state changes or the plan becomes stale, discard it and restart
with a new plan and hash.

### V-3 — Human authorization and exact-plan apply

Stop after validation at every stage. The human reviews and explicitly authorizes that
stage's exact saved-plan SHA-256 and full action set. Approval of one stage does not
approve the next. Only after this exact-plan authorization, apply the saved plan file
from its generated configuration directory:

```bash
terraform apply "$PLAN_FILE"
```

Immediately before invoking that command, recheck clean `main`, `HEAD == origin/main`,
the recorded source SHA, roadmap authorization, AWS operator identity, HCP workspace,
current billing/cap, state, and the plan file SHA-256. If any differ from the reviewed
checkpoint, do not apply; create and authorize a new plan.

Never run `terraform destroy`, apply configuration without the saved-plan filename, or
use `-auto-approve`. On a nonzero result, timeout, stale plan, or provider error, do not
retry. Reconcile live provider status and state; regenerate the temporary configuration,
produce a fresh plan, rerun the verifier, and obtain new authorization for the new hash.

### V-4 — Post-stage verification

After the key-enablement stage, read-only verify all three Transit keys report
`deletion_allowed=true`, their algorithms/exportability/versions are otherwise
unchanged, and the keys still exist. Proceed promptly to a separately planned and
authorized `vault-children` stage. After that stage, confirm every Vault child address
is absent from state and the Vault API confirms the mounts, policies, roles, and keys are
gone while the cluster still exists. Only then prepare and separately authorize
`hcp-cluster`.

After the cluster stage, confirm `frostgate-customer-zero` is absent via HCP Portal or a
read-only API. Only then prepare and separately authorize `hvn`. This stage boundary
enforces cluster-before-HVN deletion without relying on concurrent provider ordering.

After the HVN stage, confirm both HCP resources are absent; all AWS audit resources that
were present before teardown remain live and in Terraform state; and the writer still
has zero access keys. The final state must contain only persistent AWS audit resources
(plus the complete reader trio if it existed). Verify HCP workspace state and billing
portal; record the observed shutdown time. Billing settlement may lag deletion, so do
not claim zero cost until confirmed in billing.

Record apply start/end UTC, return code, resource outcomes, post-stage state count, HCP
absence, AWS preservation, billing observation, and partial failures. Do not store
credentials, tokens, Railway values, or raw sensitive plan/state JSON in evidence. The
repository remains unchanged during operational execution.

### V-5 — Partial failure, resume, and trust implications

Resume only from observed state: inspect live provider status and state addresses,
regenerate the corresponding stage from canonical source, create a new saved plan, run
the verifier, and obtain new approval for its exact hash. Never reuse a stale plan or
use `terraform state rm` to hide an object that may still exist. Vault children are
destroyed while their provider endpoint remains available; later stages need no Vault
authentication. The cluster is confirmed gone before the HVN stage. AWS resources stay
configured and state-managed, so ordinary reconciliation will not adopt/recreate them.

Reprovisioning is a new authorized ceremony: return to the ordinary `infra/` root,
confirm only the preserved AWS authority remains in state, and generate a fresh plan
before any apply. Temporary teardown configurations are not provisioning roots. Public
verification artifacts may remain verifiable, but live signing stops. **Cost containment
does not change `CUSTOMER_ZERO_TRUST_NOT_PROVEN`.**

## Rollback procedure

If the ceremony must be aborted after Checkpoint F (after `terraform apply`):

1. **Do not destroy immediately.** Running `terraform destroy` requires overriding
   `prevent_destroy = true` on all critical resources, which is intentional protection.

2. **Assess the state.** Document what was provisioned and what failed.

3. **If destroying is required:**
   - Remove `prevent_destroy = true` from affected lifecycle blocks (requires operator approval)
   - `terraform destroy` — requires the same authenticated operator identity
   - This is a cost-bearing decision: HCP cluster will incur charges until destroyed

4. **Historical signature safety:** Any signatures issued during an aborted ceremony
   remain verifiable using the public keys in `artifacts/trust/`. They are NOT automatically
   invalidated by cluster destruction.

5. **SecretIDs from an aborted ceremony:** Revoke via `vault lease revoke` if the cluster
   is still accessible. Remove from Railway Variables immediately.
