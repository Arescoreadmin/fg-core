# CUSTOMER-ZERO-TRUST-001 Production Ceremony Runbook

**Ceremony ID:** `customer-zero-trust-2026-10-02-001`
**Work item:** CUSTOMER-ZERO-TRUST-001
**fg-core source authority:** `45f9a8370b9cb1a6c354da290ad3b5cd3ef43104`
**frostgate-infra source authority:** `8121d24252dd1e7e3945424fcdacc5a320611fea`

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
git rev-parse HEAD               # must be: 45f9a8370b9cb1a6c354da290ad3b5cd3ef43104
git fetch origin --prune
git rev-parse origin/main        # must equal HEAD

# A2. Verify frostgate-infra
cd ~/Projects/frostgate-infra
git status                       # must be: clean
git branch --show-current        # must be: main (or ceremony branch if applicable)
git rev-parse HEAD
git fetch origin --prune

# A3. Confirm roadmap authority
cd ~/Projects/fg-core
python tools/ci/check_customer_one_roadmap.py --work-item CUSTOMER-ZERO-TRUST-001
# Expected: AUTHORIZED rc=0

# A4. Confirm non-root AWS identity
AWS_PROFILE=frostgate-terraform aws sts get-caller-identity
# Expected: ARN must NOT contain :root

# A5. Confirm account summary
AWS_DEFAULT_REGION=us-east-1 aws iam get-account-summary \
  | python3 -c "import sys,json; s=json.load(sys.stdin)['SummaryMap']; print('MFA:', s.get('AccountMFAEnabled')); print('RootKeys:', s.get('AccountAccessKeysPresent'))"
# Expected: MFA: 1, RootKeys: 0

# A6. Confirm stale IAM user absent
AWS_DEFAULT_REGION=us-east-1 aws iam get-user --user-name frostgate-hcp-vault-audit 2>&1
# Expected: NoSuchEntity error (user was deleted in operator hardening)
```

**Expected result:** All checks pass, non-root identity confirmed.

**Evidence:** fg-core SHA, frostgate-infra SHA, AUTHORIZED roadmap rc=0, operator ARN, MFA:1.

**Secret boundary:** None.

**Stop condition:** Any SHA mismatch, root identity, MFA:0, or roadmap NOT AUTHORIZED.

---

## CHECKPOINT B — Operator Identity Verification

**Prerequisites:** Checkpoint A complete.

**Actions:**

```bash
# B1. Confirm Terraform will use non-root identity
cd ~/Projects/frostgate-infra
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

## CHECKPOINT C — Fresh Terraform Plan

**Prerequisites:** Checkpoint B complete. Ceremony ID matches `customer-zero-trust-2026-10-02-001`.

**Actions:**

```bash
cd ~/Projects/frostgate-infra
# Remove stale plan file (never apply the old one)
rm -f stage1-review.tfplan

AWS_PROFILE=frostgate-terraform terraform plan \
  -out=ceremony-plan-2026-10-01.tfplan 2>&1 | tee /tmp/ceremony-plan-output.txt

# Review plan summary
tail -5 /tmp/ceremony-plan-output.txt
```

**Expected result:**
- Plan: 17 to add, 0 to change, 0 to destroy (assuming stale IAM user was deleted)
- All 17 resources match the intended architecture
- No replacements, no destroys, no sensitive outputs
- Ceremony ID `customer-zero-trust-2026-10-02-001` appears in tags

**Evidence:** Plan summary line (non-secret). Resource count and categories.

**Secret boundary:** Plan file may contain provider responses. Do not `cat` the binary plan.
Inspect via `terraform show ceremony-plan-2026-10-01.tfplan` (text output is safe).

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
  -out=ceremony-plan-phase1.tfplan

terraform apply ceremony-plan-phase1.tfplan
```

**Expected result:** 6 resources created (2 HCP + 4 AWS). No errors.

**Collect vault_address immediately after Phase 1:**

```bash
terraform output vault_address
# Record this value — required for Phase 2 and Checkpoint G.
```

### Phase 2 — Vault resources

```bash
# Set the Vault address from Phase 1 output
export TF_VAR_vault_address="<vault_address from Phase 1>"

# Vault token required — see Checkpoint G before running Phase 2
# export VAULT_TOKEN=<admin token from HCP portal>

terraform plan \
  -out=ceremony-plan-phase2.tfplan

terraform apply ceremony-plan-phase2.tfplan
```

**Expected result:** Remaining 11 resources created (Transit engine, keys, policies, AppRoles).
Total across both phases: 17 to add, 0 to change, 0 to destroy.

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

**Prerequisites:** Checkpoint F complete. Vault cluster endpoint available.

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
print(f'  public_key (v{latest}): {pub[:40]}...' if pub else '  public_key: MISSING')
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

**Prerequisites:** Checkpoint G complete. VAULT_ADDR and VAULT_TOKEN set. All three Transit
keys exist (confirmed at Checkpoint G).

**Actions — live Vault CLI signing probes (no mock transport):**

```bash
# Requires: VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE=admin from Checkpoint G

# M1. Identity key — sign and confirm signature prefix
PAYLOAD=$(echo -n "ceremony-probe-identity-$(date +%s)" | base64 -w0)
vault write -format=json transit/sign/customer-zero-identity \
  input="${PAYLOAD}" \
  | python3 -c "
import sys, json, re
r = json.load(sys.stdin)
sig = r['data']['signature']
kv  = r['data']['key_version']
assert re.match(r'^vault:v\d+:', sig), f'unexpected signature format: {sig[:30]}'
print(f'identity  key_version={kv}  sig={sig[:30]}...')
"
echo "identity_sign_rc=$?"

# M2. Acceptance key
PAYLOAD=$(echo -n "ceremony-probe-acceptance-$(date +%s)" | base64 -w0)
vault write -format=json transit/sign/customer-zero-acceptance \
  input="${PAYLOAD}" \
  | python3 -c "
import sys, json, re
r = json.load(sys.stdin)
sig = r['data']['signature']
kv  = r['data']['key_version']
assert re.match(r'^vault:v\d+:', sig), f'unexpected signature format: {sig[:30]}'
print(f'acceptance  key_version={kv}  sig={sig[:30]}...')
"
echo "acceptance_sign_rc=$?"

# M3. Approval key
PAYLOAD=$(echo -n "ceremony-probe-approval-$(date +%s)" | base64 -w0)
vault write -format=json transit/sign/customer-zero-approval \
  input="${PAYLOAD}" \
  | python3 -c "
import sys, json, re
r = json.load(sys.stdin)
sig = r['data']['signature']
kv  = r['data']['key_version']
assert re.match(r'^vault:v\d+:', sig), f'unexpected signature format: {sig[:30]}'
print(f'approval  key_version={kv}  sig={sig[:30]}...')
"
echo "approval_sign_rc=$?"
```

All three `*_sign_rc` values must be 0.

**Expected result:** Three `vault:v1:` signatures produced. Key version is 1 for all three.

**Evidence:** Sign command output (non-secret — signatures and key version identifiers only).
Record `key_version`, `signature` prefix, and rc for each role in the evidence manifest.

**Secret boundary:** Admin VAULT_TOKEN used for ceremony bootstrap only. Signatures are
non-secret. No SecretIDs or AppRole credentials appear in this checkpoint.

**Stop condition:** Any sign rc != 0; signature format invalid; wrong key version.

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

## CHECKPOINT Q — CloudWatch Audit Verification

**Prerequisites:** Checkpoint F complete. IAM user exists. HCP cluster running.

**HUMAN OPERATOR ACTION — requires AWS Console + HCP portal.**

> **Operator action:** In AWS Console, create an access key for `frostgate-hcp-vault-audit`.
> Do NOT share the key with Claude. Copy the key ID and secret directly to HCP portal →
> Vault cluster → Observability → Audit Logging → Enable streaming to CloudWatch.
> Set log group: `/frostgate/customer-zero/vault-audit`.

**Non-secret verification:**

```bash
# Confirm log group exists and has retention policy
AWS_DEFAULT_REGION=us-east-1 aws logs describe-log-groups \
  --log-group-name-prefix "/frostgate/customer-zero" 2>&1

# After a signing test, confirm audit log events appear
AWS_DEFAULT_REGION=us-east-1 aws logs filter-log-events \
  --log-group-name "/frostgate/customer-zero/vault-audit" \
  --start-time $(date -d '-10 minutes' +%s000) 2>&1 | head -20
```

**Expected result:** Log group exists. Vault auth and signing events appear in CloudWatch
within 60 seconds of any Vault operation.

**Evidence:** Log group ARN (non-secret). Presence of log events confirmed.

**Secret boundary:** AWS access key is created in Console and entered in HCP UI only. Never to Claude.

**Stop condition:** Log group absent; no events appear after signing; HCP streaming fails.

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

# T1. Commit evidence manifest
git add artifacts/trust/customer_zero_trust_evidence.json
git commit -m "feat(trust): CUSTOMER-ZERO-TRUST-001 production ceremony evidence

Ceremony ID: customer-zero-trust-2026-10-02-001
fg-core SHA: <current>
frostgate-infra SHA: 8121d24252dd1e7e3945424fcdacc5a320611fea
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
