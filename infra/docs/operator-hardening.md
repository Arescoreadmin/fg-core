# FrostGate Infrastructure Operator Hardening

**Work item:** CUSTOMER-ZERO-TRUST-001
**Applies to:** AWS account 398915901105
**Required before:** `terraform apply`

---

## Identity model: zero-static-credential IAM user path

FrostGate's ceremony operator identity uses a zero-static-credential chain:

```
frostgate-terraform-human (IAM user, console-only, NO access keys)
  │
  │  aws login --profile frostgate-human
  │  Browser: Console login at https://398915901105.signin.aws.amazon.com/console
  │  → username/password + MFA
  ↓
Temporary Console-derived credentials (ASIA-prefix STS, expires in hours)
MFA context: aws:MultiFactorAuthPresent = true
  │
  │  source_profile = frostgate-human in frostgate-terraform profile
  │  CLI calls sts:AssumeRole transparently
  ↓
arn:aws:sts::398915901105:assumed-role/FrostGateTerraformOperator/<session>
  │
  ↓
AWS_PROFILE=frostgate-terraform terraform plan / terraform apply
```

Properties:
- Root access keys: ZERO — root has no programmatic credentials
- Human access keys: ZERO — no AKIA-prefix static keys ever created
- `~/.aws/credentials` dependency: ZERO — no static credential file
- Credentials: temporary ASIA-prefix STS (expire automatically)
- MFA: enforced by role trust policy condition `aws:MultiFactorAuthPresent: true`
- Root routine use: ZERO — root is break-glass only

### Why not root directly

Root cannot assume IAM roles (`sts:AssumeRole` is prohibited for root). Root
is the account itself, not an IAM principal. All routine Terraform operations
must use a non-root IAM principal.

### Why not IAM Identity Center (for now)

IAM Identity Center requires creating an AWS Organization (for the org-instance
model), which triggers an account-plan change and credit expiration on the current
Free-plan account. This cost change has NOT been authorized.

IdC is documented as the recommended future migration path before multi-operator
or multi-account scale. See "Future migration" section below.

---

## Current account state

| Control | Status |
|---|---|
| Root MFA | ENABLED — AccountMFAEnabled: 1 |
| Root access keys | ABSENT — AccountAccessKeysPresent: 0 |
| `frostgate-terraform-human` IAM user | EXISTS — arn:aws:iam::398915901105:user/frostgate/frostgate-terraform-human |
| Human access keys | ZERO — confirmed `AccessKeyMetadata: []` |
| `FrostGateTerraformHumanPolicy` | EXISTS v2 — signin OAuth (remote) + sts:AssumeRole |
| `FrostGateTerraformOperator` role | EXISTS — trust narrowed to exact human user ARN + MFA condition |
| `FrostGateTerraformOperatorPolicy` | EXISTS — least-privilege 4 ceremony resources |
| `frostgate-hcp-vault-audit` conflict | DELETED — confirmed NoSuchEntity |
| `~/.aws/credentials` | ABSENT |
| `~/.aws/config` frostgate-terraform profile | credential_process — sdk bridge via get-operator-credentials.sh |
| Console password for human user | COMPLETE (implied by successful aws login + MFA) |
| MFA device for human user | ENROLLED — hardware U2F arn:aws:iam::398915901105:u2f/user/frostgate/frostgate-terraform-human/... |
| Human STS identity | LIVE_PROVEN 2026-10-02 — arn:aws:iam::398915901105:user/frostgate/frostgate-terraform-human |
| Terraform assumed-role identity | LIVE_PROVEN 2026-10-02 — assumed-role/FrostGateTerraformOperator/frostgate-terraform-session |
| Terraform plan (non-root) | COMPLETE 2026-10-02 — rc=0, 17 to add, 0 to change, 0 to destroy |
| Cost authorization | NOT GRANTED — terraform apply blocked |

---

## Step A — Root MFA [COMPLETE]

Root MFA is confirmed enabled. `AccountMFAEnabled: 1`. No action required.

---

## Step B — Delete conflicting IAM user [COMPLETE]

`frostgate-hcp-vault-audit` was deleted and verified absent. No action required.

---

## Step C — Bootstrap script [COMPLETE]

`scripts/bootstrap-operator-role.sh` was executed. All AWS resources exist:
- `FrostGateTerraformOperator` role and `FrostGateTerraformOperatorPolicy`
- `frostgate-terraform-human` IAM user (no access keys)
- `FrostGateTerraformHumanPolicy` attached
- Operator role trust narrowed to exact human user ARN with MFA condition

Rerun the script at any time — it is idempotent.

---

## Step D — Enable Console access for `frostgate-terraform-human`

**HUMAN OPERATOR ACTION REQUIRED**

The IAM user exists but has no Console password. Enable it now.

**AWS Console path:**
```
AWS Console (as root) → IAM → Users → frostgate-terraform-human
→ Security credentials → Console access → Enable
→ Set password: (strong password of your choice)
→ Require password reset on next sign-in: NO
→ Save
```

**DO NOT share the password with Claude.**

After enabling, the IAM user can log in at:
```
https://398915901105.signin.aws.amazon.com/console
```

---

## Step E — Enroll MFA for `frostgate-terraform-human`

**COMPLETE** — MFA device enrolled (hardware U2F key confirmed via
`arn:aws:iam::398915901105:u2f/user/frostgate/frostgate-terraform-human/...`).

The `aws:MultiFactorAuthPresent: true` condition on the operator role trust
policy will be satisfied when the IAM user's Console session uses the enrolled
hardware key at login.

No further action required for this step.

---

## Step F — Configure `~/.aws/config`

The `~/.aws/config` has been updated. Verify it contains these profiles:

```ini
[default]
login_session = arn:aws:iam::398915901105:root
region = us-east-1

[profile frostgate-human]
region = us-east-1

[profile frostgate-terraform]
region = us-east-1
credential_process = /home/jcosat/Projects/fg-core/infra/scripts/get-operator-credentials.sh
```

No secrets in this file. The `frostgate-human` profile's session is populated
automatically by `aws login --profile frostgate-human --region us-east-1 --remote`.

**Note on `credential_process`:** The `frostgate-terraform` profile uses
`credential_process` rather than `source_profile + role_arn`. This is required
because `aws login`'s `login_session` credential type is understood by the AWS
CLI but not by the AWS Go SDK used by Terraform. The `credential_process` script
(`scripts/get-operator-credentials.sh`) bridges this: it calls the AWS CLI
(which understands `login_session`) to assume the operator role and returns
credentials in the format the Go SDK can consume. The prior `source_profile +
role_arn` form still works for direct `aws` CLI use but Terraform requires
`credential_process`.

---

## Step G — Log in as the IAM human user

**HUMAN OPERATOR ACTION REQUIRED — run before each Terraform session**

```bash
aws login --profile frostgate-human --region us-east-1 --remote
```

Use `--remote` when running over SSH or in any environment without a local browser.
The command prints a URL and authorization code. **DO NOT log in as root.**
Open the URL on any machine, log in as the IAM user:

1. Navigate to: `https://398915901105.signin.aws.amazon.com/console`
2. Account ID: `398915901105` (pre-filled if using the IAM login URL)
3. Username: `frostgate-terraform-human`
4. Password: (the password you set in Step D)
5. MFA code: (current code from your authenticator/hardware key)
6. Authorize the device code printed by `aws login`

After successful authorization, `aws login` updates `~/.aws/config [profile
frostgate-human]` with `login_session`. The session credentials are cached in
`~/.aws/login/cache/` — temporary ASIA-prefix STS (expire automatically).

**DO NOT share the password, MFA code, device code, or browser authorization code with Claude.**

---

## Step H — Verify non-root source identity

**COMPLETE** — LIVE_PROVEN 2026-10-02 (Stage 1.6R3)

```
AWS_PROFILE=frostgate-human aws sts get-caller-identity
→ Account: 398915901105
→ Arn: arn:aws:iam::398915901105:user/frostgate/frostgate-terraform-human
→ rc=0 — NOT root
```

---

## Step I — Verify assumed-role Terraform identity

**COMPLETE** — LIVE_PROVEN 2026-10-02 (Stage 1.6R3)

```
AWS_PROFILE=frostgate-terraform aws sts get-caller-identity
→ Account: 398915901105
→ Arn: arn:aws:sts::398915901105:assumed-role/FrostGateTerraformOperator/frostgate-terraform-session
→ rc=0
```

If this fails in a future session:
- `MFA not present / AccessDenied` → re-run Step G with MFA
- `source profile must have credentials` → run Step G first

---

## Step J — Terraform plan (non-root)

**COMPLETE** — LIVE_PROVEN 2026-10-02 (Stage 1.6R3)

```
cd /home/jcosat/Projects/fg-core/infra
export AWS_PROFILE=frostgate-terraform
terraform plan -out=ceremony-plan.tfplan
→ plan rc=0
→ 17 to add, 0 to change, 0 to destroy
```

Plan identity confirmed: `assumed-role/FrostGateTerraformOperator/frostgate-terraform-session`

DO NOT apply without explicit cost authorization and operator approval.
Cost authorization is currently NOT GRANTED.

---

## Operator identity summary

| Item | ARN |
|---|---|
| Human user | `arn:aws:iam::398915901105:user/frostgate/frostgate-terraform-human` |
| Human policy | `arn:aws:iam::398915901105:policy/frostgate/FrostGateTerraformHumanPolicy` |
| Operator role | `arn:aws:iam::398915901105:role/frostgate/FrostGateTerraformOperator` |
| Operator policy | `arn:aws:iam::398915901105:policy/frostgate/FrostGateTerraformOperatorPolicy` |

---

## Operator role least-privilege policy

The `FrostGateTerraformOperatorPolicy` grants exactly the AWS API calls required
for the 4 ceremony Terraform resources:

| Resource | Actions | Scope |
|---|---|---|
| `aws_cloudwatch_log_group` | CreateLogGroup, DeleteLogGroup, ListTagsForResource, PutRetentionPolicy, TagResource, UntagResource | Specific log group ARN |
| (creation-time tagging) | TagResource | Account/region `log-group:*` with `ForAllValues:StringEquals aws:TagKeys` + `StringEquals aws:RequestTag/*` conditions scoped to the 4 ceremony tag keys |
| (list support) | DescribeLogGroups | `*` — list-type API |
| `aws_iam_user` | CreateUser, DeleteUser, GetUser, TagUser, UntagUser, ListUserTags, ListAccessKeys, ListAttachedUserPolicies, ListUserPolicies | Specific audit user ARN |
| `aws_iam_policy` | CreatePolicy, DeletePolicy, GetPolicy, GetPolicyVersion, ListPolicyVersions, ListEntitiesForPolicy | Specific audit policy ARN |
| `aws_iam_user_policy_attachment` | AttachUserPolicy, DetachUserPolicy | Both audit user and policy ARNs |
| (provider auth) | sts:GetCallerIdentity | `*` |

No AdministratorAccess, PowerUserAccess, or IAMFullAccess.

---

## Root break-glass procedure

Root is reserved for:
- Operator identity compromise / recovery
- Account-level operations requiring root (billing, support plan, account close)
- Bootstrap (first-time role/user creation via this script)

Root break-glass (root direct CLI, not via role assumption — root cannot assume roles):
1. `aws login` as root → browser → Console root login + MFA
2. Run AWS CLI commands directly with `default` profile (root session)
3. Take minimum required action only
4. Log out immediately after
5. Review CloudTrail for unexpected activity
6. Document in ceremony evidence record

---

## Required steps before terraform apply

| Step | Status |
|---|---|
| A — Root MFA | COMPLETE |
| B — Delete conflict | COMPLETE |
| C — Bootstrap script | COMPLETE |
| D — Console password for human user | COMPLETE (implied by successful MFA login) |
| E — MFA enrollment for human user | COMPLETE (hardware U2F key enrolled 2026-10-02) |
| F — `~/.aws/config` | COMPLETE (credential_process bridge configured) |
| G — `aws login --profile frostgate-human --region us-east-1 --remote` | COMPLETE (2026-10-02) |
| H — Non-root source identity proof | COMPLETE — LIVE_PROVEN 2026-10-02 |
| I — Assumed-role Terraform identity proof | COMPLETE — LIVE_PROVEN 2026-10-02 |
| J — `terraform plan` via non-root profile | COMPLETE — rc=0, 17 add, 0 change, 0 destroy (2026-10-02) |
| Cost authorization (separate gate) | NOT GRANTED — terraform apply BLOCKED |

---

## Future migration: IAM Identity Center

The current zero-static-credential IAM user approach is the **CUSTOMER-ZERO BOOTSTRAP
AUTHORITY** — appropriate for a single operator, single account, and one-time ceremony.

Migration to IAM Identity Center is recommended when:
- More than one routine human operator needs access
- Multi-account Terraform operations are required
- AWS account plan changes have been authorized (includes org creation)
- Centralized MFA enforcement across all AWS access is required

At that time, enable IAM Identity Center (org-instance), create a workforce identity,
attach `FrostGateTerraformOperatorPolicy` to a permission set, and update profiles to
use `aws configure sso`. The `FrostGateTerraformOperator` role and policy are retained
as the permission authority regardless of which identity source is used.

---

## Non-secret evidence to capture

| Item | Value |
|---|---|
| Root MFA | AccountMFAEnabled: 1 (LIVE_PROVEN 2026-10-02) |
| Root access keys | AccountAccessKeysPresent: 0 (LIVE_PROVEN 2026-10-02) |
| Human user ARN | arn:aws:iam::398915901105:user/frostgate/frostgate-terraform-human |
| Human access keys | 0 — AccessKeyMetadata: [] (LIVE_PROVEN 2026-10-02) |
| MFA device ARN | arn:aws:iam::398915901105:u2f/user/frostgate-terraform-human/frostgate-terraform-human-mfa-3WLS3ZVCZ5BP3MWJXXSBYYNKQI |
| Verified source STS ARN | arn:aws:iam::398915901105:user/frostgate/frostgate-terraform-human (LIVE_PROVEN 2026-10-02) |
| Verified Terraform STS ARN | arn:aws:sts::398915901105:assumed-role/FrostGateTerraformOperator/frostgate-terraform-session (LIVE_PROVEN 2026-10-02) |
| Terraform plan identity | assumed-role/FrostGateTerraformOperator/frostgate-terraform-session (LIVE_PROVEN 2026-10-02) |
| Terraform plan result | rc=0, 17 to add, 0 to change, 0 to destroy (LIVE_PROVEN 2026-10-02) |
| Operator role ARN | arn:aws:iam::398915901105:role/frostgate/FrostGateTerraformOperator |
| Operator policy ARN | arn:aws:iam::398915901105:policy/frostgate/FrostGateTerraformOperatorPolicy |

Record all items in the ceremony evidence manifest under `operator_identity`.
