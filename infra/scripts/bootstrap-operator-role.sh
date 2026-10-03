#!/usr/bin/env bash
# scripts/bootstrap-operator-role.sh
#
# One-time root bootstrap for the FrostGate Terraform operator identity chain.
#
# IDENTITY CHAIN (Option B — zero-static-credential IAM user path):
#
#   frostgate-terraform-human (IAM user, no access keys)
#     ↓ aws login --profile frostgate-human (browser, MFA)
#   temporary Console-derived credentials with MFA context
#     ↓ source_profile + role_arn in frostgate-terraform profile
#   FrostGateTerraformOperator assumed-role session
#     ↓
#   Terraform
#
# WHAT THIS SCRIPT DOES (non-secret, idempotent):
#   1. Create FrostGateTerraformOperator role with FrostGateTerraformOperatorPolicy
#   2. Create frostgate-terraform-human IAM user (no access keys)
#   3. Create FrostGateTerraformHumanPolicy (sts:AssumeRole only)
#   4. Attach human policy to human user
#   5. Update operator role trust policy to trust exact human user ARN
#
# AFTER THIS SCRIPT:
#   HUMAN OPERATOR ACTIONS REQUIRED (see docs/operator-hardening.md):
#   A. Enable Console access for frostgate-terraform-human (password in Console)
#   B. Enroll virtual MFA device for frostgate-terraform-human
#   C. Update ~/.aws/config (see Phase 9 in operator-hardening.md)
#   D. aws login --profile frostgate-human  (browser → IAM user login + MFA)
#   E. AWS_PROFILE=frostgate-human aws sts get-caller-identity (verify non-root)
#   F. AWS_PROFILE=frostgate-terraform aws sts get-caller-identity (verify assumed-role)
#
# CEREMONY: customer-zero-trust-2026-10-02-001
# ACCOUNT:  398915901105
# WORK ITEM: CUSTOMER-ZERO-TRUST-001

set -euo pipefail

ACCOUNT_ID="398915901105"
REGION="us-east-1"

ROLE_NAME="FrostGateTerraformOperator"
OPERATOR_POLICY_NAME="FrostGateTerraformOperatorPolicy"
ROLE_PATH="/frostgate/"
OPERATOR_POLICY_PATH="/frostgate/"

HUMAN_USER_NAME="frostgate-terraform-human"
HUMAN_USER_PATH="/frostgate/"
HUMAN_POLICY_NAME="FrostGateTerraformHumanPolicy"
HUMAN_POLICY_PATH="/frostgate/"

ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role${ROLE_PATH}${ROLE_NAME}"
OPERATOR_POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy${OPERATOR_POLICY_PATH}${OPERATOR_POLICY_NAME}"
HUMAN_USER_ARN="arn:aws:iam::${ACCOUNT_ID}:user${HUMAN_USER_PATH}${HUMAN_USER_NAME}"
HUMAN_POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy${HUMAN_POLICY_PATH}${HUMAN_POLICY_NAME}"

# ── 0. Preflight: confirm root identity ───────────────────────────────────────

echo "[preflight] Verifying caller identity..."
CALLER_ARN=$(aws --region "${REGION}" sts get-caller-identity \
  --query 'Arn' --output text)
echo "[preflight] Running as: $CALLER_ARN"

if [[ "$CALLER_ARN" != *":root"* ]]; then
  echo "[ERROR] This bootstrap script must be run as root." >&2
  echo "[ERROR] Current identity: $CALLER_ARN" >&2
  exit 1
fi

echo ""
echo "NOTE: Root cannot assume IAM roles (sts:AssumeRole prohibited for root)."
echo "      Bootstrap creates the identity chain; routine ops use frostgate-terraform-human."
echo ""

# ── PHASE A: FrostGateTerraformOperator role ──────────────────────────────────

# Initial trust policy: will be updated to exact user ARN in Phase D
# Using account root as initial principal (delegates to IAM policies)
INITIAL_TRUST=$(cat <<TRUST
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Placeholder",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
TRUST
)

# Permissions policy: minimum for 4 ceremony AWS resources
PERMISSIONS_POLICY=$(cat <<PERMS
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudWatchLogGroup",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:DeleteLogGroup",
        "logs:ListTagsForResource",
        "logs:PutRetentionPolicy",
        "logs:UntagResource"
      ],
      "Resource": "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:/frostgate/customer-zero/vault-audit"
    },
    {
      "Sid": "CloudWatchLogGroupList",
      "Effect": "Allow",
      "Action": "logs:DescribeLogGroups",
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchLogGroupTag",
      "Effect": "Allow",
      "Action": "logs:TagResource",
      "Resource": "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:*"
    },
    {
      "Sid": "IAMAuditUser",
      "Effect": "Allow",
      "Action": [
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:GetUser",
        "iam:TagUser",
        "iam:UntagUser",
        "iam:ListUserTags",
        "iam:ListAccessKeys",
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey",
        "iam:UpdateAccessKey",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies"
      ],
      "Resource": "arn:aws:iam::${ACCOUNT_ID}:user/frostgate/vault/frostgate-hcp-vault-audit"
    },
    {
      "Sid": "IAMAuditPolicy",
      "Effect": "Allow",
      "Action": [
        "iam:CreatePolicy",
        "iam:DeletePolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListPolicyVersions",
        "iam:ListEntitiesForPolicy"
      ],
      "Resource": "arn:aws:iam::${ACCOUNT_ID}:policy/frostgate/vault/frostgate-hcp-vault-audit-policy"
    },
    {
      "Sid": "IAMPolicyAttachment",
      "Effect": "Allow",
      "Action": [
        "iam:AttachUserPolicy",
        "iam:DetachUserPolicy"
      ],
      "Resource": [
        "arn:aws:iam::${ACCOUNT_ID}:user/frostgate/vault/frostgate-hcp-vault-audit",
        "arn:aws:iam::${ACCOUNT_ID}:policy/frostgate/vault/frostgate-hcp-vault-audit-policy"
      ]
    },
    {
      "Sid": "IAMGetAccountSummary",
      "Effect": "Allow",
      "Action": "iam:GetAccountSummary",
      "Resource": "*"
    },
    {
      "Sid": "STSGetCallerIdentity",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    }
  ]
}
PERMS
)

echo "[A1] Creating operator role: ${ROLE_NAME}..."
if aws --region "${REGION}" iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  echo "[A1] Role exists — skipping create"
else
  aws --region "${REGION}" iam create-role \
    --role-name "$ROLE_NAME" \
    --path "$ROLE_PATH" \
    --assume-role-policy-document "$INITIAL_TRUST" \
    --description "Least-privilege Terraform infrastructure authority — CUSTOMER-ZERO-TRUST-001" \
    --tags Key=Purpose,Value=terraform-operator Key=WorkItem,Value=CUSTOMER-ZERO-TRUST-001 \
    --output text --query 'Role.Arn'
fi

echo "[A2] Creating/updating operator permissions policy: ${OPERATOR_POLICY_NAME}..."
if aws --region "${REGION}" iam get-policy --policy-arn "$OPERATOR_POLICY_ARN" >/dev/null 2>&1; then
  echo "[A2] Policy exists — creating new default version (idempotent update)..."
  # AWS limits managed policies to 5 versions; delete the oldest non-default before adding.
  OLDEST=$(aws --region "${REGION}" iam list-policy-versions \
    --policy-arn "$OPERATOR_POLICY_ARN" \
    --query 'Versions[?!IsDefaultVersion].VersionId | sort(@) | [0]' --output text)
  if [[ -n "$OLDEST" && "$OLDEST" != "None" ]]; then
    aws --region "${REGION}" iam delete-policy-version \
      --policy-arn "$OPERATOR_POLICY_ARN" --version-id "$OLDEST"
  fi
  aws --region "${REGION}" iam create-policy-version \
    --policy-arn "$OPERATOR_POLICY_ARN" \
    --policy-document "$PERMISSIONS_POLICY" \
    --set-as-default \
    --output text --query 'PolicyVersion.VersionId'
else
  aws --region "${REGION}" iam create-policy \
    --policy-name "$OPERATOR_POLICY_NAME" \
    --path "$OPERATOR_POLICY_PATH" \
    --policy-document "$PERMISSIONS_POLICY" \
    --description "Least-privilege AWS permissions for FrostGate CUSTOMER-ZERO-TRUST-001 Terraform" \
    --output text --query 'Policy.Arn'
fi

echo "[A3] Attaching operator policy to role..."
ATTACHED=$(aws --region "${REGION}" iam list-attached-role-policies --role-name "$ROLE_NAME" \
  --query "AttachedPolicies[?PolicyArn=='${OPERATOR_POLICY_ARN}'].PolicyArn" --output text)
if [[ -n "$ATTACHED" ]]; then
  echo "[A3] Policy already attached — skipping"
else
  aws --region "${REGION}" iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn "$OPERATOR_POLICY_ARN"
fi

# ── PHASE B: frostgate-terraform-human IAM user ───────────────────────────────

echo ""
echo "[B1] Creating human operator IAM user: ${HUMAN_USER_NAME}..."
if aws --region "${REGION}" iam get-user --user-name "$HUMAN_USER_NAME" >/dev/null 2>&1; then
  echo "[B1] User exists — skipping create"
else
  aws --region "${REGION}" iam create-user \
    --user-name "$HUMAN_USER_NAME" \
    --path "$HUMAN_USER_PATH" \
    --tags Key=Purpose,Value=terraform-operator-human Key=WorkItem,Value=CUSTOMER-ZERO-TRUST-001 \
    --output text --query 'User.Arn'
fi

echo "[B2] Creating human policy: ${HUMAN_POLICY_NAME}..."
# Actions derived from SignInLocalDevelopmentAccess (arn:aws:iam::aws:policy/SignInLocalDevelopmentAccess)
# which requires signin:AuthorizeOAuth2Access + signin:CreateOAuth2Token.
# Resource is scoped to the account-specific remote public-client ARN (--remote login mode)
# rather than the managed policy's wildcard arn:aws:signin:*:*:oauth2/public-client/*.
HUMAN_POLICY_DOC=$(cat <<HPOLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SignInOAuthRemote",
      "Effect": "Allow",
      "Action": [
        "signin:AuthorizeOAuth2Access",
        "signin:CreateOAuth2Token"
      ],
      "Resource": "arn:aws:signin:${REGION}:${ACCOUNT_ID}:oauth2/public-client/remote"
    },
    {
      "Sid": "AssumeOperatorRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "${ROLE_ARN}"
    }
  ]
}
HPOLICY
)

if aws --region "${REGION}" iam get-policy --policy-arn "$HUMAN_POLICY_ARN" >/dev/null 2>&1; then
  echo "[B2] Human policy exists — skipping create"
else
  aws --region "${REGION}" iam create-policy \
    --policy-name "$HUMAN_POLICY_NAME" \
    --path "$HUMAN_POLICY_PATH" \
    --policy-document "$HUMAN_POLICY_DOC" \
    --description "aws login (remote) OAuth + sts:AssumeRole for FrostGateTerraformOperator" \
    --output text --query 'Policy.Arn'
fi

echo "[B3] Attaching human policy to human user..."
HUMAN_ATTACHED=$(aws --region "${REGION}" iam list-attached-user-policies \
  --user-name "$HUMAN_USER_NAME" \
  --query "AttachedPolicies[?PolicyArn=='${HUMAN_POLICY_ARN}'].PolicyArn" --output text)
if [[ -n "$HUMAN_ATTACHED" ]]; then
  echo "[B3] Human policy already attached — skipping"
else
  aws --region "${REGION}" iam attach-user-policy \
    --user-name "$HUMAN_USER_NAME" \
    --policy-arn "$HUMAN_POLICY_ARN"
fi

# ── PHASE C: Verify zero access keys on human user ───────────────────────────

echo ""
echo "[C] Verifying zero access keys on ${HUMAN_USER_NAME}..."
KEY_COUNT=$(aws --region "${REGION}" iam list-access-keys \
  --user-name "$HUMAN_USER_NAME" \
  --query 'length(AccessKeyMetadata)' --output text)
if [[ "$KEY_COUNT" != "0" ]]; then
  echo "[ERROR] ${HUMAN_USER_NAME} has ${KEY_COUNT} access key(s). Must be zero." >&2
  exit 1
fi
echo "[C] Access key count: 0 — CORRECT"

# ── PHASE D: Update operator role trust to exact human user ARN ───────────────

echo ""
echo "[D] Updating FrostGateTerraformOperator trust policy to exact principal..."
FINAL_TRUST=$(cat <<TRUST
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowHumanUserWithMFA",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${HUMAN_USER_ARN}"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
TRUST
)

aws --region "${REGION}" iam update-assume-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-document "$FINAL_TRUST"
echo "[D] Trust policy narrowed to: ${HUMAN_USER_ARN}"

# ── SUMMARY ───────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo " BOOTSTRAP COMPLETE — AWS resources ready"
echo "═══════════════════════════════════════════════════════════════════"
echo " Operator role:      ${ROLE_ARN}"
echo " Operator policy:    ${OPERATOR_POLICY_ARN}"
echo " Human user:         ${HUMAN_USER_ARN}"
echo " Human policy:       ${HUMAN_POLICY_ARN}"
echo " Human access keys:  0 (verified)"
echo ""
echo " ══ HUMAN OPERATOR ACTIONS REQUIRED ══"
echo ""
echo " A. Set Console password for ${HUMAN_USER_NAME}:"
echo "    AWS Console → IAM → Users → ${HUMAN_USER_NAME}"
echo "    → Security credentials → Assign console access"
echo "    → Enable console access, set a strong password"
echo "    DO NOT share the password with Claude."
echo ""
echo " B. Enroll virtual MFA device:"
echo "    AWS Console → IAM → Users → ${HUMAN_USER_NAME}"
echo "    → Security credentials → Multi-factor authentication → Assign MFA device"
echo "    → Authenticator app → scan QR code with your authenticator"
echo "    DO NOT share the MFA seed or QR code with Claude."
echo ""
echo " C. Update ~/.aws/config (add frostgate-human profile if not present):"
cat <<'CFGPRINT'
    [profile frostgate-human]
    region = us-east-1

    [profile frostgate-terraform]
    role_arn = arn:aws:iam::398915901105:role/frostgate/FrostGateTerraformOperator
    source_profile = frostgate-human
    role_session_name = frostgate-terraform-session
    region = us-east-1
CFGPRINT
echo ""
echo " D. Log in as the IAM human user:"
echo "    aws login --profile frostgate-human --region us-east-1 --remote"
echo "    → Use --remote if running over SSH or without a local browser (headless)"
echo "    → Follow the printed URL: log in to AWS Console as ${HUMAN_USER_NAME} (NOT root)"
echo "    → Use IAM user login URL: https://398915901105.signin.aws.amazon.com/console"
echo "    → Enter password + MFA code, then authorize the device"
echo "    DO NOT share login credentials, MFA codes, or authorization codes with Claude."
echo ""
echo " E. Verify non-root identity:"
echo "    AWS_PROFILE=frostgate-human aws sts get-caller-identity"
echo "    Expected ARN: arn:aws:iam::398915901105:user/frostgate/frostgate-terraform-human"
echo ""
echo " F. Verify assumed-role identity:"
echo "    AWS_PROFILE=frostgate-terraform aws sts get-caller-identity"
echo "    Expected ARN: arn:aws:sts::398915901105:assumed-role/FrostGateTerraformOperator/..."
echo "    This must NOT be root."
echo "═══════════════════════════════════════════════════════════════════"
