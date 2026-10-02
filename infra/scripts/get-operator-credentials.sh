#!/usr/bin/env bash
# scripts/get-operator-credentials.sh
#
# AWS credential_process helper for the frostgate-terraform AWS profile.
#
# PURPOSE:
#   The frostgate-human profile uses aws login's login_session credential type,
#   which the AWS CLI understands but the AWS Go SDK (used by Terraform) does not.
#   This script bridges the gap: the AWS CLI resolves login_session and calls
#   sts:AssumeRole, then outputs credentials in the credential_process JSON format
#   that the Go SDK can consume.
#
# USAGE (in ~/.aws/config):
#   [profile frostgate-terraform]
#   region = us-east-1
#   credential_process = /home/jcosat/Projects/fg-core/infra/scripts/get-operator-credentials.sh
#
# PREREQUISITE:
#   aws login --profile frostgate-human --region us-east-1 --remote
#   must have been run and completed successfully before invoking this script.
#
# OUTPUT: JSON in credential_process format (Version 1):
#   { "Version": 1, "AccessKeyId": "...", "SecretAccessKey": "...",
#     "SessionToken": "...", "Expiration": "..." }
#
# WORK ITEM: CUSTOMER-ZERO-TRUST-001

set -euo pipefail

ROLE_ARN="arn:aws:iam::398915901105:role/frostgate/FrostGateTerraformOperator"
SESSION_NAME="frostgate-terraform-session"

aws --profile frostgate-human sts assume-role \
  --role-arn "$ROLE_ARN" \
  --role-session-name "$SESSION_NAME" \
  --query 'Credentials' \
  --output json \
| python3 -c '
import sys, json
c = json.load(sys.stdin)
print(json.dumps({
    "Version": 1,
    "AccessKeyId": c["AccessKeyId"],
    "SecretAccessKey": c["SecretAccessKey"],
    "SessionToken": c["SessionToken"],
    "Expiration": c["Expiration"]
}))
'
