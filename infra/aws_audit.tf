# =============================================================================
# AWS audit infrastructure — CloudWatch log group + IAM audit principals
#
# COST-BEARING RESOURCES — DO NOT APPLY without operator approval.
#
# CloudWatch log ingestion: $0.50/GB (us-east-1, 2026).
# Vault audit volume at this scale is negligible (KB/day for synthetic tests).
# Estimated cost: < $0.01/month for the ceremony period.
# Retention 365 days: no additional charge beyond standard ingestion.
#
# IAM user and role: no direct cost. Access key: no direct cost.
# CloudWatch metrics/alarms are NOT created here — audit logs only.
#
# Authorities defined here:
#   WRITER: frostgate-hcp-vault-audit IAM user — streams audit events from HCP
#           into CloudWatch. No read authority. Access key created out-of-band.
#   READER: FrostGateVaultAuditReader IAM role — read-only, MFA-gated, for
#           independent ceremony evidence verification only.
#
# Separation of duties:
#   WRITER  != READER
#   READER  != TERRAFORM OPERATOR (FrostGateTerraformOperator lacks read actions)
#   WRITER  != TERRAFORM OPERATOR
#   Neither == runtime AppRole signing authorities
# =============================================================================

# Account identity — used to construct the reader trust policy fallback ARN.
data "aws_caller_identity" "current" {}

# CloudWatch log group for Vault audit events
resource "aws_cloudwatch_log_group" "vault_audit" {
  name              = var.cloudwatch_log_group_name
  retention_in_days = var.cloudwatch_retention_days

  tags = {
    Purpose   = "vault-audit"
    Ceremony  = var.ceremony_id
    ManagedBy = "terraform"
    WorkItem  = "CUSTOMER-ZERO-TRUST-001"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# ── IAM audit-streaming WRITER ────────────────────────────────────────────────
# Required by the HCP Vault Dedicated → CloudWatch integration.
# This identity has the minimum permissions required by the HCP integration.
# It has NO read authority (no FilterLogEvents, GetLogEvents, GetQueryResults).
#
# DESTINATION MODEL: The log group name (var.cloudwatch_log_group_name) is the
# INTENDED destination. It is pre-created by Terraform at the name encoded in
# that variable. The operator must configure HCP Vault Dedicated (Cluster →
# Observability → Audit Logging) to send to this exact name. HCP does not
# assign the destination automatically — the operator chooses it.
# To verify: confirm the HCP UI matches cloudwatch_log_group_name output and
# that log events appear in the group after a Vault operation (Checkpoint Q).
resource "aws_iam_user" "vault_audit" {
  name = "frostgate-hcp-vault-audit"
  path = "/frostgate/vault/"

  tags = {
    Purpose  = "hcp-vault-audit-streaming"
    Ceremony = var.ceremony_id
  }
}

resource "aws_iam_policy" "vault_audit" {
  name        = "frostgate-hcp-vault-audit-policy"
  path        = "/frostgate/vault/"
  description = "Minimum permissions for HCP Vault Dedicated to stream audit logs to CloudWatch. Write-only; no event-read authority."

  # POLICY STRUCTURE — TWO STATEMENTS:
  #
  # Statement 1 (VaultAuditLogWrite): write actions scoped to the exact log
  # group ARN. All actions in this statement support resource-level scoping.
  #
  # Statement 2 (VaultAuditDescribeLogGroupsUnscopedAWSLimit): DescribeLogGroups
  # CANNOT be resource-scoped — AWS CloudWatch Logs does not support resource-
  # level permissions for this action. Resource = "*" is the only valid value.
  # This is an AWS platform limitation, not a policy design choice. It is
  # documented as PROVIDER_CONTRACT_EXCEPTION in the evidence manifest.
  # Ref: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoncloudwatchlogs.html
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "VaultAuditLogWrite"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents",
        ]
        Resource = [
          aws_cloudwatch_log_group.vault_audit.arn,
          "${aws_cloudwatch_log_group.vault_audit.arn}:*",
        ]
      },
      {
        Sid    = "VaultAuditDescribeLogGroupsUnscopedAWSLimit"
        Effect = "Allow"
        Action = ["logs:DescribeLogGroups"]
        # AWS limitation: DescribeLogGroups does not support resource-level
        # permissions. Resource must be "*". Cannot be further restricted.
        Resource = ["*"]
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "vault_audit" {
  user       = aws_iam_user.vault_audit.name
  policy_arn = aws_iam_policy.vault_audit.arn
}

# Writer access key is created out-of-band via AWS Console after terraform apply.
# It is entered directly into HCP Vault cluster audit log settings (HCP UI).
# It never passes through Terraform state.

# ── IAM audit-READER role ─────────────────────────────────────────────────────
# FrostGateVaultAuditReader: independent read authority for CUSTOMER-ZERO Vault
# audit evidence verification. Used by the human operator during ceremony
# Checkpoint Q to independently confirm audit events arrived in CloudWatch.
#
# AUTHORITY BOUNDARY:
#   - Read-only: DescribeLogStreams, FilterLogEvents, GetLogEvents
#   - May NOT: PutLogEvents, CreateLogGroup, CreateLogStream, DeleteLogGroup,
#              DeleteLogStream, or any IAM/Vault mutation
#   - DescribeLogGroups (reader): same AWS limitation as writer — Resource="*"
#
# TRUST: MFA-authenticated operator only.
#   If var.operator_iam_user_arn is provided, trust is narrowed to that exact
#   IAM user (narrowest). Otherwise the account root is used as the principal
#   (still MFA-gated; allows any account IAM user who can authenticate with MFA).
#
# This role is DISTINCT from the writer user (frostgate-hcp-vault-audit) and
# from FrostGateTerraformOperator, which intentionally lacks audit read actions.
resource "aws_iam_role" "vault_audit_reader" {
  name = "FrostGateVaultAuditReader"
  path = "/frostgate/vault/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "MFARequiredOperator"
        Effect = "Allow"
        Principal = {
          AWS = var.operator_iam_user_arn != "" ? var.operator_iam_user_arn : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  tags = {
    Purpose   = "vault-audit-reader"
    Ceremony  = var.ceremony_id
    ManagedBy = "terraform"
    WorkItem  = "CUSTOMER-ZERO-TRUST-001"
  }
}

resource "aws_iam_policy" "vault_audit_reader" {
  name        = "FrostGateVaultAuditReaderPolicy"
  path        = "/frostgate/vault/"
  description = "Read-only access to CUSTOMER-ZERO Vault audit log group. No write authority."

  # POLICY STRUCTURE — TWO STATEMENTS:
  #
  # Statement 1 (VaultAuditLogRead): read actions scoped to the exact log group
  # ARN. DescribeLogStreams, FilterLogEvents, and GetLogEvents all support
  # resource-level scoping to the log group ARN.
  #
  # Statement 2 (VaultAuditReaderDescribeLogGroupsUnscopedAWSLimit):
  # DescribeLogGroups requires Resource="*" (same AWS limitation as the writer).
  # Documented as PROVIDER_CONTRACT_EXCEPTION.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "VaultAuditLogRead"
        Effect = "Allow"
        Action = [
          "logs:DescribeLogStreams",
          "logs:FilterLogEvents",
          "logs:GetLogEvents",
        ]
        Resource = [
          aws_cloudwatch_log_group.vault_audit.arn,
          "${aws_cloudwatch_log_group.vault_audit.arn}:*",
        ]
      },
      {
        Sid    = "VaultAuditReaderDescribeLogGroupsUnscopedAWSLimit"
        Effect = "Allow"
        Action = ["logs:DescribeLogGroups"]
        # AWS limitation: DescribeLogGroups does not support resource-level
        # permissions. Resource must be "*". Cannot be further restricted.
        Resource = ["*"]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "vault_audit_reader" {
  role       = aws_iam_role.vault_audit_reader.name
  policy_arn = aws_iam_policy.vault_audit_reader.arn
}
