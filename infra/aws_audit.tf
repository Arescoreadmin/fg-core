# =============================================================================
# AWS audit infrastructure — CloudWatch log group + IAM audit principal
#
# COST-BEARING RESOURCES — DO NOT APPLY without operator approval.
#
# CloudWatch log ingestion: $0.50/GB (us-east-1, 2026).
# Vault audit volume at this scale is negligible (KB/day for synthetic tests).
# Estimated cost: < $0.01/month for the ceremony period.
# Retention 365 days: no additional charge beyond standard ingestion.
#
# IAM user: no direct cost. Access key: no direct cost.
# CloudWatch metrics/alarms are NOT created here — audit logs only.
#
# This IAM identity is created exclusively for HCP Vault Dedicated audit
# log streaming. It must not be reused for any other purpose.
# Per the original prompt (Section 23): if the provider currently requires
# a wildcard CloudWatch scope, that is recorded as PROVIDER_CONTRACT_EXCEPTION
# in the evidence manifest.
# =============================================================================

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

# ── IAM audit-streaming identity ─────────────────────────────────────────────
# Required by the HCP Vault Dedicated → CloudWatch integration.
# This identity has the minimum permissions required by the HCP integration.
#
# If HCP requires broad CloudWatch permissions (e.g., cloudwatch:* or logs:*),
# this is documented as PROVIDER_CONTRACT_EXCEPTION in the evidence manifest.
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
  description = "Minimum permissions for HCP Vault Dedicated to stream audit logs to CloudWatch"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "VaultAuditLogStreaming"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents",
        ]
        Resource = [
          aws_cloudwatch_log_group.vault_audit.arn,
          "${aws_cloudwatch_log_group.vault_audit.arn}:*",
        ]
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "vault_audit" {
  user       = aws_iam_user.vault_audit.name
  policy_arn = aws_iam_policy.vault_audit.arn
}

# Access key is created out-of-band via AWS Console after terraform apply.
# It is entered directly into HCP Vault cluster audit log settings (HCP UI).
# It never passes through Terraform state.
