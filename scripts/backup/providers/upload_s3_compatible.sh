#!/usr/bin/env bash
# =============================================================================
# S3-compatible offsite provider (S3, Cloudflare R2, Backblaze B2).
#
# This is a stub that documents the expected environment and prefers rclone
# when available, falling back to aws-cli. It exits code 0 with a "skipped"
# message when credentials are not configured — so scheduled backups never
# fail merely because offsite is not yet wired up.
#
# Required env when enabled:
#   FG_BACKUP_S3_BUCKET       target bucket name
#   FG_BACKUP_S3_PREFIX       key prefix (default: frostgate/backups)
#   FG_BACKUP_S3_ENDPOINT     R2/B2 endpoint URL (omit for AWS S3)
#   AWS_ACCESS_KEY_ID         access key
#   AWS_SECRET_ACCESS_KEY     secret key
#
# Rclone alternative:
#   FG_BACKUP_RCLONE_REMOTE   configured remote name (e.g., "r2:frostgate")
# =============================================================================

upload_backup() {
  local file="${1:-}"
  local key="${2:-}"

  if [[ -z "$file" || -z "$key" ]]; then
    echo "upload_s3_compatible.sh: missing arguments (file, key)" >&2
    return 1
  fi

  if [[ ! -f "$file" ]]; then
    echo "upload_s3_compatible.sh: source file missing: $file" >&2
    return 1
  fi

  local bucket="${FG_BACKUP_S3_BUCKET:-}"
  local prefix="${FG_BACKUP_S3_PREFIX:-frostgate/backups}"
  local endpoint="${FG_BACKUP_S3_ENDPOINT:-}"
  local rclone_remote="${FG_BACKUP_RCLONE_REMOTE:-}"

  # Prefer rclone if a remote is configured and the CLI is available.
  if [[ -n "$rclone_remote" ]] && command -v rclone >/dev/null 2>&1; then
    local dest="$rclone_remote/$prefix/$key"
    if rclone copyto --quiet -- "$file" "$dest"; then
      echo "upload_s3_compatible.sh: uploaded via rclone to $dest"
      return 0
    fi
    echo "upload_s3_compatible.sh: rclone upload failed" >&2
    return 1
  fi

  # Fall back to aws-cli when credentials + bucket are present.
  if [[ -z "$bucket" || -z "${AWS_ACCESS_KEY_ID:-}" || -z "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
    echo "upload_s3_compatible.sh: offsite upload skipped: credentials not configured"
    return 0
  fi

  if ! command -v aws >/dev/null 2>&1; then
    echo "upload_s3_compatible.sh: offsite upload skipped: aws CLI not installed"
    return 0
  fi

  local s3_uri="s3://$bucket/$prefix/$key"
  local aws_args=(s3 cp --only-show-errors -- "$file" "$s3_uri")
  if [[ -n "$endpoint" ]]; then
    aws_args=(--endpoint-url "$endpoint" "${aws_args[@]}")
  fi

  if aws "${aws_args[@]}"; then
    echo "upload_s3_compatible.sh: uploaded to $s3_uri"
    return 0
  fi
  echo "upload_s3_compatible.sh: aws upload failed" >&2
  return 1
}
