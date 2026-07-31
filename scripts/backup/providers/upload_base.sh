#!/usr/bin/env bash
# =============================================================================
# Offsite upload interface.
#
# Every provider script defines a function `upload_backup` with signature:
#
#   upload_backup <local_file> <remote_key>
#
# Return codes:
#   0  success (or intentional skip — providers echo "skipped: <reason>")
#   1  hard failure (network, auth, permissions)
#   2  provider not configured — caller may decide to warn or fail
#
# Providers MUST NOT print secrets, endpoints with credentials, or the full
# contents of the backup. They MAY print the destination key and byte size.
# =============================================================================

# Default no-op; providers override.
upload_backup() {
  local _file="${1:-}"
  local _key="${2:-}"
  echo "upload_base.sh: no provider loaded (file=${_file##*/} key=${_key})"
  return 2
}
