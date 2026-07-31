#!/usr/bin/env bash
# =============================================================================
# Offsite upload interface.
#
# Every provider script defines a function `upload_backup` with signature:
#
#   upload_backup <local_file> <remote_key>
#
# Return codes (3-state contract):
#   0  success — bytes reached the destination; caller may set offsite_uploaded=true
#   1  hard failure (network, auth, permissions) — caller may fail the backup
#   2  skipped — provider not configured or dependency missing; nothing was
#      uploaded but this is not a failure. Caller MUST NOT set
#      offsite_uploaded=true and SHOULD log a warning.
#
# Callers of upload_backup MUST check the exit code and distinguish 0 (bytes
# uploaded) from 2 (intentional skip). Treating both as success would lie in
# the manifest's offsite_uploaded flag and hide missing offsite configuration.
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
