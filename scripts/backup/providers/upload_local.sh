#!/usr/bin/env bash
# =============================================================================
# Local offsite provider — copies the backup to FG_BACKUP_OFFSITE_LOCAL_PATH.
#
# Intended for development, single-host installs, or as a staging area before
# an out-of-band rsync/rclone job ships the file to true offsite storage.
# =============================================================================

upload_backup() {
  local file="${1:-}"
  local key="${2:-}"

  if [[ -z "$file" || -z "$key" ]]; then
    echo "upload_local.sh: missing arguments (file, key)" >&2
    return 1
  fi

  if [[ ! -f "$file" ]]; then
    echo "upload_local.sh: source file missing: $file" >&2
    return 1
  fi

  local dest_dir="${FG_BACKUP_OFFSITE_LOCAL_PATH:-}"
  if [[ -z "$dest_dir" ]]; then
    echo "upload_local.sh: FG_BACKUP_OFFSITE_LOCAL_PATH not set — skipping"
    return 2
  fi

  mkdir -p "$dest_dir"
  chmod 700 "$dest_dir" 2>/dev/null || true

  local dest="$dest_dir/$key"
  mkdir -p "$(dirname "$dest")"
  cp -p -- "$file" "$dest"

  local bytes
  bytes=$(stat -c %s "$dest" 2>/dev/null || wc -c < "$dest")
  echo "upload_local.sh: copied to $dest (${bytes} bytes)"
  return 0
}
