#!/usr/bin/env bash
# =============================================================================
# fg_backup.sh — FrostGate production-grade backup automation
#
# Wraps the T1-proven backup method (pgvector/pgvector:pg18 pg_dump) with:
#   - manifest generation + SHA-256 checksum
#   - optional AES-256-CBC encryption
#   - offsite upload abstraction (local / s3 / r2 / b2)
#   - configurable retention pruning
#   - restore automation into an isolated scratch container
#   - monthly restore drill with evidence write-out
#   - RPO/RTO status reporting
#
# Subcommands:
#   backup [--type scheduled|manual|pre-deploy|pre-migration|pre-maintenance|pre-engagement]
#   verify  <backup-file>
#   restore <backup-file> [--target-name <name>]
#   list
#   prune   [--dry-run]
#   drill
#   status
#
# See docs/operators/backup_automation.md for the full guide.
# =============================================================================

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/backup_config.sh"

# --- constants ---------------------------------------------------------------

FG_BACKUP_SCRIPT_VERSION="1.0.0"
FG_BACKUP_MANIFEST_SCHEMA_VERSION="1.0"

# --- global state (populated by traps + subcommands) -------------------------
TMP_PGPASS=""
CURRENT_SCRATCH_CONTAINER=""

# --- helpers -----------------------------------------------------------------

log() {
  # stderr-only human log; stdout is reserved for machine output.
  printf '[fg_backup] %s\n' "$*" >&2
}

die() {
  local code="${1:-1}"
  shift || true
  log "ERROR: $*"
  exit "$code"
}

require_bin() {
  command -v "$1" >/dev/null 2>&1 || die 3 "missing dependency: $1"
}

iso_now_utc() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

ts_now_compact() {
  date -u +"%Y%m%d_%H%M%S"
}

json_escape() {
  # Escape a value for embedding inside a JSON string. Uses python for
  # correctness; python is a hard dep of this repo.
  python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.stdin.read()))' <<<"$1"
}

cleanup() {
  local ec=$?
  if [[ -n "$TMP_PGPASS" && -f "$TMP_PGPASS" ]]; then
    shred -u "$TMP_PGPASS" 2>/dev/null || rm -f "$TMP_PGPASS"
  fi
  if [[ -n "$CURRENT_SCRATCH_CONTAINER" ]]; then
    if command -v docker >/dev/null 2>&1; then
      docker rm -f "$CURRENT_SCRATCH_CONTAINER" >/dev/null 2>&1 || true
    fi
  fi
  return "$ec"
}
trap cleanup EXIT

# Parse a postgres:// URL into HOST/PORT/USER/PASSWORD/DB globals.
# Sets PG_HOST PG_PORT PG_USER PG_PASSWORD PG_DBNAME.
parse_db_url() {
  local url="${1:?db url required}"
  # Strip scheme prefix
  local rest="${url#*://}"
  # userinfo@hostport/db?params
  local userinfo="${rest%%@*}"
  local hostpart="${rest#*@}"
  if [[ "$rest" == "$userinfo" ]]; then
    die 2 "invalid FG_BACKUP_DB_URL (missing @)"
  fi
  PG_USER="${userinfo%%:*}"
  PG_PASSWORD="${userinfo#*:}"
  # host:port/db?params -> strip query first
  hostpart="${hostpart%%\?*}"
  local hp="${hostpart%%/*}"
  local dbpart="${hostpart#*/}"
  if [[ "$hostpart" == "$dbpart" ]]; then
    dbpart="$FG_BACKUP_DB_NAME"
  fi
  PG_HOST="${hp%%:*}"
  if [[ "$hp" == *:* ]]; then
    PG_PORT="${hp##*:}"
  else
    PG_PORT="5432"
  fi
  PG_DBNAME="${dbpart:-$FG_BACKUP_DB_NAME}"
  export PG_HOST PG_PORT PG_USER PG_PASSWORD PG_DBNAME
}

write_pgpass() {
  # $1: destination path
  local dest="${1:?dest required}"
  umask 077
  printf '%s:%s:%s:%s:%s\n' \
    "$PG_HOST" "$PG_PORT" "$PG_DBNAME" "$PG_USER" "$PG_PASSWORD" > "$dest"
  chmod 600 "$dest"
}

ensure_backup_dir() {
  mkdir -p "$FG_BACKUP_DIR"
  chmod 700 "$FG_BACKUP_DIR" 2>/dev/null || true
}

# Load the correct offsite provider script into scope.
load_offsite_provider() {
  # shellcheck source=/dev/null
  . "$SCRIPT_DIR/providers/upload_base.sh"
  case "${FG_BACKUP_OFFSITE_PROVIDER:-local}" in
    local)
      # shellcheck source=/dev/null
      . "$SCRIPT_DIR/providers/upload_local.sh"
      ;;
    s3|r2|b2)
      # shellcheck source=/dev/null
      . "$SCRIPT_DIR/providers/upload_s3_compatible.sh"
      ;;
    none)
      : # keep base no-op
      ;;
    *)
      die 2 "unknown FG_BACKUP_OFFSITE_PROVIDER: $FG_BACKUP_OFFSITE_PROVIDER"
      ;;
  esac
}

sha256_file() {
  sha256sum -- "$1" | awk '{print $1}'
}

file_size_bytes() {
  stat -c %s -- "$1" 2>/dev/null || wc -c < "$1"
}

# Query production for a scalar value using the pgvector:pg18 image.
# Uses the current PG_* vars.
psql_scalar() {
  local sql="${1:?sql required}"
  docker run --rm \
    -e PGPASSWORD="$PG_PASSWORD" \
    "$FG_BACKUP_DOCKER_IMAGE" \
    psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DBNAME" \
      --no-password -tA -c "$sql" 2>/dev/null | tr -d '[:space:]' || true
}

# Encrypt file in place, output to <file>.enc, and echo the new filename.
encrypt_file() {
  local src="${1:?src required}"
  local dest="$src.enc"
  if [[ -z "${FG_BACKUP_ENCRYPTION_KEY:-}" ]]; then
    die 2 "FG_BACKUP_ENCRYPT=true but FG_BACKUP_ENCRYPTION_KEY is empty"
  fi
  require_bin openssl
  FG_BACKUP_ENCRYPTION_KEY="$FG_BACKUP_ENCRYPTION_KEY" \
    openssl enc -aes-256-cbc -pbkdf2 -iter 600000 \
      -pass env:FG_BACKUP_ENCRYPTION_KEY \
      -in "$src" -out "$dest"
  shred -u "$src" 2>/dev/null || rm -f "$src"
  echo "$dest"
}

# --- subcommand: backup ------------------------------------------------------

cmd_backup() {
  local backup_type="scheduled"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --type) backup_type="${2:?--type value required}"; shift 2 ;;
      -h|--help) print_help; exit 0 ;;
      *) die 2 "unknown argument: $1" ;;
    esac
  done

  case "$backup_type" in
    scheduled|manual|pre-deploy|pre-migration|pre-maintenance|pre-engagement) ;;
    *) die 2 "invalid --type: $backup_type" ;;
  esac

  [[ -n "$FG_BACKUP_DB_URL" ]] || die 2 "FG_BACKUP_DB_URL is required"
  # Fail fast on misconfigured encryption BEFORE we touch the network.
  if [[ "${FG_BACKUP_ENCRYPT,,}" == "true" && -z "${FG_BACKUP_ENCRYPTION_KEY:-}" ]]; then
    die 2 "FG_BACKUP_ENCRYPT=true but FG_BACKUP_ENCRYPTION_KEY is empty"
  fi
  require_bin docker
  require_bin sha256sum
  ensure_backup_dir
  load_offsite_provider

  parse_db_url "$FG_BACKUP_DB_URL"

  local start_ts_iso start_epoch
  start_ts_iso="$(iso_now_utc)"
  start_epoch="$(date -u +%s)"

  local stamp basename dump_file manifest_file
  stamp="$(ts_now_compact)"
  basename="frostgate_${stamp}_${backup_type}.dump"
  dump_file="$FG_BACKUP_DIR/$basename"
  manifest_file="$FG_BACKUP_DIR/${basename}.manifest.json"

  TMP_PGPASS="$(mktemp -p "$FG_BACKUP_TMP_DIR" .fg_pgpass.XXXXXX)"
  write_pgpass "$TMP_PGPASS"

  log "starting pg_dump ($backup_type) → $dump_file"
  docker run --rm \
    -e PGPASSWORD="$PG_PASSWORD" \
    -v "$FG_BACKUP_DIR:/backups" \
    "$FG_BACKUP_DOCKER_IMAGE" \
    pg_dump \
      --no-password \
      -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DBNAME" \
      --format=custom --no-acl --no-owner \
      -f "/backups/$basename"

  [[ -s "$dump_file" ]] || die 4 "pg_dump produced empty file"

  # Metadata: migration + db version.
  local migration_version db_version
  migration_version="$(psql_scalar 'SELECT version_num FROM alembic_version ORDER BY version_num DESC LIMIT 1')"
  [[ -n "$migration_version" ]] || migration_version="unknown"
  db_version="$(psql_scalar 'SELECT version()')"
  [[ -n "$db_version" ]] || db_version="unknown"

  local dump_size checksum
  dump_size="$(file_size_bytes "$dump_file")"
  checksum="$(sha256_file "$dump_file")"

  # Optional encryption.
  local encrypted="false"
  local final_file="$dump_file"
  if [[ "${FG_BACKUP_ENCRYPT,,}" == "true" ]]; then
    final_file="$(encrypt_file "$dump_file")"
    encrypted="true"
    # keep the manifest pointing at the archive as stored
    dump_file="$final_file"
    basename="$(basename "$final_file")"
    manifest_file="$FG_BACKUP_DIR/${basename}.manifest.json"
    # After encryption we recompute size + checksum for the encrypted artifact.
    checksum="$(sha256_file "$final_file")"
    dump_size="$(file_size_bytes "$final_file")"
  fi

  # Offsite upload (best-effort). Records outcome; does not fail the backup
  # unless provider returns hard error (1).
  local offsite_uploaded="false"
  local offsite_provider="${FG_BACKUP_OFFSITE_PROVIDER:-local}"
  local offsite_msg=""
  if [[ "$offsite_provider" != "none" ]]; then
    if offsite_msg="$(upload_backup "$final_file" "$basename" 2>&1)"; then
      offsite_uploaded="true"
      # Also upload the manifest once we write it (below).
    else
      local rc=$?
      log "offsite upload returned rc=$rc: $offsite_msg"
      if [[ "$rc" == "1" ]]; then
        die 5 "offsite upload failed: $offsite_msg"
      fi
    fi
    log "offsite: $offsite_msg"
  fi

  # Manifest.
  local end_ts_iso end_epoch duration
  end_ts_iso="$(iso_now_utc)"
  end_epoch="$(date -u +%s)"
  duration=$((end_epoch - start_epoch))

  local pg_dump_ver
  pg_dump_ver="$(docker run --rm "$FG_BACKUP_DOCKER_IMAGE" pg_dump --version 2>/dev/null | head -1 || echo unknown)"

  # Write the manifest via a clean python invocation. Arguments are passed
  # positionally so we do not have to worry about shell interpolation inside
  # a python-in-bash heredoc.
  python3 - "$manifest_file" \
    "$FG_BACKUP_MANIFEST_SCHEMA_VERSION" "$start_ts_iso" "$end_ts_iso" \
    "$backup_type" "$db_version" "$migration_version" "$dump_size" \
    "$checksum" "$final_file" "$FG_BACKUP_DOCKER_IMAGE" \
    "$pg_dump_ver" "$FG_BACKUP_OPERATOR" "$encrypted" \
    "$offsite_uploaded" "$offsite_provider" "$duration" \
    "$FG_BACKUP_RAILWAY_PLAN" "$FG_BACKUP_SCRIPT_VERSION" <<'PYEOF'
import json, sys
(_prog, path, schema_v, start_iso, end_iso, btype, db_v, mig_v, size,
 checksum, storage, image, dump_ver, operator, encrypted, offsite_uploaded,
 offsite_provider, duration, plan, script_v) = sys.argv
data = {
  "manifest_schema_version": schema_v,
  "timestamp": start_iso,
  "completed_at": end_iso,
  "backup_type": btype,
  "db_version": db_v,
  "migration_version": mig_v,
  "backup_size_bytes": int(size),
  "dump_size_bytes": int(size),
  "compression": "pg_dump custom format",
  "checksum_sha256": checksum,
  "checksum_algorithm": "sha256",
  "storage_location": storage,
  "restore_compatibility": image,
  "pg_dump_version": dump_ver,
  "pg_restore_version": dump_ver,
  "verification_status": "unverified",
  "verified_at": None,
  "operator": operator,
  "encrypted": encrypted.lower() == "true",
  "offsite_uploaded": offsite_uploaded.lower() == "true",
  "offsite_provider": None if offsite_provider in ("", "none") else offsite_provider,
  "duration_seconds": int(duration),
  "railway_plan": plan,
  "script_version": script_v,
}
with open(path, "w") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write("\n")
PYEOF

  # Upload the manifest alongside the dump.
  if [[ "$offsite_provider" != "none" ]]; then
    local m_key
    m_key="$(basename "$manifest_file")"
    upload_backup "$manifest_file" "$m_key" >/dev/null 2>&1 || true
  fi

  # Verify the manifest we just wrote against the archive (self-check).
  if verify_backup_impl "$final_file" >/dev/null 2>&1; then
    python3 - "$manifest_file" "$(iso_now_utc)" <<'PYEOF'
import json, sys
path, verified_at = sys.argv[1], sys.argv[2]
with open(path) as fh:
    data = json.load(fh)
data["verification_status"] = "verified"
data["verified_at"] = verified_at
with open(path, "w") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write("\n")
PYEOF
  else
    log "post-backup verification FAILED for $final_file"
    die 6 "verify step failed after backup"
  fi

  # Retention.
  prune_backups_impl false >/dev/null 2>&1 || log "prune step reported issues (non-fatal here)"

  # Emit summary.
  emit_backup_summary "$final_file" "$manifest_file" "$backup_type" "$checksum" \
    "$dump_size" "$duration" "$encrypted" "$offsite_uploaded" "$offsite_provider"
}

emit_backup_summary() {
  local file="$1" manifest="$2" btype="$3" checksum="$4" size="$5" duration="$6"
  local encrypted="$7" offsite_uploaded="$8" offsite_provider="$9"
  if [[ "${FG_BACKUP_JSON_OUTPUT,,}" == "true" ]]; then
    python3 - "$file" "$manifest" "$btype" "$checksum" "$size" "$duration" \
      "$encrypted" "$offsite_uploaded" "$offsite_provider" <<'PYEOF'
import json, sys
(_p, file, manifest, btype, checksum, size, duration, enc, off, prov) = sys.argv
print(json.dumps({
  "result": "ok",
  "backup_file": file,
  "manifest_file": manifest,
  "backup_type": btype,
  "checksum_sha256": checksum,
  "size_bytes": int(size),
  "duration_seconds": int(duration),
  "encrypted": enc.lower() == "true",
  "offsite_uploaded": off.lower() == "true",
  "offsite_provider": None if prov in ("", "none") else prov,
}))
PYEOF
  else
    cat >&2 <<EOF
[fg_backup] backup complete
  file          : $file
  manifest      : $manifest
  type          : $btype
  size          : $size bytes
  duration      : $duration s
  sha256        : $checksum
  encrypted     : $encrypted
  offsite       : $offsite_uploaded (provider=$offsite_provider)
EOF
  fi
}

# --- subcommand: verify ------------------------------------------------------

verify_backup_impl() {
  # Returns 0 on success, non-zero on any failure. Prints PASS/FAIL lines
  # to stdout.
  local file="${1:?backup file required}"
  local manifest="${file}.manifest.json"

  local ok=1
  if [[ ! -f "$file" ]]; then
    echo "FAIL archive_exists: $file not found"
    return 1
  fi
  echo "PASS archive_exists"

  if [[ ! -f "$manifest" ]]; then
    echo "FAIL manifest_exists: $manifest not found"
    return 1
  fi
  echo "PASS manifest_exists"

  local expected actual
  expected="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["checksum_sha256"])' "$manifest")"
  actual="$(sha256_file "$file")"
  if [[ "$expected" != "$actual" ]]; then
    echo "FAIL checksum_match expected=$expected actual=$actual"
    ok=0
  else
    echo "PASS checksum_match"
  fi

  # pg_restore --list requires the pgvector image. Skip when docker is
  # unavailable but note it as a warning.
  if command -v docker >/dev/null 2>&1; then
    # Encrypted archives cannot be read by pg_restore without decryption; skip
    # the pg_restore --list check for those (checksum still verifies bytes).
    local encrypted
    encrypted="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("encrypted", False))' "$manifest")"
    if [[ "$encrypted" == "True" || "$encrypted" == "true" ]]; then
      echo "PASS pg_restore_list (skipped: encrypted archive)"
    else
      if docker run --rm -i "$FG_BACKUP_DOCKER_IMAGE" pg_restore --list < "$file" >/dev/null 2>&1; then
        echo "PASS pg_restore_list"
      else
        echo "FAIL pg_restore_list"
        ok=0
      fi
    fi
  else
    echo "WARN pg_restore_list_skipped: docker unavailable"
  fi

  [[ "$ok" == "1" ]] || return 2
  return 0
}

cmd_verify() {
  local file="${1:-}"
  [[ -n "$file" ]] || die 2 "usage: fg_backup.sh verify <backup-file>"
  verify_backup_impl "$file"
}

# --- subcommand: list --------------------------------------------------------

cmd_list() {
  ensure_backup_dir
  if [[ "${FG_BACKUP_JSON_OUTPUT,,}" == "true" ]]; then
    python3 - "$FG_BACKUP_DIR" <<'PYEOF'
import json, os, sys
d = sys.argv[1]
items = []
for name in sorted(os.listdir(d)):
    if not name.startswith("frostgate_"):
        continue
    if name.endswith(".manifest.json"):
        continue
    path = os.path.join(d, name)
    try:
        st = os.stat(path)
    except FileNotFoundError:
        continue
    manifest = path + ".manifest.json"
    meta = {}
    if os.path.exists(manifest):
        try:
            meta = json.load(open(manifest))
        except Exception:
            meta = {}
    items.append({
        "file": name,
        "size_bytes": st.st_size,
        "mtime": int(st.st_mtime),
        "backup_type": meta.get("backup_type"),
        "verification_status": meta.get("verification_status"),
        "encrypted": meta.get("encrypted"),
    })
print(json.dumps({"backup_dir": d, "items": items}, indent=2))
PYEOF
  else
    printf '%-40s %12s %-14s %-10s %s\n' "FILE" "SIZE" "TYPE" "VERIFIED" "MTIME"
    while IFS= read -r name; do
      [[ -z "$name" ]] && continue
      local path="$FG_BACKUP_DIR/$name"
      local manifest="${path}.manifest.json"
      local size type verified mtime
      size="$(file_size_bytes "$path")"
      mtime="$(date -u -r "$path" +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo '-')"
      if [[ -f "$manifest" ]]; then
        type="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("backup_type","?"))' "$manifest")"
        verified="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("verification_status","?"))' "$manifest")"
      else
        type="?"; verified="no-manifest"
      fi
      printf '%-40s %12s %-14s %-10s %s\n' "$name" "$size" "$type" "$verified" "$mtime"
    done < <(cd "$FG_BACKUP_DIR" && ls -1 frostgate_*.dump frostgate_*.dump.enc 2>/dev/null | grep -v '\.manifest\.json$' || true)
  fi
}

# --- subcommand: prune -------------------------------------------------------

prune_backups_impl() {
  local dry_run="${1:-false}"
  python3 - "$FG_BACKUP_DIR" "$dry_run" \
    "$FG_BACKUP_RETAIN_HOURLY" "$FG_BACKUP_RETAIN_DAILY" \
    "$FG_BACKUP_RETAIN_WEEKLY" "$FG_BACKUP_RETAIN_MONTHLY" \
    "$FG_BACKUP_RETAIN_YEARLY" <<'PYEOF'
import json, os, re, sys
from datetime import datetime, timezone, timedelta

(_p, backup_dir, dry_run_s, retain_hourly, retain_daily,
 retain_weekly, retain_monthly, retain_yearly) = sys.argv
dry_run = dry_run_s.lower() == "true"
retain = {
  "hourly":  int(retain_hourly),
  "daily":   int(retain_daily),
  "weekly":  int(retain_weekly),
  "monthly": int(retain_monthly),
  "yearly":  int(retain_yearly),
}

fname_re = re.compile(r"^frostgate_(\d{8})_(\d{6})_[a-z-]+\.dump(\.enc)?$")
now = datetime.now(timezone.utc)

candidates = []
for name in sorted(os.listdir(backup_dir)):
    m = fname_re.match(name)
    if not m:
        continue
    ts_str = m.group(1) + m.group(2)
    try:
        ts = datetime.strptime(ts_str, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        continue
    candidates.append((ts, name))

# newest first
candidates.sort(key=lambda x: x[0], reverse=True)

# Never delete the single newest.
protected = set()
if candidates:
    protected.add(candidates[0][1])

def bucket_of(ts):
    age = now - ts
    if age < timedelta(hours=48):
        return "hourly"
    if age < timedelta(days=14):
        return "daily"
    if age < timedelta(days=90):
        return "weekly"
    if age < timedelta(days=730):
        return "monthly"
    return "yearly"

buckets = {"hourly": [], "daily": [], "weekly": [], "monthly": [], "yearly": []}
for ts, name in candidates:
    buckets[bucket_of(ts)].append((ts, name))

keep, drop = set(), []
for b, entries in buckets.items():
    entries.sort(key=lambda x: x[0], reverse=True)
    n_keep = retain[b]
    for i, (ts, name) in enumerate(entries):
        if i < n_keep:
            keep.add(name)
        else:
            drop.append(name)

# Always protect newest.
drop = [n for n in drop if n not in protected]

actions = []
for name in drop:
    path = os.path.join(backup_dir, name)
    manifest = path + ".manifest.json"
    actions.append({"file": name, "action": "delete", "dry_run": dry_run})
    if not dry_run:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        if os.path.exists(manifest):
            try:
                os.remove(manifest)
            except FileNotFoundError:
                pass

kept = sorted(keep | protected)
print(json.dumps({
    "dry_run": dry_run,
    "retention": retain,
    "total_before": len(candidates),
    "kept": kept,
    "dropped": [a["file"] for a in actions],
}, indent=2))
PYEOF
}

cmd_prune() {
  local dry_run=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run) dry_run=true; shift ;;
      -h|--help) print_help; exit 0 ;;
      *) die 2 "unknown argument: $1" ;;
    esac
  done
  ensure_backup_dir
  prune_backups_impl "$dry_run"
}

# --- subcommand: restore -----------------------------------------------------

# Restore a dump into a scratch container, compare counts against production
# (using FG_BACKUP_DB_URL). Never touches production.
cmd_restore() {
  local file="" target=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target-name) target="${2:?}"; shift 2 ;;
      -h|--help) print_help; exit 0 ;;
      *) if [[ -z "$file" ]]; then file="$1"; else die 2 "unexpected: $1"; fi; shift ;;
    esac
  done
  [[ -n "$file" ]] || die 2 "usage: fg_backup.sh restore <backup-file> [--target-name <name>]"
  [[ -f "$file" ]] || die 2 "backup file not found: $file"

  require_bin docker

  local manifest="${file}.manifest.json"
  [[ -f "$manifest" ]] || die 2 "manifest not found: $manifest"
  local encrypted
  encrypted="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("encrypted", False))' "$manifest")"
  if [[ "$encrypted" == "True" || "$encrypted" == "true" ]]; then
    die 2 "encrypted archive — decrypt with docs/operators/disaster_recovery.md §4 before restore"
  fi

  local stamp rand
  stamp="$(date -u +%Y%m%d)"
  rand="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  target="${target:-frostgate-restore-${stamp}-${rand}}"
  CURRENT_SCRATCH_CONTAINER="$target"

  local scratch_pass="scratch-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')-not-production"
  local scratch_port="${FG_BACKUP_SCRATCH_PORT:-5434}"

  log "creating scratch container: $target on 127.0.0.1:$scratch_port"
  docker run -d \
    --name "$target" \
    -e POSTGRES_PASSWORD="$scratch_pass" \
    -e POSTGRES_DB=restore_scratch \
    -e POSTGRES_USER=restore_user \
    -p "127.0.0.1:$scratch_port:5432" \
    "$FG_BACKUP_DOCKER_IMAGE" >/dev/null

  # Wait until postgres is ready.
  local waited=0
  until docker exec "$target" pg_isready -U restore_user -d restore_scratch >/dev/null 2>&1; do
    sleep 1
    waited=$((waited + 1))
    [[ "$waited" -lt 60 ]] || die 4 "scratch container did not become ready in 60s"
  done

  log "pg_restore into scratch"
  docker run --rm \
    -e PGPASSWORD="$scratch_pass" \
    --network host \
    -v "$(readlink -f "$file"):/restore.dump:ro" \
    "$FG_BACKUP_DOCKER_IMAGE" \
    pg_restore \
      --no-password \
      -h 127.0.0.1 -p "$scratch_port" -U restore_user -d restore_scratch \
      --no-owner --no-acl --exit-on-error /restore.dump

  # Query scratch counts.
  local scratch_counts
  scratch_counts="$(docker exec -e PGPASSWORD="$scratch_pass" "$target" \
    psql --no-password -U restore_user -d restore_scratch -tA -F '|' -c \
    "SELECT
       (SELECT COUNT(*) FROM fa_engagements),
       (SELECT COUNT(*) FROM fa_normalized_findings),
       (SELECT COUNT(*) FROM fa_engagement_audit_events),
       (SELECT COUNT(*) FROM fa_scan_results),
       (SELECT COUNT(*) FROM tenants),
       COALESCE((SELECT version_num FROM alembic_version ORDER BY version_num DESC LIMIT 1),'unknown')")"

  # Query production counts.
  parse_db_url "$FG_BACKUP_DB_URL"
  local prod_counts
  prod_counts="$(docker run --rm -e PGPASSWORD="$PG_PASSWORD" "$FG_BACKUP_DOCKER_IMAGE" \
    psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DBNAME" --no-password -tA -F '|' -c \
    "SELECT
       (SELECT COUNT(*) FROM fa_engagements),
       (SELECT COUNT(*) FROM fa_normalized_findings),
       (SELECT COUNT(*) FROM fa_engagement_audit_events),
       (SELECT COUNT(*) FROM fa_scan_results),
       (SELECT COUNT(*) FROM tenants),
       COALESCE((SELECT version_num FROM alembic_version ORDER BY version_num DESC LIMIT 1),'unknown')")"

  # Compare.
  local report_file="$FG_BACKUP_DIR/restore_report_$(ts_now_compact).json"
  python3 - "$report_file" "$file" "$target" "$prod_counts" "$scratch_counts" <<'PYEOF'
import json, sys
(_p, report_path, backup, target, prod_line, scratch_line) = sys.argv
labels = ["fa_engagements","fa_normalized_findings","fa_engagement_audit_events",
          "fa_scan_results","tenants","migration_version"]
prod = [v.strip() for v in prod_line.strip().split("|")]
scratch = [v.strip() for v in scratch_line.strip().split("|")]
prod_map = dict(zip(labels, prod))
scratch_map = dict(zip(labels, scratch))
mismatches = [k for k in labels if prod_map.get(k) != scratch_map.get(k)]
result = {
  "backup_file": backup,
  "scratch_container": target,
  "production_counts": prod_map,
  "scratch_counts": scratch_map,
  "mismatches": mismatches,
  "status": "PASS" if not mismatches else "FAIL",
}
with open(report_path, "w") as fh:
    json.dump(result, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(json.dumps(result, indent=2, sort_keys=True))
sys.exit(0 if not mismatches else 7)
PYEOF
  local rc=$?

  # Trap will destroy the scratch container.
  return $rc
}

# --- subcommand: drill -------------------------------------------------------

cmd_drill() {
  ensure_backup_dir
  local latest
  latest="$(ls -1t "$FG_BACKUP_DIR"/frostgate_*.dump 2>/dev/null | head -1 || true)"
  if [[ -z "$latest" ]]; then
    die 4 "no backup found in $FG_BACKUP_DIR — run 'fg_backup.sh backup' first"
  fi

  log "drill using $latest"
  local drill_stamp
  drill_stamp="$(date -u +%Y%m%d)"
  local evidence_dir="docs/governance/status"
  local evidence_file="$evidence_dir/restore_drill_evidence_${drill_stamp}.md"

  # Capture the restore output so we can append it to evidence.
  local drill_log
  drill_log="$(mktemp)"
  local rc=0
  cmd_restore "$latest" > "$drill_log" 2>&1 || rc=$?

  {
    echo ""
    echo "## Drill $(iso_now_utc)"
    echo ""
    echo "- Backup file: \`$(basename "$latest")\`"
    echo "- Result: $([[ $rc -eq 0 ]] && echo PASS || echo FAIL)"
    echo "- Operator: $FG_BACKUP_OPERATOR"
    echo ""
    echo '```json'
    cat "$drill_log"
    echo '```'
    echo ""
  } >> "$evidence_file"
  rm -f "$drill_log"

  log "drill evidence written to $evidence_file (result=$([[ $rc -eq 0 ]] && echo PASS || echo FAIL))"
  return $rc
}

# --- subcommand: status ------------------------------------------------------

cmd_status() {
  ensure_backup_dir
  python3 - "$FG_BACKUP_DIR" "$FG_BACKUP_RPO_WARN_HOURS" \
    "$FG_BACKUP_RTO_ESTIMATE_MINUTES" <<'PYEOF'
import json, os, sys, time
from datetime import datetime, timezone

backup_dir, rpo_warn_s, rto_est_s = sys.argv[1], sys.argv[2], sys.argv[3]
rpo_warn = float(rpo_warn_s)
rto_est = float(rto_est_s)

items = []
for name in sorted(os.listdir(backup_dir)):
    if not (name.startswith("frostgate_") and (name.endswith(".dump") or name.endswith(".dump.enc"))):
        continue
    path = os.path.join(backup_dir, name)
    try:
        st = os.stat(path)
    except FileNotFoundError:
        continue
    manifest = path + ".manifest.json"
    meta = {}
    if os.path.exists(manifest):
        try:
            meta = json.load(open(manifest))
        except Exception:
            meta = {}
    items.append((st.st_mtime, name, meta))

errors = []
if not items:
    payload = {
      "backup_status": "critical",
      "latest_backup": None,
      "latest_backup_age_hours": None,
      "latest_backup_verified": None,
      "backup_count": 0,
      "rpo_hours": None,
      "rpo_warning": True,
      "rto_estimate_minutes": rto_est,
      "last_drill_date": None,
      "errors": ["no backups found"],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    sys.exit(0)

items.sort(key=lambda x: x[0], reverse=True)
mtime, name, meta = items[0]
now = time.time()
age_hours = round((now - mtime) / 3600.0, 2)
verified = meta.get("verification_status") == "verified"

# Look for restore_drill_evidence_YYYYMMDD.md
drill_dir = os.path.join("docs", "governance", "status")
last_drill = None
if os.path.isdir(drill_dir):
    for f in sorted(os.listdir(drill_dir), reverse=True):
        if f.startswith("restore_drill_evidence_") and f.endswith(".md"):
            date_str = f[len("restore_drill_evidence_"):-len(".md")]
            try:
                datetime.strptime(date_str, "%Y%m%d")
                last_drill = f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:8]}"
                break
            except ValueError:
                pass

status = "ok"
rpo_warning = False
if age_hours > rpo_warn:
    status = "warning"
    rpo_warning = True
    errors.append(f"latest backup age ({age_hours}h) exceeds RPO warn threshold ({rpo_warn}h)")
if not verified:
    status = "warning" if status == "ok" else status
    errors.append("latest backup not verified")

payload = {
  "backup_status": status,
  "latest_backup": name,
  "latest_backup_age_hours": age_hours,
  "latest_backup_verified": verified,
  "backup_count": len(items),
  "rpo_hours": age_hours,
  "rpo_warning": rpo_warning,
  "rto_estimate_minutes": rto_est,
  "last_drill_date": last_drill,
  "errors": errors,
}
print(json.dumps(payload, indent=2, sort_keys=True))
PYEOF
}

# --- help --------------------------------------------------------------------

print_help() {
  cat >&2 <<EOF
fg_backup.sh — FrostGate production backup automation

Usage:
  fg_backup.sh backup  [--type scheduled|manual|pre-deploy|pre-migration|pre-maintenance|pre-engagement]
  fg_backup.sh verify  <backup-file>
  fg_backup.sh restore <backup-file> [--target-name <name>]
  fg_backup.sh list
  fg_backup.sh prune   [--dry-run]
  fg_backup.sh drill
  fg_backup.sh status

Configuration is loaded from scripts/backup/backup_config.sh (which reads
env vars). See docs/operators/backup_automation.md for the full guide.
EOF
}

# --- dispatch ----------------------------------------------------------------

main() {
  local cmd="${1:-}"
  [[ $# -gt 0 ]] && shift || true
  case "$cmd" in
    backup)   cmd_backup  "$@" ;;
    verify)   cmd_verify  "$@" ;;
    restore)  cmd_restore "$@" ;;
    list)     cmd_list    "$@" ;;
    prune)    cmd_prune   "$@" ;;
    drill)    cmd_drill   "$@" ;;
    status)   cmd_status  "$@" ;;
    ""|-h|--help) print_help ;;
    *) die 2 "unknown subcommand: $cmd" ;;
  esac
}

main "$@"
