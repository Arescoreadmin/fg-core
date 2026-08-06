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
DRY_RUN="false"
FG_RESTORE_DECRYPT_TMP=""

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
  # Wipe any decrypted restore temp file — plaintext must never linger.
  if [[ -n "$FG_RESTORE_DECRYPT_TMP" && -f "$FG_RESTORE_DECRYPT_TMP" ]]; then
    shred -u "$FG_RESTORE_DECRYPT_TMP" 2>/dev/null || rm -f "$FG_RESTORE_DECRYPT_TMP"
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

# Print [DRY-RUN] line to stderr and return 0 when DRY_RUN=true; return 1 otherwise.
# Callers use this to short-circuit destructive actions.
dry_run_check() {
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[DRY-RUN] %s\n' "$*" >&2
    return 0
  fi
  return 1
}

# Generate an immutable backup ID of form FG-BKP-YYYYMMDD-NNNNN. The sequence
# number is derived from the MAX sequence already recorded in today's manifest
# files, plus one. This prevents ID reuse after pruning: if archive #00003 is
# deleted, the next issued ID is #00004 (from max=3), not #00003 (from count=2).
# Falls back to counting archives when no manifests are readable — but always
# tie-breaks toward "next value from max seen" so uniqueness holds.
generate_backup_id() {
  local date_str="${1:-$(date -u +%Y%m%d)}"
  local dir="${FG_BACKUP_DIR:-.}"

  # If the dir doesn't exist yet, we start at 00001.
  if [[ ! -d "$dir" ]]; then
    printf 'FG-BKP-%s-%05d' "$date_str" 1
    return 0
  fi

  # Use python for a robust manifest scan; falls back to filename-derived
  # sequence when a manifest is missing or unparseable so pruned-manifest
  # scenarios still don't cause reuse (filenames carry the timestamp, which
  # tie-breaks safely — a new backup written 'now' will always be strictly
  # newer than any pruned entry).
  local next
  next="$(python3 - "$dir" "$date_str" <<'PYEOF'
import glob, json, os, re, sys
backup_dir, date_str = sys.argv[1], sys.argv[2]

max_seq = 0
# 1) Scan today's manifest files for stored backup_id sequence numbers.
pattern = os.path.join(backup_dir, f"frostgate_{date_str}_*.manifest.json")
id_re = re.compile(r"^FG-BKP-\d{8}-(\d+)$")
for path in glob.glob(pattern):
    try:
        with open(path) as fh:
            data = json.load(fh)
        bkid = data.get("backup_id", "")
        m = id_re.match(bkid or "")
        if m:
            seq = int(m.group(1))
            if seq > max_seq:
                max_seq = seq
    except Exception:
        # Corrupt/unreadable manifest: fall through to filename count below.
        continue

# 2) Also count today's archive filenames as a lower-bound safety net so we
#    never return a sequence smaller than the number of same-day archives
#    currently on disk (protects against manifest loss where archives remain).
archive_count = 0
for ext in (".dump", ".dump.enc"):
    archive_count += len(glob.glob(os.path.join(
        backup_dir, f"frostgate_{date_str}_*{ext}")))

# Next sequence is one past the greater of (max manifest seq, archive count).
next_seq = max(max_seq, archive_count) + 1
print(next_seq)
PYEOF
  )"
  # Guard against empty / non-numeric python output.
  if ! [[ "$next" =~ ^[0-9]+$ ]]; then
    next=1
  fi
  printf 'FG-BKP-%s-%05d' "$date_str" "$next"
}

# HMAC-SHA256 sign a manifest file in place. Reads the file content and adds:
#   manifest_signature       = "sha256-hmac:<hex>" or "unsigned"
#   manifest_signing_key_id  = "env:FG_BACKUP_MANIFEST_HMAC_KEY" or "none"
#   manifest_verify_cmd      = documented verification command
# The signature is computed over the manifest JSON as it exists BEFORE the
# three signature fields are added — verify-manifest strips them and rehashes.
sign_manifest() {
  local manifest_path="${1:?manifest path required}"
  [[ -f "$manifest_path" ]] || return 1
  local hmac_key="${FG_BACKUP_MANIFEST_HMAC_KEY:-}"
  python3 - "$manifest_path" "$hmac_key" <<'PYEOF'
import hashlib, hmac, json, sys
path, key = sys.argv[1], sys.argv[2]
with open(path) as fh:
    data = json.load(fh)
# Strip any pre-existing signature fields before hashing so verify is stable.
for f in ("manifest_signature", "manifest_signing_key_id", "manifest_verify_cmd"):
    data.pop(f, None)
canonical = json.dumps(data, indent=2, sort_keys=True) + "\n"
if key:
    digest = hmac.new(key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    data["manifest_signature"] = f"sha256-hmac:{digest}"
    data["manifest_signing_key_id"] = "env:FG_BACKUP_MANIFEST_HMAC_KEY"
else:
    data["manifest_signature"] = "unsigned"
    data["manifest_signing_key_id"] = "none"
data["manifest_verify_cmd"] = (
    'fg_backup.sh verify-manifest <manifest.json>  # requires FG_BACKUP_MANIFEST_HMAC_KEY'
)
with open(path, "w") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write("\n")
PYEOF
}

# Verify a manifest's HMAC signature. Exits 0 on match or when signature is
# "unsigned". Exits 1 on mismatch (key present but hash differs), 2 on missing
# manifest file. Prints one PASS/FAIL/UNSIGNED line to stdout.
verify_manifest_impl() {
  local manifest_path="${1:?manifest path required}"
  if [[ ! -f "$manifest_path" ]]; then
    echo "FAIL manifest_signature: manifest not found: $manifest_path"
    return 2
  fi
  local hmac_key="${FG_BACKUP_MANIFEST_HMAC_KEY:-}"
  python3 - "$manifest_path" "$hmac_key" <<'PYEOF'
import hashlib, hmac, json, sys
path, key = sys.argv[1], sys.argv[2]
with open(path) as fh:
    data = json.load(fh)
stored = data.get("manifest_signature", "unsigned")
if stored == "unsigned":
    print("UNSIGNED manifest_signature: manifest is unsigned")
    sys.exit(0)
if not stored.startswith("sha256-hmac:"):
    print(f"FAIL manifest_signature: unknown signature scheme: {stored}")
    sys.exit(1)
if not key:
    print("FAIL manifest_signature: FG_BACKUP_MANIFEST_HMAC_KEY not set but manifest is signed")
    sys.exit(1)
stored_hex = stored[len("sha256-hmac:"):]
# Recompute by stripping signature fields.
copy = dict(data)
for f in ("manifest_signature", "manifest_signing_key_id", "manifest_verify_cmd"):
    copy.pop(f, None)
canonical = json.dumps(copy, indent=2, sort_keys=True) + "\n"
digest = hmac.new(key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
if hmac.compare_digest(digest, stored_hex):
    print("PASS manifest_signature")
    sys.exit(0)
print(f"FAIL manifest_signature: expected={stored_hex} actual={digest}")
sys.exit(1)
PYEOF
}

# Update the backup health dashboard JSON. Reads current state from the
# manifest directory and writes a fresh snapshot. Never fails the caller.
update_health_dashboard() {
  local outcome="${1:-ok}"   # ok | failed
  local drill_result="${2:-}" # optional "PASS"/"FAIL" when called from drill
  local dashboard_path="${FG_BACKUP_HEALTH_DASHBOARD:-artifacts/operations/backup_health.json}"
  local dashboard_dir
  dashboard_dir="$(dirname "$dashboard_path")"
  mkdir -p "$dashboard_dir" 2>/dev/null || return 0
  python3 - "$FG_BACKUP_DIR" "$dashboard_path" "$outcome" "$drill_result" \
    "${FG_BACKUP_RPO_WARN_HOURS:-25}" <<'PYEOF' || true
import json, os, sys, time
from datetime import datetime, timezone

backup_dir, dashboard_path, outcome, drill_result, rpo_warn_s = sys.argv[1:6]
rpo_warn = float(rpo_warn_s)

def iso_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

items = []
if os.path.isdir(backup_dir):
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
        items.append((st.st_mtime, name, path, meta))

items.sort(key=lambda x: x[0], reverse=True)

last_success = None
verification_failures = 0
checksum_failures = 0
durations = []
for mtime, name, path, meta in items:
    if not last_success and meta.get("verification_status") == "verified":
        last_success = {
            "backup_id": meta.get("backup_id"),
            "timestamp": meta.get("timestamp"),
            "size_bytes": meta.get("backup_size_bytes"),
            "verified": True,
            "encrypted": bool(meta.get("encrypted", False)),
            "offsite_uploaded": bool(meta.get("offsite_uploaded", False)),
        }
    if meta.get("verification_status") == "failed":
        verification_failures += 1
    d = meta.get("duration_seconds")
    if isinstance(d, (int, float)):
        durations.append(d)

now = time.time()
age_hours = None
if items:
    age_hours = round((now - items[0][0]) / 3600.0, 2)

# Look for restore drill evidence for last_restore_drill.
drill_dir = os.path.join("docs", "governance", "status")
last_drill = None
if os.path.isdir(drill_dir):
    for f in sorted(os.listdir(drill_dir), reverse=True):
        if f.startswith("restore_drill_evidence_") and f.endswith(".md"):
            date_str = f[len("restore_drill_evidence_"):-len(".md")]
            try:
                datetime.strptime(date_str, "%Y%m%d")
                last_drill = {
                    "date": f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:8]}",
                    "result": drill_result or "UNKNOWN",
                }
                break
            except ValueError:
                pass

# Retention buckets by age (thresholds match cmd_prune classification):
#   hourly < 25h, daily < 8d, weekly < 35d, monthly < 366d, else yearly.
def bucket_of(mtime):
    age = (now - mtime) / 3600.0
    if age < 25: return "hourly"
    if age < 24 * 8: return "daily"
    if age < 24 * 35: return "weekly"
    if age < 24 * 366: return "monthly"
    return "yearly"

buckets = {"hourly": 0, "daily": 0, "weekly": 0, "monthly": 0, "yearly": 0}
for mtime, name, path, meta in items:
    buckets[bucket_of(mtime)] += 1
oldest_backup = None
if items:
    oldest_mtime = min(x[0] for x in items)
    oldest_backup = datetime.fromtimestamp(oldest_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

rpo_ok = (age_hours is not None) and (age_hours <= rpo_warn)
status = "ok"
if outcome == "failed":
    status = "critical"
elif not items:
    status = "critical"
elif not rpo_ok:
    status = "warning"

payload = {
    "generated_at": iso_now(),
    "backup_status": status,
    "last_success": last_success,
    "last_failure": None if outcome == "ok" else {"timestamp": iso_now()},
    "backup_age_hours": age_hours,
    "rpo_hours": rpo_warn,
    "rpo_ok": rpo_ok,
    "verification_status": "verified" if last_success else "unverified",
    "last_restore_drill": last_drill,
    "backup_count": len(items),
    "retention": {
        "hourly_count": buckets["hourly"],
        "daily_count": buckets["daily"],
        "weekly_count": buckets["weekly"],
        "monthly_count": buckets["monthly"],
        "yearly_count": buckets["yearly"],
        "oldest_backup": oldest_backup,
    },
    "metrics": {
        "avg_backup_duration_seconds": int(sum(durations) / len(durations)) if durations else 0,
        "avg_restore_duration_seconds": 0,
        "last_verification_failures": verification_failures,
        "last_checksum_failures": checksum_failures,
    },
}
with open(dashboard_path, "w") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
    fh.write("\n")
PYEOF
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
      --dry-run) DRY_RUN="true"; shift ;;
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
  ensure_backup_dir
  load_offsite_provider

  local start_ts_iso start_epoch
  start_ts_iso="$(iso_now_utc)"
  start_epoch="$(date -u +%s)"

  local stamp basename dump_file manifest_file backup_id
  stamp="$(ts_now_compact)"
  basename="frostgate_${stamp}_${backup_type}.dump"
  dump_file="$FG_BACKUP_DIR/$basename"
  manifest_file="$FG_BACKUP_DIR/${basename}.manifest.json"
  backup_id="$(generate_backup_id "$(date -u +%Y%m%d)")"

  # Dry-run: don't touch pg_dump or docker. Just describe the planned action.
  if dry_run_check "backup id=$backup_id type=$backup_type would write $dump_file, provider=${FG_BACKUP_OFFSITE_PROVIDER:-local}"; then
    dry_run_check "would upload to ${FG_BACKUP_OFFSITE_PROVIDER:-local}:${basename}"
    return 0
  fi

  require_bin docker
  require_bin sha256sum

  parse_db_url "$FG_BACKUP_DB_URL"

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
  migration_version="$(psql_scalar 'SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1')"
  [[ -n "$migration_version" ]] || migration_version="unknown"
  db_version="$(psql_scalar 'SELECT version()')"
  [[ -n "$db_version" ]] || db_version="unknown"

  # Capture source row counts at backup time so restore validation can
  # compare against a frozen ground truth rather than live production
  # (which will drift as writes happen between backup and restore).
  # Missing tables are tolerated (report 0) so the field is always present.
  local source_row_counts_raw
  source_row_counts_raw="$(docker run --rm \
    -e PGPASSWORD="$PG_PASSWORD" \
    "$FG_BACKUP_DOCKER_IMAGE" \
    psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DBNAME" \
      --no-password -tA -c "
      SELECT 'fa_engagements='               || COALESCE((SELECT COUNT(*)::text FROM fa_engagements),               '0')
      UNION ALL SELECT 'fa_normalized_findings='       || COALESCE((SELECT COUNT(*)::text FROM fa_normalized_findings),       '0')
      UNION ALL SELECT 'fa_engagement_audit_events='   || COALESCE((SELECT COUNT(*)::text FROM fa_engagement_audit_events),   '0')
      UNION ALL SELECT 'fa_scan_results='              || COALESCE((SELECT COUNT(*)::text FROM fa_scan_results),              '0')
      UNION ALL SELECT 'tenants='                      || COALESCE((SELECT COUNT(*)::text FROM tenants),                      '0');
      " 2>/dev/null || true)"

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
  # unless provider returns hard error (1). The provider contract is 3-state:
  #   0 = success (bytes uploaded); set offsite_uploaded=true
  #   1 = hard failure (network/auth); fail the backup
  #   2 = skipped (not configured); leave offsite_uploaded=false, warn only
  local offsite_uploaded="false"
  local offsite_provider="${FG_BACKUP_OFFSITE_PROVIDER:-local}"
  local offsite_msg=""
  if [[ "$offsite_provider" != "none" ]]; then
    local upload_exit=0
    offsite_msg="$(upload_backup "$final_file" "$basename" 2>&1)" || upload_exit=$?
    if [[ "$upload_exit" -eq 0 ]]; then
      offsite_uploaded="true"
      log "offsite: $offsite_msg"
    elif [[ "$upload_exit" -eq 2 ]]; then
      # Skip: no credentials / provider not configured. Not a failure.
      offsite_uploaded="false"
      log "offsite upload skipped: $offsite_msg"
    else
      offsite_uploaded="false"
      log "offsite upload failed (exit $upload_exit): $offsite_msg"
      die 5 "offsite upload failed: $offsite_msg"
    fi
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
    "$FG_BACKUP_RAILWAY_PLAN" "$FG_BACKUP_SCRIPT_VERSION" "$backup_id" \
    "$source_row_counts_raw" <<'PYEOF'
import json, sys
(_prog, path, schema_v, start_iso, end_iso, btype, db_v, mig_v, size,
 checksum, storage, image, dump_ver, operator, encrypted, offsite_uploaded,
 offsite_provider, duration, plan, script_v, backup_id, source_counts_raw) = sys.argv

# Parse "table=N\ntable=N\n..." into a dict[str,int]. Non-integer values are
# stored as None so operator can still see the field was present.
source_row_counts = {}
for line in source_counts_raw.splitlines():
    line = line.strip()
    if not line or "=" not in line:
        continue
    k, _, v = line.partition("=")
    k = k.strip()
    v = v.strip()
    try:
        source_row_counts[k] = int(v)
    except ValueError:
        source_row_counts[k] = None

data = {
  "backup_id": backup_id,
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
  # Row counts captured at backup time so restore compares against the frozen
  # source-of-truth from when the dump was taken, not against a moving live DB.
  "source_row_counts": source_row_counts,
}
with open(path, "w") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write("\n")
PYEOF

  # Sign the manifest (HMAC-SHA256 or "unsigned" if key absent).
  sign_manifest "$manifest_file" || log "sign_manifest failed for $manifest_file (non-fatal)"

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
    # Re-sign after mutation so signature stays consistent with contents.
    sign_manifest "$manifest_file" || log "sign_manifest (post-verify) failed (non-fatal)"
  else
    log "post-backup verification FAILED for $final_file"
    update_health_dashboard "failed" ""
    die 6 "verify step failed after backup"
  fi

  # Upload the finalized manifest offsite AFTER verify + re-sign so the remote
  # copy reflects verification_status="verified" and the up-to-date signature.
  # Uploading before verify would leave the remote copy permanently marked as
  # "unverified" even though the local manifest is verified.
  if [[ "$offsite_provider" != "none" ]]; then
    local m_key
    m_key="$(basename "$manifest_file")"
    upload_backup "$manifest_file" "$m_key" >/dev/null 2>&1 || true
  fi

  # Retention.
  prune_backups_impl false >/dev/null 2>&1 || log "prune step reported issues (non-fatal here)"

  # Health dashboard snapshot.
  update_health_dashboard "ok" ""

  log "backup complete: $backup_id"

  # Emit summary.
  emit_backup_summary "$final_file" "$manifest_file" "$backup_type" "$checksum" \
    "$dump_size" "$duration" "$encrypted" "$offsite_uploaded" "$offsite_provider" "$backup_id"
}

emit_backup_summary() {
  local file="$1" manifest="$2" btype="$3" checksum="$4" size="$5" duration="$6"
  local encrypted="$7" offsite_uploaded="$8" offsite_provider="$9"
  local backup_id="${10:-}"
  if [[ "${FG_BACKUP_JSON_OUTPUT,,}" == "true" ]]; then
    python3 - "$file" "$manifest" "$btype" "$checksum" "$size" "$duration" \
      "$encrypted" "$offsite_uploaded" "$offsite_provider" "$backup_id" <<'PYEOF'
import json, sys
(_p, file, manifest, btype, checksum, size, duration, enc, off, prov, bid) = sys.argv
print(json.dumps({
  "result": "ok",
  "backup_id": bid or None,
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
  id            : $backup_id
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
  local rc=0
  verify_backup_impl "$file" || rc=$?
  # Also verify the manifest signature (does not change verify rc unless the
  # signature is present-but-wrong).
  local manifest="${file}.manifest.json"
  if [[ -f "$manifest" ]]; then
    local sig_rc=0
    verify_manifest_impl "$manifest" || sig_rc=$?
    if [[ "$sig_rc" != "0" ]]; then
      rc=$sig_rc
    fi
  fi
  update_health_dashboard "$([[ $rc -eq 0 ]] && echo ok || echo failed)" ""
  return "$rc"
}

cmd_verify_manifest() {
  local manifest="${1:-}"
  [[ -n "$manifest" ]] || die 2 "usage: fg_backup.sh verify-manifest <manifest.json>"
  verify_manifest_impl "$manifest"
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
    # Age-range classification for retention graduation. Thresholds:
    #   hourly:  age < 25h                (slack hour to avoid edge cases)
    #   daily:   25h  <= age < 8d
    #   weekly:  8d   <= age < 35d        (5 weeks)
    #   monthly: 35d  <= age < 366d
    #   yearly:  age  >= 366d
    # This separates "how old is this backup" (bucket classification) from
    # "how many to keep per bucket type" (retention counts), so an archive
    # graduates from hourly -> daily -> weekly -> monthly -> yearly as it ages
    # rather than being pruned while still competing for hourly slots.
    age = now - ts
    if age < timedelta(hours=25):
        return "hourly"
    if age < timedelta(days=8):
        return "daily"
    if age < timedelta(days=35):
        return "weekly"
    if age < timedelta(days=366):
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
      --dry-run) DRY_RUN="true"; shift ;;
      -h|--help) print_help; exit 0 ;;
      *) if [[ -z "$file" ]]; then file="$1"; else die 2 "unexpected: $1"; fi; shift ;;
    esac
  done
  [[ -n "$file" ]] || die 2 "usage: fg_backup.sh restore <backup-file> [--target-name <name>]"

  # Dry-run short-circuit: describe planned actions without any docker/db work.
  if [[ "$DRY_RUN" == "true" ]]; then
    local stamp rand planned_target scratch_port
    stamp="$(date -u +%Y%m%d)"
    rand="dryrun"
    planned_target="${target:-frostgate-restore-${stamp}-${rand}}"
    scratch_port="${FG_BACKUP_SCRATCH_PORT:-5434}"
    dry_run_check "restore backup=$file target=$planned_target port=$scratch_port"
    dry_run_check "would compare row counts across: fa_engagements, fa_normalized_findings, fa_engagement_audit_events, fa_scan_results, tenants, schema_migrations"
    dry_run_check "no scratch container will be created and no database will be touched"
    return 0
  fi

  [[ -f "$file" ]] || die 2 "backup file not found: $file"

  require_bin docker

  # Manifest lookup: prefer <file>.manifest.json (what we write); if file is
  # a .dump.enc and that manifest is missing, also try the plain-dump name
  # (defensive — some legacy layouts kept a single manifest per timestamp).
  local manifest="${file}.manifest.json"
  if [[ ! -f "$manifest" && "$file" == *.dump.enc ]]; then
    local alt_manifest="${file%.enc}.manifest.json"
    if [[ -f "$alt_manifest" ]]; then
      manifest="$alt_manifest"
    fi
  fi
  [[ -f "$manifest" ]] || die 2 "manifest not found: $manifest"
  local encrypted
  encrypted="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("encrypted", False))' "$manifest")"

  # Handle encrypted archives inline: decrypt to a temp file, register EXIT
  # cleanup, and continue with the decrypted copy as the restore source.
  # The original .dump.enc on disk is not touched.
  local restore_source="$file"
  local decrypt_tmp=""
  if [[ "$encrypted" == "True" || "$encrypted" == "true" ]]; then
    if [[ -z "${FG_BACKUP_ENCRYPTION_KEY:-}" ]]; then
      die 2 "encrypted archive requires FG_BACKUP_ENCRYPTION_KEY to restore"
    fi
    require_bin openssl
    decrypt_tmp="$(mktemp -p "$FG_BACKUP_TMP_DIR" .fg_restore.XXXXXX.dump)"
    # Register cleanup by extending the trap-visible state.
    FG_RESTORE_DECRYPT_TMP="$decrypt_tmp"
    log "decrypting $file → $decrypt_tmp (in tmpfs)"
    FG_BACKUP_ENCRYPTION_KEY="$FG_BACKUP_ENCRYPTION_KEY" \
      openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
        -pass env:FG_BACKUP_ENCRYPTION_KEY \
        -in "$file" -out "$decrypt_tmp"
    restore_source="$decrypt_tmp"
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
    -v "$(readlink -f "$restore_source"):/restore.dump:ro" \
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
       COALESCE((SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1),'unknown')")"

  # Compare scratch counts against the manifest's captured source_row_counts
  # (frozen at backup time) rather than against live production, which drifts
  # between the backup and this restore. If the manifest predates the
  # source-count capture (older backups), fall back to a live query with a
  # loud warning so the operator knows a false mismatch is possible.
  local expected_counts_source="manifest"
  local expected_line=""
  local fallback_note=""
  expected_line="$(python3 - "$manifest" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as fh:
    data = json.load(fh)
counts = data.get("source_row_counts") or {}
labels = ["fa_engagements","fa_normalized_findings","fa_engagement_audit_events",
          "fa_scan_results","tenants"]
if not counts or not all(l in counts for l in labels):
    # Signal to caller: fall back to live query.
    print("__MANIFEST_MISSING_SOURCE_COUNTS__")
else:
    parts = [str(counts.get(l, "")) for l in labels]
    parts.append(str(data.get("migration_version", "unknown")))
    print("|".join(parts))
PYEOF
)"
  if [[ "$expected_line" == "__MANIFEST_MISSING_SOURCE_COUNTS__" ]]; then
    log "WARNING: manifest predates source-count capture; comparing against current production (may produce false mismatches)"
    expected_counts_source="production_live"
    fallback_note="manifest predates source-count capture; live production queried instead"
    parse_db_url "$FG_BACKUP_DB_URL"
    expected_line="$(docker run --rm -e PGPASSWORD="$PG_PASSWORD" "$FG_BACKUP_DOCKER_IMAGE" \
      psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DBNAME" --no-password -tA -F '|' -c \
      "SELECT
         (SELECT COUNT(*) FROM fa_engagements),
         (SELECT COUNT(*) FROM fa_normalized_findings),
         (SELECT COUNT(*) FROM fa_engagement_audit_events),
         (SELECT COUNT(*) FROM fa_scan_results),
         (SELECT COUNT(*) FROM tenants),
         COALESCE((SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1),'unknown')")"
  fi

  # Compare.
  local report_file="$FG_BACKUP_DIR/restore_report_$(ts_now_compact).json"
  python3 - "$report_file" "$file" "$target" "$expected_line" "$scratch_counts" \
    "$expected_counts_source" "$fallback_note" <<'PYEOF'
import json, sys
(_p, report_path, backup, target, expected_line, scratch_line,
 expected_source, fallback_note) = sys.argv
labels = ["fa_engagements","fa_normalized_findings","fa_engagement_audit_events",
          "fa_scan_results","tenants","migration_version"]
expected = [v.strip() for v in expected_line.strip().split("|")]
scratch = [v.strip() for v in scratch_line.strip().split("|")]
expected_map = dict(zip(labels, expected))
scratch_map = dict(zip(labels, scratch))
mismatches = [k for k in labels if expected_map.get(k) != scratch_map.get(k)]
result = {
  "backup_file": backup,
  "scratch_container": target,
  "expected_counts": expected_map,
  "expected_counts_source": expected_source,
  "scratch_counts": scratch_map,
  "mismatches": mismatches,
  "status": "PASS" if not mismatches else "FAIL",
}
if fallback_note:
    result["note"] = fallback_note
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
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run) DRY_RUN="true"; shift ;;
      -h|--help) print_help; exit 0 ;;
      *) die 2 "unknown argument: $1" ;;
    esac
  done
  ensure_backup_dir
  # Find newest backup archive (encrypted or not). find + stat gives us a
  # portable sort-by-mtime that works with both .dump and .dump.enc extensions.
  local latest
  latest="$(find "$FG_BACKUP_DIR" -maxdepth 1 -type f \
    \( -name "frostgate_*.dump" -o -name "frostgate_*.dump.enc" \) \
    -printf '%T@\t%p\n' 2>/dev/null \
    | sort -rn | head -1 | cut -f2- || true)"
  if [[ -z "$latest" ]]; then
    die 4 "no backup found in $FG_BACKUP_DIR — run 'fg_backup.sh backup' first"
  fi

  local drill_stamp
  drill_stamp="$(date -u +%Y%m%d)"
  local evidence_dir="docs/governance/status"
  local evidence_file="$evidence_dir/restore_drill_evidence_${drill_stamp}.md"

  if dry_run_check "drill would use backup=$latest, evidence would be written to $evidence_file"; then
    return 0
  fi

  log "drill using $latest"

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

  local drill_result
  drill_result="$([[ $rc -eq 0 ]] && echo PASS || echo FAIL)"
  update_health_dashboard "$([[ $rc -eq 0 ]] && echo ok || echo failed)" "$drill_result"

  log "drill evidence written to $evidence_file (result=$drill_result)"
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

# --- subcommand: inventory ---------------------------------------------------

cmd_inventory() {
  ensure_backup_dir
  local drill_dir="docs/governance/status"
  python3 - "$FG_BACKUP_DIR" "$drill_dir" "${FG_BACKUP_JSON_OUTPUT:-false}" \
    "${FG_BACKUP_RPO_WARN_HOURS:-25}" <<'PYEOF'
import json, os, sys, time

backup_dir, drill_dir, json_out_s, rpo_warn_s = sys.argv[1:5]
json_out = json_out_s.lower() == "true"
rpo_warn = float(rpo_warn_s)

# Load all drill evidence files once so we can scan for backup_id references.
drill_texts = []
if os.path.isdir(drill_dir):
    for f in sorted(os.listdir(drill_dir)):
        if f.startswith("restore_drill_evidence_") and f.endswith(".md"):
            try:
                drill_texts.append(open(os.path.join(drill_dir, f)).read())
            except Exception:
                pass
all_drill_text = "\n".join(drill_texts)

def bucket_of(age_hours):
    # Thresholds match cmd_prune classification (age-range graduation).
    if age_hours < 25: return "hourly"
    if age_hours < 24 * 8: return "daily"
    if age_hours < 24 * 35: return "weekly"
    if age_hours < 24 * 366: return "monthly"
    return "yearly"

def fmt_size(n):
    if n is None:
        return "-"
    for unit in ("B","KB","MB","GB","TB"):
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"

def fmt_age(hours):
    if hours is None:
        return "-"
    if hours < 24:
        h = int(hours); m = int((hours - h) * 60)
        return f"{h}h {m}m"
    days = int(hours // 24); rem_h = int(hours - days*24)
    return f"{days}d {rem_h}h"

now = time.time()
items = []
if os.path.isdir(backup_dir):
    for name in sorted(os.listdir(backup_dir)):
        if not (name.startswith("frostgate_") and (name.endswith(".dump") or name.endswith(".dump.enc"))):
            continue
        path = os.path.join(backup_dir, name)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            continue
        manifest_path = path + ".manifest.json"
        meta = {}
        if os.path.exists(manifest_path):
            try:
                meta = json.load(open(manifest_path))
            except Exception:
                meta = {}
        age_hours = (now - st.st_mtime) / 3600.0
        bkid = meta.get("backup_id") or "-"
        drilled = (bkid != "-" and bkid in all_drill_text) or (name in all_drill_text)
        items.append({
            "backup_id": bkid,
            "file": name,
            "age_hours": age_hours,
            "verified": meta.get("verification_status") == "verified",
            "encrypted": bool(meta.get("encrypted", False)),
            "offsite_uploaded": bool(meta.get("offsite_uploaded", False)),
            "bucket": bucket_of(age_hours),
            "drilled": drilled,
            "size_bytes": st.st_size,
        })

items.sort(key=lambda x: x["age_hours"])

if json_out:
    print(json.dumps({"backups": items, "count": len(items)}, indent=2))
    sys.exit(0)

if not items:
    print("BACKUP INVENTORY")
    print("=" * 80)
    print("no backups found")
    sys.exit(0)

header = f"{'ID':<21} {'Age':<10} {'Verified':<9} {'Encrypted':<10} {'Offsite':<8} {'Bucket':<8} {'Drilled':<8} {'Size':<8}"
print("BACKUP INVENTORY")
print("=" * 85)
print(header)
print("-" * 85)
for it in items:
    print(f"{it['backup_id']:<21} {fmt_age(it['age_hours']):<10} "
          f"{('YES' if it['verified'] else 'NO'):<9} "
          f"{('YES' if it['encrypted'] else 'NO'):<10} "
          f"{('YES' if it['offsite_uploaded'] else 'NO'):<8} "
          f"{it['bucket']:<8} "
          f"{('YES' if it['drilled'] else 'NO'):<8} "
          f"{fmt_size(it['size_bytes']):<8}")
print("=" * 85)
oldest = fmt_age(max(x["age_hours"] for x in items))
latest = fmt_age(min(x["age_hours"] for x in items))
rpo_ok = min(x["age_hours"] for x in items) <= rpo_warn
print(f"Total: {len(items)} backups | Oldest: {oldest} | Latest: {latest} | RPO: {'OK' if rpo_ok else 'BREACH'}")
PYEOF
}

# --- subcommand: metrics -----------------------------------------------------

cmd_metrics() {
  ensure_backup_dir
  python3 - "$FG_BACKUP_DIR" "${FG_BACKUP_JSON_OUTPUT:-false}" \
    "${FG_BACKUP_RPO_WARN_HOURS:-25}" <<'PYEOF'
import json, os, sys, time

backup_dir, json_out_s, rpo_warn_s = sys.argv[1:4]
json_out = json_out_s.lower() == "true"
rpo_warn = float(rpo_warn_s)

items = []
if os.path.isdir(backup_dir):
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
        items.append((st.st_mtime, st.st_size, meta))

items.sort(key=lambda x: x[0], reverse=True)

now = int(time.time())
last_success_ts = 0
last_size = 0
last_duration = 0
verify_failures = 0
for mtime, size, meta in items:
    if meta.get("verification_status") == "verified" and not last_success_ts:
        last_success_ts = int(mtime)
        last_size = int(size)
        last_duration = int(meta.get("duration_seconds") or 0)
    if meta.get("verification_status") == "failed":
        verify_failures += 1

age_seconds = (now - last_success_ts) if last_success_ts else 0
rpo_ok = 1 if (last_success_ts and (age_seconds / 3600.0) <= rpo_warn) else 0
last_restore_duration = 0  # Placeholder — restore duration not persisted per-backup.

metrics = {
    "fg_backup_last_success_timestamp_seconds": last_success_ts,
    "fg_backup_age_seconds": age_seconds,
    "fg_backup_count": len(items),
    "fg_backup_size_bytes": last_size,
    "fg_backup_last_duration_seconds": last_duration,
    "fg_backup_last_restore_duration_seconds": last_restore_duration,
    "fg_backup_verification_failures_total": verify_failures,
    "fg_backup_rpo_ok": rpo_ok,
}

if json_out:
    print(json.dumps(metrics, indent=2, sort_keys=True))
    sys.exit(0)

help_meta = {
    "fg_backup_last_success_timestamp_seconds": ("gauge", "Unix timestamp of last successful backup"),
    "fg_backup_age_seconds": ("gauge", "Age of most recent backup in seconds"),
    "fg_backup_count": ("gauge", "Total number of backups in local storage"),
    "fg_backup_size_bytes": ("gauge", "Size of most recent backup in bytes"),
    "fg_backup_last_duration_seconds": ("gauge", "Duration of most recent backup in seconds"),
    "fg_backup_last_restore_duration_seconds": ("gauge", "Duration of most recent restore drill in seconds"),
    "fg_backup_verification_failures_total": ("counter", "Total verification failures (from manifests)"),
    "fg_backup_rpo_ok": ("gauge", "Whether RPO threshold is currently met (1=ok, 0=breached)"),
}
out = []
for k, v in metrics.items():
    kind, help_text = help_meta[k]
    out.append(f"# HELP {k} {help_text}")
    out.append(f"# TYPE {k} {kind}")
    out.append(f"{k} {v}")
    out.append("")
print("\n".join(out))
PYEOF
}

# --- help --------------------------------------------------------------------

print_help() {
  cat >&2 <<EOF
fg_backup.sh — FrostGate production backup automation

Usage:
  fg_backup.sh backup  [--type scheduled|manual|pre-deploy|pre-migration|pre-maintenance|pre-engagement] [--dry-run]
  fg_backup.sh verify           <backup-file>
  fg_backup.sh verify-manifest  <manifest.json>
  fg_backup.sh restore   <backup-file> [--target-name <name>] [--dry-run]
  fg_backup.sh list
  fg_backup.sh prune     [--dry-run]
  fg_backup.sh drill     [--dry-run]
  fg_backup.sh status
  fg_backup.sh inventory
  fg_backup.sh metrics

Configuration is loaded from scripts/backup/backup_config.sh (which reads
env vars). See docs/operators/backup_automation.md for the full guide.
EOF
}

# --- dispatch ----------------------------------------------------------------

main() {
  local cmd="${1:-}"
  [[ $# -gt 0 ]] && shift || true
  case "$cmd" in
    backup)            cmd_backup          "$@" ;;
    verify)            cmd_verify          "$@" ;;
    verify-manifest)   cmd_verify_manifest "$@" ;;
    restore)           cmd_restore         "$@" ;;
    list)              cmd_list            "$@" ;;
    prune)             cmd_prune           "$@" ;;
    drill)             cmd_drill           "$@" ;;
    status)            cmd_status          "$@" ;;
    inventory)         cmd_inventory       "$@" ;;
    metrics)           cmd_metrics         "$@" ;;
    ""|-h|--help) print_help ;;
    *) die 2 "unknown subcommand: $cmd" ;;
  esac
}

main "$@"
