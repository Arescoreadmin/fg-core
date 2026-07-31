#!/usr/bin/env bash
# =============================================================================
# FrostGate backup configuration.
#
# Sourced by scripts/backup/fg_backup.sh at startup. Every variable is
# documented here; environment values override the defaults set below.
#
# WARNING: never commit real credentials. This file only holds structural
# defaults; secrets (FG_BACKUP_DB_URL, FG_BACKUP_ENCRYPTION_KEY, offsite
# credentials) must come from the caller's environment.
# =============================================================================

# ----- Database connection ---------------------------------------------------
# FG_BACKUP_DB_URL: full postgres:// URL (required). Example:
#   postgresql://postgres:PASSWORD@host:PORT/railway
# The script parses host/port/user/db/password out of this URL.
: "${FG_BACKUP_DB_URL:=}"

# FG_BACKUP_DB_NAME: database name (default: railway) — used only when the
# URL does not contain a database path.
: "${FG_BACKUP_DB_NAME:=railway}"

# ----- Local storage ---------------------------------------------------------
# FG_BACKUP_DIR: local directory that stores dumps + manifests. The script
# creates it (mode 0700) if missing.
: "${FG_BACKUP_DIR:=/var/lib/frostgate/backups}"

# FG_BACKUP_TMP_DIR: workspace for temp pgpass files. Cleaned on EXIT.
: "${FG_BACKUP_TMP_DIR:=${TMPDIR:-/tmp}}"

# ----- Docker image (T1 proven method) --------------------------------------
# Do not downgrade — pg_dump 18.x is required for the PostgreSQL 18.4 server.
: "${FG_BACKUP_DOCKER_IMAGE:=pgvector/pgvector:pg18}"

# ----- Offsite storage abstraction ------------------------------------------
# FG_BACKUP_OFFSITE_PROVIDER: local|s3|r2|b2 (default: local).
# Provider-specific variables:
#   local:            FG_BACKUP_OFFSITE_LOCAL_PATH (required when provider=local)
#   s3/r2/b2:         FG_BACKUP_S3_BUCKET, FG_BACKUP_S3_ENDPOINT (r2/b2 only),
#                     FG_BACKUP_S3_PREFIX, plus AWS_ACCESS_KEY_ID /
#                     AWS_SECRET_ACCESS_KEY (or a working rclone remote).
: "${FG_BACKUP_OFFSITE_PROVIDER:=local}"
: "${FG_BACKUP_OFFSITE_LOCAL_PATH:=${FG_BACKUP_DIR}/offsite}"
: "${FG_BACKUP_S3_BUCKET:=}"
: "${FG_BACKUP_S3_ENDPOINT:=}"
: "${FG_BACKUP_S3_PREFIX:=frostgate/backups}"

# ----- Encryption -----------------------------------------------------------
# FG_BACKUP_ENCRYPT: true|false. When true the dump is encrypted with
# openssl aes-256-cbc pbkdf2 iter=600000 immediately after pg_dump completes.
# The script exits code 2 if encryption is enabled without a key.
: "${FG_BACKUP_ENCRYPT:=false}"
: "${FG_BACKUP_ENCRYPTION_KEY:=}"

# ----- Retention (used by fg_backup.sh prune) --------------------------------
: "${FG_BACKUP_RETAIN_HOURLY:=24}"
: "${FG_BACKUP_RETAIN_DAILY:=30}"
: "${FG_BACKUP_RETAIN_WEEKLY:=12}"
: "${FG_BACKUP_RETAIN_MONTHLY:=12}"
: "${FG_BACKUP_RETAIN_YEARLY:=7}"

# ----- RPO / RTO monitoring --------------------------------------------------
# FG_BACKUP_RPO_WARN_HOURS: age (hours) at which "status" flips to warning.
# Default 25 gives 1h slack against a daily schedule.
: "${FG_BACKUP_RPO_WARN_HOURS:=25}"

# FG_BACKUP_RTO_ESTIMATE_MINUTES: baseline restore estimate reported by
# "status". T1 measured 3.5 minutes end-to-end on a 1.7 MB DB.
: "${FG_BACKUP_RTO_ESTIMATE_MINUTES:=3.5}"

# ----- Identity --------------------------------------------------------------
# FG_BACKUP_OPERATOR: operator email recorded in the manifest.
: "${FG_BACKUP_OPERATOR:=unknown@frostgate.local}"

# ----- Output ----------------------------------------------------------------
# FG_BACKUP_JSON_OUTPUT: when true, status/summary go to stdout as JSON.
: "${FG_BACKUP_JSON_OUTPUT:=false}"

# ----- Railway metadata (informational, appears in manifest) -----------------
: "${FG_BACKUP_RAILWAY_PLAN:=hobby}"

export FG_BACKUP_DB_URL FG_BACKUP_DB_NAME FG_BACKUP_DIR FG_BACKUP_TMP_DIR
export FG_BACKUP_DOCKER_IMAGE
export FG_BACKUP_OFFSITE_PROVIDER FG_BACKUP_OFFSITE_LOCAL_PATH
export FG_BACKUP_S3_BUCKET FG_BACKUP_S3_ENDPOINT FG_BACKUP_S3_PREFIX
export FG_BACKUP_ENCRYPT FG_BACKUP_ENCRYPTION_KEY
export FG_BACKUP_RETAIN_HOURLY FG_BACKUP_RETAIN_DAILY FG_BACKUP_RETAIN_WEEKLY
export FG_BACKUP_RETAIN_MONTHLY FG_BACKUP_RETAIN_YEARLY
export FG_BACKUP_RPO_WARN_HOURS FG_BACKUP_RTO_ESTIMATE_MINUTES
export FG_BACKUP_OPERATOR FG_BACKUP_JSON_OUTPUT
export FG_BACKUP_RAILWAY_PLAN
