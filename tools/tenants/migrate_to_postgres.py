"""
R7 migration: state/tenants.json → Postgres tenants table.

Run directly:
    python -m tools.tenants.migrate_to_postgres [--dry-run]

The migration is idempotent: re-runs skip already-migrated tenants.

Steps:
 1. Read state/tenants.json
 2. Validate every record
 3. Detect duplicate tenant IDs (defensive check)
 4. Detect malformed records
 5. Compare tenant_id references in api_keys table
 6. Create missing canonical tenant rows
 7. Log orphaned keys (keys with no matching tenant in JSON)
 8. Verify Postgres lookup for each migrated tenant
 9. Verify at least one credential prefix exists per tenant (informational)
10. Write migration ledger entry
11. Freeze JSON (write .frozen sentinel; stop new JSON writes)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("frostgate.migrate_to_postgres")

_MIGRATION_VERSION = "r7-v1"

# Resolve REGISTRY_PATH the same way registry.py does.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DOCKER_STATE = Path("/var/lib/frostgate/state")
_STATE_DIR = _DOCKER_STATE if _DOCKER_STATE.is_dir() else _PROJECT_ROOT / "state"
REGISTRY_PATH = Path(
    os.getenv("FG_TENANT_REGISTRY_PATH", str(_STATE_DIR / "tenants.json"))
)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class MigrationResult:
    tenants_found: int = 0
    tenants_created: int = 0
    tenants_skipped: int = 0
    tenants_failed: int = 0
    # Broken out for the readiness report; both also increment tenants_failed.
    tenants_duplicate: int = 0
    tenants_malformed: int = 0
    warnings: List[str] = field(default_factory=list)
    orphaned_key_tenant_ids: List[str] = field(default_factory=list)
    status: str = "running"
    error: Optional[str] = None
    # Set by run_migration for use in the dry-run readiness report.
    source_fingerprint: Optional[str] = None
    generated_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Sentinel helpers
# ---------------------------------------------------------------------------


def is_json_frozen() -> bool:
    """True if the .frozen sentinel file exists next to tenants.json."""
    return REGISTRY_PATH.with_suffix(".frozen").exists()


def _freeze_json(checksum: str) -> None:
    sentinel = REGISTRY_PATH.with_suffix(".frozen")
    sentinel.write_text(
        json.dumps(
            {
                "frozen_at": _now_iso(),
                "checksum": checksum,
                "migration_version": _MIGRATION_VERSION,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    log.info("tenant_registry_frozen sentinel=%s", sentinel)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Ledger writer
# ---------------------------------------------------------------------------


def _write_ledger(
    engine: Any, result: MigrationResult, checksum: Optional[str]
) -> None:
    from sqlalchemy import text

    ledger_id = uuid.uuid4().hex
    now = _now_iso()
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO tenant_migration_ledger (
                        ledger_id, run_at, source, source_checksum,
                        tenants_found, tenants_created, tenants_skipped, tenants_failed,
                        warnings, status, completed_at
                    ) VALUES (
                        :lid, :now, :src, :csum,
                        :found, :created, :skipped, :failed,
                        :warnings, :status, :completed_at
                    )
                    """
                ),
                {
                    "lid": ledger_id,
                    "now": now,
                    "src": "tenants.json",
                    "csum": checksum,
                    "found": result.tenants_found,
                    "created": result.tenants_created,
                    "skipped": result.tenants_skipped,
                    "failed": result.tenants_failed,
                    "warnings": json.dumps(result.warnings),
                    "status": result.status,
                    "completed_at": now,
                },
            )
        log.info("migration_ledger_written ledger_id=%s", ledger_id)
    except Exception as exc:
        log.warning("migration_ledger_write_failed error=%s", exc)


# ---------------------------------------------------------------------------
# Main migration function
# ---------------------------------------------------------------------------


def run_migration(
    engine: Any = None,
    *,
    dry_run: bool = False,
    stop_json_writes: bool = True,
) -> MigrationResult:
    """
    Execute the R7 migration sequence.

    Parameters
    ----------
    engine:
        SQLAlchemy engine.  If None, resolved via api.db.get_engine().
    dry_run:
        When True, validate and report but do not write to Postgres or freeze.
    stop_json_writes:
        When True (default), write .frozen sentinel after a successful migration.
    """
    result = MigrationResult()

    # Resolve engine.
    if engine is None:
        try:
            from api.db import get_engine

            engine = get_engine()
        except Exception as exc:
            result.status = "error"
            result.error = f"Cannot obtain DB engine: {exc}"
            return result

    # Step 0: skip non-Postgres environments.
    if engine.dialect.name != "postgresql":
        result.status = "skipped"
        result.warnings.append(
            f"Non-Postgres dialect ({engine.dialect.name!r}); migration skipped."
        )
        log.info("migration_skipped dialect=%s", engine.dialect.name)
        return result

    from api.tenant_repository import TenantRepository
    from sqlalchemy import text

    repo = TenantRepository(engine)

    # Step 1: read JSON file.
    if not REGISTRY_PATH.exists():
        log.info("migration_no_json_file path=%s", REGISTRY_PATH)
        result.status = "complete"
        _write_ledger(engine, result, None)
        return result

    raw_bytes = REGISTRY_PATH.read_bytes()
    checksum = hashlib.sha256(raw_bytes).hexdigest()

    try:
        raw_data: Dict[str, Any] = json.loads(raw_bytes)
    except json.JSONDecodeError as exc:
        result.status = "error"
        result.error = f"tenants.json is not valid JSON: {exc}"
        return result

    if not isinstance(raw_data, dict):
        result.status = "error"
        result.error = "tenants.json root must be a JSON object"
        return result

    # Steps 2–4: validate records; detect duplicates and malformed entries.
    seen_ids: set = set()
    valid_records: Dict[str, Dict[str, Any]] = {}

    for tenant_id, payload in raw_data.items():
        # Step 3: duplicate detection.
        if tenant_id in seen_ids:
            warn = f"Duplicate tenant_id in JSON (skipping second occurrence): {tenant_id!r}"
            result.warnings.append(warn)
            result.tenants_duplicate += 1
            result.tenants_failed += 1
            log.warning(warn)
            continue
        seen_ids.add(tenant_id)

        # Step 4: malformed record detection.
        if not tenant_id or not isinstance(tenant_id, str):
            warn = f"Malformed tenant_id (empty or non-string): {tenant_id!r}"
            result.warnings.append(warn)
            result.tenants_malformed += 1
            result.tenants_failed += 1
            continue

        if not isinstance(payload, dict):
            warn = f"Tenant {tenant_id!r} has non-object payload ({type(payload).__name__}) — skipping"
            result.warnings.append(warn)
            result.tenants_malformed += 1
            result.tenants_failed += 1
            continue

        raw_name = payload.get("name") or payload.get("display_name")
        name = raw_name if isinstance(raw_name, str) else ""
        if not name or not name.strip():
            warn = f"Tenant {tenant_id!r} has empty name — skipping"
            result.warnings.append(warn)
            result.tenants_malformed += 1
            result.tenants_failed += 1
            continue

        valid_records[tenant_id] = payload

    result.tenants_found = len(raw_data)

    # Step 5: detect orphaned api_keys (keys whose tenant_id is not in JSON).
    try:
        with engine.connect() as conn:
            key_rows = conn.execute(
                text(
                    """
                    SELECT DISTINCT tenant_id FROM api_keys
                    WHERE enabled IS TRUE AND tenant_id IS NOT NULL
                    """
                )
            ).fetchall()
        key_tenant_ids = {r[0] for r in key_rows if r[0]}
        orphaned = key_tenant_ids - set(raw_data.keys())
        if orphaned:
            result.orphaned_key_tenant_ids = sorted(orphaned)
            warn = f"Orphaned api_key tenant_ids (not in JSON): {sorted(orphaned)}"
            result.warnings.append(warn)
            log.warning(warn)
    except Exception as exc:
        # api_keys table may not exist in test/minimal envs; non-fatal.
        result.warnings.append(f"Could not query api_keys table: {exc}")
        log.warning("orphan_check_failed error=%s", exc)

    # Steps 6–9: upsert each valid tenant.
    for tenant_id, payload in valid_records.items():
        name = (payload.get("name") or payload.get("display_name") or tenant_id).strip()
        original_created_at = payload.get("created_at")
        status = payload.get("status", "active")
        # Map JSON statuses to canonical lifecycle_states.
        if status == "revoked":
            lifecycle_state = "archived"
        elif status in {"active", "suspended", "archived", "failed", "validating"}:
            lifecycle_state = status
        else:
            lifecycle_state = "active"

        if dry_run:
            result.tenants_created += 1  # report as "would create"
            continue

        try:
            _row, created = repo.upsert(
                tenant_id=tenant_id,
                display_name=name,
                lifecycle_state=lifecycle_state,
                migration_source="tenants.json",
                migration_version=_MIGRATION_VERSION,
                original_created_at=original_created_at,
            )
            if created:
                result.tenants_created += 1
                log.info("tenant_migrated tenant_id=%s", tenant_id)
            else:
                result.tenants_skipped += 1
                log.debug("tenant_already_exists tenant_id=%s", tenant_id)

        except Exception as exc:
            warn = f"Failed to upsert tenant {tenant_id!r}: {exc}"
            result.warnings.append(warn)
            result.tenants_failed += 1
            log.error(warn)
            continue

        # Step 8: verify Postgres lookup.
        try:
            verified = repo._pg_get(tenant_id)
            if verified is None:
                warn = f"Post-upsert verification failed for {tenant_id!r}: not found in Postgres"
                result.warnings.append(warn)
                log.error(warn)
        except Exception as exc:
            warn = f"Post-upsert verification error for {tenant_id!r}: {exc}"
            result.warnings.append(warn)
            log.error(warn)

        # Step 9: credential prefix check (informational).
        try:
            prefixes = repo.credential_prefixes(tenant_id)
            if not prefixes:
                log.debug("no_credential_prefixes tenant_id=%s", tenant_id)
        except Exception:
            pass  # non-fatal

    # Determine final status.
    if result.tenants_failed == 0:
        result.status = "complete"
    else:
        result.status = "partial"

    if dry_run:
        result.status = "dry_run"
        result.source_fingerprint = checksum
        result.generated_at = _now_iso()
        return result

    # Step 10: write ledger entry.
    _write_ledger(engine, result, checksum)

    # Step 11: freeze JSON if all tenants migrated successfully.
    # Re-read the JSON to catch tenants written between the initial snapshot
    # (step 1) and now.  Any new arrivals are upserted before the sentinel
    # is written so the frozen file is consistent with Postgres.
    if stop_json_writes and result.status == "complete":
        try:
            current_bytes = (
                REGISTRY_PATH.read_bytes() if REGISTRY_PATH.exists() else b"{}"
            )
            current_data: Dict[str, Any] = json.loads(current_bytes)
            new_tenant_ids = set(current_data.keys()) - set(valid_records.keys())
            if new_tenant_ids:
                warn = (
                    f"Late-arriving tenants detected before freeze "
                    f"(written after initial snapshot): {sorted(new_tenant_ids)}"
                )
                result.warnings.append(warn)
                log.warning(warn)
                for late_id in new_tenant_ids:
                    late_payload = current_data[late_id]
                    if not isinstance(late_payload, dict):
                        continue
                    late_name = (
                        (
                            late_payload.get("name")
                            or late_payload.get("display_name")
                            or late_id
                        ).strip()
                        if isinstance(
                            late_payload.get("name")
                            or late_payload.get("display_name")
                            or late_id,
                            str,
                        )
                        else late_id
                    )
                    try:
                        repo.upsert(
                            tenant_id=late_id,
                            display_name=late_name,
                            migration_source="tenants.json.late",
                            migration_version=_MIGRATION_VERSION,
                            original_created_at=late_payload.get("created_at"),
                        )
                        log.info("late_tenant_migrated tenant_id=%s", late_id)
                    except Exception as exc:
                        result.warnings.append(
                            f"Late-arrival upsert failed for {late_id!r}: {exc}"
                        )
            # Use the current checksum for the freeze sentinel.
            current_checksum = __import__("hashlib").sha256(current_bytes).hexdigest()
            _freeze_json(current_checksum)
        except Exception as exc:
            result.warnings.append(f"Could not write freeze sentinel: {exc}")
            log.warning("freeze_sentinel_failed error=%s", exc)

    return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _print_readiness_report(result: MigrationResult) -> None:
    """Print a human-readable migration readiness report to stdout."""
    ready = result.tenants_failed == 0 and result.error is None
    print()
    print("Migration Readiness Report")
    print("==========================")
    print()
    print(f"JSON tenants discovered : {result.tenants_found}")
    print(f"Duplicate tenant IDs    : {result.tenants_duplicate}")
    print(f"Malformed records       : {result.tenants_malformed}")
    print(f"Would insert            : {result.tenants_created}")
    print(f"Would skip (existing)   : {result.tenants_skipped}")
    print(f"Orphaned api_keys       : {len(result.orphaned_key_tenant_ids)}")
    print()
    if result.source_fingerprint:
        print(f"Source fingerprint      : {result.source_fingerprint}")
    if result.generated_at:
        print(f"Generated               : {result.generated_at}")
    print()
    if result.warnings:
        print(f"Warnings ({len(result.warnings)}):")
        for w in result.warnings:
            print(f"  ⚠  {w}")
        print()
    status_line = (
        "✅ READY" if ready else "❌ NOT READY — resolve warnings before proceeding"
    )
    print(f"Verdict: {status_line}")
    print()


def _write_readiness_artifact(result: MigrationResult, out_path: Path) -> None:
    """Write the readiness report as a JSON artifact for archival."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "report_type": "r7_migration_readiness",
        "status": result.status,
        "source_fingerprint": result.source_fingerprint,
        "generated_at": result.generated_at,
        "tenants_found": result.tenants_found,
        "tenants_duplicate": result.tenants_duplicate,
        "tenants_malformed": result.tenants_malformed,
        "tenants_would_insert": result.tenants_created,
        "tenants_would_skip": result.tenants_skipped,
        "tenants_failed": result.tenants_failed,
        "orphaned_key_tenant_ids": result.orphaned_key_tenant_ids,
        "warnings": result.warnings,
        "ready": result.tenants_failed == 0 and result.error is None,
    }
    if result.error:
        artifact["error"] = result.error
    out_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    log.info("readiness_artifact_written path=%s", out_path)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = argparse.ArgumentParser(
        description="R7 migration: tenants.json → Postgres"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and report without writing to Postgres",
    )
    parser.add_argument(
        "--report-out",
        metavar="PATH",
        default=None,
        help=(
            "Write the readiness report JSON artifact to this path "
            "(default when --dry-run: artifacts/migration/r7_readiness_<timestamp>.json)"
        ),
    )
    args = parser.parse_args()

    result = run_migration(dry_run=args.dry_run)

    if args.dry_run:
        _print_readiness_report(result)

        # Determine artifact path.
        ts = (result.generated_at or _now_iso()).replace(":", "").replace("+", "Z")[:18]
        default_path = (
            Path(__file__).resolve().parents[2]
            / "artifacts"
            / "migration"
            / f"r7_readiness_{ts}.json"
        )
        artifact_path = Path(args.report_out) if args.report_out else default_path
        _write_readiness_artifact(result, artifact_path)
        print(f"Artifact written: {artifact_path}")
    else:
        output = {
            "status": result.status,
            "tenants_found": result.tenants_found,
            "tenants_created": result.tenants_created,
            "tenants_skipped": result.tenants_skipped,
            "tenants_failed": result.tenants_failed,
            "warnings": result.warnings,
            "orphaned_key_tenant_ids": result.orphaned_key_tenant_ids,
        }
        if result.error:
            output["error"] = result.error
        print(json.dumps(output, indent=2))

    sys.exit(0 if result.status in {"complete", "skipped", "dry_run"} else 1)
