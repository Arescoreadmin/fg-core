from __future__ import annotations

import importlib
import logging
import os
import sqlite3
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path
from typing import Optional

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from api.config.paths import STATE_DIR  # required by tests (must appear in-source)

logger = logging.getLogger("frostgate")

# ---------------------------------------------------------------------
# SQLite path contract
# ---------------------------------------------------------------------


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _resolve_sqlite_path(path: str | None = None) -> str:
    """
    Contract behavior:
    - explicit arg wins
    - env FG_SQLITE_PATH
    - prod/staging defaults to /var/lib/frostgate/state/frostgate.db
    - test defaults repo-local (Path.cwd()/fg-test.db)
    - dev defaults STATE_DIR/frostgate.db (STATE_DIR must be referenced)
    """
    if path and str(path).strip():
        return str(Path(path).expanduser())

    env_path = (os.getenv("FG_SQLITE_PATH") or "").strip() or (
        os.getenv("SQLITE_PATH") or ""
    ).strip()
    if env_path:
        return str(Path(env_path).expanduser())

    env = (os.getenv("FG_ENV") or "dev").strip().lower()
    if env in {"production", "prod", "staging"}:
        return "/var/lib/frostgate/state/frostgate.db"

    if env == "test":
        return str(Path.cwd() / "fg-test.db")

    # dev default uses STATE_DIR (tests look for this symbol in-source)
    return str(Path(STATE_DIR) / "frostgate.db")


def _sqlite_url(sqlite_path: str) -> str:
    p = Path(sqlite_path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite+pysqlite:///{p}"


def _db_url(*, sqlite_path: Optional[str] = None) -> str:
    """
    Resolve SQLAlchemy URL.
    Explicit sqlite_path wins (used by tests/tools that must force sqlite);
    otherwise prefer FG_DB_URL when set.
    """
    if sqlite_path and str(sqlite_path).strip():
        return _sqlite_url(_resolve_sqlite_path(sqlite_path))

    db_url = (os.getenv("FG_DB_URL") or "").strip()
    if db_url:
        return db_url

    resolved = _resolve_sqlite_path(sqlite_path)
    return _sqlite_url(resolved)


# ---------------------------------------------------------------------
# Engine + sessionmaker cache
# ---------------------------------------------------------------------

_ENGINE: Engine | None = None
_SessionLocal: sessionmaker | None = None


def reset_engine_cache() -> None:
    global _ENGINE, _SessionLocal
    if _ENGINE is not None:
        try:
            _ENGINE.dispose()
        except Exception:
            pass
    _ENGINE = None
    _SessionLocal = None


def get_engine(*, sqlite_path: Optional[str] = None) -> Engine:
    global _ENGINE, _SessionLocal
    if _ENGINE is not None:
        return _ENGINE

    url = _db_url(sqlite_path=sqlite_path)
    _ENGINE = create_engine(url, future=True, pool_pre_ping=True)
    _SessionLocal = sessionmaker(
        bind=_ENGINE, autocommit=False, autoflush=False, future=True
    )

    if url.startswith("sqlite"):
        logger.info("sqlite_db=%s", url.split("///", 1)[-1])
    else:
        logger.info("db_url=%s", url.split("@", 1)[-1] if "@" in url else url)

    return _ENGINE


def get_sessionmaker(*, sqlite_path: Optional[str] = None) -> sessionmaker:
    global _SessionLocal
    if _SessionLocal is not None:
        return _SessionLocal
    get_engine(sqlite_path=sqlite_path)
    assert _SessionLocal is not None
    return _SessionLocal


# ---------------------------------------------------------------------
# Model import + Base resolution (deterministic)
# ---------------------------------------------------------------------


def _ensure_models_imported() -> None:
    """
    Import model module(s) so Base.metadata is populated.
    """
    importlib.import_module("api.db_models")
    importlib.import_module("api.db_models_cp_v2")


def _get_base():
    from api.db_models import Base  # noqa: F401 (explicit import by design)

    return Base


# ---------------------------------------------------------------------
# SQLite low-level schema enforcers (sqlite3 direct)
# ---------------------------------------------------------------------


def _sqlite_table_exists(con: sqlite3.Connection, name: str) -> bool:
    row = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return row is not None


def _sqlite_cols(con: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}


def _sqlite_add_col_if_missing(
    con: sqlite3.Connection, table: str, col: str, decl: str
) -> None:
    cols = _sqlite_cols(con, table)
    if col not in cols:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")


def _ensure_api_keys_sqlite(sqlite_path: str) -> None:
    """
    This project mints/verifies API keys via sqlite3 in api/auth_scopes.py.
    That means init_db() MUST ensure api_keys exists (and auto-migrate columns)
    in the sqlite file chosen by FG_SQLITE_PATH or passed sqlite_path.
    """
    con = sqlite3.connect(sqlite_path)
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA foreign_keys=ON")

        if not _sqlite_table_exists(con, "api_keys"):
            con.execute(
                """
                CREATE TABLE api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    prefix TEXT NOT NULL,
                    key_hash TEXT NOT NULL,
                    scopes_csv TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    tenant_id TEXT,
                    created_at INTEGER,
                    last_used_at INTEGER,
                    expires_at INTEGER,
                    hash_alg TEXT,
                    hash_params TEXT,
                    key_lookup TEXT
                )
                """
            )

        _sqlite_add_col_if_missing(con, "api_keys", "hash_alg", "TEXT")
        _sqlite_add_col_if_missing(con, "api_keys", "hash_params", "TEXT")
        _sqlite_add_col_if_missing(con, "api_keys", "key_lookup", "TEXT")
        con.commit()
    finally:
        con.close()


def _ensure_connectors_sqlite(sqlite_path: str) -> None:
    """
    Ensure connector control-plane tables exist in sqlite (dev/test).
    """
    con = sqlite3.connect(sqlite_path)
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA foreign_keys=ON")

        con.execute(
            """
            CREATE TABLE IF NOT EXISTS connectors_tenant_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                connector_id TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                config_hash TEXT NOT NULL,
                last_success_at TEXT,
                last_error_code TEXT,
                failure_count INTEGER NOT NULL DEFAULT 0,
                updated_by TEXT NOT NULL DEFAULT 'unknown',
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(tenant_id, connector_id)
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS connectors_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                connector_id TEXT NOT NULL,
                credential_id TEXT NOT NULL DEFAULT 'primary',
                principal_id TEXT NOT NULL,
                auth_mode TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                kek_version TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                revoked_at TEXT
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS connectors_audit_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                connector_id TEXT NOT NULL,
                action TEXT NOT NULL,
                params_hash TEXT NOT NULL,
                actor TEXT NOT NULL,
                request_id TEXT NOT NULL DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Backfill columns if older sqlite file exists.
        _sqlite_add_col_if_missing(
            con, "connectors_tenant_state", "last_success_at", "TEXT"
        )
        _sqlite_add_col_if_missing(
            con, "connectors_tenant_state", "last_error_code", "TEXT"
        )
        _sqlite_add_col_if_missing(
            con,
            "connectors_tenant_state",
            "failure_count",
            "INTEGER NOT NULL DEFAULT 0",
        )
        _sqlite_add_col_if_missing(
            con,
            "connectors_credentials",
            "credential_id",
            "TEXT NOT NULL DEFAULT 'primary'",
        )

        # -----------------------------------------------------------------
        # Idempotency table (dedicated, not audit ledger abuse)
        # -----------------------------------------------------------------
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS connectors_idempotency (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                connector_id TEXT NOT NULL,
                action TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                response_hash TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT NOT NULL,
                UNIQUE(tenant_id, connector_id, action, idempotency_key)
            )
            """
        )
        con.executescript(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS uq_connectors_idempotency_key
                ON connectors_idempotency (tenant_id, connector_id, action, idempotency_key);

            CREATE INDEX IF NOT EXISTS ix_connectors_idempotency_expiry
                ON connectors_idempotency (expires_at);
            """
        )

        con.commit()
    finally:
        con.close()


# ---------------------------------------------------------------------
# SQLite best-effort migration helpers (SQLAlchemy conn)
# ---------------------------------------------------------------------


def _sqlite_add_column_if_missing(conn, table: str, col: str, col_type: str) -> None:
    existing = {r[1] for r in conn.exec_driver_sql(f"PRAGMA table_info({table})")}
    if col not in existing:
        conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")


def _auto_migrate_sqlite(engine: Engine) -> None:
    """
    Best-effort sqlite migrations for legacy test DBs. Keep bounded and safe.
    """
    with engine.begin() as conn:
        tables = {
            r[0]
            for r in conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }

        if "api_keys" in tables:
            _sqlite_add_column_if_missing(conn, "api_keys", "hash_alg", "TEXT")
            _sqlite_add_column_if_missing(conn, "api_keys", "hash_params", "TEXT")
            _sqlite_add_column_if_missing(conn, "api_keys", "key_lookup", "TEXT")

        if "security_audit_log" in tables:
            _sqlite_add_column_if_missing(
                conn, "security_audit_log", "chain_id", "TEXT DEFAULT 'global'"
            )
            _sqlite_add_column_if_missing(
                conn, "security_audit_log", "prev_hash", "TEXT DEFAULT 'GENESIS'"
            )
            _sqlite_add_column_if_missing(
                conn, "security_audit_log", "entry_hash", "TEXT"
            )

        if "agent_enrollment_tokens" in tables:
            _sqlite_add_column_if_missing(
                conn, "agent_enrollment_tokens", "created_by", "TEXT DEFAULT 'unknown'"
            )
            _sqlite_add_column_if_missing(
                conn, "agent_enrollment_tokens", "reason", "TEXT DEFAULT 'unspecified'"
            )
            _sqlite_add_column_if_missing(
                conn, "agent_enrollment_tokens", "ticket", "TEXT"
            )

        if "agent_device_keys" in tables:
            _sqlite_add_column_if_missing(
                conn, "agent_device_keys", "hmac_secret_enc", "TEXT DEFAULT ''"
            )

        # Config control-plane tables
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS config_versions (
                id INTEGER PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                config_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                created_by TEXT,
                config_json JSON NOT NULL DEFAULT '{}',
                config_json_canonical TEXT NOT NULL,
                parent_hash TEXT,
                CONSTRAINT uq_config_versions_tenant_hash UNIQUE (tenant_id, config_hash)
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS tenant_config_active (
                tenant_id TEXT PRIMARY KEY,
                active_config_hash TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            """
        )

        if "decisions" in tables:
            _sqlite_add_column_if_missing(
                conn, "decisions", "config_hash", "TEXT DEFAULT 'legacy_config_hash'"
            )

            tenant_rows = conn.exec_driver_sql(
                "SELECT DISTINCT tenant_id FROM decisions WHERE tenant_id IS NOT NULL"
            ).fetchall()
            for row in tenant_rows:
                tenant_id = row[0]
                canonical = '{"legacy":true}'
                legacy_hash = "legacy_config_hash"
                conn.exec_driver_sql(
                    """
                    INSERT OR IGNORE INTO config_versions(
                        tenant_id, config_hash, created_by, config_json, config_json_canonical
                    ) VALUES (:tenant_id, :config_hash, 'migration', '{"legacy":true}', :canonical)
                    """,
                    {
                        "tenant_id": tenant_id,
                        "config_hash": legacy_hash,
                        "canonical": canonical,
                    },
                )
                conn.exec_driver_sql(
                    """
                    UPDATE decisions
                    SET config_hash = :config_hash
                    WHERE tenant_id = :tenant_id AND (config_hash IS NULL OR config_hash = '')
                    """,
                    {"tenant_id": tenant_id, "config_hash": legacy_hash},
                )
                conn.exec_driver_sql(
                    """
                    INSERT OR IGNORE INTO tenant_config_active(tenant_id, active_config_hash)
                    VALUES (:tenant_id, :config_hash)
                    """,
                    {"tenant_id": tenant_id, "config_hash": legacy_hash},
                )

            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_decisions_tenant_config_created ON decisions(tenant_id, config_hash, created_at)"
            )

        if "rag_documents" in tables:
            _sqlite_add_column_if_missing(conn, "rag_documents", "version_id", "TEXT")
            _sqlite_add_column_if_missing(conn, "rag_documents", "source_hash", "TEXT")
            _sqlite_add_column_if_missing(
                conn, "rag_documents", "normalized_source_hash", "TEXT"
            )
            _sqlite_add_column_if_missing(
                conn, "rag_documents", "version_number", "INTEGER NOT NULL DEFAULT 1"
            )
            _sqlite_add_column_if_missing(
                conn, "rag_documents", "is_current", "INTEGER NOT NULL DEFAULT 1"
            )
            _sqlite_add_column_if_missing(
                conn,
                "rag_documents",
                "ingestion_status",
                "TEXT NOT NULL DEFAULT 'indexed'",
            )
            _sqlite_add_column_if_missing(
                conn, "rag_documents", "quarantine_reason", "TEXT"
            )
            _sqlite_add_column_if_missing(
                conn, "rag_documents", "failure_reason", "TEXT"
            )
            _sqlite_add_column_if_missing(conn, "rag_documents", "indexed_at", "TEXT")
            _sqlite_add_column_if_missing(
                conn, "rag_documents", "superseded_at", "TEXT"
            )
            _sqlite_add_column_if_missing(
                conn, "rag_documents", "superseded_by_version_id", "TEXT"
            )
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_rag_documents_tenant_source_hash "
                "ON rag_documents (tenant_id, corpus_id, source_hash)"
            )
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_rag_documents_tenant_status "
                "ON rag_documents (tenant_id, corpus_id, ingestion_status, is_current)"
            )

        if "rag_chunks" in tables:
            _sqlite_add_column_if_missing(
                conn, "rag_chunks", "document_version_id", "TEXT"
            )
            _sqlite_add_column_if_missing(conn, "rag_chunks", "source_hash", "TEXT")
            _sqlite_add_column_if_missing(
                conn, "rag_chunks", "is_active", "INTEGER NOT NULL DEFAULT 1"
            )
            # PR 55 — PDF ingestion: page provenance columns
            _sqlite_add_column_if_missing(conn, "rag_chunks", "source_page", "INTEGER")
            _sqlite_add_column_if_missing(
                conn, "rag_chunks", "extraction_version", "TEXT"
            )
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_rag_chunks_tenant_version_active "
                "ON rag_chunks (tenant_id, document_version_id, is_active)"
            )

        if "rag_documents" in tables:
            # PR 55 — PDF ingestion: content_type provenance column
            _sqlite_add_column_if_missing(conn, "rag_documents", "content_type", "TEXT")

        # (The rest of your large sqlite schema block continues unchanged)
        # NOTE: You pasted duplicated ai_policy_violations creation twice; leaving it as-is is sloppy.
        # If you want it fixed: remove the duplicate block.
        # For now, respecting your requested "add patches" directive.

        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS enterprise_framework_catalog (
                framework_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS enterprise_control_catalog (
                control_id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS enterprise_control_crosswalk (
                crosswalk_id TEXT PRIMARY KEY,
                control_id TEXT NOT NULL,
                framework_id TEXT NOT NULL,
                framework_control_ref TEXT NOT NULL,
                mapping_strength TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS tenant_control_state (
                id INTEGER PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                control_id TEXT NOT NULL,
                status TEXT NOT NULL,
                note TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                UNIQUE(tenant_id, control_id)
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS evidence_anchor_records (
                id INTEGER PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                artifact_sha256 TEXT NOT NULL,
                anchored_at_utc TEXT NOT NULL,
                external_anchor_ref TEXT,
                immutable_retention BOOLEAN NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            """
        )

        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS ai_model_catalog (
                model_id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                model_name TEXT NOT NULL,
                risk_tier TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS tenant_ai_policy (
                tenant_id TEXT PRIMARY KEY,
                max_prompt_chars INTEGER NOT NULL DEFAULT 2000,
                blocked_topics_json TEXT NOT NULL DEFAULT '[]',
                require_human_review BOOLEAN NOT NULL DEFAULT 1,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS ai_inference_records (
                id INTEGER PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                inference_id TEXT NOT NULL UNIQUE,
                model_id TEXT NOT NULL,
                prompt_sha256 TEXT NOT NULL,
                response_text TEXT NOT NULL,
                context_refs_json TEXT NOT NULL DEFAULT '[]',
                created_at_utc TEXT NOT NULL,
                output_sha256 TEXT NOT NULL DEFAULT '',
                retrieval_id TEXT NOT NULL DEFAULT 'rag:none',
                policy_result TEXT NOT NULL DEFAULT 'pass',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS ai_governance_reviews (
                id INTEGER PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                review_id TEXT NOT NULL UNIQUE,
                inference_id TEXT NOT NULL,
                reviewer TEXT NOT NULL,
                decision TEXT NOT NULL,
                notes TEXT,
                created_at_utc TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS ai_device_registry (
                id INTEGER PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT 0,
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                telemetry_json TEXT NOT NULL DEFAULT '{}',
                UNIQUE(tenant_id, device_id)
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS ai_token_usage (
                id INTEGER PRIMARY KEY,
                usage_record_id TEXT NOT NULL UNIQUE,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                user_id TEXT,
                persona TEXT NOT NULL DEFAULT 'default',
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                prompt_tokens INTEGER NOT NULL DEFAULT 0,
                completion_tokens INTEGER NOT NULL DEFAULT 0,
                total_tokens INTEGER NOT NULL DEFAULT 0,
                usage_day TEXT NOT NULL,
                metering_mode TEXT NOT NULL DEFAULT 'unknown',
                estimation_mode TEXT NOT NULL DEFAULT 'estimated',
                request_hash TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                experience_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            """
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_ai_token_usage_tenant_day ON ai_token_usage(tenant_id, usage_day)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_ai_token_usage_tenant_device_day ON ai_token_usage(tenant_id, device_id, usage_day)"
        )
        conn.exec_driver_sql(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_token_usage_record_id ON ai_token_usage(usage_record_id)"
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS ai_quota_daily (
                id INTEGER PRIMARY KEY,
                quota_scope TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                device_id TEXT,
                usage_day TEXT NOT NULL,
                token_limit INTEGER NOT NULL DEFAULT 0,
                used_tokens INTEGER NOT NULL DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                UNIQUE(quota_scope, usage_day)
            )
            """
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_ai_quota_daily_tenant_day ON ai_quota_daily(tenant_id, usage_day)"
        )

        if "ai_token_usage" in tables:
            _sqlite_add_column_if_missing(
                conn, "ai_token_usage", "usage_record_id", "TEXT"
            )
            _sqlite_add_column_if_missing(
                conn, "ai_token_usage", "metering_mode", "TEXT DEFAULT 'unknown'"
            )
            _sqlite_add_column_if_missing(
                conn, "ai_token_usage", "estimation_mode", "TEXT DEFAULT 'estimated'"
            )

        if "ai_inference_records" in tables:
            _sqlite_add_column_if_missing(
                conn, "ai_inference_records", "inference_id", "TEXT"
            )
            _sqlite_add_column_if_missing(
                conn, "ai_inference_records", "response_text", "TEXT DEFAULT ''"
            )
            _sqlite_add_column_if_missing(
                conn, "ai_inference_records", "context_refs_json", "TEXT DEFAULT '[]'"
            )
            _sqlite_add_column_if_missing(
                conn,
                "ai_inference_records",
                "created_at_utc",
                "TEXT DEFAULT '1970-01-01T00:00:00Z'",
            )
            _sqlite_add_column_if_missing(
                conn, "ai_inference_records", "output_sha256", "TEXT DEFAULT ''"
            )
            _sqlite_add_column_if_missing(
                conn, "ai_inference_records", "retrieval_id", "TEXT DEFAULT 'rag:none'"
            )
            conn.exec_driver_sql(
                "UPDATE ai_inference_records "
                "SET retrieval_id = 'rag:none' "
                "WHERE retrieval_id = 'stub'"
            )
            _sqlite_add_column_if_missing(
                conn, "ai_inference_records", "policy_result", "TEXT DEFAULT 'pass'"
            )

        if "ai_policy_violations" not in tables:
            conn.exec_driver_sql(
                """
                CREATE TABLE IF NOT EXISTS ai_policy_violations (
                    id INTEGER PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    violation_code TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
                """
            )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS ai_policy_violations (
                id INTEGER PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                violation_code TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            """
        )

        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS evidence_runs (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                plane_id TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                artifact_sha256 TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                git_sha TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                status TEXT NOT NULL,
                summary_json TEXT NOT NULL DEFAULT '{}',
                retention_class TEXT NOT NULL DEFAULT 'hot',
                anchor_status TEXT NOT NULL DEFAULT 'none'
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS retention_policies (
                id INTEGER PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                retention_days INTEGER NOT NULL,
                immutable_required BOOLEAN NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                UNIQUE(tenant_id, artifact_type)
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS audit_ledger (
                id INTEGER PRIMARY KEY,
                session_id TEXT NOT NULL,
                cycle_kind TEXT NOT NULL,
                timestamp_utc TEXT NOT NULL,
                invariant_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                config_hash TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                git_commit TEXT NOT NULL,
                runtime_version TEXT NOT NULL,
                host_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL DEFAULT 'unknown',
                sha256_engine_code_hash TEXT NOT NULL DEFAULT '',
                sha256_self_hash TEXT NOT NULL UNIQUE,
                previous_record_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                details_json JSON NOT NULL DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS audit_ledger_append_only_update
            BEFORE UPDATE ON audit_ledger
            BEGIN
                SELECT RAISE(ABORT, 'audit_ledger is append-only');
            END;
            """
        )

        conn.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS audit_ledger_append_only_delete
            BEFORE DELETE ON audit_ledger
            BEGIN
                SELECT RAISE(ABORT, 'audit_ledger is append-only');
            END;
            """
        )

        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS compliance_requirements (
                id INTEGER PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                req_id TEXT NOT NULL,
                source TEXT NOT NULL,
                source_ref TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                effective_date_utc TEXT NOT NULL,
                version TEXT NOT NULL,
                status TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                owner TEXT NOT NULL,
                source_name TEXT,
                source_version TEXT,
                published_at_utc TEXT,
                retrieved_at_utc TEXT,
                bundle_sha256 TEXT,
                tags_json JSON NOT NULL DEFAULT '[]',
                created_at_utc TEXT NOT NULL,
                previous_record_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL UNIQUE,
                signature TEXT NOT NULL,
                key_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS compliance_findings (
                id INTEGER PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                req_ids_json JSON NOT NULL DEFAULT '[]',
                title TEXT NOT NULL,
                details TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                waiver_json JSON,
                detected_at_utc TEXT NOT NULL,
                evidence_refs_json JSON NOT NULL DEFAULT '[]',
                created_at_utc TEXT NOT NULL,
                previous_record_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL UNIQUE,
                signature TEXT NOT NULL,
                key_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS compliance_snapshots (
                id INTEGER PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                snapshot_id TEXT NOT NULL UNIQUE,
                summary_json JSON NOT NULL DEFAULT '{}',
                created_at_utc TEXT NOT NULL,
                previous_record_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL UNIQUE,
                signature TEXT NOT NULL,
                key_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS audit_exam_sessions (
                id INTEGER PRIMARY KEY,
                exam_id TEXT NOT NULL UNIQUE,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                window_start_utc TEXT NOT NULL,
                window_end_utc TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                export_path TEXT,
                reproduce_json JSON,
                previous_record_hash TEXT NOT NULL DEFAULT 'GENESIS',
                record_hash TEXT NOT NULL UNIQUE DEFAULT '',
                signature TEXT NOT NULL DEFAULT '',
                key_id TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS compliance_requirement_updates (
                id INTEGER PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                update_id TEXT NOT NULL UNIQUE,
                source_name TEXT NOT NULL,
                source_version TEXT NOT NULL,
                published_at_utc TEXT NOT NULL,
                retrieved_at_utc TEXT NOT NULL,
                bundle_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                diff_json JSON NOT NULL DEFAULT '{}',
                previous_record_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL UNIQUE,
                signature TEXT NOT NULL,
                key_id TEXT NOT NULL,
                created_at_utc TEXT NOT NULL
            )
            """
        )
        for table in (
            "compliance_requirements",
            "compliance_findings",
            "compliance_snapshots",
            "audit_exam_sessions",
            "compliance_requirement_updates",
        ):
            conn.exec_driver_sql(
                f"""
                CREATE TRIGGER IF NOT EXISTS {table}_append_only_update
                BEFORE UPDATE ON {table}
                BEGIN
                    SELECT RAISE(ABORT, '{table} is append-only');
                END;
                """
            )
            conn.exec_driver_sql(
                f"""
                CREATE TRIGGER IF NOT EXISTS {table}_append_only_delete
                BEFORE DELETE ON {table}
                BEGIN
                    SELECT RAISE(ABORT, '{table} is append-only');
                END;
                """
            )

        # -----------------------------------------------------------------
        # RAG corpus persistence tables (PR 14)
        # SQLite uses TEXT for metadata (JSONB not supported); the service
        # layer serialises/deserialises JSON explicitly.
        # -----------------------------------------------------------------
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS rag_corpora (
                corpus_id   TEXT NOT NULL PRIMARY KEY,
                tenant_id   TEXT NOT NULL,
                name        TEXT NOT NULL,
                description TEXT,
                metadata    TEXT,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            )
            """
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_rag_corpora_tenant_corpus "
            "ON rag_corpora (tenant_id, corpus_id)"
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS rag_documents (
                document_id TEXT NOT NULL PRIMARY KEY,
                corpus_id   TEXT NOT NULL REFERENCES rag_corpora (corpus_id),
                tenant_id   TEXT NOT NULL,
                title       TEXT NOT NULL,
                source      TEXT,
                metadata    TEXT,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL,
                version_id  TEXT,
                source_hash TEXT,
                normalized_source_hash TEXT,
                version_number INTEGER NOT NULL DEFAULT 1,
                is_current INTEGER NOT NULL DEFAULT 1,
                ingestion_status TEXT NOT NULL DEFAULT 'indexed',
                quarantine_reason TEXT,
                failure_reason TEXT,
                indexed_at TEXT,
                superseded_at TEXT,
                superseded_by_version_id TEXT
            )
            """
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_rag_documents_tenant_corpus "
            "ON rag_documents (tenant_id, corpus_id)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_rag_documents_tenant_document "
            "ON rag_documents (tenant_id, document_id)"
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS rag_chunks (
                chunk_id        TEXT    NOT NULL PRIMARY KEY,
                document_id     TEXT    NOT NULL REFERENCES rag_documents (document_id),
                corpus_id       TEXT    NOT NULL,
                tenant_id       TEXT    NOT NULL,
                text            TEXT    NOT NULL,
                ordinal         INTEGER NOT NULL,
                metadata        TEXT,
                created_at      TEXT    NOT NULL,
                content_hash    TEXT,
                embedding_state TEXT    NOT NULL DEFAULT 'pending'
                    CHECK (embedding_state IN ('pending','processing','completed','failed','skipped')),
                document_version_id TEXT,
                source_hash TEXT,
                is_active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_rag_chunks_tenant_corpus "
            "ON rag_chunks (tenant_id, corpus_id)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_rag_chunks_tenant_document "
            "ON rag_chunks (tenant_id, document_id)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_rag_chunks_pending_embedding "
            "ON rag_chunks (tenant_id, created_at) "
            "WHERE embedding_state IN ('pending', 'failed')"
        )

        # PR 53 — Provider Governance + Retrieval Evaluation Foundation
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS provider_governance_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                operational_state TEXT NOT NULL DEFAULT 'healthy',
                governance_state TEXT NOT NULL DEFAULT 'approved',
                trust_classification TEXT NOT NULL DEFAULT 'unknown',
                routing_eligible INTEGER NOT NULL DEFAULT 1,
                failover_eligible INTEGER NOT NULL DEFAULT 0,
                restrictions_json TEXT NOT NULL DEFAULT '[]',
                blocked_at TIMESTAMP,
                block_reason TEXT,
                policy_version INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                UNIQUE(tenant_id, provider_id)
            )
            """
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_provider_governance_tenant_provider "
            "ON provider_governance_records (tenant_id, provider_id)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_provider_governance_tenant_opstate "
            "ON provider_governance_records (tenant_id, operational_state)"
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS retrieval_evaluation_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                run_ref TEXT NOT NULL,
                corpus_id TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                query_count INTEGER NOT NULL DEFAULT 0,
                relevance_indicators_json TEXT NOT NULL DEFAULT '{}',
                coverage_indicators_json TEXT NOT NULL DEFAULT '{}',
                correctness_indicators_json TEXT NOT NULL DEFAULT '{}',
                evaluator_ref TEXT,
                evaluation_metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                UNIQUE(tenant_id, run_ref)
            )
            """
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_retrieval_eval_tenant_run "
            "ON retrieval_evaluation_runs (tenant_id, run_ref)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_retrieval_eval_tenant_status "
            "ON retrieval_evaluation_runs (tenant_id, status)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_retrieval_eval_tenant_corpus "
            "ON retrieval_evaluation_runs (tenant_id, corpus_id)"
        )

        # PR 54 — Evaluation Lab UI
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS evaluation_query_sets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                set_ref TEXT NOT NULL,
                name TEXT NOT NULL,
                corpus_id TEXT,
                description TEXT,
                operator_notes_json TEXT NOT NULL DEFAULT '[]',
                export_safe_metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                UNIQUE(tenant_id, set_ref)
            )
            """
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_eval_query_set_tenant_ref "
            "ON evaluation_query_sets (tenant_id, set_ref)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_eval_query_set_tenant_corpus "
            "ON evaluation_query_sets (tenant_id, corpus_id)"
        )
        conn.exec_driver_sql(
            """
            CREATE TABLE IF NOT EXISTS evaluation_query_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                set_ref TEXT NOT NULL,
                item_ref TEXT NOT NULL,
                query_category TEXT,
                expected_source_ids_json TEXT NOT NULL DEFAULT '[]',
                expected_chunk_ids_json TEXT NOT NULL DEFAULT '[]',
                expected_source_hashes_json TEXT NOT NULL DEFAULT '[]',
                expected_provenance_ids_json TEXT NOT NULL DEFAULT '[]',
                retrieval_expectations_json TEXT NOT NULL DEFAULT '{}',
                operator_notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                UNIQUE(tenant_id, set_ref, item_ref)
            )
            """
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_eval_query_item_tenant_set "
            "ON evaluation_query_items (tenant_id, set_ref)"
        )
        conn.exec_driver_sql(
            "CREATE INDEX IF NOT EXISTS ix_eval_query_item_tenant_ref "
            "ON evaluation_query_items (tenant_id, item_ref)"
        )


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------


def init_db(*, sqlite_path: Optional[str] = None) -> None:
    engine = get_engine(sqlite_path=sqlite_path)

    _ensure_models_imported()
    Base = _get_base()

    if engine.dialect.name == "sqlite":
        Base.metadata.create_all(bind=engine)

        # Ensure sqlite3-backed auth_scopes key store exists in same file
        resolved = _resolve_sqlite_path(sqlite_path)
        _ensure_api_keys_sqlite(resolved)

        # Ensure connector sqlite tables exist (including idempotency)
        _ensure_connectors_sqlite(resolved)

        # Best-effort sqlite migrations (keeps tests + mint_key working)
        try:
            _auto_migrate_sqlite(engine)
        except Exception:
            logger.exception("sqlite auto-migration failed (best effort)")

    elif engine.dialect.name == "postgresql":
        if _env_bool("FG_DB_MIGRATIONS_REQUIRED", True):
            from api.db_migrations import assert_migrations_applied  # noqa

            assert_migrations_applied(engine)

    # Optional sanity check
    try:
        insp = inspect(engine)
        tables = set(insp.get_table_names())
        if "api_keys" not in tables and engine.dialect.name == "sqlite":
            logger.warning(
                "Expected table 'api_keys' missing; tables=%s", sorted(tables)
            )
    except Exception:
        pass


@lru_cache(maxsize=1)
def _compiled_sanity_query() -> str:
    return "SELECT 1"


def db_ping(*, sqlite_path: Optional[str] = None) -> None:
    engine = get_engine(sqlite_path=sqlite_path)
    with engine.connect() as conn:
        conn.execute(text(_compiled_sanity_query()))


def get_db_no_request(*, sqlite_path: str | None = None) -> Iterator[Session]:
    """
    Back-compat helper used by tests/tools that need a DB session outside FastAPI.
    """
    SessionLocal = get_sessionmaker(sqlite_path=sqlite_path)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db(*, sqlite_path: str | None = None) -> Iterator[Session]:
    """
    FastAPI-friendly DB generator (no auth/tenant here).
    Prefer api/deps.py for request-bound tenant logic.
    """
    yield from get_db_no_request(sqlite_path=sqlite_path)


def set_tenant_context(session: Session, tenant_id: str) -> None:
    """
    Optional: Postgres-only session context binding via set_config.
    Safe no-op for sqlite.
    """
    bind = getattr(session, "bind", None)
    if bind is None or getattr(bind.dialect, "name", "") != "postgresql":
        return
    if not tenant_id:
        raise RuntimeError("tenant_id required")
    session.execute(
        text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
        {"tenant_id": tenant_id},
    )
