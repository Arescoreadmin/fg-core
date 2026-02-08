from __future__ import annotations

import sqlite3
from pathlib import Path


ROOT = Path.cwd()
DB_FILE = ROOT / "api" / "db.py"
CHAIN_FILE = ROOT / "api" / "evidence_chain.py"


PATCH_MARK = "PATCH_FG_API_KEYS_SQLITE_V1"


EVIDENCE_CHAIN_CLEAN = r'''from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import asc
from sqlalchemy.orm import Session

from api.db_models import DecisionRecord

CHAIN_ALG = "sha256/canonical-json/v1"
GENESIS_HASH = "GENESIS"


def _sha256_hex(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _canonical_json(obj: Any) -> str:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


def _coerce_datetime(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(dt: datetime | None) -> Optional[str]:
    if dt is None:
        return None
    return _coerce_datetime(dt).isoformat()


def _maybe_load_json(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return value
    return value


def _inputs_fingerprint(request_json: Any) -> str:
    payload = _maybe_load_json(request_json) or {}
    return _sha256_hex(_canonical_json(payload))


def _extract_request_id(request_json: Any) -> Optional[str]:
    payload = _maybe_load_json(request_json)
    if isinstance(payload, dict):
        return payload.get("request_id") or payload.get("requestId")
    return None


def _extract_policy_version(response_json: Any) -> Optional[str]:
    payload = _maybe_load_json(response_json)
    if isinstance(payload, dict):
        return payload.get("policy_version") or payload.get("policyVersion")
    return None


def _decision_outcome(threat_level: Optional[str], response_json: Any) -> Optional[str]:
    payload = _maybe_load_json(response_json)
    if isinstance(payload, dict):
        outcome = payload.get("decision") or payload.get("action")
        if outcome is not None:
            return str(outcome)
    return str(threat_level) if threat_level is not None else None


def build_chain_payload(
    *,
    tenant_id: Optional[str],
    request_json: Any,
    response_json: Any,
    threat_level: Optional[str],
    chain_ts: datetime,
    event_id: Optional[str],
) -> dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "request_id": _extract_request_id(request_json),
        "decision_outcome": _decision_outcome(threat_level, response_json),
        "threat_level": threat_level,
        "policy_version": _extract_policy_version(response_json),
        "inputs_fingerprint": _inputs_fingerprint(request_json),
        "chain_ts": _iso(chain_ts),
        "event_id": event_id,
    }


def compute_chain_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    payload_hash = _sha256_hex(_canonical_json(payload))
    return _sha256_hex(f"{prev_hash}:{payload_hash}")


def _latest_chain_hash_for_tenant(db: Session, tenant_id: Optional[str]) -> Optional[str]:
    # Critical: do not accidentally flush pending inserts from caller
    # and do not treat "missing chain_hash" rows as chain tips.
    with db.no_autoflush:
        row = (
            db.query(DecisionRecord)
            .filter(
                DecisionRecord.tenant_id == tenant_id,
                DecisionRecord.chain_hash.isnot(None),
            )
            .order_by(DecisionRecord.created_at.desc(), DecisionRecord.id.desc())
            .first()
        )
    return getattr(row, "chain_hash", None) if row is not None else None


def chain_fields_for_decision(
    db: Session,
    *,
    tenant_id: Optional[str],
    request_json: Any,
    response_json: Any,
    threat_level: Optional[str],
    chain_ts: datetime,
    event_id: Optional[str],
) -> dict[str, Any]:
    prev_hash = _latest_chain_hash_for_tenant(db, tenant_id) or GENESIS_HASH
    payload = build_chain_payload(
        tenant_id=tenant_id,
        request_json=request_json,
        response_json=response_json,
        threat_level=threat_level,
        chain_ts=chain_ts,
        event_id=event_id,
    )
    return {
        "prev_hash": prev_hash,
        "chain_hash": compute_chain_hash(prev_hash, payload),
        "chain_alg": CHAIN_ALG,
        "chain_ts": _coerce_datetime(chain_ts),
    }


def verify_chain_for_tenant(
    db: Session, tenant_id: Optional[str], limit: Optional[int] = None
) -> dict[str, Any]:
    query = (
        db.query(DecisionRecord)
        .filter(DecisionRecord.tenant_id == tenant_id)
        .order_by(asc(DecisionRecord.created_at), asc(DecisionRecord.id))
    )
    if limit is not None:
        query = query.limit(int(limit))

    prev_hash = GENESIS_HASH
    checked = 0

    for record in query:
        checked += 1
        if not getattr(record, "chain_hash", None):
            return {
                "ok": False,
                "first_bad_id": record.id,
                "reason": "missing_chain_hash",
                "checked": checked,
            }
        if getattr(record, "chain_alg", None) != CHAIN_ALG:
            return {
                "ok": False,
                "first_bad_id": record.id,
                "reason": "chain_alg_mismatch",
                "checked": checked,
            }
        if getattr(record, "chain_ts", None) is None:
            return {
                "ok": False,
                "first_bad_id": record.id,
                "reason": "missing_chain_ts",
                "checked": checked,
            }

        record_prev = getattr(record, "prev_hash", None)
        if (
            not isinstance(record_prev, str)
            or not isinstance(prev_hash, str)
            or not hmac.compare_digest(record_prev, prev_hash)
        ):
            return {
                "ok": False,
                "first_bad_id": record.id,
                "reason": "prev_hash_mismatch",
                "checked": checked,
            }

        payload = build_chain_payload(
            tenant_id=getattr(record, "tenant_id", None),
            request_json=getattr(record, "request_json", None),
            response_json=getattr(record, "response_json", None),
            threat_level=getattr(record, "threat_level", None),
            chain_ts=getattr(record, "chain_ts", None),
            event_id=getattr(record, "event_id", None),
        )
        expected = compute_chain_hash(prev_hash, payload)
        record_chain = getattr(record, "chain_hash", None)

        if not isinstance(record_chain, str) or not hmac.compare_digest(record_chain, expected):
            return {
                "ok": False,
                "first_bad_id": record.id,
                "reason": "chain_hash_mismatch",
                "checked": checked,
            }

        prev_hash = expected

    return {"ok": True, "first_bad_id": None, "reason": "", "checked": checked}
'''


DB_PATCH = r'''
# ===================== PATCH_FG_API_KEYS_SQLITE_V1 =====================
# This project mints/verifies API keys via sqlite3 in api/auth_scopes.py.
# That means init_db() MUST ensure api_keys exists (and auto-migrate columns)
# in the sqlite file chosen by FG_SQLITE_PATH or passed sqlite_path.
# ======================================================================

from __future__ import annotations

import sqlite3
from typing import Optional


def _sqlite_table_exists(con: sqlite3.Connection, name: str) -> bool:
    row = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return row is not None


def _sqlite_cols(con: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}


def _sqlite_add_col_if_missing(con: sqlite3.Connection, table: str, col: str, decl: str) -> None:
    cols = _sqlite_cols(con, table)
    if col not in cols:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")


def _ensure_api_keys_sqlite(sqlite_path: str) -> None:
    con = sqlite3.connect(sqlite_path)
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA foreign_keys=ON")

        if not _sqlite_table_exists(con, "api_keys"):
            # Minimal schema required by tests + auth_scopes minting.
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

        # Auto-migrate new hash columns if older table exists.
        _sqlite_add_col_if_missing(con, "api_keys", "hash_alg", "TEXT")
        _sqlite_add_col_if_missing(con, "api_keys", "hash_params", "TEXT")
        _sqlite_add_col_if_missing(con, "api_keys", "key_lookup", "TEXT")

        con.commit()
    finally:
        con.close()


# Wrap existing init_db to also ensure api_keys is present (sqlite only).
try:
    _orig_init_db = init_db  # type: ignore[name-defined]
except Exception:
    _orig_init_db = None  # type: ignore[assignment]


def init_db(*, sqlite_path: Optional[str] = None) -> None:  # type: ignore[override]
    # Call original init_db first (SQLAlchemy tables), then enforce api_keys.
    if _orig_init_db is not None:
        _orig_init_db(sqlite_path=sqlite_path)

    # Resolve the sqlite path the same way the rest of api/db.py does.
    try:
        resolved = _resolve_sqlite_path(sqlite_path)  # type: ignore[name-defined]
    except Exception:
        resolved = str(sqlite_path) if sqlite_path else ""

    if resolved:
        _ensure_api_keys_sqlite(resolved)

# =================== END PATCH_FG_API_KEYS_SQLITE_V1 ====================
'''


def main() -> None:
    # 1) Rewrite evidence_chain cleanly (fix your mangled file)
    CHAIN_FILE.write_text(EVIDENCE_CHAIN_CLEAN, encoding="utf-8")

    # 2) Append db.py patch once
    db_text = DB_FILE.read_text(encoding="utf-8")
    if PATCH_MARK not in db_text:
        DB_FILE.write_text(db_text.rstrip() + "\n" + DB_PATCH, encoding="utf-8")

    print("OK: rewrote api/evidence_chain.py and patched api/db.py for api_keys sqlite init/migration")


if __name__ == "__main__":
    main()
