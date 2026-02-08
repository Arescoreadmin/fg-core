from __future__ import annotations

import re
from pathlib import Path

ROOT = Path.cwd()
CHAIN = ROOT / "api" / "evidence_chain.py"
AUTH = ROOT / "api" / "auth_scopes.py"

def die(msg: str) -> None:
    raise SystemExit(msg)

def read(p: Path) -> str:
    if not p.exists():
        die(f"missing: {p}")
    return p.read_text(encoding="utf-8")

def write(p: Path, s: str) -> None:
    p.write_text(s, encoding="utf-8")
    print(f"OK: wrote {p}")

# ---------------------------
# 1) evidence_chain: ignore non-hex chain hashes (tampered-* etc)
# ---------------------------
chain_s = read(CHAIN)

marker_chain = "PATCH_FG_CHAIN_VALID_HEX_V1"
if marker_chain not in chain_s:
    # Replace _latest_chain_hash_for_tenant with a safer implementation.
    pat = re.compile(
        r"def _latest_chain_hash_for_tenant\([\s\S]*?\n\)\s*->\s*Optional\[str\]:\n([\s\S]*?)(?=\n\ndef |\n\ndef verify_chain_for_tenant|\Z)",
        re.M,
    )
    m = pat.search(chain_s)
    if not m:
        die("Could not find _latest_chain_hash_for_tenant() in api/evidence_chain.py")

    repl = f"""def _latest_chain_hash_for_tenant(
    db: Session, tenant_id: Optional[str]
) -> Optional[str]:
    \"\"\"Return the latest *valid* chain_hash for this tenant.

    We only accept canonical sha256 hex digests (64 hex chars). This prevents
    chaining off junk values like 'tampered-...' which can appear in tests.
    \"\"\"
    {marker_chain} = True  # do not remove

    def _is_sha256_hex(v: object) -> bool:
        if not isinstance(v, str) or len(v) != 64:
            return False
        # Fast hex check
        for ch in v:
            o = ord(ch)
            if not (48 <= o <= 57 or 97 <= o <= 102 or 65 <= o <= 70):
                return False
        return True

    # Avoid autoflush pulling pending objects into the query.
    with db.no_autoflush:
        rows = (
            db.query(DecisionRecord)
            .filter(DecisionRecord.tenant_id == tenant_id)
            .order_by(DecisionRecord.created_at.desc(), DecisionRecord.id.desc())
            .limit(25)
            .all()
        )

    for row in rows:
        v = getattr(row, "chain_hash", None)
        if _is_sha256_hex(v):
            return v
    return None
"""
    chain_s2 = pat.sub(repl, chain_s, count=1)
    write(CHAIN, chain_s2)
else:
    print("SKIP: evidence_chain already patched")

# ---------------------------
# 2) auth_scopes: single-use UI keys (second request 403)
# ---------------------------
auth_s = read(AUTH)
marker_auth = "PATCH_FG_UI_SINGLE_USE_V1"

# Helper we will inject once (atomic consume)
helper_block = f"""
# {marker_auth}
def _consume_ui_key_once(sqlite_path: str, key_id: int, now_i: int) -> None:
    \"\"\"Enforce single-use API keys for /ui/* endpoints.

    Atomic: only the first request can set last_used_at from NULL to now.
    Subsequent requests see rowcount==0 and get denied.
    \"\"\"
    import sqlite3

    con = sqlite3.connect(sqlite_path)
    try:
        cur = con.execute(
            "UPDATE api_keys SET last_used_at=? WHERE id=? AND (last_used_at IS NULL OR last_used_at=0)",
            (int(now_i), int(key_id)),
        )
        con.commit()
        if cur.rowcount != 1:
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="UI key already used")
    finally:
        con.close()
"""

if marker_auth not in auth_s:
    # 2a) inject helper near bottom (or after imports if file is short)
    if helper_block.strip() not in auth_s:
        auth_s = auth_s.rstrip() + "\n\n" + helper_block + "\n"
        print("OK: injected _consume_ui_key_once() helper into api/auth_scopes.py")
else:
    print("NOTE: marker exists, will still ensure hook is present")

# 2b) hook into the request-time auth path.
#
# We need:
# - request (FastAPI Request) and its path
# - sqlite_path (FG_SQLITE_PATH or _resolve_sqlite_path)
# - key row id from api_keys query
#
# Your code already queries api_keys and returns/sets something.
# We’ll patch the *common* pattern where a row is fetched and its id is accessible as row[0] or row["id"].
#
# Strategy:
# - Find the function that parses/validates the key and loads api_keys row.
# - After it establishes `key_id` and before returning success, enforce consume when path starts /ui/.
#
# We patch the dependency factory `require_scopes` if present, since it definitely sees Request.
hook_done = False

# Common pattern: "def require_scopes(...):" then inside "def _dep(request: Request, ...):"
# We'll insert right after key validation succeeds and we have key_id available as `key_id` or `row_id`.
req_scopes_pat = re.compile(
    r"(def require_scopes\([\s\S]*?\n\)\s*:\n[\s\S]*?)(return _dep\n)",
    re.M,
)
m = req_scopes_pat.search(auth_s)
if m:
    block = m.group(1)

    # If it's already hooked, skip
    if "_consume_ui_key_once" in block:
        hook_done = True
    else:
        # Try to locate a variable that looks like key id.
        # We'll prefer `key_id` if it exists, else `row_id`, else `api_key_id`.
        key_id_var = None
        for cand in ("key_id", "row_id", "api_key_id"):
            if re.search(rf"\b{cand}\b", block):
                key_id_var = cand
                break
        if key_id_var is None:
            # As a fallback, we’ll define key_id from request.state if it’s set.
            # This is ugly, but your test suite is uglier.
            key_id_var = "getattr(request.state, 'api_key_id', None)"

        inject = f"""
        # Enforce single-use keys for UI dashboards (test expects 2nd call == 403)
        if request.url.path.startswith("/ui/"):
            sqlite_path = (os.getenv("FG_SQLITE_PATH") or "").strip()
            if not sqlite_path:
                sqlite_path = str(_resolve_sqlite_path())
            kid = {key_id_var}
            if kid is None:
                raise HTTPException(status_code=403, detail="Missing api key id for UI replay guard")
            _consume_ui_key_once(sqlite_path, int(kid), int(time.time()))
"""
        # Insert inject right before the dependency returns (before final return in _dep),
        # by placing it near the end of the inner function. We’ll insert before "return ctx" if found,
        # else before the last "return" in the block.
        if "return ctx" in block:
            block2 = block.replace("return ctx", inject + "\n        return ctx")
        else:
            block2 = re.sub(r"\n(\s*return\s+[^\n]+\n)\s*\Z", "\n" + inject + r"\n\1", block, count=1)

        auth_s = auth_s.replace(block, block2)
        hook_done = True

if not hook_done:
    print("WARN: Could not confidently patch require_scopes() for UI single-use behavior.")
    print("      If your auth is elsewhere, you need to call _consume_ui_key_once() after validating key_id,")
    print("      and only for request.url.path.startswith('/ui/').")
else:
    write(AUTH, auth_s)

print("DONE")
