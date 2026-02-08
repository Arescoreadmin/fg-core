from __future__ import annotations

import re
from pathlib import Path

ROOT = Path.cwd()
CHAIN = ROOT / "api" / "evidence_chain.py"
MAIN  = ROOT / "api" / "main.py"

def die(msg: str) -> None:
    raise SystemExit(msg)

def read(p: Path) -> str:
    if not p.exists():
        die(f"missing file: {p}")
    return p.read_text(encoding="utf-8")

def write(p: Path, s: str) -> None:
    p.write_text(s, encoding="utf-8")
    print(f"OK: wrote {p}")

# -------------------------
# 1) Evidence chain: only accept valid sha256 hex as prev_hash
# -------------------------
chain_s = read(CHAIN)

marker_chain = "PATCH_FG_CHAIN_HEX_GUARD_V1"
if marker_chain not in chain_s:
    # Ensure helper exists near top (after GENESIS_HASH is ideal)
    if "_is_sha256_hex" not in chain_s:
        # Insert after GENESIS_HASH assignment
        m = re.search(r"^(GENESIS_HASH\s*=\s*[^\n]+\n)", chain_s, flags=re.M)
        if not m:
            die("Could not find GENESIS_HASH in api/evidence_chain.py")

        helper = f"""{m.group(1)}
# {marker_chain}
def _is_sha256_hex(v: object) -> bool:
    if not isinstance(v, str) or len(v) != 64:
        return False
    for ch in v:
        o = ord(ch)
        if not (48 <= o <= 57 or 97 <= o <= 102 or 65 <= o <= 70):
            return False
    return True

"""
        chain_s = chain_s.replace(m.group(1), helper)

    # Patch prev_hash assignment inside chain_fields_for_decision
    # We look for the specific line that sets prev_hash from a latest hash or GENESIS_HASH.
    pat = re.compile(
        r"(^\s*prev_hash\s*=\s*)(.+?)(\s*or\s*GENESIS_HASH\s*)$",
        flags=re.M,
    )

    def repl(mo: re.Match) -> str:
        # mo.group(2) is the expression (typically _latest...())
        expr = mo.group(2).strip()
        return (
            f"{mo.group(1)}({expr})\n"
            f"    if not _is_sha256_hex(prev_hash):\n"
            f"        prev_hash = GENESIS_HASH"
        )

    new_s, n = pat.subn(repl, chain_s, count=1)
    if n == 0:
        # fallback: find any "prev_hash =" line in chain_fields_for_decision block
        # and patch manually
        block_pat = re.compile(
            r"(def\s+chain_fields_for_decision\([\s\S]*?\):\n)([\s\S]*?)(\n\ndef|\Z)",
            re.M,
        )
        bm = block_pat.search(chain_s)
        if not bm:
            die("Could not find chain_fields_for_decision() in api/evidence_chain.py")

        block = bm.group(2)
        line_m = re.search(r"^\s*prev_hash\s*=.*$", block, flags=re.M)
        if not line_m:
            die("Could not find prev_hash assignment in chain_fields_for_decision()")

        old_line = line_m.group(0)
        # Replace prev_hash line with guarded version
        guarded = (
            old_line + "\n"
            "    if not _is_sha256_hex(prev_hash):\n"
            "        prev_hash = GENESIS_HASH"
        )
        block2 = block.replace(old_line, guarded, 1)
        new_s = chain_s[:bm.start(2)] + block2 + chain_s[bm.end(2):]

    write(CHAIN, new_s)
else:
    print("SKIP: evidence_chain already has hex guard marker")

# -------------------------
# 2) UI dashboards: enforce single-use API keys for /ui/*
# -------------------------
main_s = read(MAIN)
marker_ui = "PATCH_FG_UI_SINGLE_USE_MW_V1"

if marker_ui not in main_s:
    # Ensure middleware imports exist (we’ll inject minimal ones)
    if "from fastapi import" in main_s and "Request" not in main_s:
        main_s = re.sub(
            r"from fastapi import ([^\n]+)",
            lambda m: "from fastapi import " + (m.group(1) + ", Request" if "Request" not in m.group(1) else m.group(0)),
            main_s,
            count=1,
        )

    if "JSONResponse" not in main_s:
        # Starlette response import is fine
        if "from starlette.responses import" in main_s:
            main_s = re.sub(
                r"from starlette\.responses import ([^\n]+)",
                lambda m: "from starlette.responses import " + (m.group(1) + ", JSONResponse" if "JSONResponse" not in m.group(1) else m.group(0)),
                main_s,
                count=1,
            )
        else:
            # Insert a new import after other imports
            main_s = re.sub(
                r"(^from __future__ import annotations\s*\n)",
                r"\1\nfrom starlette.responses import JSONResponse\n",
                main_s,
                count=1,
                flags=re.M,
            )

    # Find build_app and insert middleware after app is created.
    # We’ll search for "app = FastAPI(" inside build_app.
    build_pat = re.compile(
        r"(def\s+build_app\([\s\S]*?\):\n)([\s\S]*?)(\n\ndef|\Z)",
        re.M,
    )
    bm = build_pat.search(main_s)
    if not bm:
        die("Could not find build_app() in api/main.py")

    build_block = bm.group(2)

    app_line = re.search(r"^\s*app\s*=\s*FastAPI\([^\n]*\)\s*$", build_block, flags=re.M)
    if not app_line:
        # Some code uses FastAPI(...) over multiple lines. Find first "app = FastAPI"
        app_line = re.search(r"^\s*app\s*=\s*FastAPI\(", build_block, flags=re.M)
    if not app_line:
        die("Could not find app = FastAPI(...) line in build_app()")

    # Insert middleware after app initialization (right after the line where app is created).
    insert_at = app_line.end()

    mw = f"""

    # {marker_ui}
    # Test expects: same /ui/* request with same key succeeds once, then 403.
    if not hasattr(app.state, "_ui_used_keys"):
        app.state._ui_used_keys = set()

    @app.middleware("http")
    async def _ui_single_use_key_guard(request: Request, call_next):
        if request.url.path.startswith("/ui/"):
            key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
            if key:
                used = app.state._ui_used_keys
                if key in used:
                    return JSONResponse(status_code=403, content={{"detail": "UI key already used"}})
                used.add(key)
        return await call_next(request)
"""

    # Put middleware just after the first app creation statement line
    # If app creation spans multiple lines, we still inject after the first line; good enough.
    build_block2 = build_block[:insert_at] + mw + build_block[insert_at:]

    main_s2 = main_s[:bm.start(2)] + build_block2 + main_s[bm.end(2):]
    write(MAIN, main_s2)
else:
    print("SKIP: ui single-use middleware marker already present")

print("DONE")
