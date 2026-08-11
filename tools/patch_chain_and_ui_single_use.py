from __future__ import annotations

import re
from pathlib import Path

ROOT = Path.cwd()
CHAIN = ROOT / "api" / "evidence_chain.py"


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

print("DONE")
