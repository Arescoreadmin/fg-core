#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

python - <<'PY'
from pathlib import Path
import re

p = Path("api/feed.py")
s = p.read_text()

# Idempotent: if /stream already exists, stop.
if re.search(r'@router\.get\(\s*["\']/stream["\']', s):
    print("✅ api/feed.py already has /feed/stream")
    raise SystemExit(0)

# --- Ensure imports ---
# Add json/asyncio if missing
need = []
if "import json" not in s:
    need.append("import json")
if "import asyncio" not in s:
    need.append("import asyncio")

if need:
    s = re.sub(
        r"(from __future__ import annotations\s*\n\n)",
        r"\1" + "\n".join(need) + "\n\n",
        s,
        count=1
    )

# Ensure Request is imported from fastapi
m = re.search(r"^from fastapi import (.+)$", s, flags=re.M)
if not m:
    raise SystemExit("ERROR: couldn't find 'from fastapi import ...' in api/feed.py")

imports = [x.strip() for x in m.group(1).split(",")]
if "Request" not in imports:
    imports.append("Request")
    s = re.sub(
        r"^from fastapi import .+$",
        "from fastapi import " + ", ".join(imports),
        s,
        flags=re.M,
        count=1
    )

# Ensure StreamingResponse import exists
if "StreamingResponse" not in s:
    if "from starlette.responses import StreamingResponse" not in s:
        s = re.sub(
            r"(from fastapi import [^\n]+\n)",
            r"\1from starlette.responses import StreamingResponse\n",
            s,
            count=1
        )

# --- Append SSE endpoint ---
sse = r'''

@router.get("/stream")
async def feed_stream(
    request: Request,
    db: Session = Depends(get_db),
    since_id: int | None = None,
    limit: int = 50,
    interval: float = 1.0,
):
    """
    Server-Sent Events stream for the live feed.
    Reuses feed_live() dynamically (no schema guessing).
    """

    async def event_gen():
        nonlocal since_id
        # Suggest client retry quickly
        yield "retry: 1000\n\n"

        while True:
            # disconnect detection (best effort)
            try:
                if await request.is_disconnected():
                    break
            except Exception:
                pass

            # Reuse existing feed_live if present
            fn = globals().get("feed_live")
            if fn is None:
                # If someone renamed it, that's on you.
                yield 'event: error\ndata: {"detail":"feed_live not found"}\n\n'
                break

            resp = fn(db=db, since_id=since_id, limit=limit)
            if hasattr(resp, "__await__"):
                resp = await resp

            data = resp.model_dump() if hasattr(resp, "model_dump") else (resp.dict() if hasattr(resp, "dict") else resp)

            # advance cursor
            try:
                since_id = data.get("next_since_id") or since_id
            except Exception:
                pass

            items = []
            try:
                items = data.get("items") or []
            except Exception:
                items = []

            if items:
                payload = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
                yield f"event: items\ndata: {payload}\n\n"
            else:
                yield "event: ping\ndata: {}\n\n"

            await asyncio.sleep(interval)

    return StreamingResponse(event_gen(), media_type="text/event-stream")
'''

s = s.rstrip() + "\n" + sse.lstrip()
p.write_text(s)
print("✅ Appended /feed/stream SSE endpoint to api/feed.py")
PY

python -m py_compile api/feed.py
echo "✅ py_compile ok"
