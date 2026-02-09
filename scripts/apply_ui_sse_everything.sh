#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

echo "==> 1) Ensure /feed/stream SSE exists (idempotent)"
python - <<'PY'
from pathlib import Path
import re

p = Path("api/feed.py")
s = p.read_text()

if re.search(r'@router\.get\(\s*["\']/stream["\']', s):
    print("✅ api/feed.py already has /feed/stream")
    raise SystemExit(0)

# Minimal, robust import fixing
def ensure_import(line: str, after_pattern: str):
    nonlocal_s = globals()["s"]
    if line in nonlocal_s:
        return
    nonlocal_s = re.sub(after_pattern, lambda m: m.group(0) + line + "\n", nonlocal_s, count=1, flags=re.M)
    globals()["s"] = nonlocal_s

# Ensure asyncio/json exist after future import
if "import asyncio" not in s or "import json" not in s:
    s = re.sub(
        r"(from __future__ import annotations\s*\n)",
        r"\1\n" + ("import asyncio\n" if "import asyncio" not in s else "") + ("import json\n" if "import json" not in s else "") + "\n",
        s,
        count=1
    )

# Ensure Request in fastapi import
m = re.search(r"^from fastapi import (.+)$", s, flags=re.M)
if not m:
    raise SystemExit("ERROR: couldn't find 'from fastapi import ...' in api/feed.py")
imports = [x.strip() for x in m.group(1).split(",")]
if "Request" not in imports:
    imports.append("Request")
    s = re.sub(r"^from fastapi import .+$", "from fastapi import " + ", ".join(imports), s, flags=re.M, count=1)

# Ensure StreamingResponse import
if "StreamingResponse" not in s:
    if "from starlette.responses import StreamingResponse" not in s:
        s = re.sub(r"(from fastapi import [^\n]+\n)", r"\1from starlette.responses import StreamingResponse\n", s, count=1)

# Append SSE endpoint
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
    Reuses feed_live() dynamically.
    """

    async def event_gen():
        nonlocal since_id
        yield "retry: 1000\n\n"

        while True:
            try:
                if await request.is_disconnected():
                    break
            except Exception:
                pass

            fn = globals().get("feed_live")
            if fn is None:
                yield 'event: error\ndata: {"detail":"feed_live not found"}\n\n'
                break

            resp = fn(db=db, since_id=since_id, limit=limit)
            if hasattr(resp, "__await__"):
                resp = await resp

            data = resp.model_dump() if hasattr(resp, "model_dump") else (resp.dict() if hasattr(resp, "dict") else resp)

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

echo "==> 2) Replace UI /ui/feed page with SSE-driven table (idempotent)"
python - <<'PY'
from pathlib import Path
import re

p = Path("api/ui.py")
s = p.read_text()

# Ensure APIRouter exists; we only replace the ui_feed function body safely.
# We'll key on 'def ui_feed' and replace that function only.

m = re.search(r"(?m)^def\s+ui_feed\s*\(", s)
if not m:
    raise SystemExit("ERROR: api/ui.py has no ui_feed() function to patch.")

# Find function block boundaries by indentation (simple but reliable)
start = m.start()
# Find next top-level def or decorator after this def
tail = s[start:]
m2 = re.search(r"(?m)^(?:@router\.|def\s+)(?!ui_feed\b)", tail)
end = start + (m2.start() if m2 else len(tail))

block = s[start:end]

# Idempotent: if already contains "EventSource" and "/feed/stream", skip
if "new EventSource" in block and "/feed/stream" in block:
    print("✅ ui_feed already SSE-enabled")
    raise SystemExit(0)

new_func = r'''def ui_feed():
    # Minimal HTML dashboard: SSE first, fallback to polling.
    return HTMLResponse(
        """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>FrostGate Live Feed</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 16px; }
    h1 { margin: 0 0 8px 0; }
    #status { display:flex; align-items:center; gap:10px; font-size: 12px; color:#444; margin: 8px 0 12px; }
    .pill { display:inline-block; padding: 2px 8px; border-radius: 999px; border: 1px solid #ccc; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { border-bottom: 1px solid #eee; padding: 6px 8px; text-align: left; vertical-align: top; }
    th { position: sticky; top: 0; background: #fff; z-index: 1; }
    tr:hover td { background: #fafafa; }
    .sev-critical,.sev-high { font-weight: 600; }
    .muted { color:#666; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; }
    details { cursor: pointer; }
    summary { list-style: none; }
    summary::-webkit-details-marker { display:none; }
  </style>
</head>
<body>
  <h1>FrostGate Live Feed</h1>
  <div id="status">
    <span class="pill" id="mode">connecting</span>
    <span class="muted" id="meta">SSE: /feed/stream</span>
  </div>

  <table>
    <thead>
      <tr>
        <th>ID</th><th>Time</th><th>Severity</th><th>Action</th><th>Title</th><th>Summary</th><th>Source</th>
      </tr>
    </thead>
    <tbody id="rows"></tbody>
  </table>

<script>
const rowsEl = document.getElementById("rows");
const modeEl = document.getElementById("mode");
const metaEl = document.getElementById("meta");

let seen = new Set();
let since_id = null;
let useSSE = true;

function esc(s){ return String(s ?? "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function fmtTime(t){ return t ? esc(t) : ""; }

function addItems(items){
  for (const it of items){
    const id = it.id;
    if (seen.has(id)) continue;
    seen.add(id);

    const sev = (it.severity || "").toLowerCase();
    const sevCls = sev ? ("sev-" + sev) : "";
    const title = esc(it.title);
    const summary = esc(it.summary);
    const source = esc(it.source);
    const action = esc(it.action_taken);
    const ts = fmtTime(it.timestamp);

    const diff = it.decision_diff ? JSON.stringify(it.decision_diff, null, 2) : "";
    const meta = it.metadata ? JSON.stringify(it.metadata, null, 2) : "";

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">${esc(id)}</td>
      <td class="mono">${ts}</td>
      <td class="${sevCls}">${esc(sev || "")}</td>
      <td>${action}</td>
      <td>${title}</td>
      <td>
        ${summary}
        ${(diff || meta) ? `
          <details>
            <summary class="muted">details</summary>
            ${diff ? `<pre class="mono">${esc(diff)}</pre>` : ""}
            ${meta ? `<pre class="mono">${esc(meta)}</pre>` : ""}
          </details>
        ` : ""}
      </td>
      <td>${source}</td>
    `;
    rowsEl.prepend(tr);
  }
}

async function poll(){
  try{
    const url = `/feed/live?limit=50` + (since_id ? `&since_id=${since_id}` : "");
    const r = await fetch(url, { credentials: "include" });
    if (!r.ok) throw new Error("poll status " + r.status);
    const data = await r.json();
    if (data?.items) addItems(data.items);
    if (data?.next_since_id) since_id = data.next_since_id;
    modeEl.textContent = "polling";
    modeEl.className = "pill";
    metaEl.textContent = "Polling: /feed/live (cookie auth)";
  }catch(e){
    modeEl.textContent = "error";
    metaEl.textContent = "Polling failed: " + e;
  }
}

function startSSE(){
  modeEl.textContent = "connecting";
  metaEl.textContent = "SSE: /feed/stream (cookie auth)";
  const url = `/feed/stream?limit=50&interval=1.0` + (since_id ? `&since_id=${since_id}` : "");
  const es = new EventSource(url, { withCredentials: true });

  es.addEventListener("items", (ev) => {
    try{
      const data = JSON.parse(ev.data);
      if (data?.items) addItems(data.items);
      if (data?.next_since_id) since_id = data.next_since_id;
      modeEl.textContent = "sse";
    }catch(e){
      modeEl.textContent = "error";
      metaEl.textContent = "SSE parse failed: " + e;
    }
  });

  es.addEventListener("ping", () => {
    modeEl.textContent = "sse";
  });

  es.onerror = () => {
    // fallback to polling if SSE fails
    if (useSSE){
      useSSE = false;
      try { es.close(); } catch(_){}
      modeEl.textContent = "fallback";
      metaEl.textContent = "SSE failed; falling back to polling.";
      poll();
      setInterval(poll, 1500);
    }
  };
}

startSSE();
</script>

</body>
</html>
"""
    )
'''
# Ensure HTMLResponse import exists
if "HTMLResponse" not in s:
    if "from fastapi.responses import HTMLResponse" not in s:
        # Insert after fastapi imports
        s = re.sub(r"(^from fastapi[^\n]*\n)", r"\1from fastapi.responses import HTMLResponse\n", s, flags=re.M, count=1)

# Replace only the ui_feed function body
# Find def ui_feed block and replace until next top-level decorator/def
start = m.start()
tail = s[start:]
m2 = re.search(r"(?m)^(?:@router\.|def\s+)(?!ui_feed\b)", tail)
end = start + (m2.start() if m2 else len(tail))
s = s[:start] + new_func + s[end:]
p.write_text(s)
print("✅ Patched ui_feed() in api/ui.py to use SSE + fallback polling")
PY

echo "==> 3) Compile + restart with FG_UI_TOKEN_GET_ENABLED=1"
python -m py_compile api/feed.py api/ui.py api/auth_scopes/__init__.py api/main.py >/dev/null
export FG_UI_TOKEN_GET_ENABLED=1
make fg-restart

echo "==> 4) Smoke: issue cookie + open UI"
curl -s -i -c /tmp/cj -H "X-API-Key: ${FG_API_KEY:?set FG_API_KEY}" "http://127.0.0.1:8000/ui/token" | head -n 12 || true
echo "✅ cookie jar:"; tail -n 2 /tmp/cj
echo "✅ SSE headers:"
curl -s -i -b /tmp/cj "http://127.0.0.1:8000/feed/stream?limit=1&interval=1.0" | head -n 12 || true
if [ "${FG_NO_OPEN:-0}" != "1" ]; then 
  xdg-open "http://127.0.0.1:8000/ui/feed" >/dev/null 2>&1 || true || true >/dev/null 2>&1 || true
fi

echo "✅ Done."

exit 0
