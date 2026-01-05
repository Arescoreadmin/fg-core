from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse

from api.auth_scopes import require_api_key_always, require_scopes
from api.ratelimit import rate_limit_guard

router = APIRouter(
    prefix="/ui",
    tags=["ui"],
    # IMPORTANT: do NOT put rate_limit_guard here or it will block /ui/token GET
)

UI_COOKIE_NAME = os.getenv("FG_UI_COOKIE_NAME", "fg_api_key")
ERR_INVALID = "Invalid or missing API key"


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _auth_enabled() -> bool:
    if os.getenv("FG_AUTH_ENABLED") is not None:
        return _env_bool("FG_AUTH_ENABLED", default=False)
    return bool(os.getenv("FG_API_KEY"))


def _is_prod() -> bool:
    return os.getenv("FG_ENV", "dev").strip().lower() in {"prod", "production"}


def _html_headers() -> dict[str, str]:
    return {
        "Cache-Control": "no-store, max-age=0",
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }


def _get_cookie_key(req: Request) -> Optional[str]:
    v = req.cookies.get(UI_COOKIE_NAME)
    if v and str(v).strip():
        return str(v).strip()
    return None


def _get_header_key(req: Request) -> Optional[str]:
    v = req.headers.get("x-api-key")
    if v and str(v).strip():
        return str(v).strip()
    return None


def _get_query_key(req: Request) -> Optional[str]:
    v = req.query_params.get("api_key") or req.query_params.get("key")
    if v and str(v).strip():
        return str(v).strip()
    return None


def _require_ui_key(req: Request) -> None:
    if not _auth_enabled():
        return
    if _get_cookie_key(req) or _get_header_key(req) or _get_query_key(req):
        return
    raise HTTPException(status_code=401, detail=ERR_INVALID)


@router.get(
    "/feed",
    response_class=HTMLResponse,
    operation_id="ui_feed_page",
    dependencies=[Depends(rate_limit_guard)],
)
@router.get("/feed", include_in_schema=False)
def ui_feed():
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
@router.post(
    "/token",
    dependencies=[
        Depends(rate_limit_guard),
        Depends(require_api_key_always),
        Depends(require_scopes("feed:read")),
    ],
    operation_id="ui_token_post",
)
def ui_token_post(
    resp: Response,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    if not x_api_key:
        raise HTTPException(status_code=401, detail=ERR_INVALID)

    key = str(x_api_key).strip()

    resp.set_cookie(
        key=UI_COOKIE_NAME,
        value=key,
        httponly=True,
        samesite="lax",
        secure=_is_prod(),
        path="/",
        max_age=60 * 60 * 8,
    )
    return {"ok": True, "api_key": key, "cookie": UI_COOKIE_NAME}


@router.get("/token", response_class=HTMLResponse, operation_id="ui_token_get")
def ui_token_get(
    request: Request,
    api_key: str | None = Query(default=None, alias="api_key"),
    key: str | None = Query(default=None),
):
    # Dev-only convenience. Keep it OFF in prod.
    if os.getenv("FG_UI_TOKEN_GET_ENABLED", "0") != "1":
        raise HTTPException(status_code=404, detail="Not Found")

    raw = (api_key or key or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="missing api_key")

    api_key_val = raw

    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>FrostGate UI Token</title>
</head>
<body>
<script>
  try {{
    localStorage.setItem("FG_API_KEY", {api_key_val!r});
  }} catch (e) {{
    console.warn("localStorage blocked:", e);
  }}
  window.location.replace("/ui/feed");
</script>
<p>Setting token…</p>
</body>
</html>
"""

    resp = HTMLResponse(content=html, headers=_html_headers())
    resp.set_cookie(
        key=UI_COOKIE_NAME,
        value=api_key_val,
        httponly=True,
        samesite="lax",
        secure=_is_prod(),
        path="/",
        max_age=60 * 60 * 8,
    )
    return resp
