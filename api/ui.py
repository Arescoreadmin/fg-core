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
    # Minimal UI: shows live feed, polls every 1s, renders as table.
    # Auth: relies on fg_api_key cookie set by /ui/token.
    return HTMLResponse(
        """<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>FrostGate Live Feed</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 16px; }
    h1 { margin: 0 0 8px 0; }
    .meta { color: #666; margin-bottom: 12px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; font-size: 13px; }
    th { background: #f5f5f5; text-align: left; position: sticky; top: 0; }
    tr:hover { background: #fafafa; }
    .pill { padding: 2px 8px; border-radius: 999px; border: 1px solid #ddd; display: inline-block; }
    .sev-critical { font-weight: 700; }
    .sev-high { font-weight: 700; }
    .small { font-size: 12px; color: #777; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  </style>
</head>
<body>
  <h1>FrostGate Live Feed</h1>
  <div class="meta">
    <span id="status" class="pill">starting…</span>
    <span class="small">Polls <span class="mono">/feed/live</span> every 1s. Uses cookie auth.</span>
  </div>

  <table>
    <thead>
      <tr>
        <th style="width:70px;">ID</th>
        <th style="width:180px;">Time</th>
        <th style="width:90px;">Severity</th>
        <th style="width:120px;">Action</th>
        <th style="width:260px;">Title</th>
        <th>Summary</th>
        <th style="width:140px;">Source</th>
      </tr>
    </thead>
    <tbody id="rows"></tbody>
  </table>

<script>
let sinceId = null;
const seen = new Set();
const statusEl = document.getElementById("status");
const rowsEl = document.getElementById("rows");

function esc(s) {
  return String(s ?? "")
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;");
}

function sevClass(sev) {
  const s = (sev || "").toLowerCase();
  if (s === "critical") return "sev-critical";
  if (s === "high") return "sev-high";
  return "";
}

function renderItem(it) {
  const id = it.id;
  if (seen.has(id)) return;
  seen.add(id);

  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td class="mono">${esc(it.id)}</td>
    <td class="mono">${esc(it.timestamp)}</td>
    <td class="${sevClass(it.severity)}">${esc(it.severity)}</td>
    <td>${esc(it.action_taken)}</td>
    <td>${esc(it.title)}</td>
    <td>${esc(it.summary)}</td>
    <td>${esc(it.source)}</td>
  `;

  rowsEl.prepend(tr);
  while (rowsEl.children.length > 200) rowsEl.removeChild(rowsEl.lastChild);
}

async function tick() {
  try {
    const url = new URL("/feed/live", window.location.origin);
    url.searchParams.set("limit", "50");
    if (sinceId !== null) url.searchParams.set("since_id", String(sinceId));

    const r = await fetch(url.toString(), { credentials: "include" });
    if (!r.ok) {
      statusEl.textContent = `HTTP ${r.status}`;
      return;
    }
    const data = await r.json();
    statusEl.textContent = "OK";
    const items = data.items || [];
    for (const it of items) renderItem(it);
    if (data.next_since_id !== undefined && data.next_since_id !== null) {
      sinceId = data.next_since_id;
    }
  } catch (e) {
    statusEl.textContent = "ERR";
    console.warn(e);
  }
}

setInterval(tick, 1000);
tick();
</script>
</body>
</html>""",
        headers={
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
        },
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
