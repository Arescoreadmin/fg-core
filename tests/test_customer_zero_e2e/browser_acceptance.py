"""Opt-in browser acceptance for the customer portal — L14-CUSTOMER-ZERO-E2E-001.

NOT collected by pytest.  Run explicitly:

    FG_CUSTOMER_ZERO_OUT=<dir> .venv/bin/python -m tests.test_customer_zero_e2e.browser_acceptance

What it does (all local, synthetic, nonproduction):

1. Builds an isolated SQLite database in a temp directory and seeds the
   Northstar customer through the same harness code as the pytest journey
   (admin provisioning, production bridges, runtime evidence, real report).
2. Starts the real core API (uvicorn, 127.0.0.1) on that database.
3. Starts the real customer portal (apps/portal, ``next dev``, 127.0.0.1)
   with NODE_ENV=development and telemetry disabled.  The portal's
   grant-secret login is a DEVELOPMENT path — it is disabled in
   production-like environments, where only OIDC named-user sessions work.
4. Drives headless Chromium over the DevTools protocol: log in with the
   portal grant secret, open dashboard / engagement / findings / reports,
   download the PDF through the portal proxy, open a non-granted
   engagement, and capture full-page screenshots.
5. Terminates exactly the processes it started.

No production credentials, no external network calls, no real customer data.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_http(url: str, timeout: float) -> None:
    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310 — loopback only
                if r.status < 500:
                    return
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(1)
    raise TimeoutError(f"{url} not ready: {last}")


def _base_env(tmp: Path) -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "FG_ENV": "test",
            "FG_SQLITE_PATH": str(tmp / "customer-zero.db"),
            "FG_AUTH_ENABLED": "1",
            "FG_API_KEY": "ci-test-key-" + "0" * 32,
            "FG_KEY_PEPPER": "ci-test-pepper",
            "FG_DEVICE_KEY_KEK_CURRENT_VERSION": "v1",
            "FG_DEVICE_KEY_KEK_V1": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
            "FG_ADMIN_ENABLED": "1",
            "FG_ENTITLEMENT_ENFORCEMENT": "false",
            "FG_REPORT_SIGNING_KEY": "cd" * 32,
            "FG_DEV_EVENTS_ENABLED": "0",
        }
    )
    for k in (
        "FG_INTERNAL_GATEWAY_SECRET",
        "FG_ADMIN_GATEWAY_INTERNAL_TOKEN",
        "FG_INTERNAL_AUTH_SECRET",
    ):
        env.pop(k, None)
    return env


def seed(env: dict[str, str], tmp: Path) -> dict[str, Any]:
    """Seed in-process with the pytest harness code; returns ids and secrets."""
    os.environ.update(env)
    import tools.tenants.registry as registry

    registry.REGISTRY_PATH = tmp / "tenants.json"
    import api.entitlements as ent

    ent.ENFORCEMENT_STRICT = False
    from fastapi.testclient import TestClient

    from api.db import init_db, reset_engine_cache
    from api.main import build_app
    from tests.test_customer_zero_e2e import _northstar as N
    from tests.test_customer_zero_e2e.conftest import Platform
    from tests.test_customer_zero_e2e.test_customer_zero_journey import (
        _engagement,
        provision,
    )

    reset_engine_cache()
    init_db(sqlite_path=env["FG_SQLITE_PATH"])
    app = build_app()
    platform = Platform(app, env["FG_API_KEY"])
    provision(platform, None)
    eid = _engagement(platform)
    N.seed_collection(eid)
    assessor = platform.client("assessor")
    rep = assessor.post(
        f"/field-assessment/engagements/{eid}/reports",
        json={"report_type": "full_assessment"},
    )
    assert rep.status_code == 201, rep.text
    grant = assessor.post(
        f"/field-assessment/engagements/{eid}/portal-grants", json={"ttl_days": 14}
    )
    assert grant.status_code == 201, grant.text
    other = assessor.post(
        "/field-assessment/engagements",
        json={
            "client_name": "SYNTHETIC — not granted",
            "assessor_id": "synthetic-assessor",
            "assessment_type": "comprehensive",
        },
    ).json()["id"]
    TestClient(app).close()
    return {
        "tenant": N.TENANT,
        "engagement_id": eid,
        "other_engagement_id": other,
        "report_version": rep.json()["version"],
        "grant_secret": grant.json()["raw_secret"],
        "bff_key": platform.keys["portal_bff"],
    }


async def _cdp(
    ws_url: str, steps: list[dict[str, Any]], out: Path
) -> list[dict[str, Any]]:
    import websockets

    results: list[dict[str, Any]] = []
    async with websockets.connect(ws_url, max_size=64 * 1024 * 1024) as ws:
        msg_id = 0

        async def call(
            method: str, params: dict[str, Any] | None = None
        ) -> dict[str, Any]:
            nonlocal msg_id
            msg_id += 1
            await ws.send(
                json.dumps({"id": msg_id, "method": method, "params": params or {}})
            )
            while True:
                data = json.loads(await ws.recv())
                if data.get("id") == msg_id:
                    return data

        await call("Page.enable")
        await call("Runtime.enable")
        await call(
            "Emulation.setDeviceMetricsOverride",
            {"width": 1366, "height": 900, "deviceScaleFactor": 1, "mobile": False},
        )
        for step in steps:
            rec: dict[str, Any] = {"name": step["name"]}
            if "url" in step:
                await call("Page.navigate", {"url": step["url"]})
                await asyncio.sleep(step.get("settle", 6))
            if "js" in step:
                r = await call(
                    "Runtime.evaluate",
                    {
                        "expression": step["js"],
                        "awaitPromise": True,
                        "returnByValue": True,
                    },
                )
                rec["js_result"] = r.get("result", {}).get("result", {}).get("value")
            if step.get("shot"):
                text = await call(
                    "Runtime.evaluate",
                    {
                        "expression": "document.body ? document.body.innerText : ''",
                        "returnByValue": True,
                    },
                )
                body = text.get("result", {}).get("result", {}).get("value") or ""
                rec["text_excerpt"] = body[:1500]
                loc = await call(
                    "Runtime.evaluate",
                    {"expression": "location.href", "returnByValue": True},
                )
                rec["final_url"] = loc.get("result", {}).get("result", {}).get("value")
                shot = await call(
                    "Page.captureScreenshot",
                    {"format": "png", "captureBeyondViewport": True},
                )
                png = base64.b64decode(shot["result"]["data"])
                path = out / f"portal_{step['name']}.png"
                path.write_bytes(png)
                rec["screenshot"] = path.name
            results.append(rec)
    return results


def main() -> int:
    out = Path(
        os.getenv("FG_CUSTOMER_ZERO_OUT") or tempfile.mkdtemp(prefix="cz-browser-")
    )
    out.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="cz-e2e-"))
    env = _base_env(tmp)
    procs: list[subprocess.Popen[bytes]] = []
    log: dict[str, Any] = {
        "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    try:
        ids = seed(env, tmp)
        log["seed"] = {
            k: v for k, v in ids.items() if k not in ("grant_secret", "bff_key")
        }
        api_port, portal_port, cdp_port = _free_port(), _free_port(), _free_port()
        core_log = open(tmp / "core.log", "wb")  # noqa: SIM115
        procs.append(
            subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "api.main:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(api_port),
                ],
                cwd=REPO,
                env=env,
                stdout=core_log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        )
        _wait_http(f"http://127.0.0.1:{api_port}/health", 90)
        portal_env = dict(os.environ)
        portal_env.update(
            {
                "NODE_ENV": "development",
                "NEXT_TELEMETRY_DISABLED": "1",
                "CORE_API_URL": f"http://127.0.0.1:{api_port}",
                "CORE_API_KEY": ids["bff_key"],
                "CORE_TENANT_ID": ids["tenant"],
                "PORTAL_SESSION_SECRET": secrets.token_hex(32),
            }
        )
        portal_log = open(tmp / "portal.log", "wb")  # noqa: SIM115
        npx = shutil.which("npx") or "npx"
        procs.append(
            subprocess.Popen(
                [npx, "next", "dev", "-p", str(portal_port), "-H", "127.0.0.1"],
                cwd=REPO / "apps" / "portal",
                env=portal_env,
                stdout=portal_log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        )
        portal = f"http://127.0.0.1:{portal_port}"
        _wait_http(f"{portal}/api/health", 240)
        chrome = (
            shutil.which("chromium")
            or shutil.which("chromium-browser")
            or shutil.which("google-chrome")
        )
        if chrome is None:
            log["browser"] = "NOT_TESTED: no Chromium"
            return 2
        profile = tmp / "chrome-profile"
        procs.append(
            subprocess.Popen(
                [
                    chrome,
                    "--headless=new",
                    f"--remote-debugging-port={cdp_port}",
                    f"--user-data-dir={profile}",
                    "--no-first-run",
                    "--disable-gpu",
                    "--no-default-browser-check",
                    "about:blank",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        )
        _wait_http(f"http://127.0.0.1:{cdp_port}/json/version", 60)
        with urllib.request.urlopen(
            f"http://127.0.0.1:{cdp_port}/json/list", timeout=5
        ) as r:  # noqa: S310
            targets = json.loads(r.read())
        ws_url = next(
            t["webSocketDebuggerUrl"] for t in targets if t.get("type") == "page"
        )
        eid, other, v = (
            ids["engagement_id"],
            ids["other_engagement_id"],
            ids["report_version"],
        )
        login_js = (
            "fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},"
            f"body:JSON.stringify({{password:{json.dumps(ids['grant_secret'])}}})}})"
            ".then(r=>r.status)"
        )
        pdf_js = (
            f"fetch('/api/core/field-assessment/engagements/{eid}/reports/{v}/export?format=pdf')"
            ".then(async r=>({status:r.status,type:r.headers.get('content-type'),"
            "state:r.headers.get('x-report-state'),bytes:(await r.arrayBuffer()).byteLength}))"
        )
        write_js = (
            f"fetch('/api/core/field-assessment/engagements/{eid}/reports',{{method:'POST',"
            "headers:{'Content-Type':'application/json'},body:JSON.stringify({report_type:'full_assessment'})})"
            ".then(r=>r.status)"
        )
        steps: list[dict[str, Any]] = [
            {
                "name": "login_page",
                "url": f"{portal}/login",
                "shot": True,
                "settle": 15,
            },
            {"name": "login", "js": login_js},
            {
                "name": "dashboard",
                "url": f"{portal}/dashboard?e={eid}",
                "shot": True,
                "settle": 15,
            },
            {
                "name": "engagement_detail",
                "url": f"{portal}/engagement/{eid}",
                "shot": True,
                "settle": 15,
            },
            {
                "name": "findings",
                "url": f"{portal}/findings?e={eid}",
                "shot": True,
                "settle": 15,
            },
            {
                "name": "reports",
                "url": f"{portal}/reports?e={eid}",
                "shot": True,
                "settle": 15,
            },
            {"name": "pdf_download", "js": pdf_js},
            {"name": "write_attempt", "js": write_js},
            {
                "name": "access_denied_other_engagement",
                "url": f"{portal}/engagement/{other}",
                "shot": True,
                "settle": 15,
            },
        ]
        log["steps"] = asyncio.run(_cdp(ws_url, steps, out))
        return 0
    finally:
        for p in reversed(procs):
            try:
                os.killpg(p.pid, signal.SIGTERM)
                p.wait(timeout=20)
            except Exception:  # noqa: BLE001
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except Exception:  # noqa: BLE001
                    pass
        for name in ("core.log", "portal.log"):
            if (tmp / name).exists():
                shutil.copy(tmp / name, out / f"browser_{name}")
        (out / "browser_acceptance.json").write_text(
            json.dumps(log, indent=2, default=str)
        )


if __name__ == "__main__":
    raise SystemExit(main())
