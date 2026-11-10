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


# Inherited database connection settings must never reach the harness: the
# core subprocess's init_db() prefers FG_DB_URL over FG_SQLITE_PATH.
_DB_ENV_DENYLIST = ("FG_DB_URL", "FG_DB_MIGRATION_URL", "DATABASE_URL")


def _is_db_connection_var(name: str) -> bool:
    return (
        name in _DB_ENV_DENYLIST
        or name.startswith("PG")
        or (name.startswith("FG_") and ("POSTGRES" in name or name.endswith("_DB_URL")))
    )


def _base_env(tmp: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not _is_db_connection_var(k)}
    env.update(
        {
            "FG_ENV": "test",
            "FG_SQLITE_PATH": str(tmp / "customer-zero.db"),
            "FG_DB_BACKEND": "sqlite",
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
    for name in [k for k in os.environ if _is_db_connection_var(k)]:
        del os.environ[name]  # update() alone would keep an inherited FG_DB_URL
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
    from api.db import get_engine

    engine = get_engine()
    # Fail closed before any write: the harness must be on its temp SQLite file.
    if (
        engine.dialect.name != "sqlite"
        or str(engine.url.database) != env["FG_SQLITE_PATH"]
    ):
        raise RuntimeError(
            f"refusing to seed: engine is {engine.url!r}, not the isolated SQLite file"
        )
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
    permitted = assessor.post(
        "/field-assessment/engagements",
        json={
            "client_name": "SYNTHETIC — draft review permitted",
            "assessor_id": "synthetic-assessor",
            "assessment_type": "comprehensive",
        },
    ).json()["id"]
    permitted_report = assessor.post(
        f"/field-assessment/engagements/{permitted}/reports",
        json={"report_type": "full_assessment"},
    )
    assert permitted_report.status_code == 201, permitted_report.text
    policy = assessor.patch(
        f"/field-assessment/engagements/{permitted}",
        json={
            "engagement_metadata": {
                "report_access_policy": {"customer_draft_review": True}
            }
        },
    )
    assert policy.status_code == 200, policy.text
    permitted_grant = assessor.post(
        f"/field-assessment/engagements/{permitted}/portal-grants",
        json={"ttl_days": 14},
    )
    assert permitted_grant.status_code == 201, permitted_grant.text
    TestClient(app).close()
    return {
        "tenant": N.TENANT,
        "engagement_id": eid,
        "other_engagement_id": other,
        "permitted_engagement_id": permitted,
        "report_version": rep.json()["version"],
        "permitted_report_version": permitted_report.json()["version"],
        "grant_secret": grant.json()["raw_secret"],
        "permitted_grant_secret": permitted_grant.json()["raw_secret"],
        "bff_key": platform.keys["portal_bff"],
    }


async def _cdp(ws_url: str, steps: list[dict[str, Any]], out: Path) -> dict[str, Any]:
    """Drive Chromium over CDP.  A reader task records console messages,
    uncaught exceptions and every network response while steps run."""
    import websockets

    console: list[dict[str, Any]] = []
    network: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
    current = {"step": ""}

    async with websockets.connect(ws_url, max_size=64 * 1024 * 1024) as ws:

        async def reader() -> None:
            async for raw in ws:
                data = json.loads(raw)
                if "id" in data and data["id"] in pending:
                    pending.pop(data["id"]).set_result(data)
                    continue
                method, params = data.get("method"), data.get("params", {})
                if method == "Runtime.consoleAPICalled" and params.get("type") in (
                    "error",
                    "warning",
                    "assert",
                ):
                    console.append(
                        {
                            "step": current["step"],
                            "type": params.get("type"),
                            "text": " ".join(
                                str(a.get("value", a.get("description", "")))
                                for a in params.get("args", [])
                            )[:500],
                        }
                    )
                elif method == "Runtime.exceptionThrown":
                    d = params.get("exceptionDetails", {})
                    console.append(
                        {
                            "step": current["step"],
                            "type": "exception",
                            "text": str(
                                (d.get("exception") or {}).get("description")
                                or d.get("text")
                            )[:500],
                        }
                    )
                elif method == "Log.entryAdded" and params.get("entry", {}).get(
                    "level"
                ) in ("error", "warning"):
                    e = params["entry"]
                    console.append(
                        {
                            "step": current["step"],
                            "type": f"log.{e.get('level')}",
                            "text": str(e.get("text"))[:500],
                            "url": e.get("url"),
                        }
                    )
                elif method == "Network.responseReceived":
                    r = params.get("response", {})
                    url = str(r.get("url", ""))
                    if "/api/" in url or r.get("status", 200) >= 400:
                        network.append(
                            {
                                "step": current["step"],
                                "status": r.get("status"),
                                "url": url.split("127.0.0.1")[-1][:300],
                                "mime": r.get("mimeType"),
                            }
                        )

        task = asyncio.create_task(reader())
        msg_id = 0

        async def call(
            method: str, params: dict[str, Any] | None = None
        ) -> dict[str, Any]:
            nonlocal msg_id
            msg_id += 1
            fut: asyncio.Future[dict[str, Any]] = (
                asyncio.get_running_loop().create_future()
            )
            pending[msg_id] = fut
            await ws.send(
                json.dumps({"id": msg_id, "method": method, "params": params or {}})
            )
            return await asyncio.wait_for(fut, timeout=120)

        def value(r: dict[str, Any]) -> Any:
            return r.get("result", {}).get("result", {}).get("value")

        for domain in ("Page", "Runtime", "Network", "Log"):
            await call(f"{domain}.enable")
        await call(
            "Emulation.setDeviceMetricsOverride",
            {"width": 1366, "height": 900, "deviceScaleFactor": 1, "mobile": False},
        )
        for step in steps:
            current["step"] = step["name"]
            rec: dict[str, Any] = {"name": step["name"]}
            if "url" in step:
                await call("Page.navigate", {"url": step["url"]})
                await asyncio.sleep(step.get("settle", 8))
            if "js" in step:
                r = await call(
                    "Runtime.evaluate",
                    {
                        "expression": step["js"],
                        "awaitPromise": True,
                        "returnByValue": True,
                    },
                )
                rec["js_result"] = value(r)
            if step.get("shot"):
                rec["final_url"] = value(
                    await call(
                        "Runtime.evaluate",
                        {"expression": "location.href", "returnByValue": True},
                    )
                )
                body = (
                    value(
                        await call(
                            "Runtime.evaluate",
                            {
                                "expression": "document.body ? document.body.innerText : ''",
                                "returnByValue": True,
                            },
                        )
                    )
                    or ""
                )
                rec["text_excerpt"] = body[:2500]
                rec["nav_links"] = value(
                    await call(
                        "Runtime.evaluate",
                        {
                            "expression": "Array.from(document.querySelectorAll('nav a, header a')).map(a=>a.textContent.trim()+'→'+a.getAttribute('href')).slice(0,40)",
                            "returnByValue": True,
                        },
                    )
                )
                shot = await call(
                    "Page.captureScreenshot",
                    {"format": "png", "captureBeyondViewport": True},
                )
                path = out / f"portal_{step['name']}.png"
                path.write_bytes(base64.b64decode(shot["result"]["data"]))
                rec["screenshot"] = path.name
            results.append(rec)
        await asyncio.sleep(1)
        task.cancel()
    return {"steps": results, "console": console, "network": network}


def _check_downloaded_pdf(
    steps: list[dict[str, Any]],
    out: Path,
    step_name: str = "pdf_download_CZ17",
) -> dict[str, Any]:
    """Validate allowed PDF bytes or report a policy denial without parsing JSON as PDF."""
    import io

    import pypdf

    step = next((x for x in steps if x["name"] == step_name), None)
    res = (step or {}).get("js_result") or {}
    b64 = res.pop("b64", None) if isinstance(res, dict) else None
    status = res.get("status") if isinstance(res, dict) else None
    if status in (401, 403):
        return {"downloaded": False, "status": status, "denied": True}
    if status != 200:
        return {"downloaded": False, "status": status, "denied": False}
    if not b64:
        return {
            "downloaded": False,
            "status": status,
            "denied": status in (401, 403),
        }
    data = base64.b64decode(b64)
    (out / "portal_downloaded_report.pdf").write_bytes(data)
    reader = pypdf.PdfReader(io.BytesIO(data))
    pages = [" ".join((p.extract_text() or "").split()) for p in reader.pages]
    mark = "DRAFT — SYNTHETIC DATA — NOT VERIFIED"
    return {
        "downloaded": True,
        "denied": False,
        "status": res.get("status"),
        "content_type": res.get("type"),
        "x_report_state_forwarded": res.get("state"),
        "x_manifest_hash_forwarded": res.get("manifest_hash"),
        "report_id_forwarded": res.get("report_id"),
        "report_version_forwarded": res.get("report_version"),
        "content_disposition": res.get("disposition"),
        "bytes": len(data),
        "pages": len(pages),
        "draft_marking_every_page": all(mark in p for p in pages),
        "visible_state_marking_every_page": all(
            (mark if res.get("state") == "DRAFT_SYNTHETIC" else "DRAFT") in p.upper()
            for p in pages
        ),
        # Byte integrity of what the customer received (CZ-29).
        "utf8_replacement_sequences": data.count(b"\xef\xbf\xbd"),
        "binary_header_intact": data[:9] == b"%PDF-1.4\n" and data[10:11] != b"\xef",
        "startxref_matches": _startxref_ok(data),
    }


def _startxref_ok(data: bytes) -> bool:
    import re

    m = re.findall(rb"startxref\s+(\d+)", data)
    return bool(m) and data[int(m[-1]) : int(m[-1]) + 4] == b"xref"


def _portal_controls_entry(res: Any, st: dict[str, Any]) -> dict[str, Any]:
    """CZ-16B verdict derived from observed denials; missing evidence is NOT_TESTED."""
    write = res("write_attempt_generate_report").get("status")
    other = res("api_other_engagement_findings").get("status")
    after = res("api_after_logout").get("status")
    logout_url = str(st.get("after_logout_dashboard", {}).get("final_url") or "")
    observed = {
        "write": write,
        "non_granted_engagement": other,
        "api_after_logout": after,
        "dashboard_after_logout_url": logout_url or None,
    }
    checks = {
        "write": None if write is None else write in (401, 403),
        "non_granted_engagement": None if other is None else other in (401, 403, 404),
        # After logout the request must not be served: denial, a login redirect
        # (fetch fails cross-origin → null), never a 2xx with data.
        "api_after_logout": None
        if not st.get("api_after_logout")
        else (after is None or after in (401, 403) or after >= 300 and after < 400),
        "dashboard_after_logout": None if not logout_url else "/login" in logout_url,
    }
    if any(v is False for v in checks.values()):
        status, blocking = "FAIL", "P0"
    elif any(v is None for v in checks.values()):
        status, blocking = "NOT_TESTED", "none"
    else:
        status, blocking = "PASS", "none"
    return dict(
        step_id="CZ-16B",
        area="security",
        capability="Portal controls through the browser",
        executed_path="portal proxy write, non-granted engagement, requests after logout",
        expected="write denied; non-granted engagement denied; no data after logout",
        actual=json.dumps(observed),
        status=status,
        blocking=blocking,
        evidence={"checks": checks},
        limitations=[f"not observed: {[k for k, v in checks.items() if v is None]}"]
        if status == "NOT_TESTED"
        else [],
    )


def _browser_matrix(log: dict[str, Any], out: Path) -> None:
    """Acceptance entries derived only from what the browser observed."""
    from tests.test_customer_zero_e2e._acceptance import Acceptance

    st = {x["name"]: x for x in log["steps"]}

    def res(name: str) -> dict[str, Any]:
        r = st.get(name, {}).get("js_result")
        return r if isinstance(r, dict) else {"status": r}

    def text(name: str) -> str:
        return str(st.get(name, {}).get("text_excerpt") or "")

    acc = Acceptance()
    pdf = log.get("pdf_via_portal") or {}
    allowed_pdf = log.get("pdf_allowed_via_portal") or {}
    listed = (res("api_engagement_list_CZ18").get("body") or {}).get("items") or []
    findings_n = len((res("api_findings").get("body") or {}).get("items") or [])
    acc.record(
        step_id="CZ-21",
        area="browser_ui",
        capability="Authenticated customer portal (browser)",
        executed_path="Chromium → apps/portal (next dev) → /api/core proxy → core API; dev grant-secret login",
        expected="customer reads dashboard, engagement, findings, remediation, reports, coverage; PDF download",
        actual=f"login={res('login').get('status')}; findings API={findings_n}; pages captured={sum(1 for x in log['steps'] if x.get('screenshot'))}",
        status="PASS"
        if res("login").get("status") == 200 and findings_n > 0
        else "FAIL",
        blocking="none"
        if res("login").get("status") == 200 and findings_n > 0
        else "P1",
        evidence={
            "screenshots": [
                x["screenshot"] for x in log["steps"] if x.get("screenshot")
            ]
        },
        limitations=[
            "Grant-secret login is a development path (disabled in production-like envs); OIDC named-user login NOT_TESTED."
        ],
    )
    acc.record(**_portal_controls_entry(res, st))
    acc.record(
        step_id="CZ-17B",
        area="security",
        capability="Draft PDF downloadable via the portal UI",
        executed_path="portal GET /api/core/…/export?format=pdf",
        expected="policy-controlled draft visibility",
        actual=json.dumps(pdf),
        status=(
            "FAIL"
            if pdf.get("downloaded")
            else "PASS"
            if pdf.get("denied")
            else "NOT_TESTED"
        ),
        blocking="P1" if pdf.get("downloaded") else "none",
        limitations=[]
        if pdf.get("denied")
        else ["No successful download or explicit authorization denial was observed."],
    )
    acc.record(
        step_id="CZ-18B",
        area="security",
        capability="Engagement list scoping via the portal UI",
        executed_path="portal GET /api/core/field-assessment/engagements",
        expected="only the granted engagement",
        actual=f"{len(listed)} engagements listed",
        status="FAIL" if len(listed) > 1 else "PASS",
        blocking="P2" if len(listed) > 1 else "none",
    )
    ws = res("api_portal_workspace_reports_CZ19")
    canonical_reports = res("api_reports").get("body", {})
    workspace_reports = ws.get("body", {})
    canonical_report_ids = {
        (item.get("report_id"), item.get("version"), item.get("manifest_hash"))
        for item in canonical_reports.get("items", [])
    }
    workspace_report_ids = {
        (item.get("report_id"), item.get("version"), item.get("manifest_hash"))
        for item in workspace_reports.get("items", [])
    }
    workspace_consistent = (
        ws.get("status") == 200 and workspace_report_ids == canonical_report_ids
    )
    acc.record(
        step_id="CZ-19B",
        area="backend_workflow",
        capability="/portal/engagement/* through the portal",
        executed_path="portal GET /api/core/portal/engagement/reports?engagement_id={granted engagement}",
        expected="consistent report authority",
        actual=f"status={ws.get('status')}; canonical identities match={workspace_consistent}",
        status="PASS" if workspace_consistent else "FAIL",
        blocking="none" if workspace_consistent else "P1",
        limitations=[]
        if workspace_consistent
        else [
            "Portal workspace identity differs from canonical Field Assessment report records."
        ],
    )
    reports_txt = text("reports")
    acc.record(
        step_id="CZ-24",
        area="browser_ui",
        capability="Report status shown to the customer",
        executed_path="/reports page",
        expected="status consistent with report_state (DRAFT — SYNTHETIC — NOT VERIFIED)",
        actual=(
            "page shows 'Finalized'"
            if "Finalized" in reports_txt
            else "no 'Finalized' label"
        )
        + "; PDF is DRAFT_SYNTHETIC",
        status="FAIL" if "Finalized" in reports_txt else "PASS",
        blocking="P1" if "Finalized" in reports_txt else "none",
        limitations=[
            "UI maps the stored record's is_finalized (immutable record) to 'Finalized'; it does not read report_state. "
            "'Compiled by' shows an internal key prefix."
        ]
        if "Finalized" in reports_txt
        else [],
    )
    dash, eng = text("dashboard"), text("engagement_detail")
    drift = "14" not in dash and findings_n == 14
    acc.record(
        step_id="CZ-25",
        area="browser_ui",
        capability="Dashboard and engagement metrics",
        executed_path="/dashboard, /engagement/{id} ← GET …/summary",
        expected=f"{findings_n} open findings, 2 critical shown",
        actual=("dashboard metrics empty ('—'); " if drift else "metrics shown; ")
        + ("engagement page says 'all resolved'" if "all resolved" in eng else ""),
        status="FAIL" if drift or "all resolved" in eng else "PASS",
        blocking="P1" if drift or "all resolved" in eng else "none",
        limitations=[
            "Contract drift: portal reads open_findings/critical_findings/scan_results; core returns "
            "open_findings_count/critical_findings_count/total_scan_results. Chips then show 'Completed'."
        ]
        if drift
        else [],
    )
    road = text("remediation")
    unsupported_timing = (
        "days" in road.lower() or "weeks" in road.lower() or "months" in road.lower()
    )
    acc.record(
        step_id="CZ-26",
        area="browser_ui",
        capability="Remediation roadmap",
        executed_path="/remediation ← GET …/remediation-roadmap",
        expected="all findings with recorded guidance; no invented timelines",
        actual=(
            "roadmap displays unsupported timing"
            if unsupported_timing
            else "roadmap renders without asserted remediation timing"
        ),
        status="FAIL" if unsupported_timing else "PASS",
        blocking="P2" if unsupported_timing else "none",
    )
    cov = text("coverage")
    acc.record(
        step_id="CZ-27",
        area="browser_ui",
        capability="Coverage page",
        executed_path="/coverage ← questionnaires",
        expected="collection limitations visible to the customer",
        actual=(
            "collection limitations shown or explicitly unavailable before release"
            if "Collection completeness and limitations" in cov
            else "collection limitations section missing"
        ),
        status="PASS" if "Collection completeness and limitations" in cov else "FAIL",
        blocking="none" if "Collection completeness and limitations" in cov else "P2",
        limitations=[
            "Draft report restrictions prevent disclosure of unreleased report proof details; coverage is explicitly marked unavailable."
        ]
        if "unavailable until a report is released" in cov
        else [],
    )
    intact = (
        bool(allowed_pdf.get("downloaded"))
        and allowed_pdf.get("utf8_replacement_sequences") == 0
        and bool(allowed_pdf.get("startxref_matches"))
        and bool(allowed_pdf.get("binary_header_intact"))
        and bool(allowed_pdf.get("x_report_state_forwarded"))
        and bool(allowed_pdf.get("x_manifest_hash_forwarded"))
        and bool(allowed_pdf.get("report_id_forwarded"))
        and bool(allowed_pdf.get("report_version_forwarded"))
        and bool(allowed_pdf.get("content_disposition"))
        and bool(allowed_pdf.get("visible_state_marking_every_page"))
    )
    allowed_items = (res("api_allowed_draft_report").get("body") or {}).get(
        "items"
    ) or []
    canonical_allowed = next(
        (
            item
            for item in allowed_items
            if item.get("report_id") == allowed_pdf.get("report_id_forwarded")
        ),
        None,
    )
    identity_consistent = bool(canonical_allowed) and (
        str(canonical_allowed.get("version"))
        == str(allowed_pdf.get("report_version_forwarded"))
        and canonical_allowed.get("manifest_hash")
        == allowed_pdf.get("x_manifest_hash_forwarded")
        and (canonical_allowed.get("report_state") or {}).get("state")
        == allowed_pdf.get("x_report_state_forwarded")
    )
    intact = intact and identity_consistent
    acc.record(
        step_id="CZ-29",
        area="report_correctness",
        capability="Byte integrity of the PDF downloaded via the portal",
        executed_path="browser fetch through the BFF proxy → bytes parsed in Python",
        expected="byte-intact PDF (no UTF-8 replacement, valid xref), state/identity headers relayed",
        actual=json.dumps(
            {
                k: allowed_pdf.get(k)
                for k in (
                    "bytes",
                    "utf8_replacement_sequences",
                    "binary_header_intact",
                    "startxref_matches",
                    "x_report_state_forwarded",
                    "x_manifest_hash_forwarded",
                    "report_id_forwarded",
                    "report_version_forwarded",
                    "content_disposition",
                    "visible_state_marking_every_page",
                )
            }
        ),
        status="PASS"
        if intact
        else "FAIL"
        if allowed_pdf.get("status") == 200
        else "PARTIAL"
        if pdf.get("denied")
        else "NOT_TESTED",
        blocking="none" if intact or allowed_pdf.get("status") != 200 else "P1",
        limitations=[]
        if intact
        else [
            "The explicitly permitted customer draft was not successfully downloaded and byte-verified."
        ]
        if allowed_pdf.get("status") != 200
        else ["PDF bytes or required identity/state headers failed validation."],
        evidence={
            "restricted_download_denied": pdf.get("denied"),
            "canonical_identity_consistent": identity_consistent,
            "allowed_download": {k: v for k, v in allowed_pdf.items() if k != "b64"},
        },
    )
    errs = [
        c
        for c in log.get("console", [])
        if c["type"] in ("error", "exception")
        and not (
            ("/favicon.ico" in c.get("url", ""))
            or (
                "verification-bundle" in c.get("url", "") and "404" in c.get("text", "")
            )
            or (
                c.get("url", "").endswith(".pdf")
                or "export?format=pdf" in c.get("url", "")
            )
            and "403" in c.get("text", "")
            or "status of 403" in c.get("text", "")
            or "redirected from" in c.get("text", "")
            and "/login?next=" in c.get("text", "")
        )
    ]
    acc.record(
        step_id="CZ-28",
        area="browser_ui",
        capability="Browser console health",
        executed_path="CDP Runtime/Log events across all steps",
        expected="no application errors",
        actual=f"{len(errs)} unexpected console errors; {len(log.get('console', []))} total entries",
        status="PARTIAL" if errs else "PASS",
        blocking="P2" if errs else "none",
        evidence={"console": log.get("console", [])[:30]},
    )
    (out / "browser_acceptance_matrix.json").write_text(
        json.dumps(acc.to_dict(), indent=2, default=str)
    )


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
            k: v
            for k, v in ids.items()
            if k not in ("grant_secret", "permitted_grant_secret", "bff_key")
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
        api = f"{portal}/api/core"

        def fetch_js(path: str, method: str = "GET", body: str | None = None) -> str:
            opts = (
                f"{{method:'{method}'"
                + (
                    f",headers:{{'Content-Type':'application/json'}},body:{json.dumps(body)}"
                    if body
                    else ""
                )
                + "}"
            )
            return (
                f"fetch('{path}',{opts}).then(async r=>{{const t=r.headers.get('content-type')||'';"
                "const b=t.includes('json')?await r.json():{bytes:(await r.arrayBuffer()).byteLength};"
                "return {status:r.status,type:t,state:r.headers.get('x-report-state'),body:b};})"
            )

        def page(name: str, path: str) -> dict[str, Any]:
            return {"name": name, "url": f"{portal}{path}", "shot": True, "settle": 12}

        steps: list[dict[str, Any]] = [
            page("login_page", "/login"),
            {"name": "login", "js": login_js},
            page("dashboard", f"/dashboard?e={eid}"),
            page("engagement_detail", f"/engagement/{eid}"),
            page("findings", f"/findings?e={eid}"),
            page("remediation", f"/remediation?e={eid}"),
            page("reports", f"/reports?e={eid}"),
            page("coverage", f"/coverage?e={eid}"),
            {
                "name": "api_engagement_list_CZ18",
                "js": fetch_js(f"{api}/field-assessment/engagements?limit=100"),
            },
            {
                "name": "api_findings",
                "js": fetch_js(
                    f"{api}/field-assessment/engagements/{eid}/findings?limit=100"
                ),
            },
            {
                "name": "api_reports",
                "js": fetch_js(f"{api}/field-assessment/engagements/{eid}/reports"),
            },
            {
                "name": "pdf_download_CZ17",
                # Downloaded bytes are returned (base64) and parsed in Python.
                "js": (
                    f"fetch('{api}/field-assessment/engagements/{eid}/reports/{v}/export?format=pdf')"
                    ".then(async r=>{const b=new Uint8Array(await r.arrayBuffer());let s='';"
                    "for(let i=0;i<b.length;i+=8192){s+=String.fromCharCode.apply(null,b.subarray(i,i+8192));}"
                    "return {status:r.status,type:r.headers.get('content-type'),"
                    "state:r.headers.get('x-report-state'),b64:btoa(s)};})"
                ),
            },
            {
                "name": "api_portal_workspace_reports_CZ19",
                "js": fetch_js(f"{api}/portal/engagement/reports?engagement_id={eid}"),
            },
            {
                "name": "write_attempt_generate_report",
                "js": fetch_js(
                    f"{api}/field-assessment/engagements/{eid}/reports",
                    "POST",
                    json.dumps({"report_type": "full_assessment"}),
                ),
            },
            {
                "name": "api_other_engagement_findings",
                "js": fetch_js(f"{api}/field-assessment/engagements/{other}/findings"),
            },
            page("access_denied_other_engagement", f"/engagement/{other}"),
            {
                "name": "logout",
                "js": "fetch('/api/auth/logout',{method:'POST'}).then(r=>r.status)",
            },
            {
                "name": "api_after_logout",
                "js": fetch_js(f"{api}/field-assessment/engagements/{eid}/findings"),
            },
            page("after_logout_dashboard", f"/dashboard?e={eid}"),
            page("login_permitted_page", "/login"),
            {
                "name": "login_permitted_draft",
                "js": (
                    "fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},"
                    f"body:JSON.stringify({{password:{json.dumps(ids['permitted_grant_secret'])}}})}})"
                    ".then(r=>r.status)"
                ),
            },
            {
                "name": "api_allowed_draft_report",
                "js": fetch_js(
                    f"{api}/field-assessment/engagements/{ids['permitted_engagement_id']}/reports"
                ),
            },
            {
                "name": "pdf_download_allowed_CZ17",
                "js": (
                    f"fetch('{api}/field-assessment/engagements/{ids['permitted_engagement_id']}/reports/"
                    f"{ids['permitted_report_version']}/export?format=pdf')"
                    ".then(async r=>{const b=new Uint8Array(await r.arrayBuffer());let s='';"
                    "for(let i=0;i<b.length;i+=8192){s+=String.fromCharCode.apply(null,b.subarray(i,i+8192));}"
                    "return {status:r.status,type:r.headers.get('content-type'),"
                    "state:r.headers.get('x-report-state'),manifest_hash:r.headers.get('x-manifest-hash'),"
                    "report_id:r.headers.get('x-report-id'),report_version:r.headers.get('x-report-version'),"
                    "disposition:r.headers.get('content-disposition'),b64:btoa(s)};})"
                ),
            },
        ]
        cdp = asyncio.run(_cdp(ws_url, steps, out))
        log["steps"] = cdp["steps"]
        log["console"] = cdp["console"]
        log["network"] = cdp["network"]
        log["pdf_via_portal"] = _check_downloaded_pdf(cdp["steps"], out)
        log["pdf_allowed_via_portal"] = _check_downloaded_pdf(
            cdp["steps"], out, step_name="pdf_download_allowed_CZ17"
        )
        _browser_matrix(log, out)
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
