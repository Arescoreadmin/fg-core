from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def _base_url() -> str:
    base_url = (os.getenv("FG_CONTROL_TOWER_BASE_URL") or "").strip()
    if not base_url:
        raise SystemExit(2)
    return base_url.rstrip("/")


def _request_json(
    base_url: str, path: str, headers: dict[str, str]
) -> tuple[int, dict, str | None]:
    req = Request(f"{base_url}{path}", headers=headers, method="GET")
    try:
        with urlopen(req, timeout=30) as resp:
            status = int(getattr(resp, "status", 200))
            payload = resp.read().decode("utf-8")
            request_id = resp.headers.get("x-request-id")
            return status, json.loads(payload) if payload else {}, request_id
    except HTTPError as exc:
        payload = exc.read().decode("utf-8") if exc.fp else ""
        request_id = None
        try:
            parsed = json.loads(payload) if payload else {}
        except Exception:
            parsed = {"raw": payload}
        return int(exc.code), parsed, request_id
    except URLError as exc:
        raise RuntimeError(f"Unable to reach {base_url}: {exc}") from exc


def _emit(artifact: dict) -> None:
    out = Path("artifacts/control_tower_trust_proof.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(artifact, sort_keys=True, indent=2), encoding="utf-8")
    print(out)


def main() -> None:
    run_at = datetime.now(timezone.utc).isoformat()
    build_sha = (
        os.getenv("GITHUB_SHA") or os.getenv("CI_COMMIT_SHA") or "unknown"
    ).strip()
    try:
        base_url = _base_url()
    except SystemExit as exc:
        artifact = {
            "status": "fail",
            "reason": "FG_CONTROL_TOWER_BASE_URL is required (example: http://127.0.0.1:8000)",
            "timestamp": run_at,
            "build_sha": build_sha,
        }
        _emit(artifact)
        raise

    api_key = (os.getenv("FG_CONTROL_TOWER_API_KEY") or "").strip()
    tenant_id = (os.getenv("FG_CONTROL_TOWER_TENANT_ID") or "").strip()

    headers: dict[str, str] = {}
    if api_key:
        headers["X-API-Key"] = api_key
    if tenant_id:
        headers["X-Tenant-ID"] = tenant_id

    artifact: dict = {
        "status": "pass",
        "timestamp": run_at,
        "build_sha": build_sha,
        "base_url": base_url,
    }

    try:
        snapshot_status, snapshot, request_id = _request_json(
            base_url, "/control-tower/snapshot", headers
        )
        verify_status, verify, _ = _request_json(
            base_url, "/forensics/chain/verify", headers
        )
        replay_status, replay, _ = _request_json(
            base_url, "/forensics/chain/verify?limit=1", headers
        )
        export_status, _, _ = _request_json(base_url, "/audit/export", headers)

        chain_pass = bool(verify.get("ok", verify.get("status") == "PASS"))
        replay_pass = bool(replay.get("ok", replay.get("status") == "PASS"))
        clamp = (
            (snapshot.get("tenant") or {}).get("clamp")
            if isinstance(snapshot, dict)
            else None
        )

        artifact.update(
            {
                "snapshot_status": snapshot_status,
                "snapshot_version": snapshot.get("version")
                if isinstance(snapshot, dict)
                else None,
                "tenant_clamp": clamp,
                "chain_verify_status": verify_status,
                "chain_verify_result": "pass" if chain_pass else "fail",
                "replay_verify_status": replay_status,
                "replay_verify_result": "pass" if replay_pass else "fail",
                "audit_export_status": export_status,
                "request_id": request_id,
            }
        )

        if snapshot_status >= 400 or verify_status >= 400 or replay_status >= 400:
            artifact["status"] = "fail"
            artifact["reason"] = "one or more trust proof checks returned non-2xx"
    except Exception as exc:
        artifact["status"] = "fail"
        artifact["reason"] = str(exc)

    _emit(artifact)
    if artifact.get("status") != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
