from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import logging
import os
import random
import socket
import ssl
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request

LOG = logging.getLogger("frostgate.agent")
logging.basicConfig(level=logging.INFO, format='{"level":"%(levelname)s","msg":"%(message)s"}')

WINDOWS_CONFIG = Path(r"C:\ProgramData\FrostGate\agent\config.json")
LINUX_CONFIG = Path("/etc/frostgate/agent/config.json")
WINDOWS_EXPECTED_DIR = Path(r"C:\ProgramData\FrostGate\agent")
LINUX_EXPECTED_DIR = Path("/usr/local/bin")


@dataclass
class AgentConfig:
    api_base_url: str
    enrollment_token: str | None
    device_key: str | None
    device_key_id: str | None
    device_id: str | None
    tenant: str | None
    heartbeat_interval: int = 30
    insecure_allow_http: bool = False
    shutdown_on_tamper: bool = False
    pinned_server_cert_sha256: str | None = None


class AgentRuntime:
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self) -> AgentConfig:
        payload = json.loads(self.config_path.read_text())
        api_base_url = str(payload["api_base_url"]).strip()
        if api_base_url.startswith("http://") and not payload.get("insecure_allow_http", False):
            raise RuntimeError("HTTPS required; set insecure_allow_http=true for development only")
        if api_base_url.startswith("http://"):
            LOG.warning("INSECURE OVERRIDE ENABLED: api_base_url uses http://")
        return AgentConfig(
            api_base_url=api_base_url.rstrip("/"),
            enrollment_token=payload.get("enrollment_token"),
            device_key=payload.get("device_key"),
            device_key_id=payload.get("device_key_id"),
            device_id=payload.get("device_id"),
            tenant=payload.get("tenant"),
            heartbeat_interval=max(5, int(payload.get("heartbeat_interval", 30))),
            insecure_allow_http=bool(payload.get("insecure_allow_http", False)),
            shutdown_on_tamper=bool(payload.get("shutdown_on_tamper", False)),
            pinned_server_cert_sha256=payload.get("pinned_server_cert_sha256"),
        )

    def _save_config(self) -> None:
        payload = self.config.__dict__.copy()
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(payload, indent=2, sort_keys=True))

    def _check_config_permissions(self) -> bool:
        if os.name == "nt":
            # ACL drift is checked in install script; runtime marks suspicious when config is writable by everyone.
            return False
        st_mode = self.config_path.stat().st_mode
        world_writable = bool(st_mode & stat.S_IWOTH)
        return world_writable

    def _ssl_context(self) -> ssl.SSLContext | None:
        if not self.config.api_base_url.startswith("https://"):
            return None
        ctx = ssl.create_default_context()
        return ctx

    def _request(self, path: str, body: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
        data = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        req = request.Request(
            f"{self.config.api_base_url}{path}",
            data=data,
            method="POST",
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        try:
            with request.urlopen(req, timeout=10, context=self._ssl_context()) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except error.HTTPError as exc:
            raise RuntimeError(f"http error: {exc.code}") from exc

    def _sign_headers(self, path: str, body: dict[str, Any]) -> dict[str, str]:
        if not self.config.device_key_id or not self.config.device_key:
            raise RuntimeError("device key material missing")
        ts = str(int(time.time()))
        nonce = hashlib.sha256(f"{ts}:{random.random()}".encode("utf-8")).hexdigest()[:24]
        body_raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        body_hash = hashlib.sha256(body_raw).hexdigest()
        canonical = "\n".join(["POST", path, body_hash, ts, nonce])
        sig = hmac.new(self.config.device_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        return {
            "X-FG-DEVICE-KEY": self.config.device_key_id,
            "X-FG-TS": ts,
            "X-FG-NONCE": nonce,
            "X-FG-SIG": sig,
        }

    def enroll_if_needed(self) -> None:
        if self.config.device_key and self.config.device_key_id:
            return
        if not self.config.enrollment_token:
            raise RuntimeError("no device_key and no enrollment_token")
        device_fingerprint = f"{socket.gethostname()}:{os.name}"
        payload = {
            "enrollment_token": self.config.enrollment_token,
            "device_fingerprint": device_fingerprint,
            "device_name": socket.gethostname(),
            "os": os.name,
            "agent_version": "mvp1.1",
        }
        resp = self._request("/agent/enroll", payload)
        self.config.device_key = str(resp["device_key"])
        self.config.device_key_id = str(resp["device_key_prefix"])
        self.config.device_id = str(resp["device_id"])
        self.config.enrollment_token = None
        self._save_config()

    def tamper_signals(self) -> dict[str, bool]:
        tamper = False
        debugged = False

        if os.name == "nt":
            debugged = bool(ctypes.windll.kernel32.IsDebuggerPresent())
            expected = WINDOWS_EXPECTED_DIR
            tamper = not str(Path(__file__).resolve()).lower().startswith(str(expected).lower())
        else:
            tracer_pid = 0
            status = Path("/proc/self/status")
            if status.exists():
                for line in status.read_text().splitlines():
                    if line.startswith("TracerPid:"):
                        tracer_pid = int(line.split(":", 1)[1].strip())
                        break
            debugged = tracer_pid > 0
            tamper = not str(Path(__file__).resolve()).startswith(str(LINUX_EXPECTED_DIR))

        tamper = tamper or debugged or self._check_config_permissions()
        return {"tamper": tamper, "debugged": debugged}

    def heartbeat_loop(self) -> int:
        while True:
            signals = self.tamper_signals()
            payload = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "agent_version": "mvp1.1",
                "os": os.name,
                "hostname": socket.gethostname(),
                "ip_addrs": [],
                "metrics": {},
                "signals": signals,
            }
            headers = self._sign_headers("/agent/heartbeat", payload)
            resp = self._request("/agent/heartbeat", payload, headers=headers)
            action = resp.get("action", "none")
            if action == "shutdown":
                LOG.warning("server requested shutdown")
                return 0
            if signals.get("tamper") and self.config.shutdown_on_tamper:
                LOG.error("tamper detected, shutting down")
                return 2
            sleep_s = self.config.heartbeat_interval + random.randint(0, 3)
            time.sleep(sleep_s)


def _default_config_path() -> Path:
    return WINDOWS_CONFIG if os.name == "nt" else LINUX_CONFIG


def main() -> int:
    runtime = AgentRuntime(_default_config_path())
    runtime.enroll_if_needed()
    return runtime.heartbeat_loop()


if __name__ == "__main__":
    raise SystemExit(main())
