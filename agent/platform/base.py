from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class OSInfo:
    system: str
    release: str
    machine: str


class PlatformInterface:
    def get_inventory(self) -> dict:
        raise NotImplementedError

    def get_persistent_id(self) -> str:
        raise NotImplementedError

    def get_os_info(self) -> OSInfo:
        raise NotImplementedError


class PortablePlatform(PlatformInterface):
    def __init__(self, persistent_id_path: str | None = None) -> None:
        self._persistent_id_path = Path(
            persistent_id_path or self._default_persistent_id_path()
        )
        self._persistent_id_degraded = False

    @staticmethod
    def _default_persistent_id_path() -> str:
        home = Path.home()
        if os.name == "posix":
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                return "/var/lib/frostgate-agent/persistent_id.json"
            return str(
                home / ".local" / "share" / "frostgate-agent" / "persistent_id.json"
            )
        return str(home / ".frostgate-agent" / "persistent_id.json")

    @property
    def persistent_id_degraded(self) -> bool:
        return self._persistent_id_degraded

    def get_inventory(self) -> dict:
        info = self.get_os_info()
        return {
            "hostname": socket.gethostname(),
            "system": info.system,
            "release": info.release,
            "machine": info.machine,
            "python": platform.python_version(),
            "persistent_id_degraded": self._persistent_id_degraded,
        }

    def derive_ephemeral_id(self) -> str:
        seed = (
            f"{platform.node()}|{platform.system()}|{platform.machine()}|"
            f"{os.getuid() if hasattr(os, 'getuid') else 'nouid'}"
        )
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()

    def get_persistent_id(self) -> str:
        try:
            self._persistent_id_path.parent.mkdir(parents=True, exist_ok=True)
            if self._persistent_id_path.exists():
                data = json.loads(self._persistent_id_path.read_text(encoding="utf-8"))
                existing = data.get("persistent_id")
                if isinstance(existing, str) and existing:
                    self._persistent_id_degraded = False
                    return existing

            persistent_id = str(uuid.uuid4())
            self._persistent_id_path.write_text(
                json.dumps({"persistent_id": persistent_id}, sort_keys=True),
                encoding="utf-8",
            )
            try:
                self._persistent_id_path.chmod(0o600)
            except PermissionError:
                pass
            self._persistent_id_degraded = False
            return persistent_id
        except Exception:  # noqa: BLE001
            self._persistent_id_degraded = True
            return self.derive_ephemeral_id()

    def get_os_info(self) -> OSInfo:
        return OSInfo(
            system=platform.system(),
            release=platform.release(),
            machine=platform.machine(),
        )
