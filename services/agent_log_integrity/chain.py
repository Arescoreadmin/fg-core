from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path


class IntegrityLogChain:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event_type: str, payload: dict) -> dict:
        prev = self.latest_hash()
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "payload": payload,
            "prev_hash": prev,
        }
        entry["current_hash"] = self._hash(entry)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def latest_hash(self) -> str:
        if not self.path.exists():
            return "GENESIS"
        line = ""
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                pass
        if not line:
            return "GENESIS"
        return json.loads(line).get("current_hash", "GENESIS")

    def verify(self) -> bool:
        prev = "GENESIS"
        if not self.path.exists():
            return True
        with self.path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                row = json.loads(raw)
                if row.get("prev_hash") != prev:
                    return False
                expected = self._hash(
                    {
                        "timestamp": row.get("timestamp"),
                        "event_type": row.get("event_type"),
                        "payload": row.get("payload"),
                        "prev_hash": row.get("prev_hash"),
                    }
                )
                if expected != row.get("current_hash"):
                    return False
                prev = row["current_hash"]
        return True

    @staticmethod
    def _hash(entry: dict) -> str:
        return hashlib.sha256(
            json.dumps(entry, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
