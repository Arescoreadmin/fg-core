from __future__ import annotations

from datetime import datetime, timezone


ALLOWED_COMMAND_TYPES = {"noop", "refresh_inventory", "refresh_posture"}


class CommandExecutor:
    def execute(self, command: dict) -> dict:
        started_at = datetime.now(timezone.utc).isoformat()
        ctype = command.get("command_type")
        if ctype not in ALLOWED_COMMAND_TYPES:
            status = "rejected"
            summary = f"unsupported command_type: {ctype}"
        else:
            status = "succeeded"
            summary = f"executed {ctype}"
        completed_at = datetime.now(timezone.utc).isoformat()
        return {
            "command_id": command["command_id"],
            "status": status,
            "started_at": started_at,
            "completed_at": completed_at,
            "result_summary": summary,
        }
