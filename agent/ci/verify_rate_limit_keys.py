from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent.app.rate_limit.keys import rate_limit_key


def main() -> None:
    key = rate_limit_key("tenant", "agent", "/v1/agent/events", "supersecret")
    assert key.startswith("tenant:tenant|agent:agent|route:/v1/agent/events|api_key_hash:")
    assert "supersecret" not in key
    print("rate limit key verified")


if __name__ == "__main__":
    main()
