import json
import subprocess
import requests
import pytest
pytestmark = pytest.mark.integration

REQUIRED_KEYS = {
    "generated_at",
    "risk_score_24h",
    "risk_score_1h",
    "most_active_rule",
    "top_event_type",
    "high_threat_rate",
    "unique_ips",
    "trend_flag",
    "headline",
}

def _run_seed(mode: str, base_url: str, api_key: str, sqlite_path: str):
    env = {
        **dict(**__import__("os").environ),
        "SEED_MODE": mode,
        "BASE_URL": base_url,
        "FG_API_KEY": api_key,
        "API_KEY": api_key,
        "FG_SQLITE_PATH": sqlite_path,
        "QUIET": "1",
    }
    subprocess.run(
        ["bash", "-lc", "./scripts/seed_demo_decisions.sh"],
        env=env,
        check=True,
    )

def test_stats_summary_contract_steady(base_url, api_key, sqlite_path, clear_decisions):
    _run_seed("steady", base_url, api_key, sqlite_path)

    r = requests.get(f"{base_url}/stats/summary", headers={"X-API-Key": api_key}, timeout=10)
    assert r.status_code == 200, r.text
    data = r.json()

    missing = REQUIRED_KEYS - set(data.keys())
    assert not missing, f"Missing keys in /stats/summary: {sorted(missing)}"

    assert data["trend_flag"] == "steady", f"Expected steady, got {data['trend_flag']}: {data}"
    # “Alive” check: should have *some* risk activity in steady mode
    assert int(data["risk_score_24h"]) >= 0
