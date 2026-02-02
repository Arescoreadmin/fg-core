import subprocess
import requests
import os
import pytest

pytestmark = pytest.mark.integration


def _run_seed(mode: str, base_url: str, api_key: str, sqlite_path: str):
    env = {
        **dict(os.environ),
        "SEED_MODE": mode,
        "BASE_URL": base_url,
        "FG_API_KEY": api_key,
        "API_KEY": api_key,
        "FG_SQLITE_PATH": sqlite_path,
        "QUIET": "1",
    }
    subprocess.run(
        ["bash", "-lc", "./scripts/seed_demo_decisions.sh"], env=env, check=True
    )


def test_demo_invariants_spike(base_url, api_key, sqlite_path, clear_decisions):
    _run_seed("spike", base_url, api_key, sqlite_path)

    r = requests.get(
        f"{base_url}/stats/summary", headers={"X-API-Key": api_key}, timeout=10
    )
    assert r.status_code == 200, r.text
    s = r.json()

    assert s["trend_flag"] == "spike", s
    assert s["top_event_type"] == "auth.bruteforce", s
    assert s["most_active_rule"] == "rule:ssh_bruteforce", s

    # “hot window” should generally be riskier than overall 24h
    assert int(s["risk_score_1h"]) >= int(s["risk_score_24h"]), s


def test_demo_invariants_drop(base_url, api_key, sqlite_path, clear_decisions):
    _run_seed("drop", base_url, api_key, sqlite_path)

    r = requests.get(
        f"{base_url}/stats/summary", headers={"X-API-Key": api_key}, timeout=10
    )
    assert r.status_code == 200, r.text
    s = r.json()

    assert s["trend_flag"] == "drop", s
    # drop mode should not show brute force dominating
    assert s["top_event_type"] in ("auth", "info"), s
    assert int(s["risk_score_24h"]) == 0, s
