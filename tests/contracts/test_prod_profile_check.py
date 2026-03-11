from scripts.prod_profile_check import ProductionProfileChecker


def test_prod_profile_checker_seeds_missing_compose_interpolation_env(monkeypatch):
    checker = ProductionProfileChecker()

    env = checker._compose_env()

    assert env["REDIS_PASSWORD"]
    assert env["POSTGRES_PASSWORD"]
    assert env["NATS_AUTH_TOKEN"]
    assert env["FG_API_KEY"]
    assert env["FG_AGENT_API_KEY"]
    assert env["FG_WEBHOOK_SECRET"]
    assert env["FG_ENCRYPTION_KEY"]
    assert env["FG_JWT_SECRET"]
