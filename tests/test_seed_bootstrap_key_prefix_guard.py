from __future__ import annotations

import pytest

from tools.seed import run_seed


def test_default_seed_keys_have_distinct_prefix_identity() -> None:
    admin_prefix = run_seed._seed_key_prefix_identity(run_seed.DEFAULT_ADMIN_KEY)
    agent_prefix = run_seed._seed_key_prefix_identity(run_seed.DEFAULT_AGENT_KEY)
    assert admin_prefix != agent_prefix


def test_guard_fails_when_seed_prefix_identities_collide() -> None:
    with pytest.raises(run_seed.SeedBootstrapError) as exc:
        run_seed._assert_distinct_key_prefixes(
            admin_key="fg_admin_seed_primary_key_000000000000",
            agent_key="fg_agent_seed_primary_key_000000000000",
        )
    assert "SEED_CONFLICT:key_prefix_collision" in str(exc.value)
