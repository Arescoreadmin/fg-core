from __future__ import annotations

from dataclasses import dataclass

from agent.core.config import ConfigManager
from agent.core.queue import SQLiteTaskQueue
from agent.runtime.runner import Runner


SAFE_ONLY_TASKS = {"ping", "self_test"}


@dataclass(frozen=True)
class HealthSnapshot:
    queue_depth: int
    deadletter_count: int
    last_success: float | None
    last_error: str | None
    config_hash_age: float | None
    degraded: bool
    queue_quarantined: bool
    queue_assurance_degraded: bool
    config_keyring_degraded: bool


def get_health_snapshot(
    *,
    queue: SQLiteTaskQueue,
    config: ConfigManager,
    runner: Runner,
    now: float,
) -> HealthSnapshot:
    return HealthSnapshot(
        queue_depth=0 if queue.quarantined else queue.depth(),
        deadletter_count=0 if queue.quarantined else queue.deadletter_count(),
        last_success=runner.last_success_at,
        last_error=runner.last_error,
        config_hash_age=config.config_age_seconds(now=now),
        degraded=config.degraded,
        queue_quarantined=queue.quarantined,
        queue_assurance_degraded=queue.sentinel_perm_degraded,
        config_keyring_degraded=config.keyring_degraded,
    )


def is_ready(
    *,
    config: ConfigManager,
    enabled_task_types: set[str],
    queue: SQLiteTaskQueue,
    safe_only_mode: bool = False,
) -> bool:
    if queue.quarantined and not safe_only_mode:
        return False

    effective_safe_only = safe_only_mode or enabled_task_types.issubset(SAFE_ONLY_TASKS)

    if not config.degraded:
        return True
    if effective_safe_only:
        return True

    for task_type in enabled_task_types:
        if config.requires_valid_config(task_type):
            return False
    return True
