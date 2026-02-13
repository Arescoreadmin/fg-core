from __future__ import annotations

from api.security.public_paths import PUBLIC_PATHS_EXACT, PUBLIC_PATHS_PREFIX

LINTER_PUBLIC_PATH_PREFIXES: tuple[str, ...] = PUBLIC_PATHS_EXACT + PUBLIC_PATHS_PREFIX


def resolve_public_paths(*, include_ui_dev_routes: bool) -> tuple[str, ...]:
    if include_ui_dev_routes:
        return PUBLIC_PATHS_EXACT + PUBLIC_PATHS_PREFIX
    return tuple(
        p for p in PUBLIC_PATHS_EXACT + PUBLIC_PATHS_PREFIX if not p.startswith("/ui")
    )
