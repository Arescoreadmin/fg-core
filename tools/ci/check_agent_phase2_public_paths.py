from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def main() -> int:
    from api.main import build_app
    from api.security.public_paths import PUBLIC_PATHS_EXACT, PUBLIC_PATHS_PREFIX

    os.environ.setdefault("FG_ENV", "test")
    os.environ.setdefault("FG_API_KEY", "ci-test-key-00000000000000000000000000000000")
    os.environ.setdefault("FG_KEY_PEPPER", "ci-test-pepper")
    os.environ.setdefault("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    os.environ.setdefault("FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
    app = build_app()
    exact = set(PUBLIC_PATHS_EXACT)
    prefixes = set(PUBLIC_PATHS_PREFIX)

    if any(prefix.startswith('/agent') for prefix in prefixes):
        print('agent public-path check: FAILED - /agent wildcard prefix is forbidden')
        return 1

    missing: list[str] = []
    for route in app.routes:
        path = getattr(route, 'path', '')
        if not isinstance(path, str):
            continue
        if not path.startswith('/agent/'):
            continue
        if path not in exact:
            missing.append(path)

    if missing:
        print('agent public-path check: FAILED - missing explicit entries:')
        for item in sorted(set(missing)):
            print(f' - {item}')
        return 1

    print('agent public-path check: OK')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
