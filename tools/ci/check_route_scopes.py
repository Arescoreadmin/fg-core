# ruff: noqa: E402
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.ci.route_checks import is_public_path, iter_route_records


# Routes that authenticate via a documented alternative mechanism and therefore do
# not use the standard require_scopes/require_permission FastAPI dependency.
# Each exemption must justify the alternative auth pattern.
_EXEMPTIONS: frozenset[str] = frozenset(
    [
        # pnu1. token in X-FG-Portal-Session is the credential. Tenant resolved via
        # SECURITY DEFINER lookup_portal_session_by_fingerprint() (migration 0171).
        # validate_session() enforces auth_version, membership state, and sets RLS
        # context. Standard require_scopes dependency does not apply to this flow.
        "/portal/named-users/me",
    ]
)


def main() -> int:
    api_root = Path("api")
    violations = [
        r
        for r in iter_route_records(api_root)
        if not is_public_path(r.full_path)
        and not r.route_has_scope_dependency
        and r.full_path not in _EXEMPTIONS
    ]

    if violations:
        print("Found non-public routes missing explicit scope dependencies:")
        for v in violations:
            print(f"- {v.file_path}:{v.function_name} [{v.method} {v.full_path}]")
        return 1

    print("OK: all non-public routes declare explicit scope dependencies.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
