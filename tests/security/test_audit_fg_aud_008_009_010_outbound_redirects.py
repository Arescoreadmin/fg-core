"""
Security regression tests for FG-AUD-008, FG-AUD-009, FG-AUD-010.

FG-AUD-008: admin_gateway/audit.py — httpx.AsyncClient must have follow_redirects=False
FG-AUD-009: admin_gateway/routers/admin.py — both httpx clients must have follow_redirects=False
FG-AUD-010: engine/pipeline.py — OPA httpx.Client must have follow_redirects=False

These are static source-text checks that prove the redirect guard is explicit and
cannot silently regress to the default (follow_redirects=True in older httpx,
follow_redirects=False in newer but implicit/version-dependent).

Non-vacuity guarantee: if follow_redirects=False is removed from any call site,
the corresponding assertion below will fail immediately.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def _httpx_clients_without_redirect_false(source: str, pattern: str) -> list[int]:
    """Return 1-based line numbers of httpx client constructions missing follow_redirects=False."""
    bad_lines = []
    for m in re.finditer(pattern, source):
        start = m.start()
        ctx = source[start : start + 300]
        if "follow_redirects" not in ctx:
            lineno = source[:start].count("\n") + 1
            bad_lines.append(lineno)
    return bad_lines


class TestFgAud008AuditFollowRedirects:
    """FG-AUD-008: admin_gateway/audit.py AuditLogger._send_to_core must set follow_redirects=False."""

    def test_asyncclient_has_follow_redirects_false(self):
        source = _read("admin_gateway/audit.py")
        bad = _httpx_clients_without_redirect_false(source, r"httpx\.AsyncClient\(")
        assert bad == [], (
            f"admin_gateway/audit.py: httpx.AsyncClient at lines {bad} missing "
            "follow_redirects=False (FG-AUD-008)"
        )

    def test_follow_redirects_not_true(self):
        source = _read("admin_gateway/audit.py")
        assert "follow_redirects=True" not in source, (
            "admin_gateway/audit.py: follow_redirects=True must never appear (FG-AUD-008)"
        )


class TestFgAud009AdminProxyFollowRedirects:
    """FG-AUD-009: admin_gateway/routers/admin.py proxy clients must set follow_redirects=False."""

    def test_all_asyncclients_have_follow_redirects_false(self):
        source = _read("admin_gateway/routers/admin.py")
        bad = _httpx_clients_without_redirect_false(source, r"httpx\.AsyncClient\(")
        assert bad == [], (
            f"admin_gateway/routers/admin.py: httpx.AsyncClient at lines {bad} missing "
            "follow_redirects=False (FG-AUD-009)"
        )

    def test_follow_redirects_not_true(self):
        source = _read("admin_gateway/routers/admin.py")
        assert "follow_redirects=True" not in source, (
            "admin_gateway/routers/admin.py: follow_redirects=True must never appear (FG-AUD-009)"
        )


class TestFgAud010OpaClientFollowRedirects:
    """FG-AUD-010: engine/pipeline.py OPA httpx.Client must set follow_redirects=False."""

    def test_client_has_follow_redirects_false(self):
        source = _read("engine/pipeline.py")
        bad = _httpx_clients_without_redirect_false(source, r"httpx\.Client\(")
        assert bad == [], (
            f"engine/pipeline.py: httpx.Client at lines {bad} missing "
            "follow_redirects=False (FG-AUD-010)"
        )

    def test_follow_redirects_not_true(self):
        source = _read("engine/pipeline.py")
        assert "follow_redirects=True" not in source, (
            "engine/pipeline.py: follow_redirects=True must never appear (FG-AUD-010)"
        )


class TestFgAud013DebugRoutesAuthNotSwallowed:
    """FG-AUD-013: /_debug/routes auth check must not be wrapped in try/except HTTPException."""

    def test_require_status_auth_not_in_try_block(self):
        source = _read("api/main.py")
        fn_match = re.search(
            r"def debug_routes\(.*?\).*?:(.*?)(?=\n    @app\.|\n    return app\b|\Z)",
            source,
            re.DOTALL,
        )
        if fn_match is None:
            return  # endpoint not present in this build — skip
        fn_body = fn_match.group(1)
        assert not re.search(r"try\s*:\s*\n\s+require_status_auth", fn_body), (
            "api/main.py: debug_routes wraps require_status_auth in try/except — "
            "auth failures silently return HTTP 200 instead of 401/403 (FG-AUD-013)"
        )


class TestFgAud014NoDeadPublicPathsProperty:
    """FG-AUD-014: AuthGateConfig must not have a dead @property public_paths."""

    def test_no_public_paths_property(self):
        import ast

        source = _read("api/middleware/auth_gate.py")
        tree = ast.parse(source, filename="api/middleware/auth_gate.py")
        dead = []
        for node in ast.walk(tree):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "public_paths"
            ):
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Name) and decorator.id == "property":
                        dead.append(node.lineno)
                        break
        assert dead == [], (
            f"api/middleware/auth_gate.py: dead AuthGateConfig.public_paths @property "
            f"at lines {dead} — _is_public() uses public_paths_exact/prefix fields only "
            "(FG-AUD-014)"
        )
