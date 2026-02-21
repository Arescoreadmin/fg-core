#!/usr/bin/env python3
from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _read(path: str) -> str:
    return (REPO / path).read_text(encoding="utf-8")


def _parse(path: str) -> ast.AST:
    return ast.parse(_read(path), filename=path)


def _allowlist_paths_for_tenant_assignment(path: str) -> bool:
    return path.startswith("tests/") or path.startswith("tools/ci/fixtures/")


def _has_allow_marker(path: str, marker: str, body: str) -> bool:
    if not _allowlist_paths_for_tenant_assignment(path):
        return False
    return marker in body


def check_no_placeholder_security_tests(failures: list[str]) -> None:
    for path in (REPO / "tests").rglob("test_*.py"):
        body = path.read_text(encoding="utf-8")
        if "assert True" in body and "security" in str(path):
            failures.append(
                f"{path.relative_to(REPO)} contains placeholder assert True"
            )


def check_auth_middleware_enforces(failures: list[str]) -> None:
    body = _read("api/middleware/auth_gate.py")
    required_markers = [
        "verify_api_key_detailed(",
        "request.state.auth = result",
        "status_code=401",
    ]
    missing = [m for m in required_markers if m not in body]
    if missing:
        failures.append(
            "api/middleware/auth_gate.py missing auth enforcement markers: "
            + ", ".join(missing)
        )


def check_no_insecure_prod_overrides(failures: list[str]) -> None:
    body = _read("tools/ci/check_prod_unsafe_config.py")
    for marker in ("fg_auth_db_fail_open", "fg_auth_allow_fallback", "fg_rl_fail_open"):
        if marker not in body:
            failures.append(
                f"tools/ci/check_prod_unsafe_config.py missing unsafe marker {marker}"
            )


def check_network_egress_policy(failures: list[str]) -> None:
    body = _read("api/security_alerts.py")
    if "_validate_alert_webhook_url" not in body:
        failures.append("api/security_alerts.py missing webhook egress validation")
    if "Blocked security alert webhook URL by egress policy" not in body:
        failures.append("api/security_alerts.py missing blocked egress audit log")


def check_stable_error_codes(failures: list[str]) -> None:
    body = _read("api/main.py")
    if "error_code" not in body:
        failures.append("api/main.py missing stable error_code response handling")


def check_ci_prod_webhook_secret_and_no_outbound_bypass(failures: list[str]) -> None:
    body = _read(".github/workflows/ci.yml")
    if "FG_ENV: prod" in body and "FG_WEBHOOK_SECRET" not in body:
        failures.append(".github/workflows/ci.yml prod job missing FG_WEBHOOK_SECRET")

    prod_gate = _read("tools/ci/check_prod_unsafe_config.py")
    for marker in (
        "fg_webhook_allow_unsigned",
        "FORBIDDEN_OUTBOUND_BYPASS_KEYS",
        "prod-like manifest must set FG_WEBHOOK_SECRET",
    ):
        if marker not in prod_gate:
            failures.append(
                "tools/ci/check_prod_unsafe_config.py missing required marker: "
                + marker
            )


def _is_request_state_tenant_attr(node: ast.AST) -> bool:
    if not isinstance(node, ast.Attribute) or node.attr != "tenant_id":
        return False
    state_attr = node.value
    return (
        isinstance(state_attr, ast.Attribute)
        and state_attr.attr == "state"
        and isinstance(state_attr.value, ast.Name)
        and state_attr.value.id == "request"
    )


def _is_result_tenant_attr(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "tenant_id"
        and isinstance(node.value, ast.Name)
        and node.value.id == "result"
    )


def check_middleware_tenant_assignment_is_key_derived(failures: list[str]) -> None:
    path = "api/middleware/auth_gate.py"
    body = _read(path)
    if _has_allow_marker(path, "FG_CI_ALLOW_TENANT_ASSIGNMENT", body):
        return

    tree = ast.parse(body, filename=path)
    assigns: list[tuple[int, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if _is_request_state_tenant_attr(tgt):
                    assigns.append((node.lineno, node.value))

    if not assigns:
        failures.append("auth_gate: missing assignment to request.state.tenant_id")
        return

    bad = [ln for ln, value in assigns if not _is_result_tenant_attr(value)]
    if bad:
        failures.append(
            "auth_gate: request.state.tenant_id must be assigned from result.tenant_id only "
            f"(bad lines: {bad})"
        )


def check_tenant_binding_helper_usage(failures: list[str]) -> None:
    resolution_tree = _parse("api/auth_scopes/resolution.py")
    has_bind = any(
        isinstance(node, ast.FunctionDef) and node.name == "bind_tenant_id"
        for node in ast.walk(resolution_tree)
    )
    if not has_bind:
        failures.append("api/auth_scopes/resolution.py missing bind_tenant_id helper")

    route_files = [
        "api/decisions.py",
        "api/ingest.py",
        "api/keys.py",
        "api/admin.py",
        "api/forensics.py",
        "api/feed.py",
        "api/stats.py",
    ]
    for path in route_files:
        body = _read(path)
        if "bind_tenant_id(" not in body and "tenant_db_required" not in body:
            failures.append(
                f"{path} missing tenant binding dependency/helper usage; add bind_tenant_id or tenant_db_required"
            )


def check_no_unknown_tenant_fallback(failures: list[str]) -> None:
    resolution_path = "api/auth_scopes/resolution.py"
    auth_gate_path = "api/middleware/auth_gate.py"

    resolution_body = _read(resolution_path)
    auth_gate_body = _read(auth_gate_path)

    if _has_allow_marker(
        resolution_path, "FG_CI_ALLOW_UNKNOWN_TENANT", resolution_body
    ):
        return
    if _has_allow_marker(auth_gate_path, "FG_CI_ALLOW_UNKNOWN_TENANT", auth_gate_body):
        return

    resolution_tree = ast.parse(resolution_body, filename=resolution_path)
    auth_gate_tree = ast.parse(auth_gate_body, filename=auth_gate_path)

    bad_unknown: list[int] = []
    for node in ast.walk(resolution_tree):
        if isinstance(node, ast.Constant) and node.value == "unknown":
            bad_unknown.append(getattr(node, "lineno", -1))

    gate_unknown: list[int] = []
    for node in ast.walk(auth_gate_tree):
        if isinstance(node, ast.Constant) and node.value == "unknown":
            gate_unknown.append(getattr(node, "lineno", -1))

    if bad_unknown:
        failures.append(
            "resolution: forbidden tenant fallback marker 'unknown' present "
            f"(lines: {sorted(set(bad_unknown))})"
        )
    if gate_unknown:
        failures.append(
            "auth_gate: forbidden tenant fallback marker 'unknown' present "
            f"(lines: {sorted(set(gate_unknown))})"
        )


def check_enterprise_extension_surfaces(failures: list[str]) -> None:
    required_dirs = [
        "services/compliance_cp_extension",
        "services/enterprise_controls_extension",
        "services/exception_breakglass_extension",
        "services/governance_risk_extension",
        "services/evidence_anchor_extension",
        "services/federation_extension",
        "services/ai_plane_extension",
        "services/plane_registry",
        "services/evidence_index",
        "services/resilience",
    ]
    for rel in required_dirs:
        if not (REPO / rel).exists():
            failures.append(f"missing required enterprise extension directory: {rel}")

    makefile = _read("Makefile")
    required_targets = [
        "compliance-cp-spot:",
        "enterprise-controls-spot:",
        "breakglass-spot:",
        "governance-risk-spot:",
        "evidence-anchor-spot:",
        "federation-spot:",
        "ai-plane-spot:",
        "ai-plane-full:",
        "enterprise-ext-spot:",
        "enterprise-smoke:",
        "plane-registry-spot:",
        "evidence-index-spot:",
        "resilience-smoke:",
        "nuclear-full:",
        "platform-inventory:",
        "openapi-summary:",
        "pr-merge-smoke:",
    ]
    for marker in required_targets:
        if marker not in makefile:
            failures.append(f"Makefile missing enterprise target marker: {marker}")



def check_required_new_governance_assets(failures: list[str]) -> None:
    required_files = [
        "tools/ci/check_openapi_security_diff.py",
        "tools/ci/check_artifact_policy.py",
        "tools/ci/openapi_baseline.json",
        "tools/ci/protected_routes_allowlist.json",
        "tools/ci/artifact_policy_allowlist.json",
        "scripts/generate_platform_inventory.py",
        "scripts/summarize_openapi_changes.py",
    ]
    for rel in required_files:
        if not (REPO / rel).exists():
            failures.append(f"missing required governance asset: {rel}")

def check_federation_jwt_signature_verification(failures: list[str]) -> None:
    """FG-AUD-001: federation service must verify JWT signatures cryptographically.

    The previous implementation decoded base64 payload only — not acceptable in production.
    """
    body = _read("services/federation_extension/service.py")

    forbidden_markers = [
        "simplified implementation for demonstration",
        "without signature verification",
        "In production, you should verify",
    ]
    for marker in forbidden_markers:
        if marker.lower() in body.lower():
            failures.append(
                f"services/federation_extension/service.py contains forbidden marker "
                f"indicating missing JWT signature verification: {marker!r}"
            )

    required_markers = ["_verify_signature", "pyjwt", "InvalidTokenError"]
    for marker in required_markers:
        if marker not in body:
            failures.append(
                f"services/federation_extension/service.py missing JWT signature "
                f"verification marker: {marker!r}"
            )


def check_federation_ssrf_guard(failures: list[str]) -> None:
    """FG-AUD-002: JWKS URL must be derived from config, never from token iss claim."""
    body = _read("services/federation_extension/service.py")

    if "urllib.request.urlopen(url, timeout=5)" in body:
        failures.append(
            "services/federation_extension/service.py: bare urllib.request.urlopen "
            "without SSRF guard detected (FG-AUD-002)"
        )

    required_ssrf_markers = [
        "_assert_safe_federation_url",
        "_fetch_jwks_no_redirect",
        "_NoRedirect",
        "federation_ssrf_blocked",
        "FG_FEDERATION_ISSUER",
    ]
    for marker in required_ssrf_markers:
        if marker not in body:
            failures.append(
                f"services/federation_extension/service.py missing SSRF guard "
                f"marker: {marker!r}"
            )


def check_oidc_follow_redirects_disabled(failures: list[str]) -> None:
    """FG-AUD-005: All outbound OIDC/JWKS HTTP calls must set follow_redirects=False."""
    import re

    for path in ("admin_gateway/auth.py", "admin_gateway/auth/oidc.py"):
        body = _read(path)
        bare = re.findall(r"httpx\.AsyncClient\(\)", body)
        if bare:
            failures.append(
                f"{path}: found {len(bare)} bare httpx.AsyncClient() without "
                "follow_redirects=False (FG-AUD-005)"
            )
        if "follow_redirects=True" in body:
            failures.append(
                f"{path}: follow_redirects=True found — OIDC redirects must be disabled"
            )


def check_rate_limiter_not_hardcoded_fail_open(failures: list[str]) -> None:
    """FG-AUD-007: RedisFirstLimiter must fail closed without explicit FG_RL_FAIL_OPEN=1."""
    body = _read("agent/app/rate_limit/redis_limiter.py")

    if "return self.fallback.allow" in body and "_fail_open_allowed" not in body:
        failures.append(
            "agent/app/rate_limit/redis_limiter.py: memory fallback without "
            "_fail_open_allowed() guard — rate limiter can fail-open (FG-AUD-007)"
        )

    required_markers = ["_fail_open_allowed", "FG_RL_FAIL_OPEN", "fail-closed"]
    for marker in required_markers:
        if marker not in body:
            failures.append(
                f"agent/app/rate_limit/redis_limiter.py missing fail-closed "
                f"guard marker: {marker!r}"
            )


def check_authgate_unmatched_not_fail_open(failures: list[str]) -> None:
    """FG-AUD-006: AuthGateMiddleware must not pass unregistered routes without auth."""
    body = _read("api/middleware/auth_gate.py")

    if '"unmatched"' in body and "unmatched_authed" not in body:
        failures.append(
            'api/middleware/auth_gate.py: "unmatched" gate present without '
            '"unmatched_authed" — unregistered routes bypass auth (FG-AUD-006)'
        )

    if "unmatched_authed" not in body:
        failures.append(
            'api/middleware/auth_gate.py: missing "unmatched_authed" gate stamp — '
            "unregistered routes must require authentication (FG-AUD-006)"
        )


def check_oidc_parse_id_token_not_demo(failures: list[str]) -> None:
    """FG-AUD-003: parse_id_token_claims must not be the insecure demo implementation.

    The forbidden markers below specifically match code artefacts of the insecure
    original implementation.  They are different from documentation that *describes*
    the old broken behaviour (which is acceptable in comments/docstrings referencing
    the fix).
    """
    body = _read("admin_gateway/auth/oidc.py")

    tree = _parse("admin_gateway/auth/oidc.py")

    # Find the parse_id_token_claims function body and check for the old insecure patterns.
    insecure_code_patterns = [
        # The exact comment that appeared in the original insecure implementation.
        "Note: In production, you should verify the JWT signature using the JWKS.",
        "This is a simplified implementation for demonstration.",
        # Old implementation: return {} on any exception — swallows auth errors.
        "return {}",
    ]
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "parse_id_token_claims":
            # Check the function source for insecure patterns by re-reading just those lines.
            import linecache
            func_lines = body.splitlines()[node.lineno - 1:node.end_lineno]
            func_src = "\n".join(func_lines)
            if "return {}" in func_src:
                failures.append(
                    "admin_gateway/auth/oidc.py: parse_id_token_claims returns empty dict {} "
                    "on error — silently swallows auth failures (FG-AUD-003)"
                )
            if (
                "base64.urlsafe_b64decode" in func_src
                and "pyjwt" not in func_src.lower()
                and "jwt.decode" not in func_src
            ):
                failures.append(
                    "admin_gateway/auth/oidc.py: parse_id_token_claims decodes base64 "
                    "without JWT signature verification (FG-AUD-003)"
                )
            break

    required = ["verify_exp", "verify_iss", "verify_aud", "follow_redirects=False"]
    for marker in required:
        if marker not in body:
            failures.append(
                f"admin_gateway/auth/oidc.py parse_id_token_claims missing "
                f"verification marker: {marker!r}"
            )


def main() -> int:
    failures: list[str] = []
    check_no_placeholder_security_tests(failures)
    check_auth_middleware_enforces(failures)
    check_no_insecure_prod_overrides(failures)
    check_network_egress_policy(failures)
    check_stable_error_codes(failures)
    check_ci_prod_webhook_secret_and_no_outbound_bypass(failures)
    check_middleware_tenant_assignment_is_key_derived(failures)
    check_tenant_binding_helper_usage(failures)
    check_no_unknown_tenant_fallback(failures)
    check_enterprise_extension_surfaces(failures)
    check_required_new_governance_assets(failures)
    # FG-AUD-001/002/003/005/006/007 guards (added by security audit).
    check_federation_jwt_signature_verification(failures)
    check_federation_ssrf_guard(failures)
    check_oidc_follow_redirects_disabled(failures)
    check_rate_limiter_not_hardcoded_fail_open(failures)
    check_authgate_unmatched_not_fail_open(failures)
    check_oidc_parse_id_token_not_demo(failures)

    if failures:
        print("security regression gates: FAILED")
        for item in failures:
            print(f" - {item}")
        return 1

    print("security regression gates: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
