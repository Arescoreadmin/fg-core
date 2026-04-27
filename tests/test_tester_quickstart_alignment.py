"""
Alignment tests for docs/tester_quickstart.md and docs/tester_collection.json.

Validates that the canonical tester journey documented in Task 10.2 is:
- consistent with the seeded environment from Task 10.1 (tools/seed/run_seed.py)
- references real route paths from the admin gateway
- references the canonical audit verification tool (tools/verify_bundle.py)
- contains the mandatory canonical tester journey folder in the collection

Matches pytest -k 'quickstart and audit' and pytest -k 'docs or collection or quickstart'.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
QUICKSTART = REPO_ROOT / "docs" / "tester_quickstart.md"
COLLECTION = REPO_ROOT / "docs" / "tester_collection.json"
SEED_SCRIPT = REPO_ROOT / "tools" / "seed" / "run_seed.py"
VERIFY_BUNDLE = REPO_ROOT / "tools" / "verify_bundle.py"


# ---------------------------------------------------------------------------
# Fixture: load collection once
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def collection() -> dict:
    assert COLLECTION.exists(), f"Collection not found: {COLLECTION}"
    return json.loads(COLLECTION.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def quickstart_text() -> str:
    assert QUICKSTART.exists(), f"Quickstart not found: {QUICKSTART}"
    return QUICKSTART.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Seed prerequisites
# ---------------------------------------------------------------------------


def test_docs_seed_script_exists() -> None:
    """Task 10.1 canonical seed script must exist."""
    assert SEED_SCRIPT.exists(), f"Seed script missing: {SEED_SCRIPT}"


def test_docs_verify_bundle_tool_exists() -> None:
    """tools/verify_bundle.py must exist — required for CTJ-7."""
    assert VERIFY_BUNDLE.exists(), f"verify_bundle tool missing: {VERIFY_BUNDLE}"


# ---------------------------------------------------------------------------
# Quickstart audit alignment
# ---------------------------------------------------------------------------


def test_quickstart_audit_path_references_seed(quickstart_text: str) -> None:
    """Quickstart must reference the canonical seed command."""
    assert "run_seed.py" in quickstart_text, (
        "Quickstart must reference 'tools/seed/run_seed.py' in the canonical tester journey"
    )


def test_quickstart_audit_path_references_verify_bundle(quickstart_text: str) -> None:
    """Quickstart canonical journey must reference tools/verify_bundle.py."""
    assert "verify_bundle.py" in quickstart_text, (
        "Quickstart must reference 'tools/verify_bundle.py' for evidence bundle verification"
    )


def test_quickstart_audit_path_references_export_path(quickstart_text: str) -> None:
    """Quickstart must reference export_path from seed output."""
    assert "export_path" in quickstart_text, (
        "Quickstart must reference 'export_path' from the seed bootstrap state"
    )


def test_quickstart_audit_path_references_session_id(quickstart_text: str) -> None:
    """Quickstart must reference session_id from seed output."""
    assert "session_id" in quickstart_text, (
        "Quickstart must reference 'session_id' from the seed bootstrap state"
    )


def test_quickstart_audit_path_references_audit_search(quickstart_text: str) -> None:
    """Quickstart canonical journey must reference the audit search endpoint."""
    assert "/admin/audit/search" in quickstart_text, (
        "Quickstart must reference GET /admin/audit/search as the audit retrieval step"
    )


def test_quickstart_audit_path_references_audit_export(quickstart_text: str) -> None:
    """Quickstart canonical journey must reference the audit export endpoint."""
    assert "/admin/audit/export" in quickstart_text, (
        "Quickstart must reference POST /admin/audit/export as the export step"
    )


def test_quickstart_audit_key_requirement_documented(quickstart_text: str) -> None:
    """Quickstart must document that AG_CORE_API_KEY needs audit:read scope."""
    assert "audit:read" in quickstart_text, (
        "Quickstart must document that AG_CORE_API_KEY requires 'audit:read' scope "
        "for audit proxy calls"
    )


def test_quickstart_canonical_path_uses_token_exchange(quickstart_text: str) -> None:
    """Quickstart canonical journey must use OIDC token-exchange, not dev bypass."""
    assert "/auth/token-exchange" in quickstart_text, (
        "Quickstart canonical journey must reference POST /auth/token-exchange "
        "as the production-aligned authentication path"
    )


def test_quickstart_audit_tenant_scoped_to_seed(quickstart_text: str) -> None:
    """Quickstart audit steps must use the canonical seed tenant."""
    assert "tenant-seed-primary" in quickstart_text, (
        "Quickstart audit steps must reference the canonical seed tenant 'tenant-seed-primary'"
    )


# ---------------------------------------------------------------------------
# Collection structure
# ---------------------------------------------------------------------------


def test_collection_is_valid_postman_v21(collection: dict) -> None:
    """Collection must be valid Postman v2.1 format."""
    assert "info" in collection
    schema = collection["info"].get("schema", "")
    assert "v2.1" in schema, f"Expected Postman v2.1 schema, got: {schema}"


def test_collection_has_canonical_journey_folder(collection: dict) -> None:
    """Collection must have a folder named '0 — Canonical Tester Journey'."""
    names = [item.get("name", "") for item in collection.get("item", [])]
    assert any("Canonical Tester Journey" in name for name in names), (
        f"Collection must have a '0 — Canonical Tester Journey' folder. Found folders: {names}"
    )


def test_collection_canonical_journey_has_audit_steps(collection: dict) -> None:
    """Canonical journey folder must include audit search and export steps."""
    canonical_folder = next(
        (
            item
            for item in collection.get("item", [])
            if "Canonical Tester Journey" in item.get("name", "")
        ),
        None,
    )
    assert canonical_folder is not None, "Canonical tester journey folder not found"

    requests_in_folder = canonical_folder.get("item", [])
    urls = []
    for req in requests_in_folder:
        raw_url = req.get("request", {}).get("url", {})
        if isinstance(raw_url, dict):
            urls.append(raw_url.get("raw", ""))
        elif isinstance(raw_url, str):
            urls.append(raw_url)

    audit_search_present = any("audit/search" in u for u in urls)
    audit_export_present = any("audit/export" in u for u in urls)

    assert audit_search_present, (
        f"Canonical journey must include GET /admin/audit/search. URLs found: {urls}"
    )
    assert audit_export_present, (
        f"Canonical journey must include POST /admin/audit/export. URLs found: {urls}"
    )


def test_collection_canonical_journey_has_auth_step(collection: dict) -> None:
    """Canonical journey folder must include an authentication step."""
    canonical_folder = next(
        (
            item
            for item in collection.get("item", [])
            if "Canonical Tester Journey" in item.get("name", "")
        ),
        None,
    )
    assert canonical_folder is not None

    requests_in_folder = canonical_folder.get("item", [])
    urls = []
    for req in requests_in_folder:
        raw_url = req.get("request", {}).get("url", {})
        if isinstance(raw_url, dict):
            urls.append(raw_url.get("raw", ""))
        elif isinstance(raw_url, str):
            urls.append(raw_url)

    auth_present = any("auth/login" in u or "auth" in u for u in urls)
    assert auth_present, (
        f"Canonical journey must include an auth step. URLs found: {urls}"
    )


def test_collection_canonical_journey_starts_with_health(collection: dict) -> None:
    """Canonical journey's first request must be health check."""
    canonical_folder = next(
        (
            item
            for item in collection.get("item", [])
            if "Canonical Tester Journey" in item.get("name", "")
        ),
        None,
    )
    assert canonical_folder is not None

    requests_in_folder = canonical_folder.get("item", [])
    assert len(requests_in_folder) >= 1, (
        "Canonical journey must have at least one request"
    )

    first_req = requests_in_folder[0]
    raw_url = first_req.get("request", {}).get("url", {})
    if isinstance(raw_url, dict):
        first_url = raw_url.get("raw", "")
    else:
        first_url = str(raw_url)

    assert "health" in first_url, (
        f"First request in canonical journey should be health check, got: {first_url}"
    )


def test_collection_uses_variables(collection: dict) -> None:
    """Collection must define base_url and tenant_id variables."""
    variables = {v["key"]: v for v in collection.get("variable", [])}
    assert "base_url" in variables, "Collection must have base_url variable"
    assert "tenant_id" in variables, "Collection must have tenant_id variable"
    assert variables["tenant_id"]["value"] == "tenant-seed-primary", (
        "tenant_id variable must default to 'tenant-seed-primary' (canonical seed tenant)"
    )


def test_collection_canonical_folder_is_first(collection: dict) -> None:
    """Canonical tester journey folder must be the first folder in the collection."""
    items = collection.get("item", [])
    assert items, "Collection must have at least one item"
    assert "Canonical Tester Journey" in items[0].get("name", ""), (
        f"First collection folder must be '0 — Canonical Tester Journey', got: {items[0].get('name')}"
    )


def test_collection_no_direct_core_routes(collection: dict) -> None:
    """Collection must not reference direct core API routes (non-gateway paths)."""
    core_only_paths = [
        "/audit/cycle/run",
        "/audit/sessions",
        "/audit/reproduce",
        "/ingest",
        "/decisions",
        "/defend",
    ]

    def _collect_urls(items: list) -> list[str]:
        urls = []
        for item in items:
            if "item" in item:
                urls.extend(_collect_urls(item["item"]))
            else:
                raw_url = item.get("request", {}).get("url", {})
                if isinstance(raw_url, dict):
                    urls.append(raw_url.get("raw", ""))
                elif isinstance(raw_url, str):
                    urls.append(raw_url)
        return urls

    all_urls = _collect_urls(collection.get("item", []))
    violations = [
        url
        for url in all_urls
        for path in core_only_paths
        if path in url and "admin" not in url.split(path)[0].rstrip("/")
    ]
    assert not violations, (
        f"Collection must not reference direct core API paths: {violations}"
    )


# ---------------------------------------------------------------------------
# Task 15.2 — Non-bypass tester journey enforcement
# ---------------------------------------------------------------------------

VALIDATE_TESTER_FLOW = REPO_ROOT / "tools" / "auth" / "validate_tester_flow.sh"


def test_quickstart_dev_bypass_marked_non_canonical(quickstart_text: str) -> None:
    """Quickstart must explicitly state that dev bypass is not the canonical tester path."""
    assert "not the canonical tester path" in quickstart_text.lower(), (
        "Quickstart must explicitly state that dev bypass is 'not the canonical tester path'. "
        "Dev bypass must never be presented as the canonical tester flow."
    )


def test_quickstart_bypass_env_var_not_in_ctj_section(quickstart_text: str) -> None:
    """FG_DEV_AUTH_BYPASS must not appear in the Canonical Tester Journey (CTJ) section."""
    # The CTJ section runs from the top of the doc to the first '---' separator
    # that follows the last CTJ-N header. We extract it by splitting on '## Prerequisites'
    # or '## Step 1' which mark the start of the expanded guide.
    ctj_end_markers = ["## Prerequisites", "## Step 1 —"]
    ctj_text = quickstart_text
    for marker in ctj_end_markers:
        if marker in quickstart_text:
            ctj_text = quickstart_text.split(marker)[0]
            break

    assert "FG_DEV_AUTH_BYPASS" not in ctj_text, (
        "FG_DEV_AUTH_BYPASS must not appear in the Canonical Tester Journey (CTJ) section. "
        "The CTJ section must remain OIDC-only."
    )


def test_quickstart_canonical_section_does_not_reference_auth_login(
    quickstart_text: str,
) -> None:
    """The CTJ section must not reference /auth/login (dev bypass endpoint)."""
    ctj_end_markers = ["## Prerequisites", "## Step 1 —"]
    ctj_text = quickstart_text
    for marker in ctj_end_markers:
        if marker in quickstart_text:
            ctj_text = quickstart_text.split(marker)[0]
            break

    assert "/auth/login" not in ctj_text, (
        "The Canonical Tester Journey (CTJ) section must not reference /auth/login. "
        "/auth/login is the dev bypass endpoint and must not appear in the canonical path."
    )


def test_collection_canonical_journey_does_not_use_bypass_endpoint(
    collection: dict,
) -> None:
    """Canonical journey folder must not contain any request to /auth/login (dev bypass)."""
    canonical_folder = next(
        (
            item
            for item in collection.get("item", [])
            if "Canonical Tester Journey" in item.get("name", "")
        ),
        None,
    )
    assert canonical_folder is not None, "Canonical tester journey folder not found"

    bypass_urls = []
    for req in canonical_folder.get("item", []):
        raw_url = req.get("request", {}).get("url", {})
        url = raw_url.get("raw", "") if isinstance(raw_url, dict) else str(raw_url)
        if "/auth/login" in url:
            bypass_urls.append(url)

    assert not bypass_urls, (
        f"Canonical journey folder must not contain requests to /auth/login (dev bypass). "
        f"Found: {bypass_urls}"
    )


def test_collection_canonical_journey_uses_token_exchange(collection: dict) -> None:
    """Canonical journey folder must contain a request to /auth/token-exchange (OIDC path)."""
    canonical_folder = next(
        (
            item
            for item in collection.get("item", [])
            if "Canonical Tester Journey" in item.get("name", "")
        ),
        None,
    )
    assert canonical_folder is not None, "Canonical tester journey folder not found"

    exchange_urls = []
    for req in canonical_folder.get("item", []):
        raw_url = req.get("request", {}).get("url", {})
        url = raw_url.get("raw", "") if isinstance(raw_url, dict) else str(raw_url)
        if "token-exchange" in url or "token_exchange" in url:
            exchange_urls.append(url)

    assert exchange_urls, (
        "Canonical journey folder must contain a request to /auth/token-exchange. "
        "The canonical tester path must use OIDC token exchange, not dev bypass."
    )


def test_validate_tester_flow_uses_oidc_not_bypass() -> None:
    """validate_tester_flow.sh must use OIDC token exchange, not /auth/login bypass."""
    assert VALIDATE_TESTER_FLOW.exists(), (
        f"validate_tester_flow.sh not found: {VALIDATE_TESTER_FLOW}"
    )
    script_text = VALIDATE_TESTER_FLOW.read_text(encoding="utf-8")

    # Must reference token-exchange (OIDC canonical path)
    assert "token-exchange" in script_text, (
        "validate_tester_flow.sh must use /auth/token-exchange (OIDC canonical path). "
        "The script must not rely on dev bypass for tester flow validation."
    )

    # Must NOT use /auth/login as an auth step (bypass endpoint)
    # Note: /auth/login may appear in comments or help text; we check it is not
    # used as a curl target for the authentication step.
    import re

    bypass_curl = re.search(
        r'curl\b[^\n]*["\'].*?/auth/login["\']',
        script_text,
    )
    assert bypass_curl is None, (
        "validate_tester_flow.sh must not use /auth/login in a curl call. "
        f"Found: {bypass_curl.group() if bypass_curl else ''}"
    )


def test_validate_tester_flow_fails_on_regression_not_skip() -> None:
    """validate_tester_flow.sh must hard-fail (exit 1) on auth regression, not silently skip."""
    assert VALIDATE_TESTER_FLOW.exists(), (
        f"validate_tester_flow.sh not found: {VALIDATE_TESTER_FLOW}"
    )
    script_text = VALIDATE_TESTER_FLOW.read_text(encoding="utf-8")

    # Script must use set -e or explicit exit 1 paths — not just skip on all failures
    assert "exit 1" in script_text, (
        "validate_tester_flow.sh must contain explicit 'exit 1' for auth regression failures. "
        "Failures must be hard errors, not silent skips."
    )

    # SKIP (exit 0) is allowed only for unavailable services — confirm it's scoped
    assert "SKIP:" in script_text or "SKIP" in script_text, (
        "validate_tester_flow.sh must distinguish service-unavailable SKIP from real failures."
    )
