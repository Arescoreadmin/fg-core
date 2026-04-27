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
from collections.abc import Generator, Sequence
from pathlib import Path
from typing import Any

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


def _iter_collection_items(
    items: Sequence[Any],
) -> Generator[dict[str, Any], None, None]:
    """Recursively yield every item (request or folder) in a collection item list."""
    for item in items:
        yield item
        nested = item.get("item")
        if isinstance(nested, list):
            yield from _iter_collection_items(nested)


def _item_url(item: dict) -> str:
    raw_url = item.get("request", {}).get("url", {})
    if isinstance(raw_url, dict):
        return raw_url.get("raw", "")
    return str(raw_url) if raw_url else ""


def test_collection_canonical_journey_does_not_use_bypass_endpoint(
    collection: dict,
) -> None:
    """Canonical journey folder must not contain /auth/login anywhere (recursive)."""
    canonical_folder = next(
        (
            item
            for item in collection.get("item", [])
            if "Canonical Tester Journey" in item.get("name", "")
        ),
        None,
    )
    assert canonical_folder is not None, "Canonical tester journey folder not found"

    bypass_urls = [
        _item_url(item)
        for item in _iter_collection_items(canonical_folder.get("item", []))
        if "/auth/login" in _item_url(item)
    ]

    assert not bypass_urls, (
        f"Canonical journey folder must not contain requests to /auth/login (dev bypass) "
        f"at any nesting level. Found: {bypass_urls}"
    )


def test_collection_canonical_journey_uses_token_exchange(collection: dict) -> None:
    """Canonical journey folder must contain /auth/token-exchange anywhere (recursive)."""
    canonical_folder = next(
        (
            item
            for item in collection.get("item", [])
            if "Canonical Tester Journey" in item.get("name", "")
        ),
        None,
    )
    assert canonical_folder is not None, "Canonical tester journey folder not found"

    exchange_urls = [
        _item_url(item)
        for item in _iter_collection_items(canonical_folder.get("item", []))
        if "token-exchange" in _item_url(item) or "token_exchange" in _item_url(item)
    ]

    assert exchange_urls, (
        "Canonical journey folder must contain a request to /auth/token-exchange "
        "(searched recursively). The canonical tester path must use OIDC token exchange."
    )


# ---------------------------------------------------------------------------
# Regression: nested bypass detection
# ---------------------------------------------------------------------------


def test_collection_canonical_bypass_detection_catches_nested_folder() -> None:
    """Regression: nested /auth/login inside a sub-folder of canonical journey is detected."""
    synthetic_collection = {
        "item": [
            {
                "name": "0 — Canonical Tester Journey",
                "item": [
                    {
                        "name": "Top-level request",
                        "request": {"url": {"raw": "{{base_url}}/health"}},
                    },
                    {
                        "name": "Sub-folder",
                        "item": [
                            {
                                "name": "Nested bypass request",
                                "request": {"url": {"raw": "{{base_url}}/auth/login"}},
                            }
                        ],
                    },
                ],
            }
        ]
    }
    canonical_folder = synthetic_collection["item"][0]
    bypass_urls = [
        _item_url(item)
        for item in _iter_collection_items(canonical_folder.get("item", []))
        if "/auth/login" in _item_url(item)
    ]
    assert bypass_urls, (
        "Recursive traversal must detect /auth/login nested inside a sub-folder "
        "of the canonical tester journey folder."
    )


def test_collection_canonical_bypass_detection_catches_direct_request() -> None:
    """Regression: direct /auth/login at top level of canonical journey is detected."""
    synthetic_collection = {
        "item": [
            {
                "name": "0 — Canonical Tester Journey",
                "item": [
                    {
                        "name": "Bypass request",
                        "request": {"url": {"raw": "{{base_url}}/auth/login"}},
                    },
                ],
            }
        ]
    }
    canonical_folder = synthetic_collection["item"][0]
    bypass_urls = [
        _item_url(item)
        for item in _iter_collection_items(canonical_folder.get("item", []))
        if "/auth/login" in _item_url(item)
    ]
    assert bypass_urls, (
        "Recursive traversal must detect /auth/login at the direct level of the canonical folder."
    )


def test_collection_canonical_token_exchange_detected_in_nested_folder() -> None:
    """Regression: token-exchange inside a sub-folder of canonical journey is detected."""
    synthetic_collection = {
        "item": [
            {
                "name": "0 — Canonical Tester Journey",
                "item": [
                    {
                        "name": "Sub-folder",
                        "item": [
                            {
                                "name": "OIDC step",
                                "request": {
                                    "url": {"raw": "{{base_url}}/auth/token-exchange"}
                                },
                            }
                        ],
                    }
                ],
            }
        ]
    }
    canonical_folder = synthetic_collection["item"][0]
    exchange_urls = [
        _item_url(item)
        for item in _iter_collection_items(canonical_folder.get("item", []))
        if "token-exchange" in _item_url(item)
    ]
    assert exchange_urls, (
        "Recursive traversal must detect token-exchange nested inside a sub-folder."
    )


def _script_bypass_lines(script_text: str) -> list[str]:
    """Return non-comment script lines that reference /auth/login.

    Strategy:
    1. Join continuation lines (backslash-newline) into logical lines.
    2. Strip comment lines (starting with #).
    3. Report any logical line containing /auth/login.

    This catches:
    - quoted URLs: curl "http://host/auth/login"
    - unquoted URLs: curl http://host/auth/login
    - variable assignments: AUTH_URL="$BASE_URL/auth/login"
    - multiline curl with backslash continuation
    """
    # Join continuation lines
    joined = script_text.replace("\\\n", " ")
    hits = []
    for line in joined.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "/auth/login" in stripped:
            hits.append(stripped)
    return hits


def test_validate_tester_flow_uses_oidc_not_bypass() -> None:
    """validate_tester_flow.sh must use OIDC token exchange, not /auth/login bypass.

    Detects /auth/login in:
    - quoted curl URLs
    - unquoted curl URLs
    - multiline curl commands (backslash continuation)
    - variable assignments used by curl
    """
    assert VALIDATE_TESTER_FLOW.exists(), (
        f"validate_tester_flow.sh not found: {VALIDATE_TESTER_FLOW}"
    )
    script_text = VALIDATE_TESTER_FLOW.read_text(encoding="utf-8")

    # Must reference token-exchange (OIDC canonical path)
    assert "token-exchange" in script_text, (
        "validate_tester_flow.sh must use /auth/token-exchange (OIDC canonical path)."
    )

    # Must NOT contain any non-comment line with /auth/login
    bypass_lines = _script_bypass_lines(script_text)
    assert not bypass_lines, (
        "validate_tester_flow.sh must not reference /auth/login in any executable line. "
        f"Found: {bypass_lines}"
    )


# ---------------------------------------------------------------------------
# Regression: _script_bypass_lines detection hardening
# ---------------------------------------------------------------------------


def test_script_bypass_detection_quoted_url() -> None:
    """_script_bypass_lines catches quoted /auth/login curl URLs."""
    script = 'curl -s "http://localhost:8100/auth/login"\n'
    assert _script_bypass_lines(script), "Must detect quoted /auth/login"


def test_script_bypass_detection_unquoted_url() -> None:
    """_script_bypass_lines catches unquoted /auth/login curl URLs."""
    script = "curl -s http://localhost:8100/auth/login\n"
    assert _script_bypass_lines(script), "Must detect unquoted /auth/login"


def test_script_bypass_detection_variable_assignment() -> None:
    """_script_bypass_lines catches AUTH_URL variable assigned /auth/login."""
    script = 'AUTH_URL="$BASE_URL/auth/login"\ncurl "$AUTH_URL"\n'
    assert _script_bypass_lines(script), (
        "Must detect variable assignment with /auth/login"
    )


def test_script_bypass_detection_multiline_curl() -> None:
    """_script_bypass_lines catches /auth/login in a multiline curl command."""
    script = "curl \\\n  -s \\\n  http://localhost:8100/auth/login\n"
    assert _script_bypass_lines(script), (
        "Must detect /auth/login across continuation lines"
    )


def test_script_bypass_detection_ignores_comments() -> None:
    """_script_bypass_lines does not flag /auth/login in comment lines."""
    script = "# Do not use /auth/login — it is dev bypass\ncurl http://host/health\n"
    assert not _script_bypass_lines(script), "Must not flag /auth/login in comments"


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
