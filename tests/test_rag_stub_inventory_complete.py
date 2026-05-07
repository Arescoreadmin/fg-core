"""Inventory completeness check for RAG stub removal documentation.

This test verifies that the RAG stub inventory document exists and is
non-empty. It is a pure presence and completeness check that always passes.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INVENTORY_PATH = REPO / "docs/ai/RAG_STUB_INVENTORY.md"
STUB_MODULE_PATH = REPO / "services/ai_plane_extension/rag_stub.py"
SEED_FILE_PATH = REPO / "seeds/rag_stub_sources_v1.json"
CI_SCRIPT_PATH = REPO / "tools/ci/check_rag_stub_references.py"


def test_rag_stub_inventory_exists_and_is_non_empty() -> None:
    """Inventory document must exist and have substantive content."""
    assert INVENTORY_PATH.exists(), (
        f"RAG stub inventory document not found at {INVENTORY_PATH}"
    )
    content = INVENTORY_PATH.read_text(encoding="utf-8")
    assert len(content) > 500, "Inventory document appears to be empty or minimal"


def test_rag_stub_inventory_contains_required_sections() -> None:
    """Inventory document must contain all required section headers."""
    content = INVENTORY_PATH.read_text(encoding="utf-8")
    required_sections = [
        "## Current Architecture",
        "## File Inventory",
        "## Import Graph",
        "## Runtime Execution Paths",
        "## Stub Metadata Surfaces",
        "## Known Fake Grounding Behavior",
        "## Risk Areas for Replacement",
        "## Security Concerns",
        "## Tenant Isolation Concerns",
        "## Recommended Removal Order",
    ]
    for section in required_sections:
        assert section in content, (
            f"Required section {section!r} missing from RAG stub inventory"
        )


def test_rag_stub_module_is_catalogued_in_inventory() -> None:
    """Inventory must reference the stub module path."""
    content = INVENTORY_PATH.read_text(encoding="utf-8")
    assert "rag_stub.py" in content, (
        "Inventory must reference services/ai_plane_extension/rag_stub.py"
    )


def test_rag_stub_seed_file_is_catalogued_in_inventory() -> None:
    """Inventory must reference the stub seed file."""
    content = INVENTORY_PATH.read_text(encoding="utf-8")
    assert "rag_stub_sources_v1.json" in content, (
        "Inventory must reference seeds/rag_stub_sources_v1.json"
    )


def test_rag_stub_module_still_exists_on_disk() -> None:
    """Stub module must still exist — this PR makes no runtime changes."""
    assert STUB_MODULE_PATH.exists(), (
        f"rag_stub.py not found at {STUB_MODULE_PATH} — "
        "this PR is reconnaissance only; no module should be deleted yet"
    )


def test_rag_stub_seed_file_still_exists_on_disk() -> None:
    """Seed file must still exist — this PR makes no runtime changes."""
    assert SEED_FILE_PATH.exists(), (
        f"Seed file not found at {SEED_FILE_PATH} — "
        "this PR is reconnaissance only; no file should be deleted yet"
    )


def test_rag_stub_ci_visibility_script_exists() -> None:
    """CI visibility script must exist."""
    assert CI_SCRIPT_PATH.exists(), (
        f"CI visibility script not found at {CI_SCRIPT_PATH}"
    )


def test_rag_stub_ci_visibility_script_exits_zero() -> None:
    """CI visibility script must always exit 0."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, str(CI_SCRIPT_PATH)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"check_rag_stub_references.py exited {result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "RAG Stub Reference Visibility Report" in result.stdout
